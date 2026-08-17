from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization

from .cli import (
    audit_publication,
    command_draft,
    promote,
    read_manifest,
    timestamp,
    write_json_atomic,
)
from .delta import create_publication_delta
from .manifest import (
    ManifestError,
    is_bmsir_plugin_artifact,
    load_private_key,
    load_public_key,
)
from .locations import (
    ARTIFACT_LOCATIONS_NAME,
    ARTIFACT_LOCATIONS_REFERENCE,
    append_artifact_locations,
    release_asset_url,
    sign_artifact_locations,
    verify_artifact_locations,
    verify_location_source,
)
from .manifest import sign_history, verify_history


SAFE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")
VALID_PLATFORMS = {"windows-x64", "macos-arm64"}


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ManifestError(f"{label} is required")
    return result


def _safe_name(value: object, label: str) -> str:
    result = _text(value, label)
    if not SAFE_NAME_RE.fullmatch(result):
        raise ManifestError(f"{label} contains unsafe characters")
    return result


def _resolve(base: Path, value: object, label: str) -> Path:
    path = Path(_text(value, label)).expanduser()
    return (base / path).resolve() if not path.is_absolute() else path.resolve()


def _read_spec(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"release spec is unreadable: {path}") from exc
    spec = _object(value, "release spec")
    if spec.get("schema_version") != 1:
        raise ManifestError("unsupported release spec schema")
    if spec.get("channel") != "test":
        raise ManifestError("prepare-release currently supports only the test channel")
    if "plugin_mandatory" in spec and not isinstance(spec["plugin_mandatory"], bool):
        raise ManifestError("plugin_mandatory must be boolean")
    _safe_name(spec.get("version"), "version")
    _safe_name(spec.get("release_tag"), "release_tag")
    base = _object(spec.get("base"), "base")
    _safe_name(base.get("release_tag"), "base.release_tag")
    _safe_name(base.get("asset_name"), "base.asset_name")
    _safe_name(spec.get("delta_asset_name"), "delta_asset_name")
    _safe_name(spec.get("snapshot_asset_name"), "snapshot_asset_name")
    signing_key_ref = _text(spec.get("signing_key_ref"), "signing_key_ref")
    if any(ord(character) < 32 for character in signing_key_ref):
        raise ManifestError("signing_key_ref is invalid")

    artifact_repository = spec.get("artifact_repository")
    if artifact_repository is not None:
        # Validate the repository using the same strict URL constructor used
        # for every generated location.
        release_asset_url(
            str(artifact_repository),
            str(spec["release_tag"]),
            "validation-placeholder",
        )

    platforms = spec.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise ManifestError("platforms must be a non-empty array")
    seen: set[str] = set()
    for index, raw in enumerate(platforms):
        platform = _object(raw, f"platforms[{index}]")
        name = _text(platform.get("platform"), f"platforms[{index}].platform")
        if name not in VALID_PLATFORMS or name in seen:
            raise ManifestError(f"invalid or duplicate platform: {name}")
        seen.add(name)
        artifacts = platform.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ManifestError(
                f"platforms[{index}].artifacts must be a non-empty array"
            )
        for artifact_index, item in enumerate(artifacts):
            if isinstance(item, str) and item.strip():
                continue
            if not isinstance(item, dict) or set(item) - {
                "path",
                "asset_name",
                "retain_on_pages",
            }:
                raise ManifestError(
                    f"platforms[{index}].artifacts[{artifact_index}] is invalid"
                )
            _text(item.get("path"), "artifact.path")
            _safe_name(item.get("asset_name"), "artifact.asset_name")
            if "retain_on_pages" in item and not isinstance(
                item["retain_on_pages"], bool
            ):
                raise ManifestError("artifact.retain_on_pages must be boolean")
            if artifact_repository is None:
                raise ManifestError(
                    "artifact_repository is required for external artifact entries"
                )
        _text(platform.get("source"), f"platforms[{index}].source")
        localized = (platform.get("notes_ja_file"), platform.get("notes_en_file"))
        if bool(localized[0]) != bool(localized[1]):
            raise ManifestError("localized note files must be supplied together")

    source_commits = _object(spec.get("source_commits"), "source_commits")
    if not source_commits or any(
        not str(key).strip()
        or not re.fullmatch(r"[0-9a-fA-F]{7,64}", str(commit).strip())
        for key, commit in source_commits.items()
    ):
        raise ManifestError("source_commits must contain names and hexadecimal commits")
    server_gate = _object(spec.get("server_gate"), "server_gate")
    client_version = _text(
        server_gate.get("client_version"), "server_gate.client_version"
    )
    if client_version != spec["version"]:
        raise ManifestError("server_gate.client_version must match the release version")
    build_hash = _text(server_gate.get("build_hash"), "server_gate.build_hash").lower()
    if not re.fullmatch(r"[0-9a-f]{7,64}", build_hash):
        raise ManifestError(
            "server_gate.build_hash must be a hexadecimal source identity"
        )
    oraja_commit = str(source_commits.get("oraja") or "").strip().lower()
    if oraja_commit and not (
        oraja_commit.startswith(build_hash) or build_hash.startswith(oraja_commit)
    ):
        raise ManifestError("server_gate.build_hash does not match source_commits.oraja")
    standalone = spec.get("standalone_release_assets", [])
    if not isinstance(standalone, list) or any(
        not isinstance(item, str) or not item.strip() for item in standalone
    ):
        raise ManifestError("standalone_release_assets must be a string array")
    if "plugin_required" in server_gate and not isinstance(
        server_gate["plugin_required"], bool
    ):
        raise ManifestError("server_gate.plugin_required must be boolean")
    if spec.get("plugin_mandatory") and not server_gate.get("plugin_required"):
        raise ManifestError(
            "plugin_mandatory requires server_gate.plugin_required=true"
        )
    if spec.get("plugin_mandatory"):
        for index, platform in enumerate(platforms):
            plugin_paths = [
                str(item if isinstance(item, str) else item.get("path") or "")
                for item in platform["artifacts"]
            ]
            plugins = [
                path
                for path in plugin_paths
                if is_bmsir_plugin_artifact(path)
            ]
            if len(plugins) != 1:
                raise ManifestError(
                    f"platforms[{index}] must contain exactly one direct BMS-IR "
                    "plugin artifact when plugin_mandatory is enabled"
                )
    asset_names: set[str] = {
        str(spec["delta_asset_name"]).casefold(),
        str(spec["snapshot_asset_name"]).casefold(),
    }
    for platform in platforms:
        for item in platform["artifacts"]:
            if not isinstance(item, dict):
                continue
            name = str(item["asset_name"])
            if name.casefold() in asset_names:
                raise ManifestError(f"duplicate release asset name: {name}")
            asset_names.add(name.casefold())
    return spec


def _artifact_items(platform: Mapping[str, Any]) -> list[dict[str, object]]:
    return [
        {"path": item, "external": False, "retain_on_pages": True}
        if isinstance(item, str)
        else {
            "path": str(item["path"]),
            "external": True,
            "asset_name": str(item["asset_name"]),
            "retain_on_pages": bool(item.get("retain_on_pages", False)),
        }
        for item in platform["artifacts"]
    ]


def _key_identity(private_key_path: Path, public_key_path: Path) -> str:
    private_public = load_private_key(private_key_path).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    expected_public = load_public_key(public_key_path).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if private_public != expected_public:
        raise ManifestError(
            "private signing key does not match the expected public key"
        )
    return hashlib.sha256(expected_public).hexdigest()


def _archive_relative(name: str) -> PurePosixPath | None:
    path = PurePosixPath(name)
    if path.is_absolute() or "\\" in name or any(part == ".." for part in path.parts):
        raise ManifestError(f"unsafe snapshot member: {name}")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    return PurePosixPath(*parts) if parts else None


def extract_snapshot(archive_path: Path, destination: Path) -> None:
    """Extract only regular files/directories from a complete snapshot."""
    if not archive_path.is_file():
        raise ManifestError(f"base snapshot is missing: {archive_path}")
    destination.mkdir()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            for member in archive:
                relative = _archive_relative(member.name)
                if relative is None:
                    continue
                target = destination.joinpath(*relative.parts)
                if target.name.startswith("._") and member.isfile():
                    continue
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ManifestError(
                        f"snapshot contains a link or special file: {member.name}"
                    )
                source = archive.extractfile(member)
                if source is None:
                    raise ManifestError(f"snapshot member is unreadable: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                target.chmod(stat.S_IMODE(member.mode))
    except (OSError, tarfile.TarError) as exc:
        raise ManifestError("base snapshot is invalid") from exc


def _pointer_paths(root: Path) -> list[Path]:
    return sorted(root.glob("channels/*/*/manifest.json"))


def _optional_path(platform: dict[str, Any], name: str, spec_dir: Path) -> Path | None:
    value = platform.get(name)
    return _resolve(spec_dir, value, name) if value else None


def _draft_args(
    *,
    spec: dict[str, Any],
    platform: dict[str, Any],
    spec_dir: Path,
    root: Path,
    private_key_path: Path,
    published_at: str,
) -> argparse.Namespace:
    bootstrap = (
        _object(platform.get("bootstrap"), "bootstrap")
        if platform.get("bootstrap")
        else {}
    )
    return argparse.Namespace(
        root=root,
        source=_resolve(spec_dir, platform["source"], "source"),
        private_key=private_key_path,
        channel=spec["channel"],
        platform=platform["platform"],
        version=spec["version"],
        notes_file=_optional_path(platform, "notes_file", spec_dir),
        notes_ja_file=_optional_path(platform, "notes_ja_file", spec_dir),
        notes_en_file=_optional_path(platform, "notes_en_file", spec_dir),
        announcements_file=_optional_path(platform, "announcements_file", spec_dir),
        mandatory=bool(spec.get("mandatory", False)),
        plugin_mandatory=bool(spec.get("plugin_mandatory", False)),
        minimum_launcher_version=str(spec.get("minimum_launcher_version", "0.1.0")),
        launcher_version=spec.get("launcher_version"),
        revoke=[str(value) for value in spec.get("revoked_versions", [])],
        bootstrap_manifest=(
            _resolve(spec_dir, bootstrap["manifest"], "bootstrap.manifest")
            if bootstrap
            else None
        ),
        bootstrap_archive=(
            _resolve(spec_dir, bootstrap["archive"], "bootstrap.archive")
            if bootstrap
            else None
        ),
        bootstrap_url=bootstrap.get("url") if bootstrap else None,
        artifact=[str(item["path"]) for item in _artifact_items(platform)],
        published_at=published_at,
    )


def _file_identity(path: Path, *, display_path: str | None = None) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {
        "path": display_path or str(path),
        "sha256": digest.hexdigest(),
        "size": size,
    }


def prepare_release(
    *,
    spec_path: Path,
    base_archive: Path,
    private_key_path: Path,
    public_key_path: Path,
    output_dir: Path,
) -> Path:
    spec_path = spec_path.resolve()
    base_archive = base_archive.resolve()
    private_key_path = private_key_path.resolve()
    public_key_path = public_key_path.resolve()
    output_dir = output_dir.resolve()
    spec = _read_spec(spec_path)

    # Do this before creating output or staging. A stale key cannot leave a
    # partial tree that looks reusable on the next attempt.
    public_key_sha256 = _key_identity(private_key_path, public_key_path)
    if output_dir.exists():
        raise ManifestError(f"output directory already exists: {output_dir}")

    spec_dir = spec_path.parent
    for index, platform in enumerate(spec["platforms"]):
        source = _resolve(
            spec_dir, platform["source"], f"platforms[{index}].source"
        )
        if not source.is_dir():
            raise ManifestError(f"platform source directory is missing: {source}")
        for artifact in _artifact_items(platform):
            path = source / str(artifact["path"])
            if not path.is_file():
                raise ManifestError(f"platform artifact is missing: {path}")

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        publication = staging / "publication"
        extract_snapshot(base_archive, publication)
        base_pointers = _pointer_paths(publication)
        if not base_pointers:
            raise ManifestError("base snapshot contains no channel pointers")
        audit_publication(publication, base_pointers, public_key_path)

        published_at = str(spec.get("published_at") or timestamp())
        prepared_platforms: list[dict[str, object]] = []
        current_pointers: list[Path] = []
        external_release_uploads: list[dict[str, object]] = []
        external_assets_directory = staging / "release-assets"
        for platform in spec["platforms"]:
            command_draft(
                _draft_args(
                    spec=spec,
                    platform=platform,
                    spec_dir=spec_dir,
                    root=publication,
                    private_key_path=private_key_path,
                    published_at=published_at,
                )
            )
            versioned = (
                publication
                / "channels"
                / spec["channel"]
                / platform["platform"]
                / "manifests"
                / f"{spec['version']}.json"
            )
            pointer = promote(publication, versioned, public_key_path)
            current_pointers.append(pointer)
            manifest = read_manifest(pointer)
            source = _resolve(spec_dir, platform["source"], "source")
            artifact_items = _artifact_items(platform)
            external_items = [item for item in artifact_items if item["external"]]
            if external_items:
                locations_path = (
                    publication
                    / "channels"
                    / spec["channel"]
                    / platform["platform"]
                    / ARTIFACT_LOCATIONS_NAME
                )
                existing_locations: list[dict[str, object]] = []
                if locations_path.exists():
                    value = read_manifest(locations_path)
                    verify_artifact_locations(
                        value, load_private_key(private_key_path).public_key()
                    )
                    existing_locations = value["locations"]
                manifest_by_path = {
                    str(item["path"]): item for item in manifest["artifacts"]
                }
                additions: list[dict[str, object]] = []
                for item in external_items:
                    path = str(item["path"])
                    artifact = manifest_by_path[path]
                    asset_name = str(item["asset_name"])
                    asset_path = external_assets_directory / asset_name
                    external_assets_directory.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source / path, asset_path)
                    url = release_asset_url(
                        str(spec["artifact_repository"]),
                        str(spec["release_tag"]),
                        asset_name,
                    )
                    addition = {
                        "version": str(spec["version"]),
                        "path": path,
                        "sha256": artifact["sha256"],
                        "size": artifact["size"],
                        "url": url,
                        "retain_on_pages": bool(item["retain_on_pages"]),
                    }
                    verify_location_source(addition, asset_path)
                    additions.append(addition)
                    external_release_uploads.append(
                        {
                            "role": "external_artifact",
                            "asset_name": asset_name,
                            **_file_identity(
                                asset_path,
                                display_path=f"release-assets/{asset_name}",
                            ),
                        }
                    )
                locations = append_artifact_locations(
                    existing_locations,
                    additions,
                    channel=spec["channel"],
                    platform=platform["platform"],
                )
                write_json_atomic(
                    locations_path,
                    sign_artifact_locations(
                        locations, load_private_key(private_key_path)
                    ),
                )
                history_path = locations_path.parent / "history.json"
                history = read_manifest(history_path)
                verify_history(
                    history, load_private_key(private_key_path).public_key()
                )
                history["artifact_locations"] = ARTIFACT_LOCATIONS_REFERENCE
                write_json_atomic(
                    history_path,
                    sign_history(history, load_private_key(private_key_path)),
                )
                for item in external_items:
                    if not bool(item["retain_on_pages"]):
                        (
                            publication
                            / "channels"
                            / spec["channel"]
                            / platform["platform"]
                            / "releases"
                            / spec["version"]
                            / str(item["path"])
                        ).unlink()
            prepared_platforms.append(
                {
                    "platform": platform["platform"],
                    "manifest": str(pointer.relative_to(publication)),
                    "artifacts": manifest["artifacts"],
                    "local_artifacts": [
                        _file_identity(source / str(artifact["path"]))
                        for artifact in artifact_items
                    ],
                }
            )

        audit_publication(
            publication,
            _pointer_paths(publication),
            public_key_path,
        )
        delta_path = staging / str(spec["delta_asset_name"])
        create_publication_delta(
            publication, current_pointers, public_key_path, delta_path
        )

        release_uploads: list[dict[str, object]] = external_release_uploads + [
            {
                "role": "signed_delta",
                **_file_identity(delta_path, display_path=delta_path.name),
            }
        ]
        for value in spec.get("standalone_release_assets", []):
            path = _resolve(spec_dir, value, "standalone_release_assets")
            if not path.is_file():
                raise ManifestError(f"standalone release asset is missing: {path}")
            release_uploads.append(
                {"role": "standalone_opt_in", **_file_identity(path)}
            )

        state = {
            "schema_version": 1,
            "status": "prepared",
            "channel": spec["channel"],
            "version": spec["version"],
            "release_tag": spec["release_tag"],
            "published_at": published_at,
            "signing_key_ref": spec["signing_key_ref"],
            "public_key_sha256": public_key_sha256,
            "source_commits": spec["source_commits"],
            "server_gate": spec["server_gate"],
            "platforms": prepared_platforms,
            "upload_policy": (
                "delta_external_and_explicit_standalone"
                if external_release_uploads and spec.get("standalone_release_assets")
                else "delta_plus_external_artifacts"
                if external_release_uploads
                else "delta_plus_explicit_standalone"
                if spec.get("standalone_release_assets")
                else "delta_only"
            ),
            "release_uploads": release_uploads,
            "workflow": {
                "file": "deploy-pages-delta.yml",
                "inputs": {
                    "base_release_tag": spec["base"]["release_tag"],
                    "base_asset_name": spec["base"]["asset_name"],
                    "release_tag": spec["release_tag"],
                    "delta_asset_name": spec["delta_asset_name"],
                    "snapshot_asset_name": spec["snapshot_asset_name"],
                },
            },
        }
        write_json_atomic(staging / "release-state.json", state)
        os.replace(staging, output_dir)
        return output_dir / "release-state.json"
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
