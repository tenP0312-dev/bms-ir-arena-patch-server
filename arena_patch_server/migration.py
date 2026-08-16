from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization

from .cli import audit_publication, read_manifest, write_json_atomic
from .locations import (
    ARTIFACT_LOCATIONS_NAME,
    ARTIFACT_LOCATIONS_REFERENCE,
    build_artifact_locations,
    file_identity,
    release_asset_name,
    release_asset_url,
    sign_artifact_locations,
    verify_artifact_locations,
    verify_location_source,
)
from .manifest import (
    ManifestError,
    load_private_key,
    load_public_key,
    safe_artifact_path,
    sign_history,
    verify_history,
    verify_manifest,
)


def _pointer_paths(root: Path) -> list[Path]:
    return sorted(root.glob("channels/*/*/manifest.json"))


def _key_identity(private_key_path: Path, public_key_path: Path) -> None:
    private_public = load_private_key(private_key_path).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    expected_public = load_public_key(public_key_path).public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if private_public != expected_public:
        raise ManifestError("private signing key does not match the expected public key")


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _asset_name(index: int, source_name: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", source_name).strip(".-") or "artifact"
    suffix = "".join(Path(name).suffixes)[-32:]
    stem_limit = max(1, 180 - len(suffix))
    stem = name[: -len(suffix)] if suffix else name
    return f"payload-{index:05d}-{stem[:stem_limit]}{suffix}"


def _artifact_relative(
    channel: str, platform: str, version: str, artifact_path: str
) -> PurePosixPath:
    return (
        PurePosixPath("channels")
        / channel
        / platform
        / "releases"
        / version
        / safe_artifact_path(artifact_path)
    )


def externalize_publication(
    *,
    root: Path,
    private_key_path: Path,
    public_key_path: Path,
    repository: str,
    release_tag: str,
    output_dir: Path,
    retain_files: list[str] | None = None,
) -> Path:
    """Create a compact, signed copy without mutating the trusted full tree.

    Every immutable manifest artifact is copied once to a flat GitHub Release
    upload directory and receives a signed location. Current release artifacts
    and the latest launcher-bearing release remain on Pages automatically so
    legacy launchers can update before consuming the new index.
    """
    root = root.resolve()
    private_key_path = private_key_path.resolve()
    public_key_path = public_key_path.resolve()
    output_dir = output_dir.resolve()
    _key_identity(private_key_path, public_key_path)
    if output_dir.exists():
        raise ManifestError(f"output directory already exists: {output_dir}")
    pointers = _pointer_paths(root)
    if not pointers:
        raise ManifestError("publication contains no channel pointers")
    audit_publication(root, pointers, public_key_path)
    if any(root.glob(f"channels/*/*/{ARTIFACT_LOCATIONS_NAME}")):
        raise ManifestError(
            "externalize-publication requires the retained full legacy snapshot"
        )

    explicit_retain: set[str] = set()
    for raw in retain_files or []:
        value = str(raw).strip()
        path = PurePosixPath(value)
        if (
            not value
            or "\\" in value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ManifestError(f"unsafe retained publication path: {value}")
        explicit_retain.add(path.as_posix())

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        publication = staging / "publication"
        release_assets = staging / "release-assets"
        publication.mkdir()
        release_assets.mkdir()
        # Copy signed metadata only. Artifacts are added below solely when the
        # compatibility policy explicitly retains them.
        for source in sorted(root.rglob("*")):
            if source.is_symlink():
                raise ManifestError("publication tree contains a symlink")
            if not source.is_file():
                continue
            relative = source.relative_to(root)
            if "releases" in relative.parts:
                continue
            _copy(source, publication / relative)

        private_key = load_private_key(private_key_path)
        public_key = load_public_key(public_key_path)
        unique_payloads: dict[tuple[str, int], tuple[str, Path]] = {}
        platform_states: list[dict[str, object]] = []
        all_artifact_paths: set[str] = set()
        auto_retain: set[str] = set()

        for pointer in pointers:
            current = read_manifest(pointer)
            verify_manifest(current, public_key)
            channel = str(current["channel"])
            platform = str(current["platform"])
            base = root / "channels" / channel / platform
            history_path = base / "history.json"
            history = read_manifest(history_path)
            verify_history(history, public_key)
            latest_launcher = history.get("latest_launcher")
            if latest_launcher is None:
                raise ManifestError(
                    f"launcher-first migration requires latest_launcher: {channel}/{platform}"
                )
            compatibility_versions = {
                str(current["version"]),
                str(latest_launcher["release_version"]),
            }
            manifests: list[dict[str, object]] = []
            for history_entry in history["versions"]:
                version = str(history_entry["version"])
                manifest_path = base / "manifests" / f"{version}.json"
                manifest = read_manifest(manifest_path)
                verify_manifest(manifest, public_key)
                if (
                    manifest.get("channel") != channel
                    or manifest.get("platform") != platform
                    or str(manifest.get("version")) != version
                ):
                    raise ManifestError("history manifest target mismatch")
                manifests.append(manifest)

            locations: list[dict[str, object]] = []
            for manifest in manifests:
                version = str(manifest["version"])
                for artifact in manifest["artifacts"]:
                    relative = _artifact_relative(
                        channel, platform, version, str(artifact["path"])
                    )
                    relative_text = relative.as_posix()
                    all_artifact_paths.add(relative_text)
                    source = root.joinpath(*relative.parts)
                    identity = (str(artifact["sha256"]), int(artifact["size"]))
                    payload = unique_payloads.get(identity)
                    if payload is None:
                        asset_name = _asset_name(
                            len(unique_payloads) + 1,
                            PurePosixPath(str(artifact["path"])).name,
                        )
                        asset_path = release_assets / asset_name
                        _copy(source, asset_path)
                        payload = (asset_name, asset_path)
                        unique_payloads[identity] = payload
                    asset_name, _asset_path = payload
                    retained = version in compatibility_versions
                    if retained:
                        auto_retain.add(relative_text)
                    locations.append(
                        {
                            "version": version,
                            "path": str(artifact["path"]),
                            "sha256": artifact["sha256"],
                            "size": artifact["size"],
                            "url": release_asset_url(
                                repository, release_tag, asset_name
                            ),
                            "retain_on_pages": retained
                            or relative_text in explicit_retain,
                        }
                    )

            locations_document = build_artifact_locations(
                locations, channel=channel, platform=platform
            )
            compact_base = publication / "channels" / channel / platform
            write_json_atomic(
                compact_base / ARTIFACT_LOCATIONS_NAME,
                sign_artifact_locations(locations_document, private_key),
            )
            compact_history_path = compact_base / "history.json"
            compact_history = read_manifest(compact_history_path)
            compact_history["artifact_locations"] = ARTIFACT_LOCATIONS_REFERENCE
            write_json_atomic(
                compact_history_path, sign_history(compact_history, private_key)
            )
            platform_states.append(
                {
                    "channel": channel,
                    "platform": platform,
                    "versions": len(manifests),
                    "locations": len(locations),
                }
            )

        unknown_retained = explicit_retain - all_artifact_paths
        if unknown_retained:
            raise ManifestError(
                f"retained paths are not signed artifacts: {sorted(unknown_retained)[:3]}"
            )
        retained_paths = auto_retain | explicit_retain
        for relative_text in sorted(retained_paths):
            relative = PurePosixPath(relative_text)
            _copy(
                root.joinpath(*relative.parts), publication.joinpath(*relative.parts)
            )

        audit_publication(
            publication,
            _pointer_paths(publication),
            public_key_path,
            external_assets_directory=release_assets,
        )
        uploads = []
        total_bytes = 0
        for asset in sorted(release_assets.iterdir()):
            size, digest = file_identity(asset)
            total_bytes += size
            uploads.append(
                {
                    "asset_name": asset.name,
                    "path": f"release-assets/{asset.name}",
                    "sha256": digest,
                    "size": size,
                }
            )
        state = {
            "schema_version": 1,
            "status": "prepared",
            "operation": "externalize_publication",
            "repository": repository,
            "release_tag": release_tag,
            "platforms": platform_states,
            "release_uploads": uploads,
            "unique_payloads": len(uploads),
            "external_payload_bytes": total_bytes,
            "retained_pages_artifacts": sorted(retained_paths),
            "source_publication_unchanged": True,
        }
        write_json_atomic(staging / "migration-state.json", state)
        os.replace(staging, output_dir)
        return output_dir / "migration-state.json"
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def stage_external_assets(
    *,
    full_root: Path,
    compact_root: Path,
    public_key_path: Path,
    repository: str,
    release_tag: str,
    output_dir: Path,
) -> tuple[int, int]:
    """Recreate signed migration assets from a trusted full snapshot.

    This is intentionally verification-only: the signed compact publication
    already fixes every URL and artifact identity, so no private key is needed
    on the GitHub runner that performs the large byte transfer.
    """
    full_root = full_root.resolve()
    compact_root = compact_root.resolve()
    public_key_path = public_key_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ManifestError(f"output directory already exists: {output_dir}")
    for protected_root in (full_root, compact_root):
        try:
            output_dir.relative_to(protected_root)
        except ValueError:
            continue
        raise ManifestError("staged assets must be outside the publication roots")

    full_pointers = _pointer_paths(full_root)
    compact_pointers = _pointer_paths(compact_root)
    if not full_pointers or not compact_pointers:
        raise ManifestError("migration publications contain no channel pointers")
    full_relative = {
        path.relative_to(full_root).as_posix() for path in full_pointers
    }
    compact_relative = {
        path.relative_to(compact_root).as_posix() for path in compact_pointers
    }
    if full_relative != compact_relative:
        raise ManifestError("full and compact publication targets differ")
    audit_publication(full_root, full_pointers, public_key_path)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent)
    )
    try:
        public_key = load_public_key(public_key_path)
        identities: dict[str, tuple[str, int]] = {}
        total_bytes = 0
        for compact_pointer in compact_pointers:
            relative = compact_pointer.relative_to(compact_root)
            compact_manifest = read_manifest(compact_pointer)
            verify_manifest(compact_manifest, public_key)
            full_manifest = read_manifest(full_root / relative)
            verify_manifest(full_manifest, public_key)
            if compact_manifest != full_manifest:
                raise ManifestError("full and compact current manifests differ")

            channel = str(compact_manifest["channel"])
            platform = str(compact_manifest["platform"])
            compact_base = compact_root / "channels" / channel / platform
            full_base = full_root / "channels" / channel / platform
            compact_history = read_manifest(compact_base / "history.json")
            full_history = read_manifest(full_base / "history.json")
            verify_history(compact_history, public_key)
            verify_history(full_history, public_key)
            compact_unsigned = dict(compact_history)
            full_unsigned = dict(full_history)
            compact_unsigned.pop("signature", None)
            compact_unsigned.pop("artifact_locations", None)
            full_unsigned.pop("signature", None)
            full_unsigned.pop("artifact_locations", None)
            if compact_unsigned != full_unsigned:
                raise ManifestError("full and compact signed histories differ")

            locations_path = compact_base / ARTIFACT_LOCATIONS_NAME
            locations = read_manifest(locations_path)
            verify_artifact_locations(locations, public_key)
            for location in locations["locations"]:
                asset_name = release_asset_name(str(location["url"]))
                if str(location["url"]) != release_asset_url(
                    repository, release_tag, asset_name
                ):
                    raise ManifestError(
                        "artifact location does not target the requested migration release"
                    )
                identity = (str(location["sha256"]), int(location["size"]))
                previous = identities.get(asset_name)
                if previous is not None:
                    if previous != identity:
                        raise ManifestError(
                            f"release asset name has conflicting identities: {asset_name}"
                        )
                    continue
                source_relative = _artifact_relative(
                    channel,
                    platform,
                    str(location["version"]),
                    str(location["path"]),
                )
                source = full_root.joinpath(*source_relative.parts)
                verify_location_source(location, source)
                _copy(source, staging / asset_name)
                identities[asset_name] = identity
                total_bytes += identity[1]

        audit_publication(
            compact_root,
            compact_pointers,
            public_key_path,
            external_assets_directory=staging,
        )
        os.replace(staging, output_dir)
        return len(identities), total_bytes
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
