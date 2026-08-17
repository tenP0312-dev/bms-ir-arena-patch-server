from __future__ import annotations

import filecmp
import json
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Mapping

from cryptography.hazmat.primitives import serialization

from .delta import _copy_atomic, _expected_directories, _file_set, _read_object
from .locations import (
    ARTIFACT_LOCATIONS_NAME,
    location_for_artifact,
    location_key,
    sign_artifact_locations,
    verify_artifact_locations,
    verify_location_source,
    verify_remote_location,
)
from .manifest import (
    ManifestError,
    VERSION_RE,
    load_private_key,
    load_public_key,
    safe_artifact_path,
    verify_manifest,
)


def _validate_target(channel: str, platform: str, version: str | None = None) -> None:
    if channel not in {"stable", "test"}:
        raise ManifestError("retention channel is invalid")
    if platform not in {"windows-x64", "macos-arm64"}:
        raise ManifestError("retention platform is invalid")
    if version is not None and not VERSION_RE.fullmatch(version):
        raise ManifestError("retention version is invalid")


def _locations_relative(channel: str, platform: str) -> PurePosixPath:
    _validate_target(channel, platform)
    return PurePosixPath("channels") / channel / platform / ARTIFACT_LOCATIONS_NAME


def _release_relative(
    channel: str, platform: str, version: str, artifact_path: str
) -> PurePosixPath:
    _validate_target(channel, platform, version)
    return (
        PurePosixPath("channels")
        / channel
        / platform
        / "releases"
        / version
        / safe_artifact_path(artifact_path)
    )


def _matching_keys(private_key_path: Path, public_key_path: Path) -> None:
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


def _write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as target:
        json.dump(value, target, ensure_ascii=False, sort_keys=True, indent=2)
        target.write("\n")
        temporary = Path(target.name)
    try:
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _manifest_artifact(
    root: Path,
    public_key_path: Path,
    *,
    channel: str,
    platform: str,
    version: str,
    artifact_path: str,
) -> dict[str, object]:
    manifest_path = (
        root
        / "channels"
        / channel
        / platform
        / "manifests"
        / f"{version}.json"
    )
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ManifestError("retained artifact manifest is missing or unsafe")
    manifest = _read_object(manifest_path)
    verify_manifest(manifest, load_public_key(public_key_path))
    if (
        manifest.get("channel") != channel
        or manifest.get("platform") != platform
        or str(manifest.get("version")) != version
    ):
        raise ManifestError("retained artifact manifest target mismatch")
    wanted = safe_artifact_path(artifact_path).casefold()
    matches = [
        artifact
        for artifact in manifest["artifacts"]
        if safe_artifact_path(artifact.get("path")).casefold() == wanted
    ]
    if len(matches) != 1:
        raise ManifestError("retained artifact is not unique in its signed manifest")
    return matches[0]


def retain_artifact_on_pages(
    root: Path,
    private_key_path: Path,
    public_key_path: Path,
    *,
    channel: str,
    platform: str,
    version: str,
    artifact_path: str,
    source: Path,
) -> Path:
    """Add one exact signed artifact as a legacy Pages mirror.

    The artifact identity and external URL remain immutable.  The only signed
    metadata transition is ``retain_on_pages: false`` to ``true``.
    """
    if not root.is_dir():
        raise ManifestError("publication root does not exist")
    _matching_keys(private_key_path, public_key_path)
    locations_path = root.joinpath(*_locations_relative(channel, platform).parts)
    if locations_path.is_symlink() or not locations_path.is_file():
        raise ManifestError("artifact-location index is missing or unsafe")
    locations = _read_object(locations_path)
    public_key = load_public_key(public_key_path)
    verify_artifact_locations(locations, public_key)
    if locations.get("channel") != channel or locations.get("platform") != platform:
        raise ManifestError("artifact-location channel/platform mismatch")

    artifact = _manifest_artifact(
        root,
        public_key_path,
        channel=channel,
        platform=platform,
        version=version,
        artifact_path=artifact_path,
    )
    location = location_for_artifact(locations, version, artifact)
    if location is None:
        raise ManifestError("retained artifact has no signed external location")
    if bool(location["retain_on_pages"]):
        raise ManifestError("artifact is already retained on Pages")
    verify_location_source(location, source)

    destination_relative = _release_relative(
        channel, platform, version, str(artifact["path"])
    )
    destination = root.joinpath(*destination_relative.parts)
    if destination.exists() or destination.is_symlink():
        raise ManifestError("legacy Pages mirror already exists")

    updated = dict(locations)
    updated_entries = [dict(entry) for entry in locations["locations"]]
    wanted = location_key(version, artifact["path"])
    changed = 0
    for entry in updated_entries:
        if location_key(entry["version"], entry["path"]) == wanted:
            entry["retain_on_pages"] = True
            changed += 1
    if changed != 1:
        raise ManifestError("retained artifact location is not unique")
    updated["locations"] = updated_entries
    signed = sign_artifact_locations(updated, load_private_key(private_key_path))

    _copy_atomic(source, destination)
    verify_location_source(location, destination)
    _write_json_atomic(locations_path, signed)
    return destination


def _retention_changes(
    base_locations: Mapping[str, object], updated_locations: Mapping[str, object]
) -> list[dict[str, object]]:
    for field in ("schema_version", "channel", "platform"):
        if base_locations.get(field) != updated_locations.get(field):
            raise ManifestError("retention delta changes location index target")
    base_entries = list(base_locations["locations"])
    updated_entries = list(updated_locations["locations"])
    if len(base_entries) != len(updated_entries):
        raise ManifestError("retention delta cannot add or remove artifact locations")
    updated_by_key = {
        location_key(entry["version"], entry["path"]): entry
        for entry in updated_entries
    }
    changes: list[dict[str, object]] = []
    for base_entry in base_entries:
        key = location_key(base_entry["version"], base_entry["path"])
        updated_entry = updated_by_key.get(key)
        if updated_entry is None:
            raise ManifestError("retention delta cannot add or remove artifact locations")
        if updated_entry == base_entry:
            continue
        expected = dict(base_entry)
        if bool(base_entry["retain_on_pages"]):
            raise ManifestError("retention delta cannot remove or rewrite a retained artifact")
        expected["retain_on_pages"] = True
        if updated_entry != expected:
            raise ManifestError("retention delta may only change retain_on_pages false to true")
        changes.append(dict(updated_entry))
    if not changes:
        raise ManifestError("retention delta does not retain any new artifacts")
    return changes


def create_retention_delta(
    base_root: Path,
    updated_root: Path,
    public_key_path: Path,
    output: Path,
) -> Path:
    """Package only monotonic Pages-retention changes from an audited copy."""
    if not base_root.is_dir() or not updated_root.is_dir():
        raise ManifestError("base and updated publication roots must exist")
    for candidate in (base_root, updated_root):
        try:
            output.resolve().relative_to(candidate.resolve())
        except ValueError:
            continue
        raise ManifestError("retention delta output must be outside publication roots")

    public_key = load_public_key(public_key_path)
    base_files = _file_set(base_root)
    updated_files = _file_set(updated_root)
    removed = base_files - updated_files
    if removed:
        raise ManifestError(f"retention update removes publication files: {sorted(removed)[:3]}")

    changed_metadata: set[str] = set()
    retained_files: set[str] = set()
    for relative in sorted(base_files & updated_files):
        base_path = base_root.joinpath(*PurePosixPath(relative).parts)
        updated_path = updated_root.joinpath(*PurePosixPath(relative).parts)
        if filecmp.cmp(base_path, updated_path, shallow=False):
            continue
        pure = PurePosixPath(relative)
        if pure.name != ARTIFACT_LOCATIONS_NAME or len(pure.parts) != 4:
            raise ManifestError(f"retention update rewrites an unrelated file: {relative}")
        base_locations = _read_object(base_path)
        updated_locations = _read_object(updated_path)
        verify_artifact_locations(base_locations, public_key)
        verify_artifact_locations(updated_locations, public_key)
        if (
            base_locations.get("channel") != updated_locations.get("channel")
            or base_locations.get("platform") != updated_locations.get("platform")
        ):
            raise ManifestError("retention delta changes location index target")
        changes = _retention_changes(base_locations, updated_locations)
        channel = str(updated_locations["channel"])
        platform = str(updated_locations["platform"])
        if pure != _locations_relative(channel, platform):
            raise ManifestError("retention location index path mismatch")
        changed_metadata.add(relative)
        for location in changes:
            artifact = _manifest_artifact(
                updated_root,
                public_key_path,
                channel=channel,
                platform=platform,
                version=str(location["version"]),
                artifact_path=str(location["path"]),
            )
            if location_for_artifact(updated_locations, str(location["version"]), artifact) is None:
                raise ManifestError("retention location does not match its signed manifest")
            retained_relative = _release_relative(
                channel,
                platform,
                str(location["version"]),
                str(location["path"]),
            ).as_posix()
            retained_path = updated_root.joinpath(*PurePosixPath(retained_relative).parts)
            verify_location_source(location, retained_path)
            retained_files.add(retained_relative)

    if not changed_metadata:
        raise ManifestError("retention update does not change an artifact-location index")
    added = updated_files - base_files
    if added != retained_files:
        raise ManifestError(
            f"retention update file mismatch: missing={sorted(retained_files - added)} "
            f"extra={sorted(added - retained_files)}"
        )
    expected = changed_metadata | retained_files
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as target:
        temporary = Path(target.name)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for relative in sorted(expected):
                archive.add(
                    updated_root.joinpath(*PurePosixPath(relative).parts),
                    arcname=relative,
                    recursive=False,
                )
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return output


def apply_retention_delta(
    root: Path,
    delta_root: Path,
    public_key_path: Path,
    *,
    verify_remote: bool = False,
) -> list[str]:
    """Apply a strict retention-only delta to an existing publication."""
    if not root.is_dir() or not delta_root.is_dir():
        raise ManifestError("base publication and delta roots must exist")
    public_key = load_public_key(public_key_path)
    actual = _file_set(delta_root)
    location_relatives = sorted(
        PurePosixPath(relative)
        for relative in actual
        if PurePosixPath(relative).name == ARTIFACT_LOCATIONS_NAME
        and len(PurePosixPath(relative).parts) == 4
    )
    if not location_relatives:
        raise ManifestError("retention delta has no artifact-location index")

    expected: set[str] = set()
    retained: list[str] = []
    mutable: list[str] = []
    applied: list[str] = []
    for relative in location_relatives:
        delta_locations = _read_object(delta_root.joinpath(*relative.parts))
        verify_artifact_locations(delta_locations, public_key)
        channel = str(delta_locations["channel"])
        platform = str(delta_locations["platform"])
        if relative != _locations_relative(channel, platform):
            raise ManifestError("retention location index path mismatch")
        base_path = root.joinpath(*relative.parts)
        if base_path.is_symlink() or not base_path.is_file():
            raise ManifestError("base artifact-location index is missing or unsafe")
        base_locations = _read_object(base_path)
        verify_artifact_locations(base_locations, public_key)
        changes = _retention_changes(base_locations, delta_locations)
        expected.add(relative.as_posix())
        mutable.append(relative.as_posix())
        for location in changes:
            version = str(location["version"])
            artifact_path = str(location["path"])
            artifact = _manifest_artifact(
                root,
                public_key_path,
                channel=channel,
                platform=platform,
                version=version,
                artifact_path=artifact_path,
            )
            if location_for_artifact(delta_locations, version, artifact) is None:
                raise ManifestError("retention location does not match its signed manifest")
            retained_relative = _release_relative(
                channel, platform, version, artifact_path
            ).as_posix()
            source = delta_root.joinpath(*PurePosixPath(retained_relative).parts)
            verify_location_source(location, source)
            destination = root.joinpath(*PurePosixPath(retained_relative).parts)
            if destination.exists() or destination.is_symlink():
                raise ManifestError("retention delta would overwrite a Pages artifact")
            if verify_remote:
                verify_remote_location(location)
            expected.add(retained_relative)
            retained.append(retained_relative)
            applied.append(f"{channel} {platform} {version}/{artifact_path}")

    actual_directories = {
        path.relative_to(delta_root).as_posix()
        for path in delta_root.rglob("*")
        if path.is_dir() and not path.is_symlink()
    }
    if actual != expected or actual_directories != _expected_directories(expected):
        raise ManifestError(
            f"retention delta tree mismatch: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )
    for relative in retained + mutable:
        _copy_atomic(
            delta_root.joinpath(*PurePosixPath(relative).parts),
            root.joinpath(*PurePosixPath(relative).parts),
        )
    return applied
