from __future__ import annotations

import json
import os
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .manifest import (
    ManifestError,
    load_public_key,
    safe_artifact_path,
    verify_artifacts,
    verify_history,
    verify_manifest,
)


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ManifestError(f"JSON root must be an object: {path}")
    return value


def _file_set(root: Path) -> set[str]:
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ManifestError("delta tree contains a symlink")
    if any(not path.is_file() and not path.is_dir() for path in paths):
        raise ManifestError("delta tree contains a special file")
    return {path.relative_to(root).as_posix() for path in paths if path.is_file()}


def _expected_directories(files: set[str]) -> set[str]:
    result: set[str] = set()
    for name in files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            result.add(parent.as_posix())
            parent = parent.parent
    return result


def _platform_paths(
    root: Path,
    pointer_relative: PurePosixPath,
    public_key: Ed25519PublicKey,
) -> tuple[dict[str, Any], dict[str, Any], set[str]]:
    pointer = root.joinpath(*pointer_relative.parts)
    if pointer.is_symlink() or not pointer.is_file():
        raise ManifestError("channel pointer is missing or unsafe")
    manifest = _read_object(pointer)
    verify_manifest(manifest, public_key)

    base = PurePosixPath("channels") / str(manifest["channel"]) / str(manifest["platform"])
    if pointer_relative != base / "manifest.json":
        raise ManifestError("manifest channel/platform does not match its delta path")

    version = str(manifest["version"])
    versioned_relative = base / "manifests" / f"{version}.json"
    versioned = root.joinpath(*versioned_relative.parts)
    if versioned.is_symlink() or not versioned.is_file() or _read_object(versioned) != manifest:
        raise ManifestError("versioned manifest does not match the channel pointer")

    history_relative = base / "history.json"
    history_path = root.joinpath(*history_relative.parts)
    if history_path.is_symlink() or not history_path.is_file():
        raise ManifestError("history index is missing or unsafe")
    history = _read_object(history_path)
    verify_history(history, public_key)
    if history.get("channel") != manifest["channel"] or history.get("platform") != manifest["platform"]:
        raise ManifestError("history channel/platform mismatch")
    if not any(str(entry.get("version")) == version for entry in history["versions"]):
        raise ManifestError("history index is missing the delta version")

    verify_artifacts(root, manifest)
    expected = {
        pointer_relative.as_posix(),
        versioned_relative.as_posix(),
        history_relative.as_posix(),
    }
    release_base = base / "releases" / version
    for artifact in manifest["artifacts"]:
        expected.add(
            (release_base / safe_artifact_path(str(artifact["path"]))).as_posix()
        )
    return manifest, history, expected


def create_publication_delta(
    root: Path,
    manifest_paths: list[Path],
    public_key_path: Path,
    output: Path,
) -> Path:
    """Package only the newly current signed releases for selected platforms."""
    if not root.is_dir():
        raise ManifestError("publication root does not exist")
    if not manifest_paths:
        raise ManifestError("at least one channel pointer is required")
    try:
        output.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise ManifestError("delta output must be outside the publication root")

    public_key = load_public_key(public_key_path)
    expected: set[str] = set()
    platforms: set[tuple[str, str]] = set()
    for manifest_path in manifest_paths:
        try:
            relative = PurePosixPath(manifest_path.resolve().relative_to(root.resolve()).as_posix())
        except ValueError as exc:
            raise ManifestError("delta manifest must be inside the publication root") from exc
        manifest, _history, platform_expected = _platform_paths(root, relative, public_key)
        identity = (str(manifest["channel"]), str(manifest["platform"]))
        if identity in platforms:
            raise ManifestError(f"duplicate delta platform: {identity[0]}/{identity[1]}")
        platforms.add(identity)
        expected.update(platform_expected)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as target:
        temporary = Path(target.name)
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for relative in sorted(expected):
                source = root.joinpath(*PurePosixPath(relative).parts)
                if source.is_symlink() or not source.is_file():
                    raise ManifestError(f"delta source is missing or unsafe: {relative}")
                archive.add(source, arcname=relative, recursive=False)
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return output


def _copy_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=destination.parent, delete=False) as target:
        temporary = Path(target.name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def apply_publication_delta(root: Path, delta_root: Path, public_key_path: Path) -> list[str]:
    """Validate and add a strict one-version delta to an existing publication."""
    if not root.is_dir() or not delta_root.is_dir():
        raise ManifestError("base publication and delta roots must exist")
    public_key = load_public_key(public_key_path)
    actual = _file_set(delta_root)
    pointer_relatives = sorted(
        PurePosixPath(relative)
        for relative in actual
        if len(PurePosixPath(relative).parts) == 4
        and PurePosixPath(relative).parts[0] == "channels"
        and PurePosixPath(relative).name == "manifest.json"
    )
    if not pointer_relatives:
        raise ManifestError("delta does not contain a channel pointer")

    expected: set[str] = set()
    immutable: list[str] = []
    mutable: list[str] = []
    applied: list[str] = []
    identities: set[tuple[str, str]] = set()
    for pointer_relative in pointer_relatives:
        manifest, history, platform_expected = _platform_paths(
            delta_root, pointer_relative, public_key
        )
        expected.update(platform_expected)
        channel = str(manifest["channel"])
        platform = str(manifest["platform"])
        version = str(manifest["version"])
        identity = (channel, platform)
        if identity in identities:
            raise ManifestError(f"duplicate delta platform: {channel}/{platform}")
        identities.add(identity)

        base = PurePosixPath("channels") / channel / platform
        base_pointer_relative = base / "manifest.json"
        base_pointer_path = root.joinpath(*base_pointer_relative.parts)
        base_history_path = root.joinpath(*(base / "history.json").parts)
        if not base_pointer_path.is_file() or not base_history_path.is_file():
            raise ManifestError(f"base publication is missing: {channel}/{platform}")
        base_manifest = _read_object(base_pointer_path)
        base_history = _read_object(base_history_path)
        verify_manifest(base_manifest, public_key)
        verify_history(base_history, public_key)
        if (
            base_manifest.get("channel") != channel
            or base_manifest.get("platform") != platform
            or base_history.get("channel") != channel
            or base_history.get("platform") != platform
        ):
            raise ManifestError("base channel/platform mismatch")
        if str(base_manifest["version"]).casefold() == version.casefold():
            raise ManifestError("delta version must differ from the base pointer")

        old_versions = base_history["versions"]
        new_versions = history["versions"]
        expected_entry = {
            "version": version,
            "published_at": str(manifest["published_at"]),
        }
        if len(new_versions) != len(old_versions) + 1 or new_versions[0] != expected_entry or new_versions[1:] != old_versions:
            raise ManifestError("delta history must strictly prepend exactly one current version")

        versioned_relative = base / "manifests" / f"{version}.json"
        release_base = base / "releases" / version
        new_immutable = [versioned_relative.as_posix()]
        new_immutable.extend(
            (release_base / safe_artifact_path(str(artifact["path"]))).as_posix()
            for artifact in manifest["artifacts"]
        )
        for relative in new_immutable:
            destination = root.joinpath(*PurePosixPath(relative).parts)
            if destination.exists() or destination.is_symlink():
                raise ManifestError(f"delta would overwrite an immutable path: {relative}")
        immutable.extend(new_immutable)
        mutable.extend([
            (base / "history.json").as_posix(),
            base_pointer_relative.as_posix(),
        ])
        applied.append(f"{channel} {platform} {version}")

    actual_directories = {
        path.relative_to(delta_root).as_posix()
        for path in delta_root.rglob("*")
        if path.is_dir() and not path.is_symlink()
    }
    if actual != expected or actual_directories != _expected_directories(expected):
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ManifestError(f"delta tree mismatch: missing={missing} extra={extra}")

    for relative in immutable + mutable:
        source = delta_root.joinpath(*PurePosixPath(relative).parts)
        destination = root.joinpath(*PurePosixPath(relative).parts)
        _copy_atomic(source, destination)
    return applied
