from __future__ import annotations

import base64
import hashlib
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote, urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .manifest import (
    ManifestError,
    SHA256_RE,
    VERSION_RE,
    canonical_bytes,
    safe_artifact_path,
)


ARTIFACT_LOCATIONS_NAME = "artifact-locations.json"
ARTIFACT_LOCATIONS_REFERENCE = {"path": ARTIFACT_LOCATIONS_NAME}
MAX_ARTIFACT_LOCATIONS = 10_000
GITHUB_REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/[A-Za-z0-9_.-]{1,100}$"
)
SAFE_RELEASE_ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$")


def release_asset_url(repository: str, tag: str, asset_name: str) -> str:
    repository = str(repository).strip()
    tag = str(tag).strip()
    asset_name = str(asset_name).strip()
    if not GITHUB_REPOSITORY_RE.fullmatch(repository):
        raise ManifestError("artifact repository must use owner/repository")
    if (
        not tag
        or any(ord(character) < 32 for character in tag)
        or "/" in tag
        or "\\" in tag
    ):
        raise ManifestError("release tag is invalid")
    if not SAFE_RELEASE_ASSET_RE.fullmatch(asset_name):
        raise ManifestError("release asset name is invalid")
    owner, name = repository.split("/", 1)
    return (
        f"https://github.com/{quote(owner, safe='')}/{quote(name, safe='')}"
        f"/releases/download/{quote(tag, safe='')}/{quote(asset_name, safe='')}"
    )


def validate_release_asset_url(value: object) -> str:
    text = str(value or "").strip()
    parsed = urlsplit(text)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ManifestError(
            "artifact location must be an HTTPS GitHub Release URL"
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port not in {None, 443}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ManifestError("artifact location must be an HTTPS GitHub Release URL")
    parts = parsed.path.split("/")
    if len(parts) != 7 or parts[3:5] != ["releases", "download"]:
        raise ManifestError("artifact location must be an HTTPS GitHub Release URL")
    decoded = [unquote(part) for part in parts]
    owner, repository, tag, asset_name = decoded[1], decoded[2], decoded[5], decoded[6]
    if not asset_name:
        raise ManifestError("artifact location release asset is missing")
    if not GITHUB_REPOSITORY_RE.fullmatch(f"{owner}/{repository}"):
        raise ManifestError("artifact location repository is invalid")
    if not tag or "/" in tag or "\\" in tag:
        raise ManifestError("artifact location release tag is invalid")
    if not SAFE_RELEASE_ASSET_RE.fullmatch(asset_name):
        raise ManifestError("artifact location release asset is invalid")
    if any("/" in value or "\\" in value for value in decoded[1:]):
        raise ManifestError("artifact location contains an encoded path separator")
    return text


def release_asset_name(url: str) -> str:
    validate_release_asset_url(url)
    return unquote(urlsplit(url).path.rsplit("/", 1)[-1])


def location_key(version: object, path: object) -> tuple[str, str]:
    return str(version).strip().casefold(), safe_artifact_path(path).casefold()


def validate_artifact_locations(
    locations: Mapping[str, object], *, require_signature: bool = True
) -> list[dict[str, object]]:
    if locations.get("schema_version") != 1:
        raise ManifestError("unsupported artifact-location schema")
    if locations.get("channel") not in {"stable", "test"}:
        raise ManifestError("invalid artifact-location channel")
    if locations.get("platform") not in {"windows-x64", "macos-arm64"}:
        raise ManifestError("invalid artifact-location platform")
    entries = locations.get("locations")
    if not isinstance(entries, list) or len(entries) > MAX_ARTIFACT_LOCATIONS:
        raise ManifestError("artifact locations must be a bounded array")
    seen: set[tuple[str, str]] = set()
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != {
            "version",
            "path",
            "sha256",
            "size",
            "url",
            "retain_on_pages",
        }:
            raise ManifestError("artifact-location fields are invalid")
        version = str(raw.get("version") or "").strip()
        if not VERSION_RE.fullmatch(version):
            raise ManifestError("artifact-location version is invalid")
        key = location_key(version, raw.get("path"))
        if key in seen:
            raise ManifestError(
                f"duplicate artifact location: {version}/{raw.get('path')}"
            )
        seen.add(key)
        if not SHA256_RE.fullmatch(str(raw.get("sha256") or "")):
            raise ManifestError("artifact-location SHA-256 is invalid")
        if not isinstance(raw.get("size"), int) or int(raw["size"]) < 0:
            raise ManifestError("artifact-location size is invalid")
        validate_release_asset_url(raw.get("url"))
        if not isinstance(raw.get("retain_on_pages"), bool):
            raise ManifestError("retain_on_pages must be boolean")
    if require_signature and not str(locations.get("signature") or ""):
        raise ManifestError("artifact-location signature is required")
    return entries


def sign_artifact_locations(
    locations: Mapping[str, object], private_key: Ed25519PrivateKey
) -> dict[str, Any]:
    unsigned = dict(locations)
    unsigned.pop("signature", None)
    validate_artifact_locations(unsigned, require_signature=False)
    signed = dict(unsigned)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(signed))
    ).decode("ascii")
    return signed


def verify_artifact_locations(
    locations: Mapping[str, object], public_key: Ed25519PublicKey
) -> None:
    validate_artifact_locations(locations)
    try:
        signature = base64.b64decode(str(locations["signature"]), validate=True)
        public_key.verify(signature, canonical_bytes(dict(locations)))
    except Exception as exc:
        raise ManifestError("artifact-location signature verification failed") from exc


def build_artifact_locations(
    entries: Iterable[Mapping[str, object]], *, channel: str, platform: str
) -> dict[str, object]:
    result = {
        "schema_version": 1,
        "channel": str(channel),
        "platform": str(platform),
        "locations": [dict(entry) for entry in entries],
    }
    validate_artifact_locations(result, require_signature=False)
    return result


def append_artifact_locations(
    existing: Iterable[Mapping[str, object]],
    additions: Iterable[Mapping[str, object]],
    *,
    channel: str,
    platform: str,
) -> dict[str, object]:
    entries = [dict(entry) for entry in existing]
    by_key = {
        location_key(entry.get("version"), entry.get("path")): entry
        for entry in entries
    }
    for raw in additions:
        entry = dict(raw)
        key = location_key(entry.get("version"), entry.get("path"))
        previous = by_key.get(key)
        if previous is not None:
            if previous != entry:
                raise ManifestError(
                    f"artifact location is immutable: {entry.get('version')}/{entry.get('path')}"
                )
            continue
        entries.append(entry)
        by_key[key] = entry
    entries.sort(
        key=lambda entry: (
            str(entry["version"]).casefold(),
            str(entry["path"]).casefold(),
        )
    )
    return build_artifact_locations(entries, channel=channel, platform=platform)


def location_for_artifact(
    locations: Mapping[str, object] | None,
    version: str,
    artifact: Mapping[str, object],
) -> dict[str, object] | None:
    if locations is None:
        return None
    wanted = location_key(version, artifact.get("path"))
    for entry in validate_artifact_locations(locations):
        if location_key(entry.get("version"), entry.get("path")) != wanted:
            continue
        if (
            str(entry["sha256"]) != str(artifact.get("sha256"))
            or int(entry["size"]) != int(artifact.get("size", -1))
        ):
            raise ManifestError(
                f"artifact location does not match signed manifest: {version}/{artifact.get('path')}"
            )
        return entry
    return None


def file_identity(path: Path) -> tuple[int, str]:
    if path.is_symlink() or not path.is_file():
        raise ManifestError(f"external artifact is missing or unsafe: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def verify_location_source(location: Mapping[str, object], path: Path) -> None:
    size, digest = file_identity(path)
    if size != int(location["size"]) or digest != str(location["sha256"]):
        raise ManifestError(
            f"external artifact does not match its signed location: {location['version']}/{location['path']}"
        )


def verify_remote_location(location: Mapping[str, object], *, timeout: float = 30.0) -> None:
    url = validate_release_asset_url(location.get("url"))
    expected_size = int(location["size"])
    request = urllib.request.Request(url, headers={"User-Agent": "bmsir-arena-patch/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            digest = hashlib.sha256()
            size = 0
            while chunk := response.read(min(1024 * 1024, expected_size + 1 - size)):
                size += len(chunk)
                if size > expected_size:
                    raise ManifestError("remote artifact is larger than its signed size")
                digest.update(chunk)
    except ManifestError:
        raise
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ManifestError(f"remote artifact fetch failed: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ManifestError(f"remote artifact fetch failed: {exc}") from exc
    if size != expected_size or digest.hexdigest() != str(location["sha256"]):
        raise ManifestError(
            f"remote artifact does not match its signed location: {location['version']}/{location['path']}"
        )
