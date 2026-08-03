from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = 1
VALID_CHANNELS = {"stable", "test"}
VALID_PLATFORMS = {"windows-x64", "macos-arm64"}
MAX_MANIFEST_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    pass


def canonical_bytes(value: dict[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("signature", None)
    return json.dumps(
        unsigned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise ManifestError("invalid Ed25519 private key") from exc


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise ManifestError("invalid Ed25519 public key") from exc


def safe_artifact_path(value: object) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or ":" in text
        or any(ord(character) < 32 for character in text)
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0] == ".bmsir-launcher-backup"
        or path.parts[0].casefold() in {"player", "bms", "replay", ".bmsir-update-staging"}
        or path.name.casefold() in {
            "config_sys.json", "config_player.json", "score.db",
            "songdata.db", "bmsir_maniac.db", "bmsir_arena.json",
            "bmsir-arena-version.txt",
        }
    ):
        raise ManifestError(f"unsafe artifact path: {text}")
    return text


def file_artifact(root: Path, relative: str) -> dict[str, object]:
    relative = safe_artifact_path(relative)
    path = root.joinpath(*PurePosixPath(relative).parts)
    if not path.is_file() or path.is_symlink():
        raise ManifestError(f"artifact is missing or unsafe: {relative}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return {
        "path": relative,
        "sha256": digest.hexdigest(),
        "size": size,
        "executable": (
            relative.lower().endswith((".exe", ".sh", ".command"))
            or bool(path.stat().st_mode & 0o111)
        ),
    }


def build_manifest(
    source_root: Path,
    artifacts: Iterable[str],
    *,
    channel: str,
    platform: str,
    version: str,
    published_at: str,
    release_notes_markdown: str = "",
    mandatory: bool = False,
    minimum_launcher_version: str = "0.1.0",
    revoked_versions: Iterable[str] = (),
) -> dict[str, Any]:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "channel": str(channel),
        "platform": str(platform),
        "version": str(version).strip(),
        "published_at": str(published_at).strip(),
        "release_notes_markdown": str(release_notes_markdown),
        "mandatory": bool(mandatory),
        "minimum_launcher_version": str(minimum_launcher_version).strip(),
        "revoked_versions": sorted({str(value).strip() for value in revoked_versions if str(value).strip()}),
        "artifacts": [file_artifact(source_root, relative) for relative in artifacts],
    }
    validate_manifest(manifest, require_signature=False)
    return manifest


def sign_manifest(manifest: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = dict(manifest)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(signed))
    ).decode("ascii")
    return signed


def validate_manifest(manifest: dict[str, Any], *, require_signature: bool = True) -> None:
    if int(manifest.get("schema_version") or 0) != SCHEMA_VERSION:
        raise ManifestError("unsupported manifest schema")
    if manifest.get("channel") not in VALID_CHANNELS:
        raise ManifestError("invalid channel")
    if manifest.get("platform") not in VALID_PLATFORMS:
        raise ManifestError("invalid platform")
    if not str(manifest.get("version") or "").strip():
        raise ManifestError("version is required")
    if not str(manifest.get("published_at") or "").strip():
        raise ManifestError("published_at is required")
    if not isinstance(manifest.get("mandatory"), bool):
        raise ManifestError("mandatory must be boolean")
    if not isinstance(manifest.get("revoked_versions"), list):
        raise ManifestError("revoked_versions must be an array")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ManifestError("artifacts must be an array")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ManifestError("artifact must be an object")
        relative = safe_artifact_path(artifact.get("path"))
        folded = relative.casefold()
        if folded in seen:
            raise ManifestError(f"duplicate artifact path: {relative}")
        seen.add(folded)
        if not SHA256_RE.fullmatch(str(artifact.get("sha256") or "")):
            raise ManifestError(f"invalid artifact SHA-256: {relative}")
        if not isinstance(artifact.get("size"), int) or int(artifact["size"]) < 0:
            raise ManifestError(f"invalid artifact size: {relative}")
        if not isinstance(artifact.get("executable"), bool):
            raise ManifestError(f"invalid executable flag: {relative}")
    if require_signature and not str(manifest.get("signature") or ""):
        raise ManifestError("signature is required")


def verify_manifest(manifest: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    validate_manifest(manifest)
    try:
        signature = base64.b64decode(str(manifest["signature"]), validate=True)
        public_key.verify(signature, canonical_bytes(manifest))
    except Exception as exc:
        raise ManifestError("manifest signature verification failed") from exc


def verify_artifacts(root: Path, manifest: dict[str, Any]) -> None:
    release_root = root / "channels" / manifest["channel"] / manifest["platform"] / "releases" / manifest["version"]
    for expected in manifest["artifacts"]:
        actual = file_artifact(release_root, expected["path"])
        if actual["sha256"] != expected["sha256"] or actual["size"] != expected["size"]:
            raise ManifestError(f"artifact mismatch: {expected['path']}")


def version_key(value: str) -> tuple[tuple[int, ...], str]:
    main, separator, suffix = str(value).strip().partition("-")
    try:
        numbers = tuple(int(part) for part in main.split("."))
    except ValueError:
        numbers = (0,)
        suffix = str(value)
    return numbers, "" if not separator else f"~{suffix}"


def check_update(
    manifest: dict[str, Any],
    *,
    channel: str,
    platform: str,
    current_version: str,
    launcher_version: str,
) -> str:
    if manifest["channel"] != channel:
        raise ManifestError("manifest channel mismatch")
    if manifest["platform"] != platform:
        raise ManifestError("manifest platform mismatch")
    if version_key(launcher_version) < version_key(str(manifest.get("minimum_launcher_version") or "0")):
        return "launcher_too_old"
    if current_version in manifest.get("revoked_versions", []):
        return "revoked"
    if version_key(str(manifest["version"])) <= version_key(current_version):
        return "current"
    return "available"


def fetch_manifest(
    url: str,
    public_key: Ed25519PublicKey,
    *,
    timeout: float,
    channel: str,
    platform: str,
    current_version: str,
    launcher_version: str,
) -> tuple[dict[str, Any], str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = response.read(MAX_MANIFEST_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ManifestError(f"manifest fetch failed: HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ManifestError(f"manifest fetch failed: {exc}") from exc
    if len(payload) > MAX_MANIFEST_BYTES:
        raise ManifestError("manifest is too large")
    try:
        manifest = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest JSON is invalid") from exc
    if not isinstance(manifest, dict):
        raise ManifestError("manifest root must be an object")
    verify_manifest(manifest, public_key)
    return manifest, check_update(
        manifest,
        channel=channel,
        platform=platform,
        current_version=current_version,
        launcher_version=launcher_version,
    )
