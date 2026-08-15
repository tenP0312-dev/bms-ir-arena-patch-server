from __future__ import annotations

import base64
import hashlib
import json
import re
import stat
import urllib.error
import urllib.request
import zipfile
from datetime import date as calendar_date
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_VERSION = 1
VALID_CHANNELS = {"stable", "test"}
VALID_PLATFORMS = {"windows-x64", "macos-arm64"}
MAX_MANIFEST_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ANNOUNCEMENT_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")
MAX_RELEASE_NOTES_BYTES = 64 * 1024
MAX_ANNOUNCEMENTS = 20
MAX_ANNOUNCEMENT_TITLE = 200
MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024 * 1024


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
            "bmsir-arena-version.txt", ".bmsir-launcher-policy.json",
            ".bmsir-launcher-policy.tmp", ".bmsir-launcher-settings.json",
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


def normalized_announcements(
    announcements: Iterable[Mapping[str, object]],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for announcement in announcements:
        result.append({
            "date": str(announcement.get("date") or "").strip(),
            "title_ja": str(announcement.get("title_ja") or "").strip(),
            "title_en": str(announcement.get("title_en") or "").strip(),
        })
    result.sort(key=lambda item: item["date"], reverse=True)
    return result


def validate_localized_content(manifest: Mapping[str, object]) -> None:
    for field in (
        "release_notes_markdown",
        "release_notes_markdown_ja",
        "release_notes_markdown_en",
    ):
        value = manifest.get(field, "")
        if not isinstance(value, str):
            raise ManifestError(f"{field} must be a string")
        if len(value.encode("utf-8")) > MAX_RELEASE_NOTES_BYTES:
            raise ManifestError(f"{field} is too large")

    announcements = manifest.get("announcements", [])
    if not isinstance(announcements, list):
        raise ManifestError("announcements must be an array")
    if len(announcements) > MAX_ANNOUNCEMENTS:
        raise ManifestError("too many announcements")
    for announcement in announcements:
        if not isinstance(announcement, dict):
            raise ManifestError("announcement must be an object")
        if set(announcement) != {"date", "title_ja", "title_en"}:
            raise ManifestError("announcement fields are invalid")
        date = announcement.get("date")
        title_ja = announcement.get("title_ja")
        title_en = announcement.get("title_en")
        if not isinstance(date, str) or not ANNOUNCEMENT_DATE_RE.fullmatch(date):
            raise ManifestError("announcement date must use YYYY-MM-DD")
        try:
            calendar_date.fromisoformat(date)
        except ValueError as exc:
            raise ManifestError("announcement date is invalid") from exc
        for field, title in (("title_ja", title_ja), ("title_en", title_en)):
            if (
                not isinstance(title, str)
                or not title.strip()
                or len(title) > MAX_ANNOUNCEMENT_TITLE
                or any(ord(character) < 32 for character in title)
            ):
                raise ManifestError(f"announcement {field} is invalid")


def build_manifest(
    source_root: Path,
    artifacts: Iterable[str],
    *,
    channel: str,
    platform: str,
    version: str,
    published_at: str,
    release_notes_markdown: str = "",
    release_notes_markdown_ja: str | None = None,
    release_notes_markdown_en: str | None = None,
    announcements: Iterable[Mapping[str, object]] = (),
    mandatory: bool = False,
    minimum_launcher_version: str = "0.1.0",
    launcher_version: str | None = None,
    revoked_versions: Iterable[str] = (),
    bootstrap: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "channel": str(channel),
        "platform": str(platform),
        "version": str(version).strip(),
        "published_at": str(published_at).strip(),
        "release_notes_markdown": str(release_notes_markdown),
        "release_notes_markdown_ja": str(
            release_notes_markdown
            if release_notes_markdown_ja is None
            else release_notes_markdown_ja
        ),
        "release_notes_markdown_en": str(
            release_notes_markdown
            if release_notes_markdown_en is None
            else release_notes_markdown_en
        ),
        "announcements": normalized_announcements(announcements),
        "mandatory": bool(mandatory),
        "minimum_launcher_version": str(minimum_launcher_version).strip(),
        "revoked_versions": sorted({str(value).strip() for value in revoked_versions if str(value).strip()}),
        "bootstrap": dict(bootstrap) if bootstrap is not None else None,
        "artifacts": [file_artifact(source_root, relative) for relative in artifacts],
    }
    if launcher_version is not None:
        manifest["launcher_version"] = str(launcher_version).strip()
    validate_manifest(manifest, require_signature=False)
    return manifest


def sign_manifest(manifest: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = dict(manifest)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(signed))
    ).decode("ascii")
    return signed


def validate_artifact_list(value: object, *, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ManifestError(f"{label} must be an array")
    seen: set[str] = set()
    for artifact in value:
        if not isinstance(artifact, dict):
            raise ManifestError(f"{label} entry must be an object")
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
    return value


def validate_bootstrap(value: object) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {"url", "sha256", "size", "artifacts"}:
        raise ManifestError("bootstrap fields are invalid")
    parsed = urlparse(str(value.get("url") or ""))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ManifestError("bootstrap URL must use HTTPS")
    if not SHA256_RE.fullmatch(str(value.get("sha256") or "")):
        raise ManifestError("invalid bootstrap SHA-256")
    size = value.get("size")
    if not isinstance(size, int) or size <= 0 or size > MAX_BOOTSTRAP_BYTES:
        raise ManifestError("invalid bootstrap size")
    artifacts = validate_artifact_list(value.get("artifacts"), label="bootstrap artifacts")
    if not artifacts:
        raise ManifestError("bootstrap artifacts cannot be empty")


def bootstrap_metadata(
    archive: Path,
    url: str,
    inventory_manifest: Mapping[str, object],
) -> dict[str, object]:
    validate_manifest(dict(inventory_manifest), require_signature=False)
    artifacts = validate_artifact_list(
        inventory_manifest.get("artifacts"),
        label="bootstrap artifacts",
    )
    if not artifacts:
        raise ManifestError("bootstrap artifacts cannot be empty")
    expected = {str(item["path"]).casefold(): item for item in artifacts}
    archive_artifact = file_artifact(archive.parent, archive.name)
    if int(archive_artifact["size"]) <= 0 or int(archive_artifact["size"]) > MAX_BOOTSTRAP_BYTES:
        raise ManifestError("invalid bootstrap size")
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(archive) as source:
            for info in source.infolist():
                name = info.filename
                path = PurePosixPath(name)
                mode = info.external_attr >> 16
                if (
                    "\\" in name
                    or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or stat.S_IFMT(mode) == stat.S_IFLNK
                ):
                    raise ManifestError(f"unsafe bootstrap entry: {name}")
                if info.is_dir():
                    continue
                if name.casefold() == "bmsir-arena-version.txt":
                    continue
                folded = name.casefold()
                expected_artifact = expected.get(folded)
                if expected_artifact is None or folded in seen:
                    raise ManifestError(f"unexpected bootstrap entry: {name}")
                if info.file_size != int(expected_artifact["size"]):
                    raise ManifestError(f"bootstrap artifact mismatch: {name}")
                digest = hashlib.sha256()
                size = 0
                with source.open(info) as payload:
                    while chunk := payload.read(1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                if (
                    size != int(expected_artifact["size"])
                    or digest.hexdigest() != expected_artifact["sha256"]
                ):
                    raise ManifestError(f"bootstrap artifact mismatch: {name}")
                if expected_artifact["executable"] and not (
                    name.lower().endswith((".exe", ".sh", ".command")) or mode & 0o111
                ):
                    raise ManifestError(f"bootstrap executable bit is missing: {name}")
                seen.add(folded)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise ManifestError("bootstrap archive is invalid") from exc
    missing = sorted(expected.keys() - seen)
    if missing:
        raise ManifestError(f"bootstrap archive is incomplete: {missing[:3]}")
    result = {
        "url": str(url),
        "sha256": archive_artifact["sha256"],
        "size": archive_artifact["size"],
        "artifacts": [dict(item) for item in artifacts],
    }
    validate_bootstrap(result)
    return result


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
    validate_localized_content(manifest)
    artifacts = validate_artifact_list(manifest.get("artifacts"), label="artifacts")
    if "launcher_version" in manifest:
        launcher_version = manifest.get("launcher_version")
        if not isinstance(launcher_version, str) or not VERSION_RE.fullmatch(launcher_version):
            raise ManifestError("launcher_version is invalid")
        artifact_paths = [str(item["path"]).casefold() for item in artifacts]
        if manifest["platform"] == "windows-x64":
            expected_launcher = (
                "bms-ir arena test.exe"
                if manifest["channel"] == "test"
                else "bms-ir arena.exe"
            )
            launcher_present = any(
                PurePosixPath(path).parent == PurePosixPath(".")
                and PurePosixPath(path).name == expected_launcher
                for path in artifact_paths
            )
        else:
            expected_app = (
                "bms-ir arena test.app"
                if manifest["channel"] == "test"
                else "bms-ir arena.app"
            )
            launcher_present = any(
                path.endswith(".app/contents/macos/bmsir-arena-launcher")
                and PurePosixPath(path).parts[0] == expected_app
                for path in artifact_paths
            )
        if not launcher_present:
            raise ManifestError(
                "launcher_version requires the platform launcher artifact"
            )
    validate_bootstrap(manifest.get("bootstrap"))
    if require_signature and not str(manifest.get("signature") or ""):
        raise ManifestError("signature is required")


def verify_manifest(manifest: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    validate_manifest(manifest)
    try:
        signature = base64.b64decode(str(manifest["signature"]), validate=True)
        public_key.verify(signature, canonical_bytes(manifest))
    except Exception as exc:
        raise ManifestError("manifest signature verification failed") from exc


def validate_history(history: dict[str, Any], *, require_signature: bool = True) -> None:
    if int(history.get("schema_version") or 0) != SCHEMA_VERSION:
        raise ManifestError("unsupported history schema")
    if history.get("channel") not in VALID_CHANNELS:
        raise ManifestError("invalid channel")
    if history.get("platform") not in VALID_PLATFORMS:
        raise ManifestError("invalid platform")
    versions = history.get("versions")
    if not isinstance(versions, list) or not versions:
        raise ManifestError("versions must be a non-empty array")
    seen: set[str] = set()
    for entry in versions:
        if not isinstance(entry, dict) or set(entry) != {"version", "published_at"}:
            raise ManifestError("history entry fields are invalid")
        version = str(entry.get("version") or "").strip()
        published_at = str(entry.get("published_at") or "").strip()
        if not version or not published_at:
            raise ManifestError("history entry version/published_at is required")
        folded = version.casefold()
        if folded in seen:
            raise ManifestError(f"duplicate history version: {version}")
        seen.add(folded)
    latest_launcher = history.get("latest_launcher")
    if latest_launcher is not None:
        if not isinstance(latest_launcher, dict) or set(latest_launcher) != {
            "release_version",
            "launcher_version",
        }:
            raise ManifestError("latest_launcher fields are invalid")
        release_version = latest_launcher.get("release_version")
        launcher_version = latest_launcher.get("launcher_version")
        if (
            not isinstance(release_version, str)
            or release_version.casefold() not in seen
            or not isinstance(launcher_version, str)
            or not VERSION_RE.fullmatch(launcher_version)
        ):
            raise ManifestError("latest_launcher is invalid")
    if require_signature and not str(history.get("signature") or ""):
        raise ManifestError("signature is required")


def sign_history(history: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = dict(history)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(signed))
    ).decode("ascii")
    return signed


def verify_history(history: dict[str, Any], public_key: Ed25519PublicKey) -> None:
    validate_history(history)
    try:
        signature = base64.b64decode(str(history["signature"]), validate=True)
        public_key.verify(signature, canonical_bytes(history))
    except Exception as exc:
        raise ManifestError("history signature verification failed") from exc


def append_history_version(
    versions: Iterable[Mapping[str, object]],
    *,
    channel: str,
    platform: str,
    version: str,
    published_at: str,
) -> dict[str, Any]:
    """Add one immutable (version, published_at) pair to a history index.

    A version that is already present must keep its original published_at;
    this mirrors the immutability of the per-version release manifest so a
    history index can never silently rewrite when an older release actually
    shipped.
    """
    version = str(version).strip()
    published_at = str(published_at).strip()
    result_versions = [dict(item) for item in versions]
    folded = version.casefold()
    for item in result_versions:
        if str(item.get("version") or "").casefold() == folded:
            if str(item.get("published_at") or "") != published_at:
                raise ManifestError(f"history entry is immutable: {version}")
            break
    else:
        result_versions.append({"version": version, "published_at": published_at})
    result_versions.sort(key=lambda entry: entry["published_at"], reverse=True)
    history = {
        "schema_version": SCHEMA_VERSION,
        "channel": str(channel),
        "platform": str(platform),
        "versions": result_versions,
    }
    validate_history(history, require_signature=False)
    return history


def latest_launcher_reference(
    manifests: Iterable[Mapping[str, object]],
) -> dict[str, str] | None:
    """Return the release carrying the maximum declared launcher version."""
    latest: dict[str, str] | None = None
    latest_published_at = ""
    for manifest in manifests:
        launcher_version = str(manifest.get("launcher_version") or "").strip()
        if not launcher_version:
            continue
        candidate = {
            "release_version": str(manifest.get("version") or "").strip(),
            "launcher_version": launcher_version,
        }
        if (
            latest is None
            or version_key(launcher_version) > version_key(latest["launcher_version"])
            or (
                version_key(launcher_version) == version_key(latest["launcher_version"])
                and str(manifest.get("published_at") or "") > latest_published_at
            )
        ):
            latest = candidate
            latest_published_at = str(manifest.get("published_at") or "")
    return latest


def verify_history_latest_launcher(
    history: Mapping[str, object],
    manifests: Iterable[Mapping[str, object]],
) -> None:
    """Verify an advertised launcher pointer against its signed manifests.

    Legacy history without the optional pointer remains valid. Once present,
    the pointer must name the exact release carrying the maximum launcher
    version in the append-only history.
    """
    advertised = history.get("latest_launcher")
    if advertised is None:
        return
    expected = latest_launcher_reference(manifests)
    if advertised != expected:
        raise ManifestError("latest_launcher does not match signed history manifests")


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
    if version_key(str(manifest["version"])) > version_key(current_version):
        return "available"
    available_launcher = str(manifest.get("launcher_version") or "").strip()
    if (
        available_launcher
        and version_key(available_launcher) > version_key(launcher_version)
    ):
        return "launcher_available"
    return "current"


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
