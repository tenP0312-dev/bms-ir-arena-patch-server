from __future__ import annotations

import argparse
import base64
import filecmp
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .archive import ArchivePartsError, assemble_release_archive
from .delta import apply_publication_delta, create_publication_delta
from .manifest import (
    ManifestError,
    append_history_version,
    bootstrap_metadata,
    build_manifest,
    fetch_manifest,
    load_private_key,
    load_public_key,
    safe_artifact_path,
    sign_history,
    sign_manifest,
    validate_manifest,
    verify_artifacts,
    verify_history,
    verify_manifest,
)


def timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as target:
        json.dump(value, target, ensure_ascii=False, sort_keys=True, indent=2)
        target.write("\n")
        temporary = Path(target.name)
    os.replace(temporary, path)


def read_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value


def copy_immutable(source_root: Path, release_root: Path, relative: str) -> None:
    relative = safe_artifact_path(relative)
    source = source_root.joinpath(*PurePosixPath(relative).parts)
    destination = release_root.joinpath(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not filecmp.cmp(source, destination, shallow=False):
            raise ManifestError(f"immutable artifact already differs: {relative}")
        return
    shutil.copy2(source, destination)


def command_keygen(args: argparse.Namespace) -> None:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    args.private_key.parent.mkdir(parents=True, exist_ok=True)
    args.public_key.parent.mkdir(parents=True, exist_ok=True)
    args.private_key.write_text(base64.b64encode(private_raw).decode("ascii") + "\n", encoding="ascii")
    os.chmod(args.private_key, 0o600)
    args.public_key.write_text(base64.b64encode(public_raw).decode("ascii") + "\n", encoding="ascii")


def command_draft(args: argparse.Namespace) -> None:
    if args.notes_file and (args.notes_ja_file or args.notes_en_file):
        raise ManifestError("--notes-file cannot be combined with localized notes")
    if bool(args.notes_ja_file) != bool(args.notes_en_file):
        raise ManifestError("both --notes-ja-file and --notes-en-file are required")
    notes = args.notes_file.read_text(encoding="utf-8") if args.notes_file else ""
    notes_ja = args.notes_ja_file.read_text(encoding="utf-8") if args.notes_ja_file else notes
    notes_en = args.notes_en_file.read_text(encoding="utf-8") if args.notes_en_file else notes
    if args.notes_ja_file:
        notes = f"{notes_ja.rstrip()}\n\n---\n\n{notes_en.lstrip()}"
    announcements: list[dict[str, object]] = []
    if args.announcements_file:
        value = json.loads(args.announcements_file.read_text(encoding="utf-8"))
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise ManifestError("announcements file must contain an array of objects")
        announcements = value
    bootstrap_values = (
        getattr(args, "bootstrap_manifest", None),
        getattr(args, "bootstrap_archive", None),
        getattr(args, "bootstrap_url", None),
    )
    if any(bootstrap_values) and not all(bootstrap_values):
        raise ManifestError(
            "--bootstrap-manifest, --bootstrap-archive, and --bootstrap-url are required together"
        )
    bootstrap = None
    if all(bootstrap_values):
        bootstrap = bootstrap_metadata(
            args.bootstrap_archive,
            args.bootstrap_url,
            read_manifest(args.bootstrap_manifest),
        )
    release_root = args.root / "channels" / args.channel / args.platform / "releases" / args.version
    for relative in args.artifact:
        copy_immutable(args.source, release_root, relative)
    manifest = build_manifest(
        release_root,
        args.artifact,
        channel=args.channel,
        platform=args.platform,
        version=args.version,
        published_at=timestamp(),
        release_notes_markdown=notes,
        release_notes_markdown_ja=notes_ja,
        release_notes_markdown_en=notes_en,
        announcements=announcements,
        mandatory=args.mandatory,
        minimum_launcher_version=args.minimum_launcher_version,
        launcher_version=getattr(args, "launcher_version", None),
        revoked_versions=args.revoke,
        bootstrap=bootstrap,
    )
    private_key = load_private_key(args.private_key)
    signed = sign_manifest(manifest, private_key)
    target = args.root / "channels" / args.channel / args.platform / "manifests" / f"{args.version}.json"
    if target.exists() and read_manifest(target) != signed:
        raise ManifestError("versioned manifest is immutable")
    write_json_atomic(target, signed)

    history_path = args.root / "channels" / args.channel / args.platform / "history.json"
    existing_versions: list[dict[str, object]] = []
    if history_path.exists():
        existing_history = read_manifest(history_path)
        verify_history(existing_history, private_key.public_key())
        if (
            existing_history.get("channel") != args.channel
            or existing_history.get("platform") != args.platform
        ):
            raise ManifestError("history channel/platform mismatch")
        existing_versions = existing_history.get("versions", [])
    history = append_history_version(
        existing_versions,
        channel=args.channel,
        platform=args.platform,
        version=args.version,
        published_at=signed["published_at"],
    )
    write_json_atomic(history_path, sign_history(history, private_key))

    print(target)


def verified_manifest(root: Path, path: Path, public_key: Path) -> dict[str, object]:
    manifest = read_manifest(path)
    verify_manifest(manifest, load_public_key(public_key))
    verify_artifacts(root, manifest)
    return manifest


def command_verify(args: argparse.Namespace) -> None:
    manifest = verified_manifest(args.root, args.manifest, args.public_key)
    print(f"OK {manifest['channel']} {manifest['platform']} {manifest['version']}")


def audit_publication(root: Path, manifest_paths: list[Path], public_key: Path) -> list[str]:
    expected: set[str] = set()
    audited: list[str] = []
    for manifest_path in manifest_paths:
        manifest = verified_manifest(root, manifest_path, public_key)
        base = PurePosixPath("channels") / str(manifest["channel"]) / str(manifest["platform"])
        pointer_relative = base / "manifest.json"
        versioned_relative = base / "manifests" / f"{manifest['version']}.json"
        pointer_path = root.joinpath(*pointer_relative.parts)
        versioned_path = root.joinpath(*versioned_relative.parts)
        if pointer_path.resolve() != manifest_path.resolve():
            raise ManifestError("audit manifest must be the channel pointer")
        if not versioned_path.is_file() or read_manifest(versioned_path) != manifest:
            raise ManifestError("versioned manifest does not match the channel pointer")
        expected.update({pointer_relative.as_posix(), versioned_relative.as_posix()})
        history_relative = base / "history.json"
        history_path = root.joinpath(*history_relative.parts)
        if not history_path.is_file():
            raise ManifestError("history index is missing for a published channel")
        history = read_manifest(history_path)
        verify_history(history, load_public_key(public_key))
        if history.get("channel") != manifest["channel"] or history.get("platform") != manifest["platform"]:
            raise ManifestError("history channel/platform mismatch")
        if not any(
            str(entry.get("version")) == str(manifest["version"])
            for entry in history.get("versions", [])
        ):
            raise ManifestError("history index is missing the current channel version")
        expected.add(history_relative.as_posix())
        release_base = base / "releases" / str(manifest["version"])
        for artifact in manifest["artifacts"]:
            expected.add(
                (release_base / safe_artifact_path(str(artifact["path"]))).as_posix()
            )
        # Every other version listed in the signed history is a legitimate
        # downgrade target the launcher can fetch (see update.rs
        # downgrade_to_version_from), so its own versioned manifest and
        # release artifacts belong in the published tree too, not just the
        # current channel pointer's.
        for entry in history.get("versions", []):
            entry_version = str(entry.get("version"))
            if entry_version == str(manifest["version"]):
                continue
            entry_versioned_relative = base / "manifests" / f"{entry_version}.json"
            entry_versioned_path = root.joinpath(*entry_versioned_relative.parts)
            entry_manifest = verified_manifest(root, entry_versioned_path, public_key)
            if (
                entry_manifest["channel"] != manifest["channel"]
                or entry_manifest["platform"] != manifest["platform"]
                or str(entry_manifest["version"]) != entry_version
            ):
                raise ManifestError(
                    f"history entry manifest does not match its own version: {entry_version}"
                )
            expected.add(entry_versioned_relative.as_posix())
            entry_release_base = base / "releases" / entry_version
            for artifact in entry_manifest["artifacts"]:
                expected.add(
                    (entry_release_base / safe_artifact_path(str(artifact["path"]))).as_posix()
                )
        audited.append(f"{manifest['channel']} {manifest['platform']} {manifest['version']}")
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ManifestError("publication tree contains a symlink")
    actual = {path.relative_to(root).as_posix() for path in paths if path.is_file()}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ManifestError(f"publication tree mismatch: missing={missing} extra={extra}")
    return audited


def command_audit(args: argparse.Namespace) -> None:
    manifest_paths = args.manifest if isinstance(args.manifest, list) else [args.manifest]
    audited = audit_publication(args.root, manifest_paths, args.public_key)
    print("AUDIT OK " + "; ".join(audited))


def promote(root: Path, manifest_path: Path, public_key: Path) -> Path:
    manifest = verified_manifest(root, manifest_path, public_key)
    target = root / "channels" / manifest["channel"] / manifest["platform"] / "manifest.json"
    write_json_atomic(target, manifest)
    return target


def command_promote(args: argparse.Namespace) -> None:
    print(promote(args.root, args.manifest, args.public_key))


def command_rollback(args: argparse.Namespace) -> None:
    manifest = args.root / "channels" / args.channel / args.platform / "manifests" / f"{args.version}.json"
    print(promote(args.root, manifest, args.public_key))


def command_revoke(args: argparse.Namespace) -> None:
    current = args.root / "channels" / args.channel / args.platform / "manifest.json"
    manifest = read_manifest(current)
    validate_manifest(manifest)
    if str(manifest.get("version") or "") == args.version:
        raise ManifestError("promote a replacement release before revoking the channel target")
    revoked = set(str(value) for value in manifest.get("revoked_versions", []))
    revoked.add(args.version)
    manifest["revoked_versions"] = sorted(revoked)
    manifest["mandatory"] = True
    manifest["published_at"] = timestamp()
    signed = sign_manifest(manifest, load_private_key(args.private_key))
    audit = args.root / "channels" / args.channel / args.platform / "revocations" / f"{args.version}-{int(datetime.now().timestamp())}.json"
    write_json_atomic(audit, signed)
    write_json_atomic(current, signed)
    print(current)


def command_serve(args: argparse.Namespace) -> None:
    handler = lambda *values, **kwargs: SimpleHTTPRequestHandler(*values, directory=str(args.root), **kwargs)
    server = ThreadingHTTPServer((args.bind, args.port), handler)
    print(f"http://{args.bind}:{server.server_port}")
    server.serve_forever()


def command_probe(args: argparse.Namespace) -> None:
    manifest, state = fetch_manifest(
        args.url,
        load_public_key(args.public_key),
        timeout=args.timeout,
        channel=args.channel,
        platform=args.platform,
        current_version=args.current_version,
        launcher_version=args.launcher_version,
    )
    print(f"{state} {manifest['version']}")


def command_assemble_archive(args: argparse.Namespace) -> None:
    print(assemble_release_archive(args.parts_directory, args.asset_name, args.output))


def command_create_delta(args: argparse.Namespace) -> None:
    print(create_publication_delta(args.root, args.manifest, args.public_key, args.output))


def command_apply_delta(args: argparse.Namespace) -> None:
    applied = apply_publication_delta(args.root, args.delta_root, args.public_key)
    print("DELTA OK " + "; ".join(applied))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="bmsir-arena-patch")
    commands = result.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)
    keygen.set_defaults(run=command_keygen)

    draft = commands.add_parser("draft")
    draft.add_argument("--root", type=Path, required=True)
    draft.add_argument("--source", type=Path, required=True)
    draft.add_argument("--private-key", type=Path, required=True)
    draft.add_argument("--channel", choices=("stable", "test"), required=True)
    draft.add_argument("--platform", choices=("windows-x64", "macos-arm64"), required=True)
    draft.add_argument("--version", required=True)
    draft.add_argument("--notes-file", type=Path)
    draft.add_argument("--notes-ja-file", type=Path)
    draft.add_argument("--notes-en-file", type=Path)
    draft.add_argument("--announcements-file", type=Path)
    draft.add_argument("--minimum-launcher-version", default="0.1.0")
    draft.add_argument(
        "--launcher-version",
        help="latest launcher version carried by the signed platform artifacts",
    )
    draft.add_argument("--mandatory", action="store_true")
    draft.add_argument("--revoke", action="append", default=[])
    draft.add_argument("--bootstrap-manifest", type=Path)
    draft.add_argument("--bootstrap-archive", type=Path)
    draft.add_argument("--bootstrap-url")
    draft.add_argument("--artifact", action="append", required=True)
    draft.set_defaults(run=command_draft)

    verify = commands.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.set_defaults(run=command_verify)

    audit = commands.add_parser("audit")
    audit.add_argument("--root", type=Path, required=True)
    audit.add_argument("--manifest", type=Path, action="append", required=True)
    audit.add_argument("--public-key", type=Path, required=True)
    audit.set_defaults(run=command_audit)

    promote_parser = commands.add_parser("promote")
    promote_parser.add_argument("--root", type=Path, required=True)
    promote_parser.add_argument("--manifest", type=Path, required=True)
    promote_parser.add_argument("--public-key", type=Path, required=True)
    promote_parser.set_defaults(run=command_promote)

    rollback = commands.add_parser("rollback")
    rollback.add_argument("--root", type=Path, required=True)
    rollback.add_argument("--channel", choices=("stable", "test"), required=True)
    rollback.add_argument("--platform", choices=("windows-x64", "macos-arm64"), required=True)
    rollback.add_argument("--version", required=True)
    rollback.add_argument("--public-key", type=Path, required=True)
    rollback.set_defaults(run=command_rollback)

    revoke = commands.add_parser("revoke")
    revoke.add_argument("--root", type=Path, required=True)
    revoke.add_argument("--channel", choices=("stable", "test"), required=True)
    revoke.add_argument("--platform", choices=("windows-x64", "macos-arm64"), required=True)
    revoke.add_argument("--version", required=True)
    revoke.add_argument("--private-key", type=Path, required=True)
    revoke.set_defaults(run=command_revoke)

    serve = commands.add_parser("serve")
    serve.add_argument("--root", type=Path, required=True)
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=0)
    serve.set_defaults(run=command_serve)

    probe = commands.add_parser("probe")
    probe.add_argument("--url", required=True)
    probe.add_argument("--public-key", type=Path, required=True)
    probe.add_argument("--channel", choices=("stable", "test"), required=True)
    probe.add_argument("--platform", choices=("windows-x64", "macos-arm64"), required=True)
    probe.add_argument("--current-version", required=True)
    probe.add_argument("--launcher-version", default="0.1.0")
    probe.add_argument("--timeout", type=float, default=10.0)
    probe.set_defaults(run=command_probe)

    assemble_archive = commands.add_parser("assemble-archive")
    assemble_archive.add_argument("--parts-directory", type=Path, required=True)
    assemble_archive.add_argument("--asset-name", required=True)
    assemble_archive.add_argument("--output", type=Path, required=True)
    assemble_archive.set_defaults(run=command_assemble_archive)

    create_delta = commands.add_parser("create-delta")
    create_delta.add_argument("--root", type=Path, required=True)
    create_delta.add_argument("--manifest", type=Path, action="append", required=True)
    create_delta.add_argument("--public-key", type=Path, required=True)
    create_delta.add_argument("--output", type=Path, required=True)
    create_delta.set_defaults(run=command_create_delta)

    apply_delta = commands.add_parser("apply-delta")
    apply_delta.add_argument("--root", type=Path, required=True)
    apply_delta.add_argument("--delta-root", type=Path, required=True)
    apply_delta.add_argument("--public-key", type=Path, required=True)
    apply_delta.set_defaults(run=command_apply_delta)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.run(args)
        return 0
    except (ArchivePartsError, ManifestError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
