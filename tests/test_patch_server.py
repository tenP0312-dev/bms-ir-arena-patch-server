from __future__ import annotations

import base64
import json
import socketserver
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena_patch_server.manifest import (
    ManifestError,
    append_history_version,
    bootstrap_metadata,
    build_manifest,
    check_update,
    fetch_manifest,
    sign_history,
    sign_manifest,
    safe_artifact_path,
    verify_artifacts,
    verify_history,
    verify_manifest,
)
from arena_patch_server.cli import command_audit, command_draft, write_json_atomic


class ResponseHandler(BaseHTTPRequestHandler):
    payload = b""
    status = 200
    delay = 0.0

    def do_GET(self) -> None:
        if self.delay:
            time.sleep(self.delay)
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        try:
            self.wfile.write(self.payload)
        except BrokenPipeError:
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        return


class PatchServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public = self.private.public_key()
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        source = self.root / "source"
        source.mkdir()
        (source / "Arena.jar").write_bytes(b"arena")
        self.manifest = build_manifest(
            source,
            ["Arena.jar"],
            channel="test",
            platform="windows-x64",
            version="0.4.14",
            published_at="2026-08-03T00:00:00Z",
            release_notes_markdown="## Test\n- Portable",
            release_notes_markdown_ja="## テスト\n- ポータブル",
            release_notes_markdown_en="## Test\n- Portable",
            announcements=[{
                "date": "2026-08-03",
                "title_ja": "テスト配信を開始しました",
                "title_en": "Internal testing is now available",
            }],
        )
        self.signed = sign_manifest(self.manifest, self.private)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def serve(self, *, payload: bytes | None = None, status: int = 200, delay: float = 0.0):
        handler = type("FixtureHandler", (ResponseHandler,), {
            "payload": payload if payload is not None else json.dumps(self.signed).encode(),
            "status": status,
            "delay": delay,
        })
        server = socketserver.TCPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{server.server_address[1]}/manifest.json"

    def _signed_history(self, *, channel: str, platform: str, version: str, published_at: str):
        history = append_history_version(
            [],
            channel=channel,
            platform=platform,
            version=version,
            published_at=published_at,
        )
        return sign_history(history, self.private)

    def test_signature_rejects_tampering(self) -> None:
        verify_manifest(self.signed, self.public)
        tampered = dict(self.signed)
        tampered["version"] = "9.9.9"
        with self.assertRaisesRegex(ManifestError, "signature"):
            verify_manifest(tampered, self.public)

    def test_localized_release_notes_and_announcements_are_signed(self) -> None:
        verify_manifest(self.signed, self.public)
        self.assertIn("ポータブル", self.signed["release_notes_markdown_ja"])
        self.assertIn("Portable", self.signed["release_notes_markdown_en"])
        self.assertEqual("2026-08-03", self.signed["announcements"][0]["date"])

        tampered = json.loads(json.dumps(self.signed))
        tampered["announcements"][0]["title_ja"] = "改ざん"
        with self.assertRaisesRegex(ManifestError, "signature"):
            verify_manifest(tampered, self.public)

    def test_legacy_release_notes_remain_valid(self) -> None:
        legacy = dict(self.signed)
        legacy.pop("release_notes_markdown_ja")
        legacy.pop("release_notes_markdown_en")
        legacy.pop("announcements")
        legacy = sign_manifest(legacy, self.private)
        verify_manifest(legacy, self.public)

    def test_invalid_announcements_are_rejected(self) -> None:
        source = self.root / "source"
        cases = (
            [{"date": "2026/08/03", "title_ja": "告知", "title_en": "Notice"}],
            [{"date": "2026-13-40", "title_ja": "告知", "title_en": "Notice"}],
            [{"date": "2026-08-03", "title_ja": "", "title_en": "Notice"}],
            [{"date": "2026-08-03", "title_ja": "告知", "title_en": "x" * 201}],
        )
        for announcements in cases:
            with self.assertRaises(ManifestError):
                build_manifest(
                    source,
                    ["Arena.jar"],
                    channel="test",
                    platform="windows-x64",
                    version="0.4.14",
                    published_at="2026-08-03T00:00:00Z",
                    announcements=announcements,
                )

    def test_draft_cli_reads_localized_notes_and_announcements(self) -> None:
        source = self.root / "cli-source"
        source.mkdir()
        (source / "Arena.jar").write_bytes(b"arena")
        private_key = self.root / "test.key"
        private_key.write_text(
            base64.b64encode(
                self.private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        notes_ja = self.root / "notes-ja.md"
        notes_en = self.root / "notes-en.md"
        announcements = self.root / "announcements.json"
        notes_ja.write_text("## 更新\n- 日本語", encoding="utf-8")
        notes_en.write_text("## Update\n- English", encoding="utf-8")
        announcements.write_text(json.dumps([{
            "date": "2026-08-03",
            "title_ja": "更新のお知らせ",
            "title_en": "Update notice",
        }]), encoding="utf-8")
        args = type("Args", (), {
            "root": self.root / "publication",
            "source": source,
            "private_key": private_key,
            "channel": "test",
            "platform": "windows-x64",
            "version": "0.4.14.4",
            "notes_file": None,
            "notes_ja_file": notes_ja,
            "notes_en_file": notes_en,
            "announcements_file": announcements,
            "mandatory": True,
            "minimum_launcher_version": "0.2.4",
            "revoke": [],
            "artifact": ["Arena.jar"],
        })()
        command_draft(args)
        manifest_path = (
            args.root / "channels/test/windows-x64/manifests/0.4.14.4.json"
        )
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        verify_manifest(manifest, self.public)
        self.assertIn("日本語", manifest["release_notes_markdown"])
        self.assertIn("English", manifest["release_notes_markdown"])
        self.assertEqual("## 更新\n- 日本語", manifest["release_notes_markdown_ja"])
        self.assertEqual("Update notice", manifest["announcements"][0]["title_en"])
        self.assertTrue(manifest["mandatory"])

    def test_draft_cli_creates_and_appends_history(self) -> None:
        source = self.root / "history-source"
        source.mkdir()
        (source / "Arena.jar").write_bytes(b"arena")
        private_key = self.root / "history-test.key"
        private_key.write_text(
            base64.b64encode(
                self.private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode("ascii"),
            encoding="ascii",
        )

        def draft_args(version: str):
            return type("Args", (), {
                "root": self.root / "history-publication",
                "source": source,
                "private_key": private_key,
                "channel": "test",
                "platform": "windows-x64",
                "version": version,
                "notes_file": None,
                "notes_ja_file": None,
                "notes_en_file": None,
                "announcements_file": None,
                "mandatory": False,
                "minimum_launcher_version": "0.1.0",
                "revoke": [],
                "artifact": ["Arena.jar"],
            })()

        command_draft(draft_args("0.4.14"))
        history_path = self.root / "history-publication/channels/test/windows-x64/history.json"
        history = json.loads(history_path.read_text(encoding="utf-8"))
        verify_history(history, self.public)
        self.assertEqual(["0.4.14"], [entry["version"] for entry in history["versions"]])

        command_draft(draft_args("0.4.15"))
        history = json.loads(history_path.read_text(encoding="utf-8"))
        verify_history(history, self.public)
        self.assertEqual(
            {"0.4.14", "0.4.15"},
            {entry["version"] for entry in history["versions"]},
        )
        self.assertEqual(
            1,
            len([entry for entry in history["versions"] if entry["version"] == "0.4.14"]),
        )

    def test_history_entry_is_immutable(self) -> None:
        history = append_history_version(
            [],
            channel="test",
            platform="windows-x64",
            version="0.4.14",
            published_at="2026-08-03T00:00:00Z",
        )
        with self.assertRaisesRegex(ManifestError, "immutable"):
            append_history_version(
                history["versions"],
                channel="test",
                platform="windows-x64",
                version="0.4.14",
                published_at="2026-08-04T00:00:00Z",
            )

    def test_history_signature_rejects_tampering(self) -> None:
        signed = self._signed_history(
            channel="test",
            platform="windows-x64",
            version="0.4.14",
            published_at="2026-08-03T00:00:00Z",
        )
        verify_history(signed, self.public)
        tampered = json.loads(json.dumps(signed))
        tampered["versions"][0]["version"] = "9.9.9"
        with self.assertRaisesRegex(ManifestError, "signature"):
            verify_history(tampered, self.public)

    def test_mutable_player_data_cannot_be_a_release_artifact(self) -> None:
        for value in (
            "player/player1/score.db",
            "score.db",
            "config_sys.json",
            "bmsir-arena-version.txt",
            ".bmsir-launcher-policy.json",
            ".bmsir-launcher-policy.tmp",
            ".bmsir-update-staging/file",
        ):
            with self.assertRaisesRegex(ManifestError, "unsafe artifact path"):
                safe_artifact_path(value)

    def test_artifacts_are_verified_from_immutable_version_directory(self) -> None:
        release = self.root / "channels/test/windows-x64/releases/0.4.14"
        release.mkdir(parents=True)
        (release / "Arena.jar").write_bytes(b"arena")
        verify_artifacts(self.root, self.signed)
        (release / "Arena.jar").write_bytes(b"tampered")
        with self.assertRaisesRegex(ManifestError, "mismatch"):
            verify_artifacts(self.root, self.signed)

    def test_macos_bundle_binary_preserves_executable_flag(self) -> None:
        source = self.root / "mac-source"
        executable = (
            source
            / "BMS-IR Arena Test.app"
            / "Contents"
            / "MacOS"
            / "bmsir-arena-launcher"
        )
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"launcher")
        executable.chmod(0o755)
        manifest = build_manifest(
            source,
            ["BMS-IR Arena Test.app/Contents/MacOS/bmsir-arena-launcher"],
            channel="test",
            platform="macos-arm64",
            version="0.4.14.3",
            published_at="2026-08-03T00:00:00Z",
        )
        self.assertTrue(manifest["artifacts"][0]["executable"])

    def test_bootstrap_archive_is_verified_and_signed(self) -> None:
        source = self.root / "bootstrap-source"
        (source / "runtime/bin").mkdir(parents=True)
        (source / "ir").mkdir()
        files = {
            "Arena.jar": b"body",
            "runtime/bin/java.exe": b"java",
            "ir/bms_ir_arena.jar": b"plugin",
        }
        for relative, payload in files.items():
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        inventory = build_manifest(
            source,
            files,
            channel="test",
            platform="windows-x64",
            version="0.4.14.8",
            published_at="2026-08-04T00:00:00Z",
        )
        archive = self.root / "bootstrap.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for relative in files:
                target.write(source / relative, relative)
        bootstrap = bootstrap_metadata(
            archive,
            "https://example.test/releases/bootstrap.zip",
            inventory,
        )
        delta = self.root / "delta"
        delta.mkdir()
        (delta / "BMS-IR Arena Test.exe").write_bytes(b"launcher")
        manifest = sign_manifest(
            build_manifest(
                delta,
                ["BMS-IR Arena Test.exe"],
                channel="test",
                platform="windows-x64",
                version="0.4.14.9",
                published_at="2026-08-04T01:00:00Z",
                bootstrap=bootstrap,
            ),
            self.private,
        )

        verify_manifest(manifest, self.public)
        self.assertEqual(3, len(manifest["bootstrap"]["artifacts"]))
        self.assertEqual(archive.stat().st_size, manifest["bootstrap"]["size"])

    def test_bootstrap_archive_rejects_unlisted_files(self) -> None:
        source = self.root / "bootstrap-invalid-source"
        source.mkdir()
        (source / "Arena.jar").write_bytes(b"body")
        inventory = build_manifest(
            source,
            ["Arena.jar"],
            channel="test",
            platform="windows-x64",
            version="0.4.14.8",
            published_at="2026-08-04T00:00:00Z",
        )
        archive = self.root / "bootstrap-invalid.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.write(source / "Arena.jar", "Arena.jar")
            target.writestr("unexpected.dat", b"unexpected")

        with self.assertRaisesRegex(ManifestError, "unexpected bootstrap entry"):
            bootstrap_metadata(
                archive,
                "https://example.test/releases/bootstrap-invalid.zip",
                inventory,
            )

    def test_fetch_reports_available_and_stale(self) -> None:
        server, url = self.serve()
        try:
            manifest, state = fetch_manifest(
                url,
                self.public,
                timeout=1,
                channel="test",
                platform="windows-x64",
                current_version="0.4.13",
                launcher_version="0.1.0",
            )
            self.assertEqual("0.4.14", manifest["version"])
            self.assertEqual("available", state)
            self.assertEqual(
                "current",
                check_update(
                    manifest,
                    channel="test",
                    platform="windows-x64",
                    current_version="0.4.14",
                    launcher_version="0.1.0",
                ),
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_fetch_rejects_wrong_platform(self) -> None:
        server, url = self.serve()
        try:
            with self.assertRaisesRegex(ManifestError, "platform mismatch"):
                fetch_manifest(
                    url,
                    self.public,
                    timeout=1,
                    channel="test",
                    platform="macos-arm64",
                    current_version="0.4.13",
                    launcher_version="0.1.0",
                )
        finally:
            server.shutdown()
            server.server_close()

    def test_fetch_handles_404_and_timeout(self) -> None:
        server, url = self.serve(status=404)
        try:
            with self.assertRaisesRegex(ManifestError, "fetch failed"):
                fetch_manifest(
                    url, self.public, timeout=1, channel="test",
                    platform="windows-x64", current_version="0.4.13",
                    launcher_version="0.1.0",
                )
        finally:
            server.shutdown()
            server.server_close()

        server, url = self.serve(delay=0.25)
        try:
            with self.assertRaisesRegex(ManifestError, "fetch failed"):
                fetch_manifest(
                    url, self.public, timeout=0.02, channel="test",
                    platform="windows-x64", current_version="0.4.13",
                    launcher_version="0.1.0",
                )
        finally:
            server.shutdown()
            server.server_close()

    def test_revoked_current_version_requires_replacement(self) -> None:
        manifest = dict(self.signed)
        manifest["revoked_versions"] = ["0.4.13"]
        manifest = sign_manifest(manifest, self.private)
        self.assertEqual(
            "revoked",
            check_update(
                manifest,
                channel="test",
                platform="windows-x64",
                current_version="0.4.13",
                launcher_version="0.1.0",
            ),
        )

    def test_public_key_fixture_is_raw_base64(self) -> None:
        raw = self.public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.assertEqual(32, len(base64.b64decode(base64.b64encode(raw))))

    def test_publication_audit_rejects_extra_files(self) -> None:
        publication = self.root / "publication"
        release = publication / "channels/test/windows-x64/releases/0.4.14"
        release.mkdir(parents=True)
        (release / "Arena.jar").write_bytes(b"arena")
        pointer = publication / "channels/test/windows-x64/manifest.json"
        versioned = publication / "channels/test/windows-x64/manifests/0.4.14.json"
        write_json_atomic(pointer, self.signed)
        write_json_atomic(versioned, self.signed)
        write_json_atomic(
            publication / "channels/test/windows-x64/history.json",
            self._signed_history(
                channel="test",
                platform="windows-x64",
                version="0.4.14",
                published_at=self.signed["published_at"],
            ),
        )
        key_directory = TemporaryDirectory()
        self.addCleanup(key_directory.cleanup)
        public_key = Path(key_directory.name) / "test.pub"
        public_key.write_text(
            base64.b64encode(
                self.public.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        args = type("Args", (), {
            "root": publication,
            "manifest": pointer,
            "public_key": public_key,
        })()
        command_audit(args)
        (publication / "extra.txt").write_text("not signed", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "publication tree mismatch"):
            command_audit(args)

    def test_publication_audit_requires_every_history_entrys_files(self) -> None:
        # Every version listed in the signed history is a legitimate
        # downgrade target (see downgrade_to_version_from in the launcher),
        # so the published tree must contain that version's own manifest
        # and release artifacts too -- not just the current channel
        # pointer's -- or a real launcher downgrade would 404 against a
        # tree that passed audit.
        publication = self.root / "history-audit-publication"
        old_source = self.root / "history-audit-old-source"
        old_source.mkdir()
        (old_source / "Arena.jar").write_bytes(b"old-arena")
        old_manifest = sign_manifest(
            build_manifest(
                old_source,
                ["Arena.jar"],
                channel="test",
                platform="windows-x64",
                version="0.4.13",
                published_at="2026-08-02T00:00:00Z",
            ),
            self.private,
        )
        old_release = publication / "channels/test/windows-x64/releases/0.4.13"
        old_release.mkdir(parents=True)
        (old_release / "Arena.jar").write_bytes(b"old-arena")
        write_json_atomic(
            publication / "channels/test/windows-x64/manifests/0.4.13.json", old_manifest
        )

        current_release = publication / "channels/test/windows-x64/releases/0.4.14"
        current_release.mkdir(parents=True)
        (current_release / "Arena.jar").write_bytes(b"arena")
        pointer = publication / "channels/test/windows-x64/manifest.json"
        versioned = publication / "channels/test/windows-x64/manifests/0.4.14.json"
        write_json_atomic(pointer, self.signed)
        write_json_atomic(versioned, self.signed)

        history = append_history_version(
            [],
            channel="test",
            platform="windows-x64",
            version="0.4.13",
            published_at="2026-08-02T00:00:00Z",
        )
        history = append_history_version(
            history["versions"],
            channel="test",
            platform="windows-x64",
            version="0.4.14",
            published_at=self.signed["published_at"],
        )
        write_json_atomic(
            publication / "channels/test/windows-x64/history.json",
            sign_history(history, self.private),
        )

        key_directory = TemporaryDirectory()
        self.addCleanup(key_directory.cleanup)
        public_key = Path(key_directory.name) / "test.pub"
        public_key.write_text(
            base64.b64encode(
                self.public.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        args = type("Args", (), {
            "root": publication,
            "manifest": pointer,
            "public_key": public_key,
        })()
        command_audit(args)

        # A historical entry whose own manifest fails verification (here,
        # tampered after signing) must still fail audit, not be silently
        # skipped.
        tampered_old_manifest = dict(old_manifest)
        tampered_old_manifest["version"] = "0.4.13"
        tampered_old_manifest["minimum_launcher_version"] = "9.9.9"
        write_json_atomic(
            publication / "channels/test/windows-x64/manifests/0.4.13.json",
            tampered_old_manifest,
        )
        with self.assertRaisesRegex(ManifestError, "signature"):
            command_audit(args)

    def test_publication_audit_accepts_exact_multi_platform_tree(self) -> None:
        publication = self.root / "multi-publication"
        windows_release = publication / "channels/test/windows-x64/releases/0.4.14"
        windows_release.mkdir(parents=True)
        (windows_release / "Arena.jar").write_bytes(b"arena")
        windows_pointer = publication / "channels/test/windows-x64/manifest.json"
        windows_versioned = publication / "channels/test/windows-x64/manifests/0.4.14.json"
        write_json_atomic(windows_pointer, self.signed)
        write_json_atomic(windows_versioned, self.signed)
        write_json_atomic(
            publication / "channels/test/windows-x64/history.json",
            self._signed_history(
                channel="test",
                platform="windows-x64",
                version="0.4.14",
                published_at=self.signed["published_at"],
            ),
        )

        mac_source = self.root / "mac-publication-source"
        mac_source.mkdir()
        (mac_source / "Arena.jar").write_bytes(b"mac-arena")
        mac_manifest = sign_manifest(
            build_manifest(
                mac_source,
                ["Arena.jar"],
                channel="test",
                platform="macos-arm64",
                version="0.4.14",
                published_at="2026-08-03T00:00:00Z",
            ),
            self.private,
        )
        mac_release = publication / "channels/test/macos-arm64/releases/0.4.14"
        mac_release.mkdir(parents=True)
        (mac_release / "Arena.jar").write_bytes(b"mac-arena")
        mac_pointer = publication / "channels/test/macos-arm64/manifest.json"
        mac_versioned = publication / "channels/test/macos-arm64/manifests/0.4.14.json"
        write_json_atomic(mac_pointer, mac_manifest)
        write_json_atomic(mac_versioned, mac_manifest)
        write_json_atomic(
            publication / "channels/test/macos-arm64/history.json",
            self._signed_history(
                channel="test",
                platform="macos-arm64",
                version="0.4.14",
                published_at="2026-08-03T00:00:00Z",
            ),
        )

        key_directory = TemporaryDirectory()
        self.addCleanup(key_directory.cleanup)
        public_key = Path(key_directory.name) / "test.pub"
        public_key.write_text(
            base64.b64encode(
                self.public.public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        args = type(
            "Args",
            (),
            {
                "root": publication,
                "manifest": [windows_pointer, mac_pointer],
                "public_key": public_key,
            },
        )()
        command_audit(args)


if __name__ == "__main__":
    unittest.main()
