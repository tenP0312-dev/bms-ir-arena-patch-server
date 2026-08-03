from __future__ import annotations

import base64
import json
import socketserver
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena_patch_server.manifest import (
    ManifestError,
    build_manifest,
    check_update,
    fetch_manifest,
    sign_manifest,
    safe_artifact_path,
    verify_artifacts,
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

    def test_publication_audit_accepts_exact_multi_platform_tree(self) -> None:
        publication = self.root / "multi-publication"
        windows_release = publication / "channels/test/windows-x64/releases/0.4.14"
        windows_release.mkdir(parents=True)
        (windows_release / "Arena.jar").write_bytes(b"arena")
        windows_pointer = publication / "channels/test/windows-x64/manifest.json"
        windows_versioned = publication / "channels/test/windows-x64/manifests/0.4.14.json"
        write_json_atomic(windows_pointer, self.signed)
        write_json_atomic(windows_versioned, self.signed)

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
