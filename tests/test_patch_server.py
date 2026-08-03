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

    def test_mutable_player_data_cannot_be_a_release_artifact(self) -> None:
        for value in (
            "player/player1/score.db",
            "score.db",
            "config_sys.json",
            "bmsir-arena-version.txt",
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


if __name__ == "__main__":
    unittest.main()
