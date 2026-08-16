from __future__ import annotations

import base64
import hashlib
import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena_patch_server.cli import command_draft, promote
from arena_patch_server.locations import (
    append_artifact_locations,
    location_for_artifact,
    release_asset_url,
    sign_artifact_locations,
    verify_artifact_locations,
    verify_remote_location,
)
from arena_patch_server.manifest import ManifestError
from arena_patch_server.migration import externalize_publication


class ArtifactLocationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.private_path = self.root / "test.key"
        self.public_path = self.root / "test.pub"
        self.private_path.write_text(
            base64.b64encode(
                self.private.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        self.public_path.write_text(
            base64.b64encode(
                self.private.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )
            ).decode("ascii"),
            encoding="ascii",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signed_location_binds_manifest_identity_and_rejects_tampering(self) -> None:
        artifact = {
            "path": "Arena-oraja.jar",
            "sha256": "12" * 32,
            "size": 123,
            "executable": False,
        }
        entry = {
            "version": "0.4.14.49",
            "path": artifact["path"],
            "sha256": artifact["sha256"],
            "size": artifact["size"],
            "url": release_asset_url(
                "tenP0312-dev/bms-ir-arena-patch-server",
                "test-0.4.14.49",
                "windows-x64-Arena-oraja.jar",
            ),
            "retain_on_pages": False,
        }
        document = append_artifact_locations(
            [], [entry], channel="test", platform="windows-x64"
        )
        signed = sign_artifact_locations(document, self.private)
        verify_artifact_locations(signed, self.private.public_key())
        self.assertEqual(
            entry,
            location_for_artifact(signed, "0.4.14.49", artifact),
        )

        tampered = json.loads(json.dumps(signed))
        tampered["locations"][0]["url"] = tampered["locations"][0][
            "url"
        ].replace("test-0.4.14.49", "test-9.9.9")
        with self.assertRaisesRegex(ManifestError, "signature"):
            verify_artifact_locations(tampered, self.private.public_key())

        mismatch = dict(artifact, size=124)
        with self.assertRaisesRegex(ManifestError, "does not match"):
            location_for_artifact(signed, "0.4.14.49", mismatch)

    def test_remote_location_hashes_the_downloaded_release_bytes(self) -> None:
        payload = b"external-release-asset"
        location = {
            "version": "0.4.14.49",
            "path": "Arena-oraja.jar",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "url": release_asset_url(
                "tenP0312-dev/bms-ir-arena-patch-server",
                "test-0.4.14.49",
                "windows-x64-Arena-oraja.jar",
            ),
            "retain_on_pages": False,
        }
        with patch(
            "arena_patch_server.locations.urllib.request.urlopen",
            return_value=io.BytesIO(payload),
        ):
            verify_remote_location(location)
        broken = dict(location, size=len(payload) + 1)
        with patch(
            "arena_patch_server.locations.urllib.request.urlopen",
            return_value=io.BytesIO(payload),
        ), self.assertRaisesRegex(ManifestError, "does not match"):
            verify_remote_location(broken)

    def _draft(
        self,
        publication: Path,
        *,
        version: str,
        body: bytes,
        launcher_version: str | None = None,
    ) -> None:
        source = self.root / f"source-{version}"
        source.mkdir()
        (source / "Arena-oraja.jar").write_bytes(body)
        artifacts = ["Arena-oraja.jar"]
        if launcher_version:
            (source / "BMS-IR Arena Test.exe").write_bytes(b"launcher")
            artifacts.append("BMS-IR Arena Test.exe")
        args = type(
            "Args",
            (),
            {
                "root": publication,
                "source": source,
                "private_key": self.private_path,
                "channel": "test",
                "platform": "windows-x64",
                "version": version,
                "notes_file": None,
                "notes_ja_file": None,
                "notes_en_file": None,
                "announcements_file": None,
                "mandatory": False,
                "minimum_launcher_version": "0.1.0",
                "launcher_version": launcher_version,
                "revoke": [],
                "bootstrap_manifest": None,
                "bootstrap_archive": None,
                "bootstrap_url": None,
                "artifact": artifacts,
                "published_at": f"2026-08-{10 + int(version[-1])}T00:00:00Z",
            },
        )()
        command_draft(args)
        promote(
            publication,
            publication
            / "channels/test/windows-x64/manifests"
            / f"{version}.json",
            self.public_path,
        )

    def test_externalization_is_non_destructive_and_keeps_compatibility_files(self) -> None:
        publication = self.root / "publication"
        self._draft(publication, version="1.0.0", body=b"historical")
        self._draft(
            publication,
            version="1.0.1",
            body=b"launcher-release",
            launcher_version="0.2.26",
        )
        self._draft(publication, version="1.0.2", body=b"current")
        historical = (
            publication
            / "channels/test/windows-x64/releases/1.0.0/Arena-oraja.jar"
        )
        output = self.root / "externalized"
        state_path = externalize_publication(
            root=publication,
            private_key_path=self.private_path,
            public_key_path=self.public_path,
            repository="tenP0312-dev/bms-ir-arena-patch-server",
            release_tag="test-external-artifacts-1",
            output_dir=output,
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertTrue(state["source_publication_unchanged"])
        self.assertTrue(historical.is_file())
        self.assertFalse(
            (
                output
                / "publication/channels/test/windows-x64/releases/1.0.0/Arena-oraja.jar"
            ).exists()
        )
        self.assertTrue(
            (
                output
                / "publication/channels/test/windows-x64/releases/1.0.2/Arena-oraja.jar"
            ).is_file()
        )
        self.assertTrue(
            (
                output
                / "publication/channels/test/windows-x64/releases/1.0.1/BMS-IR Arena Test.exe"
            ).is_file()
        )
        self.assertGreater(state["unique_payloads"], 0)


if __name__ == "__main__":
    unittest.main()
