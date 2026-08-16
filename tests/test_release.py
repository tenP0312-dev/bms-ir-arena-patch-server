from __future__ import annotations

import base64
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena_patch_server.cli import audit_publication, command_draft, promote
from arena_patch_server.delta import apply_publication_delta
from arena_patch_server.manifest import ManifestError
from arena_patch_server.release import prepare_release


class TransactionalReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
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
        self.base = self.root / "base"
        self._seed_platform("windows-x64")
        self._seed_platform("macos-arm64")
        self.archive = self.root / "base.tar.gz"
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.base, arcname=".")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seed_platform(self, platform: str) -> None:
        source = self.root / f"seed-{platform}"
        source.mkdir()
        (source / "Arena.jar").write_bytes(f"old-{platform}".encode())
        args = type(
            "Args",
            (),
            {
                "root": self.base,
                "source": source,
                "private_key": self.private_path,
                "channel": "test",
                "platform": platform,
                "version": "1.0.0",
                "notes_file": None,
                "notes_ja_file": None,
                "notes_en_file": None,
                "announcements_file": None,
                "mandatory": False,
                "minimum_launcher_version": "0.1.0",
                "launcher_version": None,
                "revoke": [],
                "bootstrap_manifest": None,
                "bootstrap_archive": None,
                "bootstrap_url": None,
                "artifact": ["Arena.jar"],
                "published_at": "2026-08-15T00:00:00Z",
            },
        )()
        command_draft(args)
        manifest = (
            self.base
            / "channels"
            / "test"
            / platform
            / "manifests"
            / "1.0.0.json"
        )
        promote(self.base, manifest, self.public_path)

    def _write_spec(self, *, standalone: bool = False, external: bool = False) -> Path:
        platforms = []
        for platform in ("windows-x64", "macos-arm64"):
            source = self.root / f"new-{platform}"
            source.mkdir(exist_ok=True)
            (source / "Arena.jar").write_bytes(f"new-{platform}".encode())
            platforms.append(
                {
                    "platform": platform,
                    "source": str(source),
                    "artifacts": (
                        [
                            {
                                "path": "Arena.jar",
                                "asset_name": f"{platform}-Arena.jar",
                                "retain_on_pages": False,
                            }
                        ]
                        if external
                        else ["Arena.jar"]
                    ),
                }
            )
        extra = self.root / "standalone.zip"
        extra.write_bytes(b"fallback")
        spec = {
            "schema_version": 1,
            "channel": "test",
            "version": "1.0.1",
            "release_tag": "test-1.0.1",
            "published_at": "2026-08-16T00:00:00Z",
            "signing_key_ref": "arena-test-current",
            "base": {
                "release_tag": "test-1.0.0",
                "asset_name": "snapshot-1.0.0.tar.gz",
            },
            "delta_asset_name": "delta-1.0.1.tar.gz",
            "snapshot_asset_name": "snapshot-1.0.1.tar.gz",
            "source_commits": {"oraja": "abcdef12", "plugin": "12345678"},
            "server_gate": {
                "client_version": "1.0.1",
                "build_hash": "abcdef12",
            },
            "platforms": platforms,
        }
        if external:
            spec["artifact_repository"] = (
                "tenP0312-dev/bms-ir-arena-patch-server"
            )
        if standalone:
            spec["standalone_release_assets"] = [str(extra)]
        path = self.root / ("spec-standalone.json" if standalone else "spec.json")
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def test_prepares_clean_delta_and_state_with_delta_only_default(self) -> None:
        output = self.root / "prepared"
        state_path = prepare_release(
            spec_path=self._write_spec(),
            base_archive=self.archive,
            private_key_path=self.private_path,
            public_key_path=self.public_path,
            output_dir=output,
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual("delta_only", state["upload_policy"])
        self.assertEqual(
            ["signed_delta"],
            [item["role"] for item in state["release_uploads"]],
        )
        self.assertEqual(
            "test-1.0.0", state["workflow"]["inputs"]["base_release_tag"]
        )
        self.assertTrue((output / "delta-1.0.1.tar.gz").is_file())
        self.assertTrue(
            (
                output
                / "publication/channels/test/windows-x64/releases/1.0.0/Arena.jar"
            ).is_file()
        )

    def test_rejects_wrong_private_key_before_creating_output(self) -> None:
        wrong = Ed25519PrivateKey.generate()
        wrong_path = self.root / "wrong.key"
        wrong_path.write_text(
            base64.b64encode(
                wrong.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            ).decode("ascii"),
            encoding="ascii",
        )
        output = self.root / "must-not-exist"
        with self.assertRaisesRegex(ManifestError, "does not match"):
            prepare_release(
                spec_path=self._write_spec(),
                base_archive=self.archive,
                private_key_path=wrong_path,
                public_key_path=self.public_path,
                output_dir=output,
            )
        self.assertFalse(output.exists())

    def test_standalone_assets_require_explicit_opt_in(self) -> None:
        state_path = prepare_release(
            spec_path=self._write_spec(standalone=True),
            base_archive=self.archive,
            private_key_path=self.private_path,
            public_key_path=self.public_path,
            output_dir=self.root / "prepared-standalone",
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual("delta_plus_explicit_standalone", state["upload_policy"])
        self.assertEqual(
            ["signed_delta", "standalone_opt_in"],
            [item["role"] for item in state["release_uploads"]],
        )

    def test_external_artifacts_are_staged_and_removed_from_pages_delta(self) -> None:
        output = self.root / "prepared-external"
        state_path = prepare_release(
            spec_path=self._write_spec(external=True),
            base_archive=self.archive,
            private_key_path=self.private_path,
            public_key_path=self.public_path,
            output_dir=output,
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        self.assertEqual("delta_plus_external_artifacts", state["upload_policy"])
        self.assertEqual(
            ["external_artifact", "external_artifact", "signed_delta"],
            [item["role"] for item in state["release_uploads"]],
        )
        self.assertTrue(
            (output / "release-assets/windows-x64-Arena.jar").is_file()
        )
        self.assertFalse(
            (
                output
                / "publication/channels/test/windows-x64/releases/1.0.1/Arena.jar"
            ).exists()
        )
        with tarfile.open(output / "delta-1.0.1.tar.gz", "r:gz") as archive:
            names = {name.removeprefix("./") for name in archive.getnames()}
        self.assertIn(
            "channels/test/windows-x64/artifact-locations.json", names
        )
        self.assertNotIn(
            "channels/test/windows-x64/releases/1.0.1/Arena.jar", names
        )
        applied = self.root / "applied-external"
        shutil.copytree(self.base, applied)
        delta = self.root / "extracted-external-delta"
        delta.mkdir()
        with tarfile.open(output / "delta-1.0.1.tar.gz", "r:gz") as archive:
            archive.extractall(delta, filter="data")
        self.assertEqual(
            ["test macos-arm64 1.0.1", "test windows-x64 1.0.1"],
            sorted(apply_publication_delta(applied, delta, self.public_path)),
        )
        audit_publication(
            applied,
            sorted(applied.glob("channels/test/*/manifest.json")),
            self.public_path,
        )

    def test_base_audit_failure_leaves_no_partial_output(self) -> None:
        (self.base / "unsigned-extra.txt").write_text("extra", encoding="utf-8")
        broken_archive = self.root / "broken-base.tar.gz"
        with tarfile.open(broken_archive, "w:gz") as archive:
            archive.add(self.base, arcname=".")
        output = self.root / "must-remain-absent"
        with self.assertRaisesRegex(ManifestError, "publication tree mismatch"):
            prepare_release(
                spec_path=self._write_spec(),
                base_archive=broken_archive,
                private_key_path=self.private_path,
                public_key_path=self.public_path,
                output_dir=output,
            )
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
