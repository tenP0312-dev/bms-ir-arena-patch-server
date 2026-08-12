from __future__ import annotations

import base64
import json
import shutil
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena_patch_server.cli import audit_publication, write_json_atomic
from arena_patch_server.delta import apply_publication_delta, create_publication_delta
from arena_patch_server.manifest import (
    ManifestError,
    append_history_version,
    build_manifest,
    sign_history,
    sign_manifest,
)


class PublicationDeltaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        self.private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public_raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.public_key = self.workspace / "test.pub"
        self.public_key.write_text(base64.b64encode(public_raw).decode("ascii"), encoding="ascii")
        self.base = self.workspace / "base"
        self.target = self.workspace / "target"
        self._publish(
            self.base,
            platform="windows-x64",
            version="1.0.0",
            published_at="2026-08-10T00:00:00Z",
            payload=b"old-windows",
        )
        shutil.copytree(self.base, self.target)
        self.windows_pointer = self._publish(
            self.target,
            platform="windows-x64",
            version="1.0.1",
            published_at="2026-08-11T00:00:00Z",
            payload=b"new-windows",
        )
        self.archive = self.workspace / "delta.tar.gz"
        self.delta = self.workspace / "delta"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _publish(
        self,
        root: Path,
        *,
        platform: str,
        version: str,
        published_at: str,
        payload: bytes,
    ) -> Path:
        source = self.workspace / f"source-{root.name}-{platform}-{version}"
        source.mkdir()
        (source / "Arena.jar").write_bytes(payload)
        manifest = sign_manifest(
            build_manifest(
                source,
                ["Arena.jar"],
                channel="test",
                platform=platform,
                version=version,
                published_at=published_at,
            ),
            self.private,
        )
        base = root / "channels" / "test" / platform
        release = base / "releases" / version
        release.mkdir(parents=True)
        (release / "Arena.jar").write_bytes(payload)
        pointer = base / "manifest.json"
        write_json_atomic(pointer, manifest)
        write_json_atomic(base / "manifests" / f"{version}.json", manifest)

        versions: list[dict[str, object]] = []
        history_path = base / "history.json"
        if history_path.exists():
            versions = json.loads(history_path.read_text(encoding="utf-8"))["versions"]
        history = append_history_version(
            versions,
            channel="test",
            platform=platform,
            version=version,
            published_at=published_at,
        )
        write_json_atomic(history_path, sign_history(history, self.private))
        return pointer

    def _extract_delta(self, manifests: list[Path] | None = None) -> None:
        create_publication_delta(
            self.target,
            manifests or [self.windows_pointer],
            self.public_key,
            self.archive,
        )
        self.delta.mkdir()
        with tarfile.open(self.archive, "r:gz") as archive:
            archive.extractall(self.delta, filter="data")

    def test_packages_only_current_release_and_applies_it(self) -> None:
        self._extract_delta()
        actual = {
            path.relative_to(self.delta).as_posix()
            for path in self.delta.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            {
                "channels/test/windows-x64/manifest.json",
                "channels/test/windows-x64/history.json",
                "channels/test/windows-x64/manifests/1.0.1.json",
                "channels/test/windows-x64/releases/1.0.1/Arena.jar",
            },
            actual,
        )

        self.assertEqual(
            ["test windows-x64 1.0.1"],
            apply_publication_delta(self.base, self.delta, self.public_key),
        )
        self.assertEqual(
            ["test windows-x64 1.0.1"],
            audit_publication(
                self.base,
                [self.base / "channels/test/windows-x64/manifest.json"],
                self.public_key,
            ),
        )

    def test_accepts_multiple_changed_platforms(self) -> None:
        self._publish(
            self.base,
            platform="macos-arm64",
            version="1.0.0",
            published_at="2026-08-10T00:00:00Z",
            payload=b"old-macos",
        )
        self._publish(
            self.target,
            platform="macos-arm64",
            version="1.0.0",
            published_at="2026-08-10T00:00:00Z",
            payload=b"old-macos",
        )
        mac_pointer = self._publish(
            self.target,
            platform="macos-arm64",
            version="1.0.1",
            published_at="2026-08-11T00:00:00Z",
            payload=b"new-macos",
        )
        self._extract_delta([self.windows_pointer, mac_pointer])

        applied = apply_publication_delta(self.base, self.delta, self.public_key)

        self.assertEqual(
            ["test macos-arm64 1.0.1", "test windows-x64 1.0.1"],
            applied,
        )
        audit_publication(
            self.base,
            [
                self.base / "channels/test/windows-x64/manifest.json",
                self.base / "channels/test/macos-arm64/manifest.json",
            ],
            self.public_key,
        )

    def test_rejects_rewritten_history_even_when_resigned(self) -> None:
        self._extract_delta()
        history_path = self.delta / "channels/test/windows-x64/history.json"
        history = json.loads(history_path.read_text(encoding="utf-8"))
        history["versions"][1]["published_at"] = "2026-08-09T00:00:00Z"
        write_json_atomic(history_path, sign_history(history, self.private))

        with self.assertRaisesRegex(ManifestError, "strictly prepend"):
            apply_publication_delta(self.base, self.delta, self.public_key)

    def test_rejects_immutable_overwrite(self) -> None:
        self._extract_delta()
        collision = self.base / "channels/test/windows-x64/manifests/1.0.1.json"
        collision.parent.mkdir(parents=True, exist_ok=True)
        collision.write_text("already present", encoding="utf-8")

        with self.assertRaisesRegex(ManifestError, "immutable path"):
            apply_publication_delta(self.base, self.delta, self.public_key)

    def test_rejects_extra_missing_and_symlink_paths(self) -> None:
        self._extract_delta()
        (self.delta / "extra.txt").write_text("unsigned", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "delta tree mismatch"):
            apply_publication_delta(self.base, self.delta, self.public_key)

        (self.delta / "extra.txt").unlink()
        artifact = self.delta / "channels/test/windows-x64/releases/1.0.1/Arena.jar"
        artifact.unlink()
        with self.assertRaisesRegex(ManifestError, "missing or unsafe"):
            apply_publication_delta(self.base, self.delta, self.public_key)

        artifact.write_bytes(b"new-windows")
        (self.delta / "link").symlink_to(artifact)
        with self.assertRaisesRegex(ManifestError, "symlink"):
            apply_publication_delta(self.base, self.delta, self.public_key)

    def test_rejects_output_inside_publication_tree(self) -> None:
        with self.assertRaisesRegex(ManifestError, "outside"):
            create_publication_delta(
                self.target,
                [self.windows_pointer],
                self.public_key,
                self.target / "delta.tar.gz",
            )


if __name__ == "__main__":
    unittest.main()
