from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from arena_patch_server.archive import ArchivePartsError, assemble_release_archive


class ReleaseArchivePartsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.download = self.root / "download"
        self.download.mkdir()
        self.output = self.root / "assembled" / "channel.tar.gz"
        self.asset_name = "channel.tar.gz"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_copies_a_single_archive_for_backward_compatibility(self) -> None:
        (self.download / self.asset_name).write_bytes(b"single archive")

        assemble_release_archive(self.download, self.asset_name, self.output)

        self.assertEqual(b"single archive", self.output.read_bytes())

    def test_joins_numbered_parts_in_order(self) -> None:
        (self.download / f"{self.asset_name}.part000").write_bytes(b"abc")
        (self.download / f"{self.asset_name}.part001").write_bytes(b"def")
        (self.download / f"{self.asset_name}.part002").write_bytes(b"g")

        assemble_release_archive(self.download, self.asset_name, self.output)

        self.assertEqual(b"abcdefg", self.output.read_bytes())

    def test_rejects_a_missing_part(self) -> None:
        (self.download / f"{self.asset_name}.part000").write_bytes(b"abc")
        (self.download / f"{self.asset_name}.part002").write_bytes(b"def")

        with self.assertRaisesRegex(ArchivePartsError, "contiguous"):
            assemble_release_archive(self.download, self.asset_name, self.output)

        self.assertFalse(self.output.exists())

    def test_rejects_mixed_single_and_multipart_assets(self) -> None:
        (self.download / self.asset_name).write_bytes(b"single")
        (self.download / f"{self.asset_name}.part000").write_bytes(b"part")

        with self.assertRaisesRegex(ArchivePartsError, "cannot be mixed"):
            assemble_release_archive(self.download, self.asset_name, self.output)

    def test_rejects_malformed_part_names_and_sizes(self) -> None:
        (self.download / f"{self.asset_name}.part00x").write_bytes(b"abc")
        with self.assertRaisesRegex(ArchivePartsError, "invalid archive part name"):
            assemble_release_archive(self.download, self.asset_name, self.output)

        (self.download / f"{self.asset_name}.part00x").unlink()
        (self.download / f"{self.asset_name}.part000").write_bytes(b"a")
        (self.download / f"{self.asset_name}.part001").write_bytes(b"longer")
        with self.assertRaisesRegex(ArchivePartsError, "sizes are inconsistent"):
            assemble_release_archive(self.download, self.asset_name, self.output)


if __name__ == "__main__":
    unittest.main()
