from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path


class ArchivePartsError(ValueError):
    pass


def assemble_release_archive(
    parts_directory: Path,
    asset_name: str,
    output: Path,
) -> Path:
    """Copy one archive asset or join its numbered release-asset parts."""
    if not asset_name or Path(asset_name).name != asset_name:
        raise ArchivePartsError("asset name must be a plain filename")
    if not parts_directory.is_dir():
        raise ArchivePartsError("parts directory does not exist")

    exact = parts_directory / asset_name
    prefixed = sorted(
        path
        for path in parts_directory.iterdir()
        if path.is_file() and path.name.startswith(asset_name + ".part")
    )
    if exact.is_file():
        if prefixed:
            raise ArchivePartsError("archive and multipart assets cannot be mixed")
        sources = [exact]
    else:
        pattern = re.compile(re.escape(asset_name) + r"\.part([0-9]{3})")
        indexed: list[tuple[int, Path]] = []
        for path in prefixed:
            match = pattern.fullmatch(path.name)
            if match is None:
                raise ArchivePartsError(f"invalid archive part name: {path.name}")
            indexed.append((int(match.group(1)), path))
        indexed.sort()
        if not indexed:
            raise ArchivePartsError("archive asset or multipart assets are missing")
        indexes = [index for index, _path in indexed]
        if indexes != list(range(len(indexed))):
            raise ArchivePartsError("archive part indexes must start at 000 and be contiguous")
        sizes = [path.stat().st_size for _index, path in indexed]
        if any(size <= 0 for size in sizes):
            raise ArchivePartsError("archive parts must not be empty")
        if any(size != sizes[0] for size in sizes[:-1]) or sizes[-1] > sizes[0]:
            raise ArchivePartsError("archive part sizes are inconsistent")
        sources = [path for _index, path in indexed]

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as target:
        temporary = Path(target.name)
        try:
            for source in sources:
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, target, length=1024 * 1024)
            target.flush()
            os.fsync(target.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    os.replace(temporary, output)
    return output
