from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from .utils import file_kind, hash_file


class ArchiveSecurityError(ValueError):
    pass


@dataclass(frozen=True)
class ArchiveLimits:
    max_entries: int = 100_000
    max_uncompressed_size: int = 20 * 1024 * 1024 * 1024
    max_single_file_size: int = 8 * 1024 * 1024 * 1024
    max_compression_ratio: int = 10_000


def _validated_destination(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or not relative.parts:
        raise ArchiveSecurityError(f"Unsafe archive path: {name!r}")
    if any(part in ("", ".", "..") for part in relative.parts):
        raise ArchiveSecurityError(f"Unsafe archive path: {name!r}")
    destination = root.joinpath(*relative.parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ArchiveSecurityError(f"Archive path escapes extraction directory: {name!r}") from exc
    return destination


def safe_extract_ipa(
    archive: zipfile.ZipFile,
    destination: Path,
    *,
    limits: ArchiveLimits | None = None,
    warning: Callable[[str], None] | None = None,
) -> None:
    limits = limits or ArchiveLimits()
    members = archive.infolist()
    if len(members) > limits.max_entries:
        raise ArchiveSecurityError(
            f"Archive contains {len(members)} entries; limit is {limits.max_entries}"
        )

    total_size = sum(member.file_size for member in members)
    if total_size > limits.max_uncompressed_size:
        raise ArchiveSecurityError(
            f"Archive expands to {total_size} bytes; limit is {limits.max_uncompressed_size}"
        )

    destination.mkdir(parents=True, exist_ok=True)
    extracted_total = 0
    for member in members:
        target = _validated_destination(destination, member.filename)
        if member.file_size > limits.max_single_file_size:
            raise ArchiveSecurityError(f"Archive entry is too large: {member.filename}")
        if member.flag_bits & 0x1:
            raise ArchiveSecurityError(f"Encrypted ZIP entry is not supported: {member.filename}")
        if member.file_size and not member.compress_size:
            raise ArchiveSecurityError(f"Invalid compressed size: {member.filename}")
        if member.compress_size and member.file_size / member.compress_size > limits.max_compression_ratio:
            raise ArchiveSecurityError(f"Suspicious compression ratio: {member.filename}")

        mode = (member.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            if warning:
                warning(f"Skipped symbolic link in archive: {member.filename}")
            continue
        if member.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with archive.open(member, "r") as source, target.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                written += len(chunk)
                extracted_total += len(chunk)
                if written > limits.max_single_file_size:
                    raise ArchiveSecurityError(f"Archive entry exceeded size limit: {member.filename}")
                if extracted_total > limits.max_uncompressed_size:
                    raise ArchiveSecurityError("Archive exceeded total extraction size limit")
                output.write(chunk)
        if target.stat().st_size != member.file_size:
            raise ArchiveSecurityError(f"Extracted size mismatch: {member.filename}")
        if mode:
            permissions = mode & 0o755
            if permissions:
                target.chmod(permissions)


def build_file_index(root: Path, ipa_path: Path | None = None) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
        relative = path.relative_to(root).as_posix()
        is_directory = path.is_dir()
        entry: dict[str, object] = {
            "name": path.name,
            "relative_path": relative,
            "archive_path": relative,
            "full_path": f"{ipa_path}!/{relative}" if ipa_path else relative,
            "size": 0 if is_directory else path.stat().st_size,
            "type": file_kind(path),
            "is_directory": is_directory,
            "sha256": "",
        }
        if not is_directory:
            entry["sha256"] = hash_file(path)["sha256"]
        entries.append(entry)
    return entries
