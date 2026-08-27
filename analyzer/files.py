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


@dataclass(frozen=True)
class ImageExtractionResult:
    destination: Path
    file_count: int
    total_size: int


IMAGE_HEADER_SIZE = 4096


def _detected_image_suffix(header: bytes) -> str | None:
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return ".webp"
    if header.startswith(b"BM"):
        return ".bmp"
    if header.startswith((b"II*\x00", b"MM\x00*")):
        return ".tiff"
    if header.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if header.startswith(b"icns"):
        return ".icns"
    if header.startswith(b"%PDF-"):
        return ".pdf"
    if header.startswith(b"\x13\xab\xa1\x5c"):
        return ".astc"
    if header.startswith(b"DDS "):
        return ".dds"
    if header.startswith(b"\xabKTX 11\xbb\r\n\x1a\n"):
        return ".ktx"
    if header.startswith(b"\xabKTX 20\xbb\r\n\x1a\n"):
        return ".ktx2"
    if header.startswith(b"PVR\x03"):
        return ".pvr"
    if header.startswith((b"\xff\x0a", b"\x00\x00\x00\x0cJXL \r\n\x87\n")):
        return ".jxl"

    if len(header) >= 12 and header[4:8] == b"ftyp":
        brands = header[8:64]
        if any(brand in brands for brand in (b"avif", b"avis")):
            return ".avif"
        if any(
            brand in brands
            for brand in (b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1")
        ):
            return ".heic"

    normalized = header.removeprefix(b"\xef\xbb\xbf").lstrip().lower()
    svg_position = normalized.find(b"<svg")
    html_position = normalized.find(b"<html")
    if 0 <= svg_position < IMAGE_HEADER_SIZE and (
        html_position < 0 or svg_position < html_position
    ):
        return ".svg"
    return None


def _output_image_name(original_name: str, suffix: str, used_names: set[str]) -> str:
    original = PurePosixPath(original_name).name
    original_suffix = PurePosixPath(original).suffix.lower()
    compatible_suffixes = {
        ".jpg": {".jpg", ".jpeg"},
        ".png": {".png", ".apng"},
        ".tiff": {".tif", ".tiff"},
        ".heic": {".heic", ".heif"},
    }
    if original_suffix == suffix or original_suffix in compatible_suffixes.get(suffix, set()):
        desired = original
    else:
        stem = original[: -len(original_suffix)] if original_suffix else original
        desired = f"{stem or 'image'}{suffix}"

    candidate = desired
    stem = candidate[: -len(PurePosixPath(candidate).suffix)]
    extension = PurePosixPath(candidate).suffix
    number = 2
    while candidate.casefold() in used_names:
        candidate = f"{stem}-{number}{extension}"
        number += 1
    used_names.add(candidate.casefold())
    return candidate


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


def extract_image_resources(
    ipa_path: str | Path,
    destination: str | Path,
    *,
    limits: ArchiveLimits | None = None,
) -> ImageExtractionResult:
    source_path = Path(ipa_path).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    limits = limits or ArchiveLimits()

    if not source_path.is_file():
        raise FileNotFoundError(f"IPA file does not exist: {source_path}")
    if destination_path.exists() and not destination_path.is_dir():
        raise NotADirectoryError(f"Export destination is not a directory: {destination_path}")

    with zipfile.ZipFile(source_path, "r") as archive:
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

        used_names = (
            {item.name.casefold() for item in destination_path.iterdir()}
            if destination_path.is_dir()
            else set()
        )
        selected: list[tuple[zipfile.ZipInfo, Path]] = []
        selected_size = 0
        for member in members:
            _validated_destination(destination_path, member.filename)
            if member.file_size > limits.max_single_file_size:
                raise ArchiveSecurityError(f"Archive entry is too large: {member.filename}")
            if member.flag_bits & 0x1:
                raise ArchiveSecurityError(
                    f"Encrypted ZIP entry is not supported: {member.filename}"
                )
            if member.file_size and not member.compress_size:
                raise ArchiveSecurityError(f"Invalid compressed size: {member.filename}")
            if (
                member.compress_size
                and member.file_size / member.compress_size > limits.max_compression_ratio
            ):
                raise ArchiveSecurityError(f"Suspicious compression ratio: {member.filename}")
            mode = (member.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                continue
            if member.is_dir():
                continue

            with archive.open(member, "r") as source:
                detected_suffix = _detected_image_suffix(source.read(IMAGE_HEADER_SIZE))
            if detected_suffix is None:
                continue

            output_name = _output_image_name(member.filename, detected_suffix, used_names)
            target = destination_path / output_name
            selected.append((member, target))
            selected_size += member.file_size

        if not selected:
            return ImageExtractionResult(destination_path, 0, 0)

        destination_path.mkdir(parents=True, exist_ok=True)
        written_total = 0
        for member, target in selected:
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(member, "r") as source, target.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    written += len(chunk)
                    written_total += len(chunk)
                    if written > limits.max_single_file_size:
                        raise ArchiveSecurityError(
                            f"Archive entry exceeded size limit: {member.filename}"
                        )
                    if written_total > limits.max_uncompressed_size:
                        raise ArchiveSecurityError("Archive exceeded total extraction size limit")
                    output.write(chunk)
            if written != member.file_size:
                raise ArchiveSecurityError(f"Extracted size mismatch: {member.filename}")

    return ImageExtractionResult(destination_path, len(selected), selected_size)


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
