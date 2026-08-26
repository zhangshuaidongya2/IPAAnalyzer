from __future__ import annotations

import hashlib
import mimetypes
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def run_command(
    args: list[str], *, input_data: bytes | None = None, timeout: float = 30
) -> CommandResult:
    """Run a command without a shell and always return a structured result."""
    command = [str(arg) for arg in args]
    executable = command[0] if command else ""
    if not executable or shutil.which(executable) is None:
        return CommandResult(command, 127, "", f"Command not found: {executable}")

    try:
        completed = subprocess.run(
            command,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            shell=False,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout.decode("utf-8", errors="replace"),
            stderr=completed.stderr.decode("utf-8", errors="replace"),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
        message = f"Command timed out after {timeout:g}s"
        return CommandResult(command, 124, stdout, f"{stderr}\n{message}".strip())
    except OSError as exc:
        return CommandResult(command, 126, "", f"Unable to run command: {exc}")


def hash_file(path: Path, algorithms: tuple[str, ...] = ("sha256",)) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in algorithms}
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def file_kind(path: Path) -> str:
    if path.is_dir():
        return "directory"
    mime, _ = mimetypes.guess_type(path.name)
    if path.suffix == ".plist":
        return "property list"
    if path.name == "embedded.mobileprovision":
        return "provisioning profile"
    return mime or "binary"


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"
