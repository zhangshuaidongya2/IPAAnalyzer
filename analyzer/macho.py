from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import run_command


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) in MACHO_MAGICS
    except OSError:
        return False


def parse_architectures(lipo_output: str, file_output: str = "") -> list[str]:
    text = lipo_output.strip()
    if " are: " in text:
        text = text.rsplit(" are: ", 1)[1]
    elif " architecture: " in text:
        text = text.rsplit(" architecture: ", 1)[1]
    architectures = re.findall(r"(?<![\w])(?:arm64e?|x86_64|i[3-6]86|armv7s?|armv6)(?![\w])", text)
    if not architectures:
        architectures = re.findall(
            r"(?<![\w])(?:arm64e?|x86_64|i[3-6]86|armv7s?|armv6)(?![\w])", file_output
        )
    return list(dict.fromkeys(architectures))


def parse_dependencies(output: str) -> list[str]:
    dependencies: list[str] = []
    for line in output.splitlines()[1:]:
        line = line.strip()
        if not line or line.endswith(":") or line.startswith("("):
            continue
        name = re.sub(r"\s+\(compatibility version.*$", "", line)
        if name:
            dependencies.append(name)
    return list(dict.fromkeys(dependencies))


def _load_command_blocks(output: str) -> list[str]:
    return re.split(r"(?=^Load command \d+\s*$)", output, flags=re.MULTILINE)


def parse_load_commands(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "minimum_os": "",
        "sdk": "",
        "uuids": [],
        "rpaths": [],
        "libraries": [],
        "encryption_info": [],
        "load_commands": [],
    }
    important = {
        "LC_BUILD_VERSION",
        "LC_VERSION_MIN_IPHONEOS",
        "LC_LOAD_DYLIB",
        "LC_LOAD_WEAK_DYLIB",
        "LC_REEXPORT_DYLIB",
        "LC_RPATH",
        "LC_UUID",
        "LC_CODE_SIGNATURE",
        "LC_ENCRYPTION_INFO",
        "LC_ENCRYPTION_INFO_64",
    }
    for block in _load_command_blocks(output):
        command_match = re.search(r"^\s*cmd\s+(LC_[A-Z0-9_]+)", block, re.MULTILINE)
        if not command_match:
            continue
        command = command_match.group(1)
        if command in important:
            result["load_commands"].append(command)
        if command == "LC_BUILD_VERSION":
            minos = re.search(r"^\s*minos\s+(\S+)", block, re.MULTILINE)
            sdk = re.search(r"^\s*sdk\s+(\S+)", block, re.MULTILINE)
            if minos:
                result["minimum_os"] = minos.group(1)
            if sdk:
                result["sdk"] = sdk.group(1)
        elif command == "LC_VERSION_MIN_IPHONEOS":
            version = re.search(r"^\s*version\s+(\S+)", block, re.MULTILINE)
            sdk = re.search(r"^\s*sdk\s+(\S+)", block, re.MULTILINE)
            if version and not result["minimum_os"]:
                result["minimum_os"] = version.group(1)
            if sdk and not result["sdk"]:
                result["sdk"] = sdk.group(1)
        elif command == "LC_UUID":
            match = re.search(r"^\s*uuid\s+([0-9A-Fa-f-]+)", block, re.MULTILINE)
            if match:
                result["uuids"].append(match.group(1))
        elif command == "LC_RPATH":
            match = re.search(r"^\s*path\s+(.+?)\s+\(offset", block, re.MULTILINE)
            if match:
                result["rpaths"].append(match.group(1))
        elif command in {"LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB"}:
            match = re.search(r"^\s*name\s+(.+?)\s+\(offset", block, re.MULTILINE)
            if match:
                result["libraries"].append(match.group(1))
        elif command in {"LC_ENCRYPTION_INFO", "LC_ENCRYPTION_INFO_64"}:
            values: dict[str, int | str] = {"command": command}
            for key in ("cryptoff", "cryptsize", "cryptid"):
                match = re.search(rf"^\s*{key}\s+(\d+)", block, re.MULTILINE)
                if match:
                    values[key] = int(match.group(1))
            result["encryption_info"].append(values)

    for key in ("uuids", "rpaths", "libraries", "load_commands"):
        result[key] = list(dict.fromkeys(result[key]))
    return result


def analyze_macho(path: Path) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    file_command = run_command(["file", str(path)])
    file_type = file_command.stdout.strip()
    file_prefix = f"{path}: "
    if file_type.startswith(file_prefix):
        file_type = file_type[len(file_prefix) :]
    raw: dict[str, Any] = {"file": file_command.to_dict()}
    if not is_macho(path):
        return (
            {
                "path": str(path),
                "file_type": file_type,
                "architectures": [],
                "minimum_os": "",
                "sdk": "",
                "encrypted": False,
                "cryptid": None,
                "encryption_info": [],
                "uuids": [],
                "rpaths": [],
                "libraries": [],
                "load_commands": [],
                "pie": False,
            },
            raw,
            [f"Not a recognized Mach-O binary: {path.name}"],
        )

    lipo = run_command(["lipo", "-archs", str(path)])
    libraries = run_command(["otool", "-L", str(path)])
    load_commands = run_command(["otool", "-l", str(path)])
    headers = run_command(["otool", "-hv", str(path)])
    raw.update(
        {
            "lipo": lipo.to_dict(),
            "otool_L": libraries.to_dict(),
            "otool_l": load_commands.to_dict(),
            "otool_hv": headers.to_dict(),
        }
    )

    errors: list[str] = []
    for label, command in (
        ("file", file_command),
        ("lipo", lipo),
        ("otool -L", libraries),
        ("otool -l", load_commands),
        ("otool -hv", headers),
    ):
        if not command.succeeded:
            detail = command.stderr.strip() or command.stdout.strip() or "unknown error"
            errors.append(f"Mach-O {label} failed for {path.name}: {detail}")

    parsed = parse_load_commands(load_commands.stdout)
    dependency_list = parse_dependencies(libraries.stdout) if libraries.succeeded else []
    if not dependency_list:
        dependency_list = parsed["libraries"]
    cryptids = [
        item.get("cryptid") for item in parsed["encryption_info"] if "cryptid" in item
    ]
    result = {
        "path": str(path),
        "file_type": file_type,
        "architectures": parse_architectures(lipo.stdout, file_command.stdout),
        "minimum_os": parsed["minimum_os"],
        "sdk": parsed["sdk"],
        "encrypted": any(value == 1 for value in cryptids),
        "cryptid": cryptids[0] if len(cryptids) == 1 else (cryptids or None),
        "encryption_info": parsed["encryption_info"],
        "uuids": parsed["uuids"],
        "rpaths": parsed["rpaths"],
        "libraries": dependency_list,
        "load_commands": parsed["load_commands"],
        "pie": bool(re.search(r"\bPIE\b", headers.stdout)),
    }
    return result, raw, errors
