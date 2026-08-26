from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any


class PlistError(ValueError):
    pass


OVERVIEW_FIELDS = {
    "name": "CFBundleName",
    "display_name": "CFBundleDisplayName",
    "bundle_id": "CFBundleIdentifier",
    "version": "CFBundleShortVersionString",
    "build": "CFBundleVersion",
    "minimum_os": "MinimumOSVersion",
    "executable": "CFBundleExecutable",
    "package_type": "CFBundlePackageType",
    "supported_platforms": "CFBundleSupportedPlatforms",
    "device_family": "UIDeviceFamily",
    "required_capabilities": "UIRequiredDeviceCapabilities",
    "platform_name": "DTPlatformName",
    "platform_version": "DTPlatformVersion",
    "sdk_name": "DTSDKName",
    "sdk_build": "DTSDKBuild",
    "xcode": "DTXcode",
    "xcode_build": "DTXcodeBuild",
}


def load_plist(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            value = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException, ValueError) as exc:
        raise PlistError(f"Unable to parse {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise PlistError(f"Expected a dictionary in {path.name}")
    return value


def loads_plist(data: bytes | str) -> dict[str, Any]:
    encoded = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
    try:
        value = plistlib.loads(encoded)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise PlistError(f"Unable to parse property list data: {exc}") from exc
    if not isinstance(value, dict):
        raise PlistError("Expected a property list dictionary")
    return value


def plist_xml(value: dict[str, Any]) -> str:
    try:
        return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PlistError(f"Unable to format property list: {exc}") from exc


def extract_overview(info: dict[str, Any]) -> dict[str, Any]:
    overview = {name: info.get(key) for name, key in OVERVIEW_FIELDS.items()}
    overview["display_name"] = overview["display_name"] or overview["name"]
    return overview
