from __future__ import annotations

from pathlib import Path
from typing import Any

from .macho import analyze_macho
from .plist import PlistError, load_plist
from .signing import analyze_code_signature
from .utils import directory_size, hash_file


EXTENSION_TYPES = {
    "com.apple.share-services": "Share Extension",
    "com.apple.usernotifications.service": "Notification Service Extension",
    "com.apple.usernotifications.content-extension": "Notification Content Extension",
    "com.apple.widget-extension": "Widget",
    "com.apple.widgetkit-extension": "Widget",
    "com.apple.keyboard-service": "Keyboard Extension",
    "com.apple.fileprovider-nonui": "File Provider",
    "com.apple.fileprovider-actionsui": "File Provider UI",
    "com.apple.networkextension.packet-tunnel": "VPN Extension",
    "com.apple.networkextension.app-proxy": "VPN Extension",
    "com.apple.intents-service": "Intents Extension",
}


def _relative(path: Path, extraction_root: Path) -> str:
    return path.relative_to(extraction_root).as_posix()


def _bundle_info(bundle: Path) -> tuple[dict[str, Any], list[str]]:
    plist_path = bundle / "Info.plist"
    if not plist_path.is_file():
        return {}, [f"Info.plist is missing in {bundle.name}"]
    try:
        return load_plist(plist_path), []
    except PlistError as exc:
        return {}, [str(exc)]


def analyze_frameworks(app_path: Path, extraction_root: Path) -> list[dict[str, Any]]:
    frameworks_root = app_path / "Frameworks"
    if not frameworks_root.is_dir():
        return []

    candidates = list(frameworks_root.rglob("*.framework")) + list(
        frameworks_root.rglob("*.dylib")
    )
    candidates = sorted(
        (item for item in candidates if item.is_dir() or item.is_file()),
        key=lambda item: item.as_posix().lower(),
    )
    results: list[dict[str, Any]] = []
    for item in candidates:
        errors: list[str] = []
        info: dict[str, Any] = {}
        if item.suffix == ".framework":
            info, info_errors = _bundle_info(item)
            errors.extend(info_errors)
            executable_name = info.get("CFBundleExecutable") or item.stem
            executable = item / str(executable_name)
            size = directory_size(item)
        else:
            executable_name = item.name
            executable = item
            size = item.stat().st_size

        macho: dict[str, Any] = {}
        raw_macho: dict[str, Any] = {}
        sha256 = ""
        if executable.is_file():
            macho, raw_macho, macho_errors = analyze_macho(executable)
            macho["path"] = _relative(executable, extraction_root)
            errors.extend(macho_errors)
            sha256 = hash_file(executable)["sha256"]
        else:
            errors.append(f"Framework executable is missing: {executable_name}")

        signature, _, raw_signature, signature_errors = analyze_code_signature(item)
        errors.extend(signature_errors)
        results.append(
            {
                "name": item.name,
                "path": _relative(item, extraction_root),
                "size": size,
                "bundle_id": info.get("CFBundleIdentifier", ""),
                "version": info.get("CFBundleShortVersionString")
                or info.get("CFBundleVersion", ""),
                "executable": executable_name,
                "architectures": macho.get("architectures", []),
                "signed": signature.get("valid_structure", False),
                "signature": signature,
                "libraries": macho.get("libraries", []),
                "sha256": sha256,
                "macho": macho,
                "errors": errors,
                "raw": {
                    "info_plist": info,
                    "macho": raw_macho,
                    "codesign": raw_signature,
                },
            }
        )
    return results


def analyze_extensions(app_path: Path, extraction_root: Path) -> list[dict[str, Any]]:
    plugins_root = app_path / "PlugIns"
    if not plugins_root.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for bundle in sorted(plugins_root.rglob("*.appex"), key=lambda item: item.as_posix().lower()):
        if not bundle.is_dir():
            continue
        info, errors = _bundle_info(bundle)
        extension = info.get("NSExtension", {}) or {}
        point = extension.get("NSExtensionPointIdentifier", "") if isinstance(extension, dict) else ""
        attributes = extension.get("NSExtensionAttributes", {}) if isinstance(extension, dict) else {}
        principal = ""
        if isinstance(extension, dict):
            principal = extension.get("NSExtensionPrincipalClass", "")
        executable_name = info.get("CFBundleExecutable", "")
        executable = bundle / str(executable_name) if executable_name else None
        signature, entitlements, raw_signature, signature_errors = analyze_code_signature(bundle)
        errors.extend(signature_errors)
        results.append(
            {
                "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle.stem,
                "path": _relative(bundle, extraction_root),
                "bundle_id": info.get("CFBundleIdentifier", ""),
                "type": EXTENSION_TYPES.get(point, point or "Unknown Extension"),
                "extension_point": point,
                "principal_class": principal,
                "version": info.get("CFBundleShortVersionString", ""),
                "build": info.get("CFBundleVersion", ""),
                "minimum_os": info.get("MinimumOSVersion", ""),
                "executable": executable_name,
                "executable_exists": bool(executable and executable.is_file()),
                "entitlements": entitlements,
                "signed": signature.get("valid_structure", False),
                "errors": errors,
                "raw": {
                    "info_plist": info,
                    "NSExtension": extension,
                    "NSExtensionAttributes": attributes,
                    "codesign": raw_signature,
                },
            }
        )
    return results


def analyze_embedded_bundles(app_path: Path, extraction_root: Path) -> list[dict[str, Any]]:
    locations = (("Watch", "Watch App"), ("AppClips", "App Clip"))
    results: list[dict[str, Any]] = []
    for directory, bundle_type in locations:
        root = app_path / directory
        if not root.is_dir():
            continue
        for bundle in sorted(root.rglob("*.app"), key=lambda item: item.as_posix().lower()):
            if not bundle.is_dir():
                continue
            info, errors = _bundle_info(bundle)
            signature, entitlements, raw_signature, signature_errors = analyze_code_signature(bundle)
            errors.extend(signature_errors)
            results.append(
                {
                    "name": info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle.stem,
                    "type": bundle_type,
                    "path": _relative(bundle, extraction_root),
                    "bundle_id": info.get("CFBundleIdentifier", ""),
                    "version": info.get("CFBundleShortVersionString", ""),
                    "build": info.get("CFBundleVersion", ""),
                    "executable": info.get("CFBundleExecutable", ""),
                    "minimum_os": info.get("MinimumOSVersion", ""),
                    "entitlements": entitlements,
                    "signed": signature.get("valid_structure", False),
                    "errors": errors,
                    "raw": {"info_plist": info, "codesign": raw_signature},
                }
            )
    return results
