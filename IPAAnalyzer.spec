from __future__ import annotations

import os
import re
from pathlib import Path

from macholib.MachO import MachO
from macholib.mach_o import LC_BUILD_VERSION, LC_VERSION_MIN_MACOSX


PROJECT_ROOT = Path(SPECPATH)
RAW_VERSION = os.environ.get("IPA_ANALYZER_VERSION", "0.1.0").lstrip("v")
VERSION_PARTS = re.findall(r"\d+", RAW_VERSION)[:3] or ["0", "1", "0"]
VERSION = ".".join(VERSION_PARTS)
ICON_PATH = PROJECT_ROOT / "assets" / "AppIcon.icns"
TARGET_ARCH = os.environ.get("PYINSTALLER_TARGET_ARCH") or None
CODESIGN_IDENTITY = os.environ.get("CODESIGN_IDENTITY") or None
ENTITLEMENTS_PATH = os.environ.get("ENTITLEMENTS_PATH") or None
JCTOOLS = os.environ.get("IPA_ANALYZER_JCTOOLS") == "1"


a = Analysis(
    [str(PROJECT_ROOT / "gui_main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "assets" / "AppIcon-1024.png"), "assets"),
        (str(PROJECT_ROOT / "LICENSE"), "Licenses/IPAInspector"),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="IPA Analyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    target_arch=TARGET_ARCH,
    codesign_identity=CODESIGN_IDENTITY,
    entitlements_file=ENTITLEMENTS_PATH,
)
collection = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="IPA Analyzer",
)

# Qt/Python wheels can require a newer macOS than the application itself.
# Declare the actual requirement so hosts can report it before launching.
minimum_macos = 13 << 16
for _, binary_path, typecode in a.binaries:
    if typecode not in {"BINARY", "EXTENSION"}:
        continue
    for header in MachO(binary_path).headers:
        for command, data, _ in header.commands:
            if command.cmd == LC_BUILD_VERSION:
                minimum_macos = max(minimum_macos, data.minos)
            elif command.cmd == LC_VERSION_MIN_MACOSX:
                minimum_macos = max(minimum_macos, data.version)
minimum_macos_string = ".".join(str((minimum_macos >> shift) & 255) for shift in (16, 8, 0))

app = BUNDLE(
    collection,
    name="IPAInspector.app" if JCTOOLS else "IPA Analyzer.app",
    icon=str(ICON_PATH) if ICON_PATH.is_file() else None,
    bundle_identifier="com.jctools.phoneinfo.ipa-inspector" if JCTOOLS else "com.ipaanalyzer.desktop",
    version=VERSION,
    info_plist={
        "CFBundleDisplayName": "IPA 分析 — JCTools" if JCTOOLS else "IPA Analyzer",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSApplicationCategoryType": "public.app-category.developer-tools",
        "LSMinimumSystemVersion": minimum_macos_string,
        "LSMultipleInstancesProhibited": True,
        "NSHighResolutionCapable": True,
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "iOS Application Archive",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate",
                "LSItemContentTypes": ["com.apple.itunes.ipa"],
                "CFBundleTypeExtensions": ["ipa"],
            }
        ],
        "UTImportedTypeDeclarations": [
            {
                "UTTypeIdentifier": "com.apple.itunes.ipa",
                "UTTypeDescription": "iOS Application Archive",
                "UTTypeConformsTo": ["public.zip-archive"],
                "UTTypeTagSpecification": {
                    "public.filename-extension": ["ipa"],
                    "public.mime-type": "application/octet-stream",
                },
            }
        ],
    },
)
