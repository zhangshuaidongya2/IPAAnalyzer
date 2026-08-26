from __future__ import annotations

import os
import re
from pathlib import Path


PROJECT_ROOT = Path(SPECPATH)
RAW_VERSION = os.environ.get("IPA_ANALYZER_VERSION", "0.1.0").lstrip("v")
VERSION_PARTS = re.findall(r"\d+", RAW_VERSION)[:3] or ["0", "1", "0"]
VERSION = ".".join(VERSION_PARTS)
ICON_PATH = PROJECT_ROOT / "assets" / "AppIcon.icns"
TARGET_ARCH = os.environ.get("PYINSTALLER_TARGET_ARCH") or None
CODESIGN_IDENTITY = os.environ.get("CODESIGN_IDENTITY") or None
ENTITLEMENTS_PATH = os.environ.get("ENTITLEMENTS_PATH") or None


a = Analysis(
    [str(PROJECT_ROOT / "gui_main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[],
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
app = BUNDLE(
    collection,
    name="IPA Analyzer.app",
    icon=str(ICON_PATH) if ICON_PATH.is_file() else None,
    bundle_identifier="com.ipaanalyzer.desktop",
    version=VERSION,
    info_plist={
        "CFBundleDisplayName": "IPA Analyzer",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSApplicationCategoryType": "public.app-category.developer-tools",
        "LSMinimumSystemVersion": "13.0",
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
