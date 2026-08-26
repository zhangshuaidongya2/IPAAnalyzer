from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzer import IPAAnalysisError, IPAAnalyzer


class IPAAnalyzerTests(unittest.TestCase):
    def make_ipa(self, root: Path, name: str = "示例 App.ipa") -> Path:
        ipa = root / name
        info = {
            "CFBundleName": "Example",
            "CFBundleDisplayName": "Example App",
            "CFBundleIdentifier": "com.example.app",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "CFBundleExecutable": "Example Binary",
            "CFBundlePackageType": "APPL",
            "MinimumOSVersion": "15.0",
            "UIDeviceFamily": [1, 2],
            "NSCameraUsageDescription": "Scan codes",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example"]}],
            "LSApplicationQueriesSchemes": ["wechat"],
        }
        extension_info = {
            "CFBundleName": "Share",
            "CFBundleIdentifier": "com.example.app.share",
            "CFBundleShortVersionString": "1.2.3",
            "CFBundleVersion": "42",
            "CFBundleExecutable": "Share",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.share-services"},
        }
        framework_info = {
            "CFBundleIdentifier": "com.example.SampleKit",
            "CFBundleShortVersionString": "2.0",
            "CFBundleExecutable": "SampleKit",
        }
        with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "Payload/Example.app/Info.plist",
                plistlib.dumps(info, fmt=plistlib.FMT_BINARY),
            )
            archive.writestr("Payload/Example.app/Example Binary", b"not-macho")
            archive.writestr("Payload/Example.app/Assets.car", b"assets")
            archive.writestr("Payload/Example.app/embedded.mobileprovision", b"invalid-profile")
            archive.writestr(
                "Payload/Example.app/Frameworks/SampleKit.framework/Info.plist",
                plistlib.dumps(framework_info),
            )
            archive.writestr(
                "Payload/Example.app/Frameworks/SampleKit.framework/SampleKit", b"framework"
            )
            archive.writestr(
                "Payload/Example.app/PlugIns/Share.appex/Info.plist",
                plistlib.dumps(extension_info),
            )
            archive.writestr("Payload/Example.app/PlugIns/Share.appex/Share", b"extension")
        return ipa

    def test_full_analysis_survives_unavailable_optional_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = self.make_ipa(Path(temporary))
            result = IPAAnalyzer().analyze(ipa)

        self.assertEqual(result.basic["bundle_id"], "com.example.app")
        self.assertEqual(result.basic["minimum_os"], "15.0")
        self.assertEqual(result.signing["type"], "Unknown")
        self.assertTrue(result.provision["present"])
        self.assertEqual(result.frameworks[0]["name"], "SampleKit.framework")
        self.assertEqual(result.extensions[0]["type"], "Share Extension")
        self.assertEqual(result.url_schemes["registered"], ["example"])
        camera = next(item for item in result.permissions if item["permission"] == "Camera")
        self.assertTrue(camera["declared"])
        self.assertGreater(result.size_info["uncompressed_size"], 0)
        self.assertEqual(len(result.hashes["ipa_sha256"]), 64)
        self.assertTrue(any(item["relative_path"].endswith("Info.plist") for item in result.files))
        self.assertIn("mobileprovision_source", result.raw)
        self.assertIn("frameworks", result.raw)
        parsed_json = json.loads(result.to_json())
        self.assertEqual(parsed_json["basic"]["display_name"], "Example App")

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "unsafe.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("../outside", b"bad")
            with self.assertRaisesRegex(IPAAnalysisError, "Unsafe IPA archive"):
                IPAAnalyzer().analyze(ipa)

    def test_minimal_app_without_optional_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "minimal.ipa"
            info = {
                "CFBundleName": "Minimal",
                "CFBundleIdentifier": "com.example.minimal",
                "CFBundleExecutable": "Minimal",
                "CFBundlePackageType": "APPL",
            }
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Minimal.app/Info.plist", plistlib.dumps(info))
                archive.writestr("Payload/Minimal.app/Minimal", b"not-macho")
            result = IPAAnalyzer().analyze(ipa)
        self.assertFalse(result.provision["present"])
        self.assertEqual(result.frameworks, [])
        self.assertEqual(result.extensions, [])
        self.assertEqual(result.embedded_bundles, [])

    def test_rejects_missing_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "empty.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Info.plist", plistlib.dumps({}))
            with self.assertRaisesRegex(IPAAnalysisError, "Payload"):
                IPAAnalyzer().analyze(ipa)

    def test_rejects_damaged_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ipa = Path(temporary) / "damaged.ipa"
            ipa.write_bytes(b"not a zip")
            with self.assertRaisesRegex(IPAAnalysisError, "Invalid or damaged"):
                IPAAnalyzer().analyze(ipa)
