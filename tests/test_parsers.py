from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from analyzer.macho import analyze_macho, parse_architectures, parse_dependencies, parse_load_commands
from analyzer.signing import classify_signing
from analyzer.utils import CommandResult


OTOOL_LOAD_COMMANDS = """
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform IOS
    minos 15.0
      sdk 17.4
Load command 2
      cmd LC_UUID
  cmdsize 24
     uuid 11111111-2222-3333-4444-555555555555
Load command 3
          cmd LC_RPATH
      cmdsize 40
         path @executable_path/Frameworks (offset 12)
Load command 4
          cmd LC_LOAD_DYLIB
      cmdsize 80
         name /System/Library/Frameworks/UIKit.framework/UIKit (offset 24)
Load command 5
          cmd LC_ENCRYPTION_INFO_64
      cmdsize 24
     cryptoff 16384
    cryptsize 8192
      cryptid 1
"""


class ParserTests(unittest.TestCase):
    def test_parses_macho_load_commands(self) -> None:
        parsed = parse_load_commands(OTOOL_LOAD_COMMANDS)
        self.assertEqual(parsed["minimum_os"], "15.0")
        self.assertEqual(parsed["sdk"], "17.4")
        self.assertEqual(parsed["uuids"], ["11111111-2222-3333-4444-555555555555"])
        self.assertEqual(parsed["rpaths"], ["@executable_path/Frameworks"])
        self.assertEqual(parsed["encryption_info"][0]["cryptid"], 1)

    def test_parses_architectures_and_dependencies(self) -> None:
        architectures = parse_architectures(
            "Architectures in the fat file: App are: arm64 arm64e"
        )
        self.assertEqual(architectures, ["arm64", "arm64e"])
        dependencies = parse_dependencies(
            "App:\n"
            "\t@rpath/Sample.framework/Sample (compatibility version 1.0.0, current version 1.0.0)\n"
            "\t/usr/lib/libobjc.A.dylib (compatibility version 1.0.0, current version 228.0.0)\n"
        )
        self.assertEqual(
            dependencies,
            ["@rpath/Sample.framework/Sample", "/usr/lib/libobjc.A.dylib"],
        )

    def test_signing_classification_uses_multiple_indicators(self) -> None:
        development = classify_signing(
            {
                "ProvisionedDevices": ["device"],
                "Entitlements": {"get-task-allow": True},
                "TeamIdentifier": ["TEAM123"],
            },
            {"valid_structure": True},
            {},
            profile_present=True,
        )
        self.assertEqual(development["type"], "Development")
        self.assertGreaterEqual(len(development["evidence"]), 3)

        unknown = classify_signing({}, {}, {}, profile_present=False)
        self.assertEqual(unknown["type"], "Unknown")

        undecodable_profile = classify_signing({}, {}, {}, profile_present=True)
        self.assertEqual(undecodable_profile["type"], "Unknown")

    def test_macho_command_failures_are_reported(self) -> None:
        with TemporaryDirectory() as temporary:
            binary = Path(temporary) / "Fake Mach-O"
            binary.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(28))

            def failed_command(args: list[str], **kwargs: object) -> CommandResult:
                del kwargs
                return CommandResult(args, 1, "", "simulated failure")

            with patch("analyzer.macho.run_command", side_effect=failed_command):
                result, raw, errors = analyze_macho(binary)

        self.assertEqual(result["architectures"], [])
        self.assertIn("otool_L", raw)
        self.assertTrue(any("otool -l failed" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
