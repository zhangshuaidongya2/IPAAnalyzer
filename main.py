from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from analyzer import IPAAnalysisError, IPAAnalyzer
from analyzer.utils import format_bytes
from models import IPAAnalysisResult


def _value(value: Any) -> str:
    if value is None or value == "":
        return "-"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "-"
    return str(value)


def _row(label: str, value: Any) -> str:
    return f"{label:<20}{_value(value)}"


def format_summary(result: IPAAnalysisResult) -> str:
    basic = result.basic
    signing = result.signing
    macho = result.macho
    declared_permissions = [
        item["permission"] for item in result.permissions if item.get("declared")
    ]
    lines = [
        "=" * 58,
        "IPA Analyzer",
        "=" * 58,
        "",
        "[Basic]",
        _row("Name", basic.get("display_name") or basic.get("name")),
        _row("Bundle ID", basic.get("bundle_id")),
        _row("Version", basic.get("version")),
        _row("Build", basic.get("build")),
        _row("Minimum iOS", basic.get("minimum_os")),
        _row("Executable", basic.get("executable")),
        _row("IPA Size", format_bytes(result.size_info.get("ipa_size"))),
        "",
        "[Signing]",
        _row("Type", signing.get("type")),
        _row("Team ID", signing.get("team_id")),
        _row("Profile", signing.get("profile_name")),
        _row("Expiration", signing.get("expiration_date")),
        "",
        "[Mach-O]",
        _row("Architecture", macho.get("architectures")),
        _row("Minimum OS", macho.get("minimum_os")),
        _row("SDK", macho.get("sdk")),
        _row("Encrypted", "Yes" if macho.get("encrypted") else "No"),
        _row("Crypt ID", macho.get("cryptid")),
        "",
        "[Permissions]",
        _row("Declared", declared_permissions),
        "",
        "[Frameworks]",
        *([item["name"] for item in result.frameworks] or ["-"]),
        "",
        "[Extensions]",
        *([item["name"] for item in result.extensions] or ["-"]),
    ]
    if result.errors:
        lines.extend(["", f"[Warnings: {len(result.errors)}]", *result.errors])
    lines.append("=" * 58)
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect an iOS IPA without executing its contents.")
    parser.add_argument("ipa", nargs="?", help="path to the .ipa file")
    parser.add_argument("--json", dest="json_path", help="write the full report to this JSON file")
    parser.add_argument("--gui", action="store_true", help="open the PySide6 desktop interface")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        try:
            from ui.app import run_gui
        except ImportError as exc:
            parser.error(f"PySide6 is required for GUI mode: {exc}")
        return run_gui(args.ipa)
    if not args.ipa:
        parser.error("an IPA path is required unless --gui is used")

    try:
        result = IPAAnalyzer().analyze(args.ipa)
    except IPAAnalysisError as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 2
    print(format_summary(result))

    if args.json_path:
        destination = Path(args.json_path).expanduser()
        try:
            destination.write_text(result.to_json() + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Unable to write JSON report: {exc}", file=sys.stderr)
            return 3
        print(f"JSON report: {destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
