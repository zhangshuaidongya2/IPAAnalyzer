from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IPA Analyzer desktop application")
    parser.add_argument("ipa", nargs="?", help="IPA file to open")
    parser.add_argument("--jctools", action="store_true", help="open as the JCTools IPA analysis tool")
    parser.add_argument("--downloads-directory", type=Path, help="default directory for opening and exporting files")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    args, _ = parser.parse_known_args(argv)
    if args.smoke_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from ui.app import run_gui

    return run_gui(
        args.ipa,
        title="IPA 分析 — JCTools" if args.jctools else "IPA Analyzer",
        files_directory=args.downloads_directory,
        quit_after_ms=500 if args.smoke_test else None,
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
