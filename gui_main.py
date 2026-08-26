from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IPA Analyzer desktop application")
    parser.add_argument("ipa", nargs="?", help="IPA file to open")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    args, _ = parser.parse_known_args(argv)
    if args.smoke_test:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from ui.app import run_gui

    return run_gui(args.ipa, quit_after_ms=500 if args.smoke_test else None)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
