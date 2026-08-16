#!/usr/bin/env python3
"""Format every role's rules.json with a single canonical layout.

The repo keeps one rules.json per OS role under
``cis_image/roles/<role>/files/rules.json``.  Historically these were edited
by hand and drifted into two incompatible indentation styles (2-space and
4-space, plus a non-standard array-element indent).  That made every bulk edit
produce a thousand-line diff and invited the next one to clobber the format
again.

This script enforces ONE canonical layout for all of them so the diff of any
future change stays minimal and mechanical re-formatting can never silently
change content.

Canonical layout
----------------
Standard-library ``json.dumps(indent=2, ensure_ascii=False)`` plus a single
trailing newline.  This is deterministic: re-running on an already-formatted
file is a no-op, so the check mode is stable in CI.

Usage
-----
    python3 scripts/format_rules.py --check     # exit 1 if any file is off
    python3 scripts/format_rules.py --write     # rewrite all files in place
    python3 scripts/format_rules.py --check --verbose

Exit code 0 = all files match the canonical layout; 1 = at least one does not
(or it fails to parse).  Pure stdlib, safe to run anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_GLOB = "cis_image/roles/*/files/rules.json"


def canonical(text: str) -> str:
    """Return the canonical-formatted version of a rules.json document."""
    data = json.loads(text)  # raises on invalid JSON
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def iter_rules_files():
    for path in sorted(REPO_ROOT.glob(RULES_GLOB)):
        yield path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="exit 1 if any rules.json is not in canonical form")
    mode.add_argument("--write", action="store_true",
                      help="rewrite every rules.json in canonical form")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    bad = []
    for path in iter_rules_files():
        try:
            text = path.read_text(encoding="utf-8")
            wanted = canonical(text)
        except Exception as exc:  # noqa: BLE001 - report any parse/IO error
            print(f"ERROR  {path.relative_to(REPO_ROOT)}: {exc}")
            bad.append(path)
            continue

        if text == wanted:
            if args.verbose:
                print(f"ok     {path.relative_to(REPO_ROOT)}")
            continue

        if args.write:
            path.write_text(wanted, encoding="utf-8")
            print(f"wrote  {path.relative_to(REPO_ROOT)}")
        else:
            print(f"diff   {path.relative_to(REPO_ROOT)}")
            bad.append(path)

    if bad:
        if args.check:
            print(f"\n{len(bad)} file(s) not in canonical format. "
                  "Run: python3 scripts/format_rules.py --write")
        return 1
    print("all rules.json files are in canonical format") if args.verbose else None
    return 0


if __name__ == "__main__":
    sys.exit(main())
