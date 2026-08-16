#!/usr/bin/env python3
"""Verify README.md stays in sync with the codebase's CLI surface.

Ensures every subcommand registered by ``cis_image.build_parser()`` and every
OS profile in ``cis_image.PROFILES`` is documented in README.md (as
``cis-image <cmd>`` / the profile name).  Run in CI so adding or removing a
command or profile without updating the docs fails the build.

Usage:
    python3 scripts/check_readme.py [--readme PATH]

The check is pure stdlib + the installed ``cis_image`` package (already
importable in the CI test job, where this runs after ``pip install -e .``).
Exit code 0 = docs current; 1 = something is missing.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Must stay in sync with the profiles dict in cis_image/_profiles.py — the
# check uses this to find profile names in README without importing the full
# module at parse time (kept as a flat alternation for the regex).
_PROFILE_NAMES = (
    "ubuntu2004", "ubuntu2204", "ubuntu2404",
    "rhel8", "rhel9", "rhel10",
    "tencentos3", "tencentos4",
    "win2016", "win2019", "win2022", "win2025",
)


def registered_subcommands() -> set[str]:
    """Return the set of subcommand names the CLI actually registers."""
    import cis_image
    parser = cis_image.build_parser()
    return set(parser._subparsers._group_actions[0].choices)


def readme_documented_subcommands(readme_text: str,
                                  registered: set[str]) -> set[str]:
    """Which of *registered* subcommands appear in *readme_text*."""
    found: set[str] = set()
    # Longest-first so `verify` doesn't swallow `verify-image`.
    ordered = sorted(registered, key=len, reverse=True)
    for m in re.finditer(r"cis-image\s+([a-z][a-z-]*)", readme_text):
        word = m.group(1)
        for cmd in ordered:
            if word == cmd or word.startswith(cmd + "-"):
                found.add(cmd)
                break
    return found


def readme_documented_profiles(readme_text: str) -> set[str]:
    """Which profile names appear in *readme_text*."""
    pattern = r"\b(?:" + "|".join(re.escape(p) for p in _PROFILE_NAMES) + r")\b"
    return set(re.findall(pattern, readme_text))


def check_readme(readme_text: str, registered: set[str],
                 profiles: set[str]) -> list[str]:
    """Return a list of human-readable problems, empty when docs are current."""
    errors: list[str] = []

    doc_cmds = readme_documented_subcommands(readme_text, registered)
    missing_cmds = sorted(registered - doc_cmds)
    if missing_cmds:
        errors.append("README.md does not document these subcommand(s): "
                      + ", ".join(missing_cmds))

    doc_profiles = readme_documented_profiles(readme_text)
    missing_profiles = sorted(profiles - doc_profiles)
    if missing_profiles:
        errors.append("README.md does not mention these OS profile(s): "
                      + ", ".join(missing_profiles))

    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--readme", default=str(REPO_ROOT / "README.md"),
                   help="Path to README.md (default: repo README)")
    p.add_argument("--check-tests", action="store_true",
                   help="Also verify tests/test_check_readme.py's hardcoded "
                        "command/profile lists match the live CLI (default: off)")
    args = p.parse_args(argv)

    readme_path = Path(args.readme)
    if not readme_path.exists():
        print(f"check_readme: README not found: {readme_path}", file=sys.stderr)
        return 1

    try:
        registered = registered_subcommands()
    except Exception as exc:  # import/build_parser failure
        print(f"check_readme: could not load cis_image CLI: {exc}",
              file=sys.stderr)
        return 2

    import cis_image
    profiles = set(cis_image.PROFILES.keys())

    readme_text = readme_path.read_text(encoding="utf-8")
    errors = check_readme(readme_text, registered, profiles)

    if args.check_tests:
        errors += check_test_consistency(registered, profiles)

    if errors:
        print("check_readme: documentation is out of date with the code:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print("  Update README.md / tests to keep docs current.",
              file=sys.stderr)
        return 1

    print(f"check_readme: README documents all {len(registered)} subcommands "
          f"and {len(profiles)} profiles OK")
    return 0


def check_test_consistency(registered: set[str],
                           profiles: set[str]) -> list[str]:
    """Ensure tests/test_check_readme.py's hardcoded expected lists match the
    live CLI, so a command/profile added to the parser but not to the tests
    (or vice-versa) is caught instead of silently drifting."""
    errors: list[str] = []

    test_file = REPO_ROOT / "tests" / "test_check_readme.py"
    if not test_file.exists():
        errors.append(f"test file not found: {test_file}")
        return errors

    text = test_file.read_text(encoding="utf-8")

    # ALL_CMDS: a Python set literal in the test, e.g.
    #   ALL_CMDS = {"audit", "build", ..., "verify-image"}
    m = re.search(r"ALL_CMDS\s*=\s*\{(.*?)\}", text, re.DOTALL)
    test_cmds: set[str] = set()
    if m:
        test_cmds = set(re.findall(r"['\"]([A-Za-z0-9_-]+)['\"]", m.group(1)))
    missing_cmds = sorted(registered - test_cmds)
    if missing_cmds:
        errors.append("tests/test_check_readme.py ALL_CMDS is missing command(s): "
                      + ", ".join(missing_cmds))
    extra_cmds = sorted(test_cmds - registered)
    if extra_cmds:
        errors.append("tests/test_check_readme.py ALL_CMDS lists unknown command(s): "
                      + ", ".join(extra_cmds))

    # The test references the script's own _PROFILE_NAMES via
    # `check_readme._PROFILE_NAMES`, so it can't drift from this module; the
    # canonical list here is _PROFILE_NAMES. Verify the test references it.
    if "check_readme._PROFILE_NAMES" not in text:
        errors.append("tests/test_check_readme.py no longer references "
                      "check_readme._PROFILE_NAMES for profile checks")

    return errors


if __name__ == "__main__":
    sys.exit(main())
