from __future__ import annotations

import argparse
import sys

import ohbs_image

from ._audit import cmd_audit
from ._commands import (
    cmd_build,
    cmd_check_source,
    cmd_clean,
    cmd_cleanup_images,
    cmd_drift,
    cmd_images,
    cmd_init,
    cmd_list,
    cmd_pending,
    cmd_preflight,
    cmd_scan,
    cmd_test,
    cmd_validate,
    cmd_verify,
    cmd_verify_image,
)
from ._logging import VERSION, _setup_logging, fail
from ._profiles import DEFAULT_WORKDIR, PROFILE_NAMES_HELP


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="ohbs-image.toml",
                        help="Path to config file (default ./ohbs-image.toml)")
    common.add_argument("--workdir", default=DEFAULT_WORKDIR,
                        help=f"Rendered working directory (default ./{DEFAULT_WORKDIR})")

    parser = argparse.ArgumentParser(
        prog="ohbs-image",
        description="ohbs-hardened Golden Image Builder (Packer × Tencent Cloud CVM)",
        epilog=f"Supported profiles: {PROFILE_NAMES_HELP}",
    )
    parser.add_argument("--version", action="version", version=f"ohbs-image {VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Generate sample ohbs-image.toml")
    p_init.add_argument("--target", default=".", help="Output directory (default: current)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    p_init.set_defaults(func=cmd_init)

    p_pre = sub.add_parser("preflight", parents=[common], help="Run pre-flight checks")
    p_pre.set_defaults(func=cmd_preflight)

    p_val = sub.add_parser("validate", parents=[common], help="Render + packer validate")
    p_val.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ohbs-image summary)")
    p_val.add_argument("--debug", action="store_true",
                       help="Enable Packer debug logging (PACKER_LOG=1)")
    p_val.set_defaults(func=cmd_validate)

    p_bld = sub.add_parser("build", parents=[common], help="Render + packer build (produce image)")
    p_bld.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ohbs-image summary)")
    p_bld.add_argument("--debug", action="store_true",
                       help="Enable Packer debug logging (PACKER_LOG=1)")
    p_bld.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p_bld.add_argument("--log-file", default=None,
                       help="Write full build log to file (in addition to stderr)")
    p_bld.add_argument("--skip-if-unchanged", action="store_true",
                       help="Skip the rebuild when inputs (source image, rules, "
                            "benchmark, level) are unchanged since the last "
                            "successful build (change detection, P1#7)")
    p_bld.set_defaults(func=cmd_build)

    p_cln = sub.add_parser("clean", parents=[common], help="Remove working directory")
    p_cln.set_defaults(func=cmd_clean)

    p_img = sub.add_parser("images", help="List recorded builds (image lineage)")
    p_img.add_argument("--latest", action="store_true", help="Show only the newest record")
    p_img.add_argument("-n", "--limit", type=int, default=10,
                       help="Max records to show (default 10; 0 = all)")
    p_img.set_defaults(func=cmd_images)

    p_vrf = sub.add_parser("verify", help="Verify a SLSA provenance signature")
    p_vrf.add_argument("--provenance", default=None,
                       help="Path to a .provenance.json file")
    p_vrf.add_argument("--image", default=None,
                       help="Image ID to look up its provenance (e.g. img-xxx)")
    p_vrf.set_defaults(func=cmd_verify)

    p_lst = sub.add_parser("list", help="Enumerate available profiles with metadata")
    p_lst.add_argument("--versions", action="store_true",
                       help="Show rule-catalog sha256 + engine version per profile (#19)")
    p_lst.set_defaults(func=cmd_list)

    p_scn = sub.add_parser("scan", parents=[common], help="Audit-only build (no remediation) with score gate")
    p_scn.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ohbs-image summary)")
    p_scn.add_argument("--debug", action="store_true",
                       help="Enable Packer debug logging (PACKER_LOG=1)")
    p_scn.add_argument("--min-score", type=float, default=85.0,
                       help="Gate threshold in percent (default 85)")
    p_scn.add_argument("--sarif", default=None,
                       help="Write a SARIF 2.1.0 report of failed rules to PATH")
    p_scn.add_argument("--xccdf", default=None,
                       help="Write an XCCDF 1.2 TestResult report of failed rules to PATH (P2#8)")
    p_scn.set_defaults(func=cmd_scan)

    p_pnd = sub.add_parser("pending", parents=[common],
                           help="Change detection: report whether a rebuild is needed (P1#7)")
    p_pnd.set_defaults(func=cmd_pending)

    p_aud = sub.add_parser(
        "audit",
        help="Independent third-party audit (oscap / inspec / kitty) with a score gate (P0#1)")
    p_aud.add_argument("--tool", choices=["oscap", "inspec", "kitty"], required=True,
                       help="Audit tool: oscap (SCAP content) | inspec (dev-sec baseline) | kitty (Windows CSV)")
    p_aud.add_argument("--host", default=None, help="Target host to audit (required for oscap/inspec)")
    p_aud.add_argument("--ssh-user", default="root", help="SSH user for oscap/inspec (default root)")
    p_aud.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22)")
    p_aud.add_argument("--ssh-key", default=None, help="SSH private key path (default: agent/keys)")
    p_aud.add_argument("--profile", default="xccdf_org.ssgproject.content_profile_cis",
                       help="oscap profile id (default: CIS profile in scap-security-guide)")
    p_aud.add_argument("--datastream", default=None,
                       help="oscap SCAP datastream path on the target (e.g. /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml)")
    p_aud.add_argument("--baseline", default=None,
                       help="inspec baseline (default dev-sec/linux-baseline)")
    p_aud.add_argument("--parse", default=None,
                       help="kitty: path to a HardeningKitty audit CSV export to parse (P2#11)")
    p_aud.add_argument("--min-score", type=float, default=85.0,
                       help="Gate threshold in percent (default 85)")
    p_aud.add_argument("--sarif", default=None, help="Write findings as SARIF 2.1.0 to PATH")
    p_aud.add_argument("--xccdf", default=None, help="Write findings as XCCDF 1.2 to PATH")
    p_aud.set_defaults(func=cmd_audit)

    p_vrf_img = sub.add_parser(
        "verify-image", parents=[common],
        help="Clean-boot verification: boot a probe from a produced image, "
             "re-audit on fresh boot, terminate (P0#3)")
    p_vrf_img.add_argument("--image", required=True,
                           help="Image ID to verify (e.g. img-xxxx)")
    p_vrf_img.add_argument("--min-score", type=float, default=85.0,
                           help="Gate threshold in percent (default 85)")
    p_vrf_img.set_defaults(func=cmd_verify_image)

    p_drift = sub.add_parser(
        "drift", parents=[common],
        help="Detect configuration drift on a running instance vs the "
             "image baseline (round-2 #12)")
    p_drift.add_argument("--host", required=True,
                         help="IP of the running instance to check for drift")
    p_drift.add_argument("--image", default="",
                         help="Producing image ID (baseline from its shipped audit; optional)")
    p_drift.add_argument("--baseline", default="",
                         help="Path to a saved baseline JSON (overrides --image)")
    p_drift.add_argument("--ssh-user", default="", help="SSH user (default: profile's)")
    p_drift.add_argument("--ssh-port", type=int, default=0, help="SSH port (default: profile's)")
    p_drift.add_argument("--save-baseline", action="store_true",
                         help="Save the current host scan as a baseline and exit")
    p_drift.set_defaults(func=cmd_drift)

    p_src = sub.add_parser(
        "check-source", parents=[common],
        help="Vendor image refresh detection — is the source image newer "
             "than the last build? (round-2 #20)")
    p_src.set_defaults(func=cmd_check_source)

    p_tst = sub.add_parser("test", parents=[common], help="Test the build pipeline")
    p_tst.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ohbs-image summary)")
    p_tst.add_argument("--debug", action="store_true",
                       help="Enable Packer debug logging (PACKER_LOG=1)")
    p_tst.add_argument("--idempotency", action="store_true",
                       help="Re-run apply and fail if the second pass makes changes")
    p_tst.set_defaults(func=cmd_test)

    p_clnimg = sub.add_parser(
        "cleanup-images",
        help="Retire old golden images by lineage age (dry-run by default)")
    p_clnimg.add_argument("--older-than", type=int, default=30,
                          help="Delete builds older than N days (default 30)")
    p_clnimg.add_argument("--keep-latest", type=int, default=1,
                          help="Keep the newest N builds (default 1)")
    p_clnimg.add_argument("--unused-since", type=int, default=0,
                          help="Only delete images NOT shared with other "
                               "accounts (in-use guard, round-2 #16); 0 = off")
    p_clnimg.add_argument("--apply", action="store_true",
                          help="Actually delete images (default is a dry run)")
    p_clnimg.set_defaults(func=cmd_cleanup_images)

    return parser

def main(argv: list[str] | None = None) -> int:
    """Entry point — parse args, dispatch to subcommand, return exit code."""
    _setup_logging()
    parser = ohbs_image.build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    _setup_logging(verbose=args.verbose)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print(file=sys.stderr)
        fail("interrupted")
        return 130
    except Exception as exc:  # never leak a raw traceback to end users
        import traceback as _tb
        _tb.print_exc(file=sys.stderr)
        fail(f"internal error: {type(exc).__name__}: {exc}")
        return 70
