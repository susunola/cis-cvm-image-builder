#!/usr/bin/env python3
"""Real end-to-end test: bring up a real Tencent Cloud CVM jump box, clone
the repo onto it, install deps, run the full pytest/ruff/mypy suite over
SSH, then tear the instance (and its temporary key pair) back down.

This is a *supplement* to tests/test_ohbs_image.py, not a replacement.  The
existing pytest suite mocks the ohbs_image._tc3_api boundary — it is fast, free,
and covers API response edge cases (null fields, wrong nesting, etc.) very
well, but it can never catch "does `pip install -e .` actually work on a
clean AlmaLinux box", "is the real network path from a CVM reachable", or
"did we drift from the real Tencent Cloud API contract". Those only show up
by running against something real.

Usage (default — just tests this repo's own toolchain on the jump box):
    export TENCENTCLOUD_SECRET_ID=...
    export TENCENTCLOUD_SECRET_KEY=...
    python3 scripts/real_e2e_test.py \\
        --region ap-guangzhou --zone ap-guangzhou-3 \\
        --vpc-id vpc-xxxxxxxx --subnet-id subnet-xxxxxxxx \\
        --security-group-id sg-xxxxxxxx [--yes]

Usage (opt-in — also trigger a REAL `ohbs-image build` for one or more
profile+level combinations, each on its OWN temporary build CVM reached
from the jump box over the private network):
    python3 scripts/real_e2e_test.py --target-mode single \\
        --profile rhel8 --level 1 ... (same region/zone/vpc/... flags)
    python3 scripts/real_e2e_test.py --target-mode all-linux ...   # 8 profiles x --levels (default L1+L2)
    python3 scripts/real_e2e_test.py --target-mode all ...         # +4 Windows profiles (default up to 24 builds)
    # To restrict which CIS Level(s) run, pass --levels 1 / --levels 2 /
    # --levels both, or set E2E_LEVELS / E2E_MAX_PARALLEL_BUILDS in scripts/e2e.env.

The instance and temporary SSH key pair are ALWAYS torn down on exit
(success, failure, or Ctrl-C) unless --keep-on-failure is passed and the
remote run actually failed. Any images produced by --target-mode
single/all-linux/all are ALWAYS deleted at the end of the run — this script
never leaves a billed golden image behind.

Hard requirements (see CONTRIBUTING.md "Running the real end-to-end test"):
  - ohbs-image must already be installed in editable mode on THIS machine
    (`pip install -e .`) — this script imports ohbs_image._tc3_api directly to
    avoid re-implementing the TC3-HMAC-SHA256 signing logic.
  - The security group passed via --security-group-id must already allow
    inbound TCP/22 from this machine's public IP. This script does not
    modify security group rules.
  - This creates a REAL, billed CVM instance. It is destroyed automatically
    at the end of the run.
  - --target-mode single/all-linux/all additionally requires:
      * one E2E_TARGET_IMAGE_<PROFILE> env var per profile to build (see
        scripts/e2e.env.example) — profiles left unset are skipped in
        all-linux/all mode, or a hard error in single mode.
      * the security group must ALSO allow inbound TCP/22 (Linux builds) /
        TCP/5986 (Windows builds) from the jump box's PUBLIC IP — each build
        CVM gets a public IP and is reached from the jump box over the public
        internet (the jump box and targets may be in DIFFERENT regions/VPCs).
        All target build CVMs share ONE uniform placement
        (E2E_TARGET_REGION / E2E_TARGET_ZONE / E2E_TARGET_VPC_ID /
        E2E_TARGET_SUBNET_ID / E2E_TARGET_SG_ID), each field falling back to
        the jump box's --region/--zone/--vpc-id/--subnet-id/
        --security-group-id when unset. Only the target IMAGE is per-profile
        (E2E_TARGET_IMAGE_<PROFILE>).
      * WINRM_PASSWORD set if any Windows profile is in scope.
    Each combination is a REAL, billed CVM (auto-destroyed by packer at the
    end of its own build); the resulting image is deleted by this script
    right after the batch finishes.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from ohbs_image import PROFILES, ConfigError, _tc3_api, banner, fail, info, ok, warn  # noqa: E402

DEFAULT_IMAGE_ID = "img-31d8ynuj"
DEFAULT_INSTANCE_TYPE = "SA5.MEDIUM2"
REPO_URL = "https://github.com/susunola/ohbs-image.git"
LAST_INSTANCE_FILE = REPO_ROOT / "logs" / "e2e_last_instance.json"
BOOT_TIMEOUT_SECONDS = 900
# The jump box is a freshly-launched AlmaLinux CVM; boot + cloud-init + SSH
# startup can occasionally exceed 3 minutes. 360s avoids spurious "SSH not
# ready" failures on a slow-but-healthy instance.
SSH_READY_TIMEOUT_SECONDS = 360

# Same list-comprehension pattern as tests/test_ohbs_image.py's LINUX_PROFILES
# — used by --target-mode all-linux to enumerate every non-Windows profile.
LINUX_PROFILES = [k for k, v in PROFILES.items() if v.get("family") != "windows"]

# Ordered (name, human label) for every step recorded by REMOTE_SCRIPT when
# --target-mode is "toolchain" (the default / original behaviour).
TOOLCHAIN_STEPS = [
    ("python_check", "Python 3.12 / git check"),
    ("clone", "Clone repository"),
    ("venv", "Create venv + install dev deps"),
    ("ruff", "ruff check"),
    ("mypy", "mypy"),
    ("pytest", "pytest"),
]

# Steps recorded when --target-mode is single/all-linux/all — the matrix
# mode skips ruff/mypy/pytest (those are covered by the toolchain mode) and
# instead prepares packer + ansible-core (+ ansible.windows when any
# Windows profile is in scope) before handing off to run_matrix.py.
MATRIX_BASE_STEPS = [
    ("python_check", "Python 3.12 / git check"),
    ("clone", "Clone repository"),
    ("venv", "Create venv + install dev deps"),
    ("packer_install", "Install packer"),
    ("ansible_install", "Install ansible-core"),
]
MATRIX_WINDOWS_STEP = ("ansible_windows_collection", "Install ansible.windows collection")
MATRIX_FINAL_STEP = ("profile_matrix", "Run profile+level build matrix")


def build_steps(target_mode: str, needs_windows: bool) -> list[tuple[str, str]]:
    """Return the ordered (name, label) steps REMOTE_SCRIPT will record for
    this run. Must match what REMOTE_SCRIPT actually executes for the same
    (target_mode, needs_windows) — see fetch_remote_reports()/
    build_step_results(), which rely on this same list to know which log
    files to expect. A step that's never going to run must not appear here,
    otherwise it comes back "not run" and incorrectly fails the whole run
    (see compute_overall_passed())."""
    if target_mode == "toolchain":
        return list(TOOLCHAIN_STEPS)
    steps = list(MATRIX_BASE_STEPS)
    if needs_windows:
        steps.append(MATRIX_WINDOWS_STEP)
    steps.append(MATRIX_FINAL_STEP)
    return steps


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--image-id", default=DEFAULT_IMAGE_ID)
    # region/zone have no default: the image, VPC, subnet, and security
    # group are all region-scoped, and a stale ap-guangzhou default here
    # previously caused a confusing "security group id is None" error when
    # the caller's actual resources lived in a different region.
    p.add_argument("--region", required=True,
                    help="Must match the region your --vpc-id/--subnet-id/"
                         "--security-group-id/--image-id actually live in.")
    p.add_argument("--zone", required=True,
                    help="Availability zone within --region for the instance.")
    p.add_argument("--instance-type", default=DEFAULT_INSTANCE_TYPE)
    p.add_argument("--vpc-id", required=True)
    p.add_argument("--subnet-id", required=True)
    p.add_argument("--security-group-id", required=True)
    p.add_argument("--ssh-user", default="root")
    p.add_argument("--branch", default="main")
    p.add_argument("--yes", "-y", action="store_true",
                    help="Skip the cost confirmation prompt")
    p.add_argument("--keep-on-failure", action="store_true",
                    help="Do not terminate the instance if the remote test run fails "
                         "(useful for logging in to debug)")
    p.add_argument("--timeout", type=int, default=BOOT_TIMEOUT_SECONDS,
                   metavar="SECONDS",
                   help=f"Boot/poll timeout for a public IP (default {BOOT_TIMEOUT_SECONDS}s)")
    p.add_argument("--ssh-timeout", type=int, default=SSH_READY_TIMEOUT_SECONDS,
                   metavar="SECONDS",
                   help=f"Timeout for SSH to become reachable (default {SSH_READY_TIMEOUT_SECONDS}s)")
    p.add_argument("--target-mode", choices=["toolchain", "single", "all-linux", "all"],
                    default="toolchain",
                    help="toolchain (default): only test this repo's own toolchain "
                         "(venv/ruff/mypy/pytest) on the jump box. single: trigger one "
                         "real `ohbs-image build` for --profile/--level. all-linux: every "
                         "Linux profile x --levels (up to 16 real builds). all: +every "
                         "Windows profile x --levels (up to 24 real builds).")
    p.add_argument("--profile", choices=list(PROFILES),
                    help="Required (and only used) with --target-mode single.")
    p.add_argument("--level", type=int, choices=[1, 2],
                    help="Required (and only used) with --target-mode single — which "
                         "CIS Level to build (1 or 2).")
    p.add_argument("--levels", type=_parse_levels, default=None,
                    help="Which CIS Levels to build in --target-mode all-linux/all. "
                         "One of '1', '2', or 'both'/'1,2'. Ignored in single mode "
                         "(use --level there). Default 'both'. "
                         "May also be set via E2E_LEVELS in scripts/e2e.env.")
    p.add_argument("--max-parallel-builds", type=int,
                    help="Max concurrent `ohbs-image build` subprocesses on the jump "
                         "box in all-linux/all mode. Defaults to $E2E_MAX_PARALLEL_BUILDS "
                         "if set, otherwise 4.")
    p.add_argument("--build-instance-type", default=DEFAULT_INSTANCE_TYPE,
                    help="Instance type for each profile's temporary build CVM "
                         "(independent of --instance-type, which is the jump box).")
    args = p.parse_args()

    # --max-parallel-builds default comes from env, else 4. (Default is
    # resolved here rather than in add_argument so an unset env var can't
    # accidentally override an explicit CLI flag — argparse's default= would
    # otherwise always win when the flag is omitted.)
    if args.max_parallel_builds is None:
        env_parallel = os.environ.get("E2E_MAX_PARALLEL_BUILDS", "")
        try:
            args.max_parallel_builds = int(env_parallel) if env_parallel.strip() else 4
        except ValueError:
            fail(f"E2E_MAX_PARALLEL_BUILDS must be an integer, got {env_parallel!r}")
            sys.exit(1)

    # --levels default comes from env, else "both". Same reasoning as above.
    if args.levels is None:
        env_levels = os.environ.get("E2E_LEVELS", "")
        if env_levels.strip():
            try:
                args.levels = _parse_levels(env_levels)
            except argparse.ArgumentTypeError as exc:
                fail(str(exc))
                sys.exit(1)
        else:
            args.levels = (1, 2)

    if args.target_mode == "single":
        if not args.profile or not args.level:
            fail("--target-mode single requires both --profile and --level")
            sys.exit(1)
    else:
        if args.profile or args.level:
            fail(f"--profile/--level are only valid with --target-mode single "
                 f"(got --target-mode {args.target_mode})")
            sys.exit(1)
        # --levels is only meaningful in batch modes; leave it as-is there.
        args.levels = tuple(sorted(set(args.levels)))

    return args


def _parse_levels(value: str) -> tuple[int, ...]:
    """Parse --levels / E2E_LEVELS ('1', '2', 'both', '1,2') into a tuple of
    {1,2}. Raises argparse.ArgumentTypeError so invalid CLI values fail
    cleanly; invalid env values are handled by the caller."""
    v = (value or "").strip().lower()
    if v in ("1", "l1"):
        return (1,)
    if v in ("2", "l2"):
        return (2,)
    if v in ("both", "1,2", "2,1", "12", "all"):
        return (1, 2)
    raise argparse.ArgumentTypeError(
        f"invalid levels {value!r} — expected '1', '2', or 'both'")


@dataclass
class ProfileCombo:
    profile: str
    level: int
    image_id: str
    family: str  # "linux" / "windows"
    skip_reason: str = ""  # set only for combos that are skipped, never built


@dataclass
class ProfileBuildResult:
    profile: str
    level: int
    status: str  # "passed" / "failed" / "skipped"
    exit_code: int | None
    score: float | None
    image_ids: list[str]
    log_tail: str
    skip_reason: str = ""
    instance_type: str = ""  # actual build CVM type used (after any stockout fallback)


def target_placement(args: argparse.Namespace) -> dict[str, str]:
    """Resolve the ONE shared cloud placement used for every profile's
    TARGET build CVM.

    The target placement is UNIFORM across all profiles — it is read from
    the global env vars E2E_TARGET_REGION / E2E_TARGET_ZONE /
    E2E_TARGET_VPC_ID / E2E_TARGET_SUBNET_ID / E2E_TARGET_SG_ID, falling
    back to the jump box's --region/--zone/--vpc-id/--subnet-id/
    --security-group-id when any of them is unset.

    The "TARGET_" prefix distinguishes these from the JUMP box's own
    placement (E2E_REGION / E2E_VPC_ID / ...) — the jump box is the compile
    machine that runs the suite and drives the builds; each profile's target
    build CVM is the machine that actually gets hardened. Only the target
    IMAGE id is per-profile (E2E_TARGET_IMAGE_<PROFILE>); the placement is
    shared so all target machines live in the same region/VPC/etc."""
    return {
        "region": os.environ.get("E2E_TARGET_REGION", args.region),
        "zone": os.environ.get("E2E_TARGET_ZONE", args.zone),
        "vpc_id": os.environ.get("E2E_TARGET_VPC_ID", args.vpc_id),
        "subnet_id": os.environ.get("E2E_TARGET_SUBNET_ID", args.subnet_id),
        "security_group_id": os.environ.get("E2E_TARGET_SG_ID", args.security_group_id),
    }


def resolve_combos(args: argparse.Namespace) -> tuple[list[ProfileCombo], list[ProfileCombo]]:
    """Work out which profile+level combinations --target-mode wants to
    build, using only this process's own os.environ (scripts/e2e.env is
    `source`d by the caller before this script runs, so
    E2E_TARGET_IMAGE_<PROFILE> is already present here).

    Returns (combos_to_build, skipped). Skipped combos never reach the
    remote host at all — they are reported directly from local state.
    """
    if args.target_mode == "single":
        profile, level = args.profile, args.level
        family = "windows" if PROFILES[profile].get("family") == "windows" else "linux"
        image_id = os.environ.get(f"E2E_TARGET_IMAGE_{profile.upper()}", "")
        if not image_id:
            fail(f"--target-mode single requires E2E_TARGET_IMAGE_{profile.upper()} to be set "
                 f"(see scripts/e2e.env.example)")
            sys.exit(1)
        combos = [ProfileCombo(profile, level, image_id, family)]
        skipped: list[ProfileCombo] = []
    else:
        profile_names = LINUX_PROFILES if args.target_mode == "all-linux" else list(PROFILES)
        levels = args.levels if getattr(args, "levels", None) else (1, 2)
        combos = []
        skipped = []
        for profile in profile_names:
            family = "windows" if PROFILES[profile].get("family") == "windows" else "linux"
            image_id = os.environ.get(f"E2E_TARGET_IMAGE_{profile.upper()}", "")
            for level in (1, 2):  # always enumerate both; filter below
                combo = ProfileCombo(profile, level, image_id, family)
                if not image_id:
                    combo.skip_reason = "no image configured"
                    skipped.append(combo)
                elif level not in levels:
                    combo.skip_reason = "level not requested"
                    skipped.append(combo)
                else:
                    combos.append(combo)

    if any(c.family == "windows" for c in combos) and not os.environ.get("WINRM_PASSWORD"):
        fail("WINRM_PASSWORD must be set — at least one Windows profile is in scope")
        sys.exit(1)

    return combos, skipped


def ensure_nonempty_combos(args: argparse.Namespace,
                            combos: list[ProfileCombo],
                            skipped: list[ProfileCombo]) -> None:
    """Abort before any CVM is launched if a matrix run would build nothing.

    In --target-mode single/all-linux/all, a run where ZERO profile+level
    combinations are configured is almost always a misconfiguration, not a
    deliberate "run nothing" — most commonly the E2E_TARGET_IMAGE_<PROFILE>
    vars exist in scripts/e2e.env but were NOT exported (or `set -a` was not
    used before `source`), so this process never received them. Launching the
    jump box anyway would waste time and cloud cost on a run that reports
    only "skipped: no image configured".

    Partial configuration is still allowed: if at least one combo builds, the
    unconfigured profiles are skipped as before. Only the all-empty case is
    treated as a hard error.
    """
    if combos:
        return  # at least one build will run — fine

    if args.target_mode == "single":
        # single mode already fails inside resolve_combos() on a missing
        # image; this guard is only reached for the batch modes.
        return

    missing = sorted({c.profile for c in skipped})
    if not missing:
        return  # nothing configured and nothing skipped → nothing to do
    fail(f"--target-mode {args.target_mode}: no profile has a configured target "
         f"image, so nothing would be built. Found no E2E_TARGET_IMAGE_<PROFILE> "
         f"in the environment for: {', '.join(missing)}.")
    fail("This is usually a `source`/export issue, not a missing value: the "
         "E2E_TARGET_IMAGE_* vars are in scripts/e2e.env but were not exported "
         "into this process. Run `set -a` before `source scripts/e2e.env` (then "
         "`set +a`), or add `export` to those lines in e2e.env.")
    sys.exit(1)


def confirm_cost(args: argparse.Namespace, combos: list[ProfileCombo],
                  skipped: list[ProfileCombo]) -> None:
    if args.yes:
        return
    banner("Real end-to-end test — cost confirmation")
    info("This will create a REAL, billed CVM instance:")
    info(f"  image={args.image_id}  type={args.instance_type}  "
         f"region={args.region}  zone={args.zone}")
    info("The instance is automatically destroyed once the test run finishes "
         "(expect ~5-10 minutes total).")
    if combos:
        combo_list = ", ".join(f"{c.profile} L{c.level}" for c in combos)
        info(f"This will ALSO create {len(combos)} additional REAL, billed build "
             f"CVM(s) — one per profile+level combination, each auto-destroyed by "
             f"packer at the end of its own build, up to "
             f"{args.max_parallel_builds} running concurrently:")
        info(f"  {combo_list}")
        info("Expect ~10-30 minutes PER combination. The resulting image(s) are "
             "deleted automatically once the batch finishes.")
    if skipped:
        skip_list = ", ".join(f"{c.profile} L{c.level}" for c in skipped)
        warn(f"Skipping (no image configured): {skip_list}")
    reply = input("Proceed? [y/N] ").strip().lower()
    if reply != "y":
        fail("Aborted by user")
        sys.exit(1)


def creds() -> tuple[str, str, str | None]:
    sid = os.environ.get("TENCENTCLOUD_SECRET_ID", "")
    skey = os.environ.get("TENCENTCLOUD_SECRET_KEY", "")
    tok = os.environ.get("TENCENTCLOUD_SECURITY_TOKEN") or None
    if not sid or not skey:
        fail("TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY must be set")
        sys.exit(1)
    return sid, skey, tok


def generate_keypair(tmpdir: Path) -> tuple[Path, Path]:
    priv = tmpdir / "e2e_key"
    pub = tmpdir / "e2e_key.pub"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(priv)],
        check=True, capture_output=True,
    )
    priv.chmod(0o600)
    return priv, pub


# Tencent Cloud API codes that are transient (throttling / internal blips) and
# worth retrying with backoff.  Deterministic errors (auth, bad params) are not.
_RETRYABLE_CODES = {"RequestLimitExceeded", "RequestLimitExceeded.UinLimitExceeded",
                    "InternalError", "InternalError.RequestTimeout", "ResourceInUse"}


def _is_retryable(exc: Exception) -> bool:
    """True when *exc* looks like a transient, retry-worthy failure."""
    if isinstance(exc, (OSError, TimeoutError)):  # socket/DNS/conn from _tc3_api
        return True
    msg = str(exc).lower()
    # _tc3_api converts transport failures (URLError / socket / DNS / conn
    # reset) into a ConfigError whose message is not an OSError subclass — so
    # match those message shapes explicitly.  Throttling codes are retryable too.
    if any(pat in msg for pat in ("request failed", "network error")):
        return True
    return any(code.lower() in msg for code in _RETRYABLE_CODES)


def _with_retry(fn, *args, retries: int = 3, base_delay: float = 1.0,
                retry_on: list[type] | None = None, **kwargs):
    """Call *fn* with exponential backoff on transient failures.

    Retries *retries* times (default 3 → waits 1s/2s/4s) when the failure is
    retryable (network error, throttling, or an exception in *retry_on*).
    Non-retryable exceptions propagate immediately.
    """
    delay = base_delay
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - centralised retry policy
            last_exc = exc
            if not _is_retryable(exc) and not (retry_on and isinstance(exc, tuple(retry_on))):
                raise
            if attempt < retries - 1:
                info(f"  retryable failure ({exc}); retrying in {delay:g}s "
                     f"({attempt + 1}/{retries - 1})")
                time.sleep(delay)
                delay *= 2
    assert last_exc is not None
    raise last_exc


def import_keypair(region: str, sid: str, skey: str, tok: str | None, pub_path: Path) -> str:
    pub_key = pub_path.read_text().strip()
    resp = _with_retry(
        _tc3_api, "cvm", "ImportKeyPair", "2017-03-12", region,
        {"KeyName": f"ohbs_image_e2e_{int(time.time())}",
         "ProjectId": 0,
         "PublicKey": pub_key},
        sid, skey, tok)
    resp_r = resp.get("Response", {})
    if "Error" in resp_r:
        raise ConfigError(f"ImportKeyPair failed: {resp_r['Error']}")
    key_id = resp_r.get("KeyId")
    if not key_id:
        raise ConfigError("ImportKeyPair returned no KeyId")
    return str(key_id)


def run_instance(args: argparse.Namespace, sid: str, skey: str, tok: str | None,
                  key_id: str) -> str:
    resp = _with_retry(
        _tc3_api,
        "cvm", "RunInstances", "2017-03-12", args.region,
        {"ImageId": args.image_id,
         "InstanceType": args.instance_type,
         "InstanceChargeType": "POSTPAID_BY_HOUR",
         "InstanceName": f"CIS_E2E_jumpbox_{int(time.time())}",
         "Placement": {"Zone": args.zone},
         "VirtualPrivateCloud": {"VpcId": args.vpc_id, "SubnetId": args.subnet_id},
         "SecurityGroupIds": [args.security_group_id],
         "LoginSettings": {"KeyIds": [key_id]},
         "InternetAccessible": {"PublicIpAssigned": True,
                                "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR",
                                "InternetMaxBandwidthOut": 5},
         "InstanceCount": 1,
         "TagSpecification": [{"ResourceType": "instance",
                               "Tags": [{"Key": "purpose", "Value": "cis-e2e-jumpbox"},
                                        {"Key": "ephemeral", "Value": "true"}]}]},
        sid, skey, tok)
    resp_r = resp.get("Response", {})
    if "Error" in resp_r:
        raise ConfigError(f"RunInstances failed: {resp_r['Error']}")
    ids = resp_r.get("InstanceIdSet") or []
    if not ids:
        raise ConfigError("RunInstances returned no InstanceId")
    return str(ids[0])


def save_last_instance(instance_id: str, key_id: str, region: str) -> None:
    LAST_INSTANCE_FILE.parent.mkdir(exist_ok=True)
    LAST_INSTANCE_FILE.write_text(json.dumps(
        {"instance_id": instance_id, "key_id": key_id, "region": region}, indent=2))


def clear_last_instance() -> None:
    LAST_INSTANCE_FILE.unlink(missing_ok=True)


def wait_for_public_ip(region: str, sid: str, skey: str, tok: str | None,
                        instance_id: str, timeout: int = BOOT_TIMEOUT_SECONDS,
                        max_consecutive_errors: int = 10) -> str:
    """Poll DescribeInstances for a public IP.

    *timeout* bounds the total wait.  If the poll hits *max_consecutive_errors*
    transport failures in a row (e.g. sustained network outage) it aborts early
    instead of silently polling for the whole *timeout* window.
    """
    deadline = time.time() + timeout
    consecutive_errors = 0
    while time.time() < deadline:
        try:
            resp = _tc3_api("cvm", "DescribeInstances", "2017-03-12", region,
                            {"InstanceIds": [instance_id]}, sid, skey, tok)
        except Exception:
            consecutive_errors += 1
            if consecutive_errors >= max_consecutive_errors:
                raise ConfigError(
                    f"Instance {instance_id} public-IP poll hit {max_consecutive_errors} "
                    f"consecutive API/network errors — aborting instead of polling to timeout"
                ) from None
            time.sleep(10)
            continue
        consecutive_errors = 0
        resp_r = resp.get("Response", {})
        error = resp_r.get("Error")
        if error:
            # Auth/permission errors are not transient — surface them
            # immediately instead of silently polling.
            raise ConfigError(f"DescribeInstances failed: {error}")
        insts = resp_r.get("InstanceSet") or []
        if insts:
            inst = insts[0]
            st = inst.get("InstanceState") or ""
            state = st.get("State", "") if isinstance(st, dict) else str(st)
            if state == "RUNNING":
                addrs = inst.get("PublicIpAddresses") or []
                if addrs:
                    return str(addrs[0])
        time.sleep(10)
    return ""


def wait_for_ssh(host: str, ssh_user: str, key_path: Path,
                 timeout: int = SSH_READY_TIMEOUT_SECONDS) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        cp = subprocess.run(
            ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
             f"{ssh_user}@{host}", "true"],
            capture_output=True,
        )
        if cp.returncode == 0:
            return
        time.sleep(5)
    raise ConfigError(f"SSH to {host} did not become ready within {timeout}s")


# Kept outside the repo checkout dir on purpose: step_clone does `rm -rf`
# on REPO_DIR, which would otherwise wipe out earlier steps' own logs.
REMOTE_LOG_DIR = "/root/cis-e2e-logs"
REMOTE_REPO_DIR = "/root/ohbs-image"

# AlmaLinux 10 (the img-31d8ynuj default) ships Python 3.12, not 3.11 —
# RHEL 10 dropped the python3.11 package name entirely.
TOOLCHAIN_REMOTE_SCRIPT = """
set -uo pipefail
LOGDIR={log_dir}
REPO_DIR={repo_dir}
mkdir -p "$LOGDIR"

# Each step is captured to its own log file and always reports EXIT:<code>
# as its last line, then run_step itself always "succeeds" (no `set -e`
# abort) so every later step still gets a chance to run and be recorded —
# a single early failure (e.g. a missing package) must not hide whether
# ruff/mypy/pytest would otherwise have passed.
run_step() {{
    local name="$1"
    shift
    echo
    echo "[remote] ==== $name ===="
    "$@" > "$LOGDIR/$name.log" 2>&1
    local code=$?
    echo "EXIT:$code" >> "$LOGDIR/$name.log"
    cat "$LOGDIR/$name.log"
    echo "[remote] ==== $name exit=$code ===="
}}

step_python_check() {{
    if ! command -v python3.12 >/dev/null 2>&1; then
        echo "installing python3.12"
        dnf install -y python3.12 python3.12-pip git
    fi
    command -v git >/dev/null 2>&1 || dnf install -y git
}}

step_clone() {{
    rm -rf "$REPO_DIR"
    git clone --branch {branch} --depth 1 {repo_url} "$REPO_DIR"
    cd "$REPO_DIR" && git rev-parse HEAD > "$LOGDIR/commit.txt"
}}

step_venv() {{
    cd "$REPO_DIR" || return 1
    python3.12 -m venv .venv
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -e ".[dev]"
}}

step_ruff() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    ruff check ohbs_image
}}

step_mypy() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    mypy ohbs_image --ignore-missing-imports
}}

step_pytest() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    pytest -v --tb=short --junitxml="$LOGDIR/pytest_junit.xml"
}}

run_step python_check step_python_check
run_step clone step_clone
run_step venv step_venv
run_step ruff step_ruff
run_step mypy step_mypy
run_step pytest step_pytest
echo
echo "[remote] all steps complete"
"""

# run_matrix.py is written to the remote host and driven from
# MATRIX_REMOTE_SCRIPT below. It fans out `ohbs-image build` (one per
# profile+level combo) with a bounded thread pool, using ohbs_image's own
# packer-output parsers so score/image_id extraction never drifts from what
# `ohbs-image build` itself considers authoritative.
RUN_MATRIX_PY = '''
import json
import os
import re
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, "REPO_DIR_PLACEHOLDER")
from ohbs_image import _extract_image_ids, _tc3_api  # noqa: E402

TOML_TEMPLATE = """[build]
profile = "{profile}"
region = "{region}"
zone = "{zone}"
instance_type = "{instance_type}"
source_image_id = "{image_id}"
vpc_id = "{vpc_id}"
subnet_id = "{subnet_id}"
security_group_id = "{security_group_id}"
# Target build CVMs get a public IP and are reached from the jump box over
# the public internet (the jump box and targets may live in different
# regions/VPCs where private routing does not exist, e.g. jump box in
# ap-hongkong, targets in ap-guangzhou). The target security group must
# allow inbound TCP/22 (Linux) / TCP/5986 (Windows) from the jump box.
associate_public_ip = true
instance_name = "CIS_E2E_{profile}_L{level}"
{disk_block}
[image]
name_prefix = "e2e-{profile}-l{level}"
copy_regions = []

[cis]
level = {level}

[cloud]
secret_id_env = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
{winrm_line}
"""

WORKDIR = Path("MATRIX_WORKDIR_PLACEHOLDER")
CIS_IMAGE_BIN = "CIS_IMAGE_BIN_PLACEHOLDER"
BUILD_INSTANCE_TYPE = "BUILD_INSTANCE_TYPE_PLACEHOLDER"

# Fallback target build instance types, tried in order when the primary
# (BUILD_INSTANCE_TYPE) fails with ResourceInsufficient.SpecifiedInstanceType
# (the instance type is understocked in the target zone — a transient Tencent
# Cloud inventory condition, not a config error). Override with the
# E2E_BUILD_INSTANCE_TYPES env var (comma-separated, e.g. "S6.MEDIUM2,SA2.MEDIUM2").
DEFAULT_FALLBACK_INSTANCE_TYPES = ["S6.MEDIUM2", "SA2.MEDIUM2"]

# Shared placement for every target build CVM (see target_placement() in
# real_e2e_test.py) — the same region/VPC/etc. is used for all profiles.
TARGET_REGION = "REGION_PLACEHOLDER"
TARGET_ZONE = "ZONE_PLACEHOLDER"
TARGET_VPC_ID = "VPC_ID_PLACEHOLDER"
TARGET_SUBNET_ID = "SUBNET_ID_PLACEHOLDER"
TARGET_SG_ID = "SECURITY_GROUP_ID_PLACEHOLDER"


def _redact(text):
    """Strip secrets that this process received from stdout/stderr before
    they land in the HTML report. build_one runs on the jump box where
    WINRM_PASSWORD / the cloud secret key live in env — if packer or
    ansible ever echoes one of them, we must not persist it."""
    for name in ("WINRM_PASSWORD", "TENCENTCLOUD_SECRET_KEY"):
        val = os.environ.get(name, "")
        if val:
            text = text.replace(val, "***")
    return text


def _parse_score(all_lines):
    """ohbs-image build reports the score as "Re-audit score: 94.8%" (not
    packer's bare "Score: 91.5%"), so _extract_score won't match — extract it
    from the combined stream here."""
    for line in all_lines:
        if m := re.search(r"re-audit score:\\s*(\\d+(?:\\.\\d+)?)\\s*%", line, re.IGNORECASE):
            return float(m.group(1))
    return None


def _disk_type_for(instance_type):
    """Map an instance type to the root-disk type it actually supports.

    Packer's tencentcloud-cvm builder defaults to CLOUD_PREMIUM, but not
    every family supports it — SA-series (SA2/SA5/...) only take CLOUD_SSD and
    fail with '[19045] CVM not support the required disk' otherwise. Other
    families (S5/S6/M5/...) are fine on CLOUD_PREMIUM. We derive the family
    from the leading alphabetic prefix (e.g. 'SA5.MEDIUM4' -> 'SA') so the
    mapping is explicit and covers every family, not just a SA heuristic."""
    family = re.match(r"([A-Za-z]+)", instance_type or "").group(1).upper()
    if family.startswith("SA"):
        return "CLOUD_SSD"
    return "CLOUD_PREMIUM"


def _disk_block(instance_type):
    """TOML block pinning the root-disk type for the target build CVM to the
    one its instance family supports (see _disk_type_for). Uses ohbs-image's
    [build.packer] passthrough. Returns '' when the default (CLOUD_PREMIUM)
    already applies, so behaviour is unchanged for non-SA types."""
    disk = _disk_type_for(instance_type)
    if disk == "CLOUD_PREMIUM":
        return ""
    return "\\n[build.packer]\\ndisk_type = \\"CLOUD_SSD\\""


def _stock_aware_types():
    """Pick target build instance types by ACTUAL zone inventory, not a
    hard-coded list.

    Queries Tencent Cloud DescribeZoneInstanceConfigInfos for the target zone,
    keeps 2c4g (Cpu=2, Memory=4 -> 'MEDIUM4') types whose Status is SELL,
    deduplicates, and ranks them: S-series (CLOUD_PREMIUM, cheapest/first)
    before SA-series (need CLOUD_SSD), then by name for determinism. This
    means we launch a type that is known to be in stock instead of blindly
    trying types that may be SOLD_OUT (which packer surfaces as
    ResourceInsufficient.SpecifiedInstanceType).

    Overrides:
      * E2E_BUILD_INSTANCE_TYPES (comma-separated) wins if set — explicit
        operator choice.
      * On any API/parse failure, or if no 2c4g type is SELL, we fall back to
        [BUILD_INSTANCE_TYPE] + DEFAULT_FALLBACK_INSTANCE_TYPES so the run
        still proceeds.
    """
    env_types = os.environ.get("E2E_BUILD_INSTANCE_TYPES", "").strip()
    if env_types:
        return [t.strip() for t in env_types.split(",") if t.strip()]
    try:
        sid = os.environ.get("TENCENTCLOUD_SECRET_ID", "")
        skey = os.environ.get("TENCENTCLOUD_SECRET_KEY", "")
        tok = os.environ.get("TENCENTCLOUD_SECURITY_TOKEN") or None
        resp = _tc3_api("cvm", "DescribeZoneInstanceConfigInfos", "2017-03-12",
                        TARGET_REGION,
                        {"Filters": [{"Name": "zone", "Values": [TARGET_ZONE]}]},
                        sid, skey, tok)
        qset = (resp.get("Response", {}) or {}).get("InstanceTypeQuotaSet", [])
        sell = set()
        for it in qset:
            name = it.get("InstanceType") or ""
            # "any 2c4g machine is fine" — include every in-stock 2-core /
            # 4 GiB type regardless of its marketing size name.
            if it.get("Cpu") == 2 and it.get("Memory") == 4 \
               and it.get("Status") == "SELL":
                sell.add(name)
        # Always keep the operator-specified / known-good types in the list so a
        # previously-verified type (e.g. S6.MEDIUM2) is never dropped just
        # because the API ranks a different family first. Deduped below.
        guaranteed = [BUILD_INSTANCE_TYPE] + DEFAULT_FALLBACK_INSTANCE_TYPES
        if not sell:
            return guaranteed
        # Rank: S-series first (CLOUD_PREMIUM), then SA-series (CLOUD_SSD),
        # then the rest, each subgroup sorted by name for determinism. Known-good
        # types are pulled to the very front so the run prefers a verified type.
        def _rank(t):
            if t in guaranteed:
                return (-1, t)
            fam = re.match(r"([A-Za-z]+)", t).group(1).upper()
            if fam.startswith("S") and not fam.startswith("SA"):
                return (0, t)
            if fam.startswith("SA"):
                return (1, t)
            return (2, t)
        return sorted(sell | set(guaranteed), key=_rank)
    except Exception:
        # Inventory lookup is best-effort; never let it block a run.
        return [BUILD_INSTANCE_TYPE] + DEFAULT_FALLBACK_INSTANCE_TYPES


def _attempt_build(combo, instance_type, attempt_dir):
    """Run one `ohbs-image build` for combo using instance_type. Returns a
    result dict with the combined output already parsed."""
    profile, level = combo["profile"], combo["level"]
    image_id = combo["image_id"]
    family = combo["family"]
    attempt_dir.mkdir(parents=True, exist_ok=True)
    toml_path = attempt_dir / "ohbs-image.toml"
    winrm_line = "winrm_password_env = \\"WINRM_PASSWORD\\"" if family == "windows" else ""
    toml_path.write_text(TOML_TEMPLATE.format(
        profile=profile, level=level, image_id=image_id,
        region=TARGET_REGION, zone=TARGET_ZONE,
        instance_type=instance_type,
        vpc_id=TARGET_VPC_ID, subnet_id=TARGET_SUBNET_ID,
        security_group_id=TARGET_SG_ID,
        winrm_line=winrm_line,
        disk_block=_disk_block(instance_type),
    ))
    cp = subprocess.run(
        [CIS_IMAGE_BIN, "build", "--config", str(toml_path),
         "--workdir", str(attempt_dir / "workdir"), "--yes"],
        capture_output=True, text=True, cwd=str(attempt_dir),
    )
    # `ohbs-image build` writes nearly all readable output to STDERR: packer
    # output is printed via print(file=sys.stderr) inside run_packer, and the
    # ok()/info() summary lines go through the logging handler (stderr). The
    # produced image ID and score only appear in that combined stream, so we
    # must parse stdout+stderr together, not stdout alone.
    combined = cp.stdout + "\\n" + cp.stderr
    all_lines = combined.splitlines()
    return {
        "profile": profile, "level": level,
        "exit_code": cp.returncode,
        "score": _parse_score(all_lines),
        "image_ids": _extract_image_ids(all_lines),
        "log_tail": _redact(combined[-12000:]),
        "instance_type": instance_type,
    }


def build_one(combo):
    profile, level = combo["profile"], combo["level"]
    types = _stock_aware_types()
    last = None
    for idx, instance_type in enumerate(types):
        attempt_dir = WORKDIR / f"{profile}-l{level}" if idx == 0 else WORKDIR / f"{profile}-l{level}-{idx}"
        result = _attempt_build(combo, instance_type, attempt_dir)
        last = result
        if result["exit_code"] == 0:
            return result
        # Retry with the next in-stock type when the failure is a launch-time
        # (inventory/placement) problem rather than a hardening failure:
        #   * ResourceInsufficient.SpecifiedInstanceType  — type understocked
        #   * "not exist" after "Waiting for instance ready" — instance was
        #     reclaimed immediately (transient zone/subnet inventory mismatch)
        #   * "CVM not support the required disk"          — wrong disk type
        #     (shouldn't happen given _disk_type_for, but retry defensively)
        # Any OTHER failure (e.g. ansible hardening error, low score) is a real
        # problem and surfaces immediately instead of burning the rest of the
        # candidate list on the same broken profile.
        tail = result["log_tail"] or ""
        launch_failure = (
            "ResourceInsufficient.SpecifiedInstanceType" in tail  # type understocked
            or "not exist" in tail                                # reclaimed after launch
            or "not support the required disk" in tail            # wrong disk type
            # The source image is gated to certain instance families; this
            # 2c4g type can't boot it ("No image found under current
            # instance_type(...) restriction"). Not a config error — try the
            # next in-stock type, which may be from a compatible family.
            or "No image found under current instance_type" in tail
        )
        if not launch_failure:
            return result
        print(f"[matrix] {profile} L{level}: instance type {instance_type} "
              f"launch failed ({tail.splitlines()[-1][:80]!r}) — trying next "
              f"({len(types)-idx-1} left)", flush=True)
    return last


def main():
    combos = json.loads(Path(sys.argv[1]).read_text())
    max_workers = int(sys.argv[3])
    results_path = Path(sys.argv[2])
    total = len(combos)
    lock = threading.Lock()
    done = {"n": 0}
    results = []

    def record(combo, result):
        # Thread-safe incremental persistence + progress line so the caller
        # (and the streamed remote log) can watch builds land one by one
        # instead of waiting for the whole batch. Each result is appended to
        # matrix_results.json as soon as its build finishes.
        with lock:
            done["n"] += 1
            results.append(result)
            status = "passed" if result["exit_code"] == 0 else "FAILED"
            score = f"{result['score']:g}%" if result.get("score") is not None else "-"
            imgs = ",".join(result["image_ids"]) or "-"
            print(f"[matrix] {done['n']}/{total} {combo['profile']} L{combo['level']} "
                  f"-> {status} (score {score}, image {imgs})", flush=True)
            # Rewrite the whole file each time (small N) so it always holds
            # a valid JSON array the caller can parse even mid-run.
            results_path.write_text(json.dumps(results))

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(build_one, combo): combo for combo in combos}
        for fut, combo in futures.items():
            record(combo, fut.result())
    print(f"[matrix] all {total} build(s) complete", flush=True)


if __name__ == "__main__":
    main()
'''

MATRIX_REMOTE_SCRIPT = """
set -uo pipefail
LOGDIR={log_dir}
REPO_DIR={repo_dir}
mkdir -p "$LOGDIR"

export TENCENTCLOUD_SECRET_ID={secret_id}
export TENCENTCLOUD_SECRET_KEY={secret_key}
export TENCENTCLOUD_SECURITY_TOKEN={secret_token}
export WINRM_PASSWORD={winrm_password}

run_step() {{
    local name="$1"
    shift
    echo
    echo "[remote] ==== $name ===="
    # tee so output streams LIVE to the SSH stdout (and thus the local
    # console / log) as it is produced, not only when the step finishes —
    # otherwise a multi-build matrix looks "stuck" for tens of minutes.
    "$@" 2>&1 | tee "$LOGDIR/$name.log"
    local code=${{PIPESTATUS[0]}}
    echo "EXIT:$code" >> "$LOGDIR/$name.log"
    echo "[remote] ==== $name exit=$code ===="
}}

step_python_check() {{
    if ! command -v python3.12 >/dev/null 2>&1; then
        echo "installing python3.12"
        dnf install -y python3.12 python3.12-pip git
    fi
    command -v git >/dev/null 2>&1 || dnf install -y git
}}

step_clone() {{
    rm -rf "$REPO_DIR"
    git clone --branch {branch} --depth 1 {repo_url} "$REPO_DIR"
    cd "$REPO_DIR" && git rev-parse HEAD > "$LOGDIR/commit.txt"
}}

step_venv() {{
    cd "$REPO_DIR" || return 1
    python3.12 -m venv .venv
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -e ".[dev]"
}}

step_packer_install() {{
    if ! command -v packer >/dev/null 2>&1; then
        dnf install -y dnf-plugins-core
        dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
        dnf install -y packer
    fi
}}

step_ansible_install() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    pip install --quiet "ansible-core>=2.15"
}}

step_ansible_windows_collection() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    ansible-galaxy collection install ansible.windows
}}

step_profile_matrix() {{
    cd "$REPO_DIR" || return 1
    source .venv/bin/activate
    cat > "$LOGDIR/combos.json" <<'COMBOS_EOF'
{combos_json}
COMBOS_EOF
    cat > "$LOGDIR/run_matrix.py" <<'MATRIX_EOF'
{run_matrix_py}
MATRIX_EOF
    python3.12 "$LOGDIR/run_matrix.py" "$LOGDIR/combos.json" \\
        "$LOGDIR/matrix_results.json" {max_parallel}
}}

run_step python_check step_python_check
run_step clone step_clone
run_step venv step_venv
run_step packer_install step_packer_install
run_step ansible_install step_ansible_install
{windows_collection_step}
run_step profile_matrix step_profile_matrix
echo
echo "[remote] all steps complete"
"""


def run_remote_suite(host: str, ssh_user: str, key_path: Path, branch: str,
                      log_path: Path) -> int:
    script = TOOLCHAIN_REMOTE_SCRIPT.format(
        branch=branch, repo_url=REPO_URL,
        log_dir=REMOTE_LOG_DIR, repo_dir=REMOTE_REPO_DIR)
    return _run_remote_script(host, ssh_user, key_path, script, log_path)


def run_remote_matrix(host: str, ssh_user: str, key_path: Path, branch: str,
                       log_path: Path, combos: list[ProfileCombo],
                       target_placement: dict[str, str],
                       build_instance_type: str,
                       max_parallel: int, sid: str, skey: str, tok: str | None) -> int:
    needs_windows = any(c.family == "windows" for c in combos)
    winrm_password = os.environ.get("WINRM_PASSWORD", "") if needs_windows else ""

    # Every target build CVM shares ONE placement (see target_placement()) —
    # only the per-profile image differs. Pass the shared placement into
    # run_matrix.py as globals rather than per-combo.
    combos_json = json.dumps([
        {"profile": c.profile, "level": c.level, "image_id": c.image_id,
         "family": c.family}
        for c in combos
    ])

    run_matrix_py = (
        RUN_MATRIX_PY
        .replace("REPO_DIR_PLACEHOLDER", REMOTE_REPO_DIR)
        .replace("MATRIX_WORKDIR_PLACEHOLDER", f"{REMOTE_LOG_DIR}/matrix-builds")
        .replace("CIS_IMAGE_BIN_PLACEHOLDER", f"{REMOTE_REPO_DIR}/.venv/bin/ohbs-image")
        .replace("BUILD_INSTANCE_TYPE_PLACEHOLDER", build_instance_type)
        .replace("REGION_PLACEHOLDER", target_placement["region"])
        .replace("ZONE_PLACEHOLDER", target_placement["zone"])
        .replace("VPC_ID_PLACEHOLDER", target_placement["vpc_id"])
        .replace("SUBNET_ID_PLACEHOLDER", target_placement["subnet_id"])
        .replace("SECURITY_GROUP_ID_PLACEHOLDER", target_placement["security_group_id"])
    )

    windows_collection_step = (
        "run_step ansible_windows_collection step_ansible_windows_collection"
        if needs_windows else ""
    )

    script = MATRIX_REMOTE_SCRIPT.format(
        branch=branch, repo_url=REPO_URL,
        log_dir=REMOTE_LOG_DIR, repo_dir=REMOTE_REPO_DIR,
        secret_id=shlex.quote(sid), secret_key=shlex.quote(skey),
        secret_token=shlex.quote(tok or ""), winrm_password=shlex.quote(winrm_password),
        combos_json=combos_json, run_matrix_py=run_matrix_py,
        max_parallel=max_parallel, windows_collection_step=windows_collection_step,
    )
    return _run_remote_script(host, ssh_user, key_path, script, log_path)


def _redact_line(line: str) -> str:
    """Strip secrets this process holds from a streamed/printed line before
    it is persisted. Guards against a secret leaking into the plain-text
    remote log or the HTML report if packer/ansible ever echoes it."""
    for name in ("WINRM_PASSWORD", "TENCENTCLOUD_SECRET_KEY",
                 "TENCENTCLOUD_SECRET_ID"):
        val = os.environ.get(name, "")
        if val and val in line:
            line = line.replace(val, "***")
    return line


def _run_remote_script(host: str, ssh_user: str, key_path: Path, script: str,
                        log_path: Path) -> int:
    log_path.parent.mkdir(exist_ok=True)
    with subprocess.Popen(
        ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", f"{ssh_user}@{host}", "bash", "-s"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    ) as proc, log_path.open("w") as log_f:
        assert proc.stdin is not None
        proc.stdin.write(script)
        proc.stdin.close()
        assert proc.stdout is not None
        for line in proc.stdout:
            safe = _redact_line(line)
            sys.stdout.write(safe)
            log_f.write(safe)
        proc.wait()
        return proc.returncode


def fetch_remote_reports(host: str, ssh_user: str, key_path: Path,
                          steps: list[tuple[str, str]]) -> dict[str, str]:
    """Best-effort pull of every step's log, the commit hash, and (in
    toolchain mode) the pytest JUnit XML / (in matrix mode) matrix_results.json
    from the remote host in a single SSH round-trip.

    A step whose log file doesn't exist (it never ran, e.g. because the
    instance died mid-run) comes back as an empty string rather than
    raising — the caller treats an empty/missing report as "not run".
    """
    keys_to_paths = {name: f"{REMOTE_LOG_DIR}/{name}.log" for name, _ in steps}
    keys_to_paths["commit"] = f"{REMOTE_LOG_DIR}/commit.txt"
    keys_to_paths["pytest_junit"] = f"{REMOTE_LOG_DIR}/pytest_junit.xml"
    keys_to_paths["matrix_results"] = f"{REMOTE_LOG_DIR}/matrix_results.json"

    cat_cmds = [
        f'echo "===CIS_E2E_FILE:{key}==="; '
        f'[ -f "{path}" ] && cat "{path}"; '
        f'echo "===CIS_E2E_END==="'
        for key, path in keys_to_paths.items()
    ]
    script = "\n".join(cat_cmds)

    try:
        cp = subprocess.run(
            ["ssh", "-i", str(key_path), "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
             f"{ssh_user}@{host}", "bash", "-s"],
            input=script, capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        warn(f"Could not fetch remote step reports: {exc}")
        return {}

    blob = cp.stdout
    results: dict[str, str] = {}
    for key in keys_to_paths:
        m = re.search(
            rf"===CIS_E2E_FILE:{re.escape(key)}===\n(.*?)===CIS_E2E_END===",
            blob, re.DOTALL)
        results[key] = m.group(1) if m else ""
    return results


@dataclass
class StepResult:
    name: str
    label: str
    exit_code: int | None  # None = log missing entirely (never ran / unfetchable)
    log: str

    @property
    def status(self) -> str:
        if self.exit_code is None:
            return "not run"
        return "passed" if self.exit_code == 0 else "failed"


def build_step_results(reports: dict[str, str],
                        steps: list[tuple[str, str]]) -> list[StepResult]:
    """Turn fetch_remote_reports()'s raw per-step log text into StepResults,
    peeling the trailing 'EXIT:<code>' line that run_step() appends."""
    results = []
    for name, label in steps:
        raw = reports.get(name, "")
        if not raw.strip():
            results.append(StepResult(name, label, None, ""))
            continue
        lines = raw.splitlines()
        exit_code: int | None = None
        if lines and lines[-1].startswith("EXIT:"):
            try:
                exit_code = int(lines[-1].split(":", 1)[1])
            except ValueError:
                exit_code = None
            lines = lines[:-1]
        results.append(StepResult(name, label, exit_code, "\n".join(lines)))
    return results


def compute_overall_passed(steps: list[StepResult],
                            profile_results: list[ProfileBuildResult] | None = None) -> bool:
    steps_ok = all(s.exit_code == 0 for s in steps)
    if not profile_results:
        return steps_ok
    profiles_ok = all(r.status != "failed" for r in profile_results)
    return steps_ok and profiles_ok


def build_profile_results(skipped: list[ProfileCombo],
                           matrix_results_json: str) -> list[ProfileBuildResult]:
    """Merge locally-determined skips with the remote matrix_results.json
    (produced by run_matrix.py) into one ordered list for reporting."""
    results = [
        ProfileBuildResult(c.profile, c.level, "skipped", None, None, [], "",
                           skip_reason=c.skip_reason or "no image configured")
        for c in skipped
    ]
    if matrix_results_json.strip():
        try:
            raw = json.loads(matrix_results_json)
        except json.JSONDecodeError:
            raw = []
        for item in raw:
            exit_code = item.get("exit_code")
            status = "passed" if exit_code == 0 else "failed"
            results.append(ProfileBuildResult(
                item.get("profile", "?"), item.get("level", 0), status,
                exit_code, item.get("score"), item.get("image_ids", []),
                item.get("log_tail", ""),
                instance_type=item.get("instance_type", "")))
    return results


@dataclass
class JunitCase:
    classname: str
    name: str
    time: float
    status: str  # passed / failed / error / skipped
    message: str = ""


@dataclass
class JunitSummary:
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    cases: list[JunitCase] = field(default_factory=list)
    note: str = ""


def parse_junit_xml(xml_text: str) -> JunitSummary:
    """Parse pytest's --junitxml output (stdlib xml.etree, no new dep)."""
    if not xml_text.strip():
        return JunitSummary(note="No JUnit XML available (pytest step likely never ran).")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return JunitSummary(note=f"Could not parse JUnit XML: {exc}")

    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        return JunitSummary(note="JUnit XML has no <testsuite> element.")

    summary = JunitSummary()
    for tc in suite.findall("testcase"):
        classname = tc.get("classname", "")
        name = tc.get("name", "")
        try:
            time_s = float(tc.get("time", "0") or 0)
        except ValueError:
            time_s = 0.0
        failure = tc.find("failure")
        error = tc.find("error")
        skipped = tc.find("skipped")
        if failure is not None:
            status, message = "failed", failure.get("message", "") or (failure.text or "").strip()
            summary.failed += 1
        elif error is not None:
            status, message = "error", error.get("message", "") or (error.text or "").strip()
            summary.errors += 1
        elif skipped is not None:
            status, message = "skipped", skipped.get("message", "") or (skipped.text or "").strip()
            summary.skipped += 1
        else:
            status, message = "passed", ""
            summary.passed += 1
        summary.total += 1
        summary.cases.append(JunitCase(classname, name, time_s, status, message))
    return summary


def _step_row_html(step: StepResult) -> str:
    badge_cls = {"passed": "badge-pass", "failed": "badge-fail",
                 "not run": "badge-skip"}[step.status]
    log_html = html.escape(step.log) if step.log else "(no output captured)"
    open_attr = "" if step.status == "passed" else " open"
    return (
        f'<tr><td>{html.escape(step.label)}</td>'
        f'<td><span class="badge {badge_cls}">{step.status.upper()}</span></td></tr>'
        f'<tr><td colspan="2"><details{open_attr}>'
        f'<summary>log</summary><pre>{log_html}</pre></details></td></tr>'
    )


def _junit_case_row_html(case: JunitCase) -> str:
    badge_cls = {"passed": "badge-pass", "failed": "badge-fail",
                 "error": "badge-fail", "skipped": "badge-skip"}[case.status]
    return (
        f'<tr><td>{html.escape(case.classname)}</td>'
        f'<td>{html.escape(case.name)}</td>'
        f'<td><span class="badge {badge_cls}">{case.status.upper()}</span></td>'
        f'<td>{case.time:.2f}s</td>'
        f'<td><pre>{html.escape(case.message)}</pre></td></tr>'
    )


def _profile_result_row_html(r: ProfileBuildResult) -> str:
    badge_cls = {"passed": "badge-pass", "failed": "badge-fail",
                 "skipped": "badge-skip"}[r.status]
    score_text = f"{r.score:g}%" if r.score is not None else "—"
    images_text = html.escape(", ".join(r.image_ids)) if r.image_ids else "—"
    itype_text = html.escape(r.instance_type) if r.instance_type else "—"
    if r.status == "skipped":
        detail_html = f'<td colspan="2">{html.escape(r.skip_reason)}</td>'
    else:
        log_html = html.escape(r.log_tail) if r.log_tail else "(no output captured)"
        open_attr = "" if r.status == "passed" else " open"
        detail_html = (
            f'<td>{score_text}</td><td>{images_text}</td><td>{itype_text}</td></tr>'
            f'<tr><td colspan="6"><details{open_attr}>'
            f'<summary>log (tail)</summary><pre>{log_html}</pre></details></td>'
        )
    return (
        f'<tr><td>{html.escape(r.profile)}</td><td>L{r.level}</td>'
        f'<td><span class="badge {badge_cls}">{r.status.upper()}</span></td>'
        f'{detail_html}</tr>'
    )


def render_html_report(
    *,
    overall_passed: bool,
    started_at: float,
    duration_s: float,
    instance_id: str,
    region: str,
    zone: str,
    image_id: str,
    branch: str,
    commit: str,
    steps: list[StepResult],
    junit: JunitSummary,
    profile_results: list[ProfileBuildResult] | None = None,
    log_path: str | None = None,
) -> str:
    """Self-contained HTML report (inline CSS, no external assets/network
    calls) so it can be opened offline. Follows the codebase's existing
    report-building style (f-strings, stdlib only, escape all interpolated
    text) used by _audit_results_sarif/_audit_results_xccdf."""
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started_at))
    banner_cls = "banner-pass" if overall_passed else "banner-fail"
    banner_text = "PASSED" if overall_passed else "FAILED"
    steps_html = "".join(_step_row_html(s) for s in steps)
    non_passed_cases = [c for c in junit.cases if c.status != "passed"]
    junit_rows = "".join(_junit_case_row_html(c) for c in non_passed_cases)
    junit_note_html = f'<p class="note">{html.escape(junit.note)}</p>' if junit.note else ""
    junit_table_html = (
        '<table><thead><tr><th>Class</th><th>Test</th><th>Status</th>'
        '<th>Time</th><th>Message</th></tr></thead>'
        f'<tbody>{junit_rows}</tbody></table>'
        if non_passed_cases else
        "<p>All tests passed — no failures/errors/skips to show.</p>"
    )

    matrix_html = ""
    if profile_results:
        matrix_rows = "".join(_profile_result_row_html(r) for r in profile_results)
        matrix_html = f"""
<h2>Profile Build Matrix</h2>
<table>
  <thead><tr><th>Profile</th><th>Level</th><th>Status</th>
  <th>Score</th><th>Image ID(s)</th><th>Instance Type</th></tr></thead>
  <tbody>{matrix_rows}</tbody>
</table>
"""

    log_link_html = ""
    if log_path:
        log_link_html = (
            f'<p class="note">Full remote log (complete packer/ansible '
            f'output for every step, including each profile build): '
            f'<code>{html.escape(str(log_path))}</code></p>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ohbs-image real E2E report — {html.escape(when)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 2rem;
          color: #1a1a1a; background: #fafafa; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #555; margin-bottom: 1.5rem; }}
  .meta span {{ display: inline-block; margin-right: 1.5rem; }}
  .banner {{ padding: 1rem 1.5rem; border-radius: 8px; font-size: 1.4rem;
             font-weight: 700; color: #fff; margin-bottom: 1.5rem; }}
  .banner-pass {{ background: #1e8e3e; }}
  .banner-fail {{ background: #c5221f; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px;
            font-size: 0.85rem; font-weight: 600; color: #fff; }}
  .badge-pass {{ background: #1e8e3e; }}
  .badge-fail {{ background: #c5221f; }}
  .badge-skip {{ background: #888; }}
  pre {{ white-space: pre-wrap; word-break: break-word; max-height: 400px;
         overflow-y: auto; background: #f7f7f7; padding: 0.75rem;
         border-radius: 4px; margin: 0; font-size: 0.85rem; }}
  details summary {{ cursor: pointer; font-weight: 600; padding: 0.4rem 0; }}
  .note {{ color: #a15c00; font-style: italic; }}
  .counts span {{ margin-right: 1.5rem; font-weight: 600; }}
</style>
</head>
<body>
<h1>ohbs-image real end-to-end test report</h1>
<div class="meta">
  <span><strong>When:</strong> {html.escape(when)}</span>
  <span><strong>Duration:</strong> {duration_s:.0f}s</span>
  <span><strong>Instance:</strong> {html.escape(instance_id)}</span>
  <span><strong>Region/Zone:</strong> {html.escape(region)}/{html.escape(zone)}</span>
  <span><strong>Image:</strong> {html.escape(image_id)}</span>
  <span><strong>Branch:</strong> {html.escape(branch)}</span>
  <span><strong>Commit:</strong> {html.escape(commit or "(unknown)")}</span>
</div>
<div class="banner {banner_cls}">Overall result: {banner_text}</div>
{log_link_html}

<h2>Steps</h2>
<table>
  <thead><tr><th>Step</th><th>Status</th></tr></thead>
  <tbody>{steps_html}</tbody>
</table>
{matrix_html}
<h2>pytest results</h2>
{junit_note_html}
<p class="counts">
  <span>Total: {junit.total}</span>
  <span>Passed: {junit.passed}</span>
  <span>Failed: {junit.failed}</span>
  <span>Errors: {junit.errors}</span>
  <span>Skipped: {junit.skipped}</span>
</p>
{junit_table_html}
</body>
</html>
"""


def terminate_instance(region: str, sid: str, skey: str, tok: str | None,
                        instance_id: str) -> None:
    try:
        _with_retry(_tc3_api, "cvm", "TerminateInstances", "2017-03-12", region,
                    {"InstanceIds": [instance_id]}, sid, skey, tok)
        ok(f"Instance terminated: {instance_id}")
    except Exception as exc:
        warn(f"Failed to terminate instance {instance_id}: {exc} — "
             f"please terminate it manually")


def delete_keypair(region: str, sid: str, skey: str, tok: str | None, key_id: str) -> None:
    try:
        _with_retry(_tc3_api, "cvm", "DeleteKeyPairs", "2017-03-12", region,
                    {"KeyIds": [key_id]}, sid, skey, tok)
        ok(f"Key pair deleted: {key_id}")
    except Exception as exc:
        warn(f"Failed to delete key pair {key_id}: {exc} — "
             f"please delete it manually")


def verify_instance_terminated(region: str, sid: str, skey: str, tok: str | None,
                                instance_id: str, timeout: int = 120) -> bool:
    """Poll DescribeInstances to confirm *instance_id* is gone after terminate.

    TerminateInstances is async — the instance may still show RUNNING for a
    short window.  Returns True when it disappears (or errors out) within
    *timeout*; False if it's still around (so the operator knows it may keep
    incurring cost).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = _with_retry(_tc3_api, "cvm", "DescribeInstances", "2017-03-12",
                               region, {"InstanceIds": [instance_id]}, sid, skey, tok)
        except Exception:
            # DescribeInstances failing (e.g. instance no longer queryable) is
            # a good sign it's gone — treat as terminated.
            return True
        resp_r = resp.get("Response", {})
        if "Error" in resp_r or not resp_r.get("InstanceSet"):
            return True
        time.sleep(5)
    return False


def delete_batch_images(region: str, sid: str, skey: str, tok: str | None,
                         image_ids: list[str]) -> None:
    """Best-effort delete every image produced by a --target-mode
    single/all-linux/all batch — mirrors terminate_instance()/
    delete_keypair()'s try/except/warn style. This script never leaves a
    billed golden image behind after a batch run."""
    if not image_ids:
        return
    try:
        _with_retry(_tc3_api, "cvm", "DeleteImages", "2017-03-12", region,
                    {"ImageIds": image_ids}, sid, skey, tok)
        ok(f"Deleted {len(image_ids)} batch image(s): {', '.join(image_ids)}")
    except Exception as exc:
        warn(f"Failed to delete batch images {image_ids}: {exc} — "
             f"please delete them manually")


def main() -> int:
    args = parse_args()
    sid, skey, tok = creds()

    combos: list[ProfileCombo] = []
    skipped: list[ProfileCombo] = []
    if args.target_mode != "toolchain":
        combos, skipped = resolve_combos(args)
        ensure_nonempty_combos(args, combos, skipped)

    confirm_cost(args, combos, skipped)

    instance_id: str | None = None
    key_id: str | None = None
    overall_passed = False
    run_start = time.time()
    batch_image_ids: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        try:
            banner("Generating temporary SSH key pair")
            priv_key, pub_key = generate_keypair(tmpdir)

            banner("Registering key pair with Tencent Cloud")
            key_id = import_keypair(args.region, sid, skey, tok, pub_key)
            ok(f"KeyId: {key_id}")

            banner(f"Launching instance from {args.image_id}")
            instance_id = run_instance(args, sid, skey, tok, key_id)
            save_last_instance(instance_id, key_id, args.region)
            ok(f"InstanceId: {instance_id}")

            banner("Waiting for instance to reach RUNNING with a public IP")
            public_ip = wait_for_public_ip(args.region, sid, skey, tok, instance_id,
                                           timeout=args.timeout)
            if not public_ip:
                raise ConfigError(
                    f"Instance {instance_id} did not get a public IP within "
                    f"{args.timeout}s")
            ok(f"Public IP: {public_ip}")

            banner("Waiting for SSH to become reachable")
            wait_for_ssh(public_ip, args.ssh_user, priv_key, timeout=args.ssh_timeout)
            ok("SSH is up")

            needs_windows = any(c.family == "windows" for c in combos)
            steps_spec = build_steps(args.target_mode, needs_windows)

            run_start = time.time()
            log_path = REPO_ROOT / "logs" / f"e2e-{int(run_start)}.log"
            html_path = REPO_ROOT / "logs" / f"e2e-{int(run_start)}.html"

            if args.target_mode == "toolchain":
                banner("Running remote test suite (ruff, mypy, pytest)")
                run_remote_suite(public_ip, args.ssh_user, priv_key, args.branch, log_path)
            else:
                banner(f"Running remote profile build matrix ({len(combos)} combination(s))")
                run_remote_matrix(
                    public_ip, args.ssh_user, priv_key, args.branch, log_path, combos,
                    target_placement(args), args.build_instance_type,
                    args.max_parallel_builds, sid, skey, tok)
            info(f"Full remote log saved to {log_path}")

            banner("Fetching structured step reports")
            reports = fetch_remote_reports(public_ip, args.ssh_user, priv_key, steps_spec)
            steps = build_step_results(reports, steps_spec)
            junit = parse_junit_xml(reports.get("pytest_junit", ""))
            profile_results = (
                build_profile_results(skipped, reports.get("matrix_results", ""))
                if args.target_mode != "toolchain" else None
            )
            if profile_results:
                batch_image_ids = [
                    img for r in profile_results for img in r.image_ids
                ]
            overall_passed = compute_overall_passed(steps, profile_results)
            duration_s = time.time() - run_start

            report_html = render_html_report(
                overall_passed=overall_passed,
                started_at=run_start,
                duration_s=duration_s,
                instance_id=instance_id,
                region=args.region,
                zone=args.zone,
                image_id=args.image_id,
                branch=args.branch,
                commit=reports.get("commit", "").strip(),
                steps=steps,
                junit=junit,
                profile_results=profile_results,
                log_path=str(log_path),
            )
            try:
                html_path.write_text(report_html, encoding="utf-8")
                ok(f"HTML report saved to {html_path}")
            except OSError as exc:
                warn(f"Could not write HTML report: {exc}")

            for step in steps:
                if step.status == "failed":
                    fail(f"  step failed: {step.label}")
                elif step.status == "not run":
                    warn(f"  step not run: {step.label}")
            if profile_results:
                for r in profile_results:
                    if r.status == "failed":
                        fail(f"  profile build failed: {r.profile} L{r.level}")
                    elif r.status == "skipped":
                        warn(f"  profile build skipped: {r.profile} L{r.level} "
                             f"({r.skip_reason})")

            if overall_passed:
                ok("Real end-to-end test PASSED")
            else:
                fail("Real end-to-end test FAILED — see HTML report for details")

        except ConfigError as exc:
            fail(str(exc))
            overall_passed = False
        except KeyboardInterrupt:
            warn("Interrupted by user — cleaning up")
            overall_passed = False
        except Exception as exc:
            fail(f"Unexpected error: {exc}")
            overall_passed = False
        finally:
            if batch_image_ids:
                delete_batch_images(args.region, sid, skey, tok, batch_image_ids)
            keep = args.keep_on_failure and not overall_passed
            if instance_id and not keep:
                terminate_instance(args.region, sid, skey, tok, instance_id)
                if not verify_instance_terminated(args.region, sid, skey, tok, instance_id):
                    warn(f"Jump box {instance_id} still reported running after terminate — "
                         f"it may continue to incur cost. Check the Tencent Cloud console.")
            elif instance_id and keep:
                warn(f"--keep-on-failure set: instance NOT destroyed. "
                     f"InstanceId={instance_id} region={args.region} — "
                     f"remember to terminate it manually.")
            if key_id and not keep:
                delete_keypair(args.region, sid, skey, tok, key_id)
            if not keep:
                clear_last_instance()

    return 0 if overall_passed else 1


if __name__ == "__main__":
    sys.exit(main())
