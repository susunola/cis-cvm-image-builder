#!/usr/bin/env python3
"""Real end-to-end test: bring up a real Tencent Cloud CVM jump box, clone
the repo onto it, install deps, run the full pytest/ruff/mypy suite over
SSH, then tear the instance (and its temporary key pair) back down.

This is a *supplement* to tests/test_cis_image.py, not a replacement.  The
existing pytest suite mocks the cis_image._tc3_api boundary — it is fast, free,
and covers API response edge cases (null fields, wrong nesting, etc.) very
well, but it can never catch "does `pip install -e .` actually work on a
clean AlmaLinux box", "is the real network path from a CVM reachable", or
"did we drift from the real Tencent Cloud API contract". Those only show up
by running against something real.

Usage:
    export TENCENTCLOUD_SECRET_ID=...
    export TENCENTCLOUD_SECRET_KEY=...
    python3 scripts/real_e2e_test.py \\
        --vpc-id vpc-xxxxxxxx --subnet-id subnet-xxxxxxxx \\
        --security-group-id sg-xxxxxxxx [--yes]

The instance and temporary SSH key pair are ALWAYS torn down on exit
(success, failure, or Ctrl-C) unless --keep-on-failure is passed and the
remote run actually failed.

Hard requirements (see CONTRIBUTING.md "Running the real end-to-end test"):
  - cis-image must already be installed in editable mode on THIS machine
    (`pip install -e .`) — this script imports cis_image._tc3_api directly to
    avoid re-implementing the TC3-HMAC-SHA256 signing logic.
  - The security group passed via --security-group-id must already allow
    inbound TCP/22 from this machine's public IP. This script does not
    modify security group rules.
  - This creates a REAL, billed CVM instance. It is destroyed automatically
    at the end of the run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cis_image import ConfigError, _tc3_api, banner, fail, info, ok, warn  # noqa: E402

DEFAULT_IMAGE_ID = "img-31d8ynuj"
DEFAULT_REGION = "ap-guangzhou"
DEFAULT_ZONE = "ap-guangzhou-3"
DEFAULT_INSTANCE_TYPE = "S5.MEDIUM2"
REPO_URL = "https://github.com/susunola/cis-cvm-image-builder.git"
LAST_INSTANCE_FILE = REPO_ROOT / "logs" / "e2e_last_instance.json"
BOOT_TIMEOUT_SECONDS = 900
SSH_READY_TIMEOUT_SECONDS = 180


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--image-id", default=DEFAULT_IMAGE_ID)
    p.add_argument("--region", default=DEFAULT_REGION)
    p.add_argument("--zone", default=DEFAULT_ZONE)
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
    return p.parse_args()


def confirm_cost(args: argparse.Namespace) -> None:
    if args.yes:
        return
    banner("Real end-to-end test — cost confirmation")
    info("This will create a REAL, billed CVM instance:")
    info(f"  image={args.image_id}  type={args.instance_type}  "
         f"region={args.region}  zone={args.zone}")
    info("The instance is automatically destroyed once the test run finishes "
         "(expect ~5-10 minutes total).")
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


def import_keypair(region: str, sid: str, skey: str, tok: str | None, pub_path: Path) -> str:
    pub_key = pub_path.read_text().strip()
    resp = _tc3_api("cvm", "ImportKeyPair", "2017-03-12", region,
                     {"KeyName": f"cis-image-e2e-{int(time.time())}",
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
    resp = _tc3_api(
        "cvm", "RunInstances", "2017-03-12", args.region,
        {"ImageId": args.image_id,
         "InstanceType": args.instance_type,
         "InstanceChargeType": "POSTPAID_BY_HOUR",
         "InstanceName": "cis-image-e2e-test",
         "Placement": {"Zone": args.zone},
         "VirtualPrivateCloud": {"VpcId": args.vpc_id, "SubnetId": args.subnet_id},
         "SecurityGroupIds": [args.security_group_id],
         "LoginSettings": {"KeyIds": [key_id]},
         "InternetAccessible": {"PublicIpAssigned": True,
                                "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR",
                                "InternetMaxBandwidthOut": 5},
         "InstanceCount": 1,
         "TagSpecification": [{"ResourceType": "instance",
                               "Tags": [{"Key": "purpose", "Value": "cis-image-e2e-test"},
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
                        instance_id: str) -> str:
    deadline = time.time() + BOOT_TIMEOUT_SECONDS
    while time.time() < deadline:
        try:
            resp = _tc3_api("cvm", "DescribeInstances", "2017-03-12", region,
                            {"InstanceIds": [instance_id]}, sid, skey, tok)
        except Exception:
            time.sleep(10)
            continue
        resp_r = resp.get("Response", {})
        error = resp_r.get("Error")
        if error:
            # Auth/permission errors are not transient — surface them
            # immediately instead of silently polling for 15 minutes.
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


def wait_for_ssh(host: str, ssh_user: str, key_path: Path) -> None:
    deadline = time.time() + SSH_READY_TIMEOUT_SECONDS
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
    raise ConfigError(f"SSH to {host} did not become ready within "
                      f"{SSH_READY_TIMEOUT_SECONDS}s")


REMOTE_SCRIPT = """
set -euo pipefail
echo "[remote 1/5] Checking python3 version"
if ! command -v python3.11 >/dev/null 2>&1; then
    echo "[remote]   installing python3.11"
    dnf install -y python3.11 python3.11-pip git >/dev/null
fi
command -v git >/dev/null 2>&1 || dnf install -y git >/dev/null

echo "[remote 2/5] Cloning {branch}"
rm -rf /root/cis-cvm-image-builder
git clone --branch {branch} --depth 1 {repo_url} /root/cis-cvm-image-builder
cd /root/cis-cvm-image-builder
echo "     commit: $(git rev-parse --short HEAD)"

echo "[remote 3/5] Creating venv + installing dev deps"
python3.11 -m venv .venv
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"

echo "[remote 4/5] ruff + mypy"
ruff check cis_image
mypy cis_image --ignore-missing-imports

echo "[remote 5/5] pytest"
pytest -v --tb=short
"""


def run_remote_suite(host: str, ssh_user: str, key_path: Path, branch: str,
                      log_path: Path) -> int:
    script = REMOTE_SCRIPT.format(branch=branch, repo_url=REPO_URL)
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
            sys.stdout.write(line)
            log_f.write(line)
        proc.wait()
        return proc.returncode


def terminate_instance(region: str, sid: str, skey: str, tok: str | None,
                        instance_id: str) -> None:
    try:
        _tc3_api("cvm", "TerminateInstances", "2017-03-12", region,
                 {"InstanceIds": [instance_id]}, sid, skey, tok)
        ok(f"Instance terminated: {instance_id}")
    except Exception as exc:
        warn(f"Failed to terminate instance {instance_id}: {exc} — "
             f"please terminate it manually")


def delete_keypair(region: str, sid: str, skey: str, tok: str | None, key_id: str) -> None:
    try:
        _tc3_api("cvm", "DeleteKeyPairs", "2017-03-12", region,
                 {"KeyIds": [key_id]}, sid, skey, tok)
        ok(f"Key pair deleted: {key_id}")
    except Exception as exc:
        warn(f"Failed to delete key pair {key_id}: {exc} — "
             f"please delete it manually")


def main() -> int:
    args = parse_args()
    sid, skey, tok = creds()
    confirm_cost(args)

    instance_id: str | None = None
    key_id: str | None = None
    remote_exit_code = 1

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
            public_ip = wait_for_public_ip(args.region, sid, skey, tok, instance_id)
            if not public_ip:
                raise ConfigError(
                    f"Instance {instance_id} did not get a public IP within "
                    f"{BOOT_TIMEOUT_SECONDS}s")
            ok(f"Public IP: {public_ip}")

            banner("Waiting for SSH to become reachable")
            wait_for_ssh(public_ip, args.ssh_user, priv_key)
            ok("SSH is up")

            banner("Running remote test suite (ruff, mypy, pytest)")
            log_path = REPO_ROOT / "logs" / f"e2e-{int(time.time())}.log"
            remote_exit_code = run_remote_suite(
                public_ip, args.ssh_user, priv_key, args.branch, log_path)
            info(f"Full remote log saved to {log_path}")

            if remote_exit_code == 0:
                ok("Real end-to-end test PASSED")
            else:
                fail(f"Real end-to-end test FAILED (exit code {remote_exit_code})")

        except ConfigError as exc:
            fail(str(exc))
            remote_exit_code = 1
        except KeyboardInterrupt:
            warn("Interrupted by user — cleaning up")
            remote_exit_code = 130
        except Exception as exc:
            fail(f"Unexpected error: {exc}")
            remote_exit_code = 1
        finally:
            keep = args.keep_on_failure and remote_exit_code != 0
            if instance_id and not keep:
                terminate_instance(args.region, sid, skey, tok, instance_id)
            elif instance_id and keep:
                warn(f"--keep-on-failure set: instance NOT destroyed. "
                     f"InstanceId={instance_id} region={args.region} — "
                     f"remember to terminate it manually.")
            if key_id and not keep:
                delete_keypair(args.region, sid, skey, tok, key_id)
            if not keep:
                clear_last_instance()

    return remote_exit_code


if __name__ == "__main__":
    sys.exit(main())
