from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import UTC
from typing import Any, cast

import ohbs_image

from ._config import ResolvedConfig
from ._logging import ConfigError, ok, warn


def _creds(sid_env: str, skey_env: str, tok_env: str) -> tuple[str, str, str | None]:
    """Read Tencent Cloud credentials from the environment by env-var name.

    Returns (secret_id, secret_key, token).  The token is None when the
    optional token env-var is unset.  No validation here — callers decide
    whether missing credentials are fatal or fail-open.
    """
    tok = os.environ.get(tok_env, "") or None
    return os.environ.get(sid_env, ""), os.environ.get(skey_env, ""), tok


def _image_ids_still_exist(region: str, image_ids: list[str],
                           r: ResolvedConfig | None = None) -> bool:
    """Best-effort: True when *any* of *image_ids* still exists in *region*.

    Fails CLOSED (returns False) on missing credentials/API errors: change
    detection must never *skip* a rebuild because of a transient API
    problem — skipping could leave users on a silently stale image.  When
    *r* is given, its custom credential env-var names are honoured.
    """
    if not image_ids:
        return False
    try:
        return bool(ohbs_image._images_exist(region, image_ids[:5], r=r))
    except Exception:
        return False  # fail closed — rebuild on any lookup error

def _tc3_api(service: str, action: str, version: str, region: str,
             params: dict[str, Any], secret_id: str, secret_key: str,
             token: str | None = None, max_retries: int = 3) -> dict[str, Any]:
    """Call a Tencent Cloud API v3 endpoint with TC3-HMAC-SHA256 signing.

    Retries transient failures — connection resets, timeouts, and 429/5xx
    gateway responses — up to *max_retries* attempts with exponential
    backoff (1s, 2s, ...). Client errors (4xx other than 429) and non-network
    failures (e.g. a malformed JSON response body) are never retried, since
    retrying would not change the outcome.  Every terminal failure is raised
    as a ConfigError with a clear, actionable message so callers degrade
    gracefully instead of crashing on a raw urllib/OSError.
    """
    import hashlib
    import hmac
    import time
    import urllib.error
    from datetime import datetime

    host = f"{service}.tencentcloudapi.com"
    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d")
    payload = json.dumps(params, separators=(",", ":"))
    ct = "application/json; charset=utf-8"
    canonical_headers = (f"content-type:{ct}\n"
                         f"host:{host}\n"
                         f"x-tc-action:{action.lower()}\n")
    signed_headers = "content-type;host;x-tc-action"

    def _h(s: str) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    canonical_request = "\n".join(["POST", "/", "", canonical_headers,
                                   signed_headers, _h(payload)])
    credential_scope = f"{date}/{service}/tc3_request"
    string_to_sign = "\n".join(["TC3-HMAC-SHA256", str(timestamp),
                                credential_scope, _h(canonical_request)])
    secret_date = hmac.new(("TC3" + secret_key).encode(), date.encode(),
                           hashlib.sha256).digest()
    secret_service = hmac.new(secret_date, service.encode(), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, b"tc3_request", hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode(),
                         hashlib.sha256).hexdigest()
    authorization = (f"TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {
        "Authorization": authorization,
        "Content-Type": ct,
        "Host": host,
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Region": region,
        "X-TC-Timestamp": str(timestamp),
    }
    if token:
        headers["X-TC-Token"] = token
    req = urllib.request.Request(f"https://{host}", data=payload.encode("utf-8"),
                                 headers=headers, method="POST")
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return cast("dict[str, Any]", json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as exc:
            # Only retry rate-limit/gateway errors; a real 4xx (bad request,
            # auth failure, ...) won't be fixed by trying again.
            if exc.code not in (429, 500, 502, 503, 504) or attempt == max_retries - 1:
                raise ConfigError(
                    f"Tencent Cloud API {action} ({service}) request failed: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            # Network-layer failure (DNS, reset, timeout) — worth a retry.
            if attempt == max_retries - 1:
                raise ConfigError(
                    f"Tencent Cloud API {action} ({service}) request failed: {exc.reason}") from exc
        except (TimeoutError, ConnectionError, OSError) as exc:  # socket.timeout / conn reset
            if attempt == max_retries - 1:
                raise ConfigError(
                    f"Tencent Cloud API {action} ({service}) network error: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"Tencent Cloud API {action} ({service}) returned invalid JSON") from exc
        time.sleep(2 ** attempt)
    # The loop always returns or raises above; this guards against a
    # non-exhaustive-path static-analysis warning.
    raise AssertionError("unreachable")

def _my_public_ip() -> str | None:
    """Best-effort discovery of the outbound public IP `ohbs-image` runs from.

    Returns None on any failure (offline, blocked egress, DNS) — the caller
    must treat that as "can't verify" rather than "blocked".
    """
    for url in ("https://ifconfig.me/ip", "https://api.ipify.org"):
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
                ip = str(resp.read().decode("utf-8")).strip()
            import ipaddress
            ipaddress.ip_address(ip)  # validates it's a real IP, nothing else
            return ip
        except Exception:
            continue
    return None

def _sg_ingress_allows(policies: dict[str, Any], ip: str, port: int) -> bool | None:
    """Check whether *ip*:*port*/TCP is allowed by a DescribeSecurityGroupPolicies
    response's Ingress rules.

    Returns True/False when the rules give a definite answer, or None when a
    rule can't be evaluated locally (references a security-group / address
    template / service template instead of a plain CidrBlock+Port — those
    require additional API calls to resolve, so we don't guess).
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    saw_unresolvable = False
    for rule in policies.get("Ingress", []):
        cidr = rule.get("CidrBlock") or rule.get("Ipv6CidrBlock")
        proto = str(rule.get("Protocol", "")).upper()
        rule_port = rule.get("Port")
        action = str(rule.get("Action", "")).upper()
        if not cidr or proto not in ("TCP", "ALL"):
            if rule.get("SecurityGroupId") or rule.get("AddressTemplate") or rule.get("ServiceTemplate"):
                saw_unresolvable = True
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr not in net:
            continue
        if proto == "TCP" and rule_port:
            ports_ok = False
            for part in str(rule_port).split(","):
                part = part.strip()
                if not part:
                    continue
                # "ALL" (whole value or a list item) matches any port.
                if part.upper() == "ALL":
                    ports_ok = True
                    break
                try:
                    if "-" in part:
                        lo, hi = part.split("-", 1)
                        if int(lo) <= port <= int(hi):
                            ports_ok = True
                            break
                    elif int(part) == port:
                        ports_ok = True
                        break
                except ValueError:
                    # Unparseable port token (e.g. a service-template name) —
                    # skip it; the rule is treated as non-matching below.
                    continue
            if not ports_ok:
                continue
        return action == "ACCEPT"
    return None if saw_unresolvable else False

def _check_security_group_ingress(r: ResolvedConfig) -> None:
    """Warn (never fail) preflight if the SG looks like it will block the
    build port from this machine's public IP.  Best-effort only: any
    ambiguity (unresolvable rule, no credentials, API error, no outbound
    internet) is treated as "can't verify" and silently skipped — this must
    never produce a false failure that blocks a valid build.
    """
    if not r.security_group_id:
        return
    port = 3389 if r.family == "windows" else (r.ssh_port or 22)
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        return
    my_ip = ohbs_image._my_public_ip()
    if not my_ip:
        return
    try:
        resp = ohbs_image._tc3_api("vpc", "DescribeSecurityGroupPolicies", "2017-03-12",
                        r.region, {"SecurityGroupId": r.security_group_id},
                        sid, skey, tok or None)
    except Exception:
        return
    policies = resp.get("Response", {}).get("SecurityGroupPolicySet")
    if not policies or "Error" in resp.get("Response", {}):
        return
    allowed = _sg_ingress_allows(policies, my_ip, port)
    if allowed is False:
        proto_label = "WinRM/3389" if r.family == "windows" else f"SSH/{port}"
        warn(f"Security group {r.security_group_id} does not appear to allow "
             f"{proto_label} from this machine's public IP ({my_ip}) — Packer "
             f"will likely time out connecting to the build instance. Add an "
             f"inbound rule for {my_ip}/32 : TCP {port} before running 'build'.")

def _images_exist(region: str, image_ids: list[str],
                  r: ResolvedConfig | None = None) -> list[str]:
    """Return which of *image_ids* still exist in *region* (via DescribeImages).

    Credentials come from the resolved config's custom env-var names when
    *r* is given, otherwise from the default TENCENTCLOUD_* variables.
    """
    if not image_ids:
        return []
    sid_env = r.secret_id_env if r else "TENCENTCLOUD_SECRET_ID"
    skey_env = r.secret_key_env if r else "TENCENTCLOUD_SECRET_KEY"
    tok_env = r.security_token_env if r else "TENCENTCLOUD_SECURITY_TOKEN"
    sid, skey, tok = _creds(sid_env, skey_env, tok_env)
    if not sid or not skey:
        raise ConfigError(f"{sid_env} / {skey_env} not set — "
                          "cannot query images for cleanup")
    try:
        resp = ohbs_image._tc3_api("cvm", "DescribeImages", "2017-03-12", region,
                        {"ImageIds": image_ids}, sid, skey, tok or None)
    except Exception as exc:
        raise ConfigError(f"DescribeImages failed: {exc}") from exc
    existing = [i["ImageId"] for i in resp.get("Response", {}).get("ImageSet", [])]
    return existing

def _delete_images(region: str, image_ids: list[str]) -> None:
    sid, skey, tok = _creds("TENCENTCLOUD_SECRET_ID",
                         "TENCENTCLOUD_SECRET_KEY",
                         "TENCENTCLOUD_SECURITY_TOKEN")
    try:
        resp = ohbs_image._tc3_api("cvm", "DeleteImages", "2017-03-12", region,
                        {"ImageIds": image_ids}, sid, skey, tok or None)
    except Exception as exc:
        raise ConfigError(f"DeleteImages failed: {exc}") from exc
    if "Error" in resp.get("Response", {}):
        raise ConfigError(f"DeleteImages failed: {resp['Response']['Error']}")

def _image_is_shared(region: str, image_id: str) -> bool:
    """Return True when *image_id* is shared with other accounts (#16).

    Uses cvm:DescribeImageSharePermission.  Fails OPEN (returns True, i.e.
    "keep the image") when credentials/API are unavailable so cleanup
    never deletes an image it cannot prove is unused.
    """
    sid, skey, tok = _creds("TENCENTCLOUD_SECRET_ID",
                         "TENCENTCLOUD_SECRET_KEY",
                         "TENCENTCLOUD_SECURITY_TOKEN")
    if not sid or not skey:
        return True  # can't prove it's unused → keep
    try:
        resp = ohbs_image._tc3_api("cvm", "DescribeImageSharePermission", "2017-03-12",
                        region, {"ImageId": image_id}, sid, skey, tok or None)
    except Exception as exc:
        warn(f"DescribeImageSharePermission failed for {image_id}: {exc} "
             f"— keeping image")
        return True
    r = resp.get("Response", {})
    if "Error" in r:
        return True  # API error → keep
    shares = (r.get("SharePermissionSet") or []) + (r.get("AccountSet") or [])
    return bool(shares)

def _source_image_created(r: ResolvedConfig) -> str:
    """Query the source image's CreatedTime ("" when unavailable)."""
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        return ""
    try:
        resp = ohbs_image._tc3_api("cvm", "DescribeImages", "2017-03-12", r.region,
                        {"ImageIds": [r.source_image_id]}, sid, skey, tok or None)
    except Exception:
        return ""
    imgs = resp.get("Response", {}).get("ImageSet") or []
    if not imgs:
        return ""
    # Public images report CreatedTime as null — treat as unavailable.
    return str(imgs[0].get("CreatedTime") or "")

def _probe_setup_keypair(r: ResolvedConfig) -> tuple[str, str, str]:
    """Create a throwaway SSH key pair for the probe instance.

    Generates an ed25519 key locally via ssh-keygen (paramiko/cryptography
    are deliberately not runtime deps) and imports the public half with
    cvm:ImportKeyPair — the same pattern as scripts/real_e2e_test.py.
    Returns (key_id, private_key_path, public_key_text).  The caller MUST
    call _probe_teardown_keypair() once the probe is done — otherwise both
    the cloud KeyPair and the local temp dir leak.
    """
    import secrets
    import tempfile
    import time as _time
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        raise ConfigError(
            f"{r.secret_id_env} / {r.secret_key_env} not set — "
            "cannot import the probe key pair")
    tmpdir = tempfile.mkdtemp(prefix="ohbs-image-probe-")
    priv = os.path.join(tmpdir, "probe_key")
    try:
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", priv],
                       check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ConfigError(f"ssh-keygen failed — cannot create probe key pair: {exc}") from exc
    os.chmod(priv, 0o600)
    with open(priv + ".pub", encoding="utf-8") as fh:
        pub = fh.read().strip()
    # TencentCloud ImportKeyPair KeyName rules (enforced, tightened 2026-08):
    # max 25 chars AND no hyphen — "ohbs-image-probe-<ts>-<hex>" failed on
    # both ("too long" then "include illegal character `-`").  Use letters +
    # digits only: "ohbsp<ts><hex>" = 5+10+4 = 19 chars.
    key_name = f"ohbsp{int(_time.time())}{secrets.token_hex(2)}"
    resp = ohbs_image._tc3_api("cvm", "ImportKeyPair", "2017-03-12", r.region,
                    {"KeyName": key_name, "ProjectId": 0, "PublicKey": pub},
                    sid, skey, tok or None)
    resp_r = resp.get("Response", {})
    if "Error" in resp_r:
        raise ConfigError(f"ImportKeyPair failed: {resp_r['Error']}")
    key_id = resp_r.get("KeyId")
    if not key_id:
        raise ConfigError("ImportKeyPair returned no KeyId")
    return str(key_id), priv, pub

def _probe_teardown_keypair(r: ResolvedConfig, key_id: str, priv_path: str) -> None:
    """Best-effort cleanup of the probe key pair (cloud KeyPair + local files)."""
    import shutil
    if key_id:
        sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
        if sid and skey:
            try:
                ohbs_image._tc3_api("cvm", "DeleteKeyPairs", "2017-03-12", r.region,
                         {"KeyIds": [key_id]}, sid, skey, tok or None)
            except Exception as exc:
                warn(f"Could not delete probe key pair {key_id}: {exc}")
    if priv_path:
        shutil.rmtree(os.path.dirname(priv_path), ignore_errors=True)

def _probe_launch(r: ResolvedConfig, image_id: str, instance_name: str,
                  key_ids: list[str] | None = None, pub_key: str = "") -> str:
    """Launch a probe instance from *image_id*; return instance-id.

    *key_ids* (from _probe_setup_keypair) is wired into LoginSettings —
    without it the instance gets NO credentials and the key-only
    (BatchMode=yes) SSH probe can never connect.  *pub_key* additionally
    seeds the key for the image's 'ohbsimage' build user via UserData:
    CIS hardening sets PermitRootLogin no, so the default LoginSettings
    injection (root) is not a usable login channel on a hardened image.
    """
    import base64
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        raise ConfigError(
            f"{r.secret_id_env} / {r.secret_key_env} not set — "
            "cannot launch verification instance")
    # TencentCloud RunInstances — the built image may be a custom image of
    # any family; we launch with the SAME placement as the build itself.
    params: dict[str, Any] = {
        "ImageId": image_id,
        "InstanceType": r.instance_type,
        "InstanceChargeType": "POSTPAID_BY_HOUR",
        "InstanceName": instance_name,
        "Placement": {"Zone": r.zone},
        "VirtualPrivateCloud": {"VpcId": r.vpc_id,
                                "SubnetId": r.subnet_id},
        "SecurityGroupIds": [r.security_group_id],
        "InternetAccessible": {"PublicIpAssigned": r.associate_public_ip,
                               "InternetChargeType": "TRAFFIC_POSTPAID_BY_HOUR",
                               "InternetMaxBandwidthOut": 1},
        "InstanceCount": 1,
        "TagSpecification": [{"ResourceType": "instance",
                              "Tags": [{"Key": "purpose", "Value": "ohbs-image-verify"},
                                       {"Key": "ephemeral", "Value": "true"}]}]}
    if key_ids:
        params["LoginSettings"] = {"KeyIds": key_ids}
    if pub_key:
        # Root SSH is disabled by CIS hardening (PermitRootLogin no); the
        # 'ohbsimage' build user (sudo, same authorized_keys — see the
        # install-ansible provisioner) is the viable login, so install the
        # probe key for it via cloud-init user-data.  Log every step to
        # /var/log/ohbs-probe-key.log so a failed clean-boot probe can be
        # diagnosed from the instance console.  (The image finalize now runs
        # `cloud-init clean` before snapshot so user-data scripts reliably
        # re-run on the probe's first boot.)
        ud = ("#!/bin/bash\n"
              "exec >> /var/log/ohbs-probe-key.log 2>&1\n"
              "echo \"[ohbs-probe-key] $(date -Is) start\"\n"
              "h=$(getent passwd ohbsimage | cut -d: -f6)\n"
              "echo \"[ohbs-probe-key] ohbsimage home=${h:-MISSING}\"\n"
              "if [ -z \"$h\" ] || [ ! -d \"$h\" ]; then\n"
              "  echo '[ohbs-probe-key] WARN: ohbsimage has no home dir - cannot inject key'\n"
              "  exit 0\n"
              "fi\n"
              "install -d -m 700 -o ohbsimage -g ohbsimage \"$h/.ssh\"\n"
              "umask 077\n"
              f"if ! grep -qF '{pub_key}' \"$h/.ssh/authorized_keys\" 2>/dev/null; then\n"
              f"  echo '{pub_key}' >> \"$h/.ssh/authorized_keys\"\n"
              "fi\n"
              "chown -R ohbsimage:ohbsimage \"$h/.ssh\"\n"
              "chmod 700 \"$h/.ssh\" && chmod 600 \"$h/.ssh/authorized_keys\"\n"
              "command -v restorecon >/dev/null 2>&1 && restorecon -R \"$h/.ssh\" 2>/dev/null || true\n"
              "echo '[ohbs-probe-key] done'\n")
        params["UserData"] = base64.b64encode(ud.encode("utf-8")).decode("ascii")
    resp = ohbs_image._tc3_api("cvm", "RunInstances", "2017-03-12", r.region,
                    params, sid, skey, tok or None)
    resp_r = resp.get("Response", {})
    if "Error" in resp_r:
        raise ConfigError(f"RunInstances failed: {resp_r['Error']}")
    ids = resp_r.get("InstanceIdSet") or []
    if not ids:
        raise ConfigError("RunInstances returned no InstanceId")
    return cast(str, ids[0])

def _probe_public_ip(r: ResolvedConfig, instance_id: str) -> str:
    """Poll DescribeInstancesStatus/DescribeInstances for a public IP.

    Returns the public IP once the instance is RUNNING and reachable, or
    "" when the timeout (default ~15 min) expires.
    """
    import time as _time
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        raise ConfigError(
            f"{r.secret_id_env} / {r.secret_key_env} not set — "
            "cannot query the verification instance")
    deadline = _time.time() + 900
    while _time.time() < deadline:
        try:
            resp = ohbs_image._tc3_api("cvm", "DescribeInstances", "2017-03-12", r.region,
                            {"InstanceIds": [instance_id]}, sid, skey, tok or None)
        except ConfigError:
            raise  # credential/API errors are fatal — do not poll for 15 min
        except Exception:
            pass  # transient network/parse issues — keep polling
        else:
            insts = resp.get("Response", {}).get("InstanceSet") or []
            if insts:
                inst = insts[0]
                # InstanceState is a plain string ("RUNNING"); tolerate a dict too.
                st = inst.get("InstanceState") or ""
                state = st.get("State", "") if isinstance(st, dict) else str(st)
                if state == "RUNNING":
                    pub = ""
                    for nic in inst.get("NetworkInterfaceSet") or []:
                        # PublicIpAddresses may be absent OR an empty list.
                        addrs = nic.get("PublicIpAddresses") or []
                        pub = addrs[0] if addrs else pub
                    if not pub:
                        addrs = inst.get("PublicIpAddresses") or []
                        pub = addrs[0] if addrs else ""
                    if pub:
                        return pub
        _time.sleep(10)
    return ""

def _probe_terminate(r: ResolvedConfig, instance_id: str) -> None:
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    try:
        ohbs_image._tc3_api("cvm", "TerminateInstances", "2017-03-12", r.region,
                 {"InstanceIds": [instance_id]}, sid, skey, tok or None)
        ok(f"Verification instance terminated: {instance_id}")
    except Exception as exc:
        warn(f"Could not terminate verification instance {instance_id}: {exc}")

def _probe_ssh_ready(ip: str, ssh_port: int, ssh_user: str,
                     key_path: str | None = None, timeout_s: int = 600) -> bool:
    """Wait for SSH on the probe instance (best-effort BatchMode probe)."""
    import time as _time
    deadline = _time.time() + timeout_s
    key_args = ["-i", key_path] if key_path else []
    while _time.time() < deadline:
        try:
            cp = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
                 *key_args, "-p", str(ssh_port), f"{ssh_user}@{ip}",
                 "true"],
                capture_output=True, text=True, timeout=20)
            if cp.returncode == 0:
                return True
        except Exception:
            pass
        _time.sleep(10)
    return False

def _probe_ssh_ready_any(ip: str, ssh_port: int,
                         candidates: list[tuple[str, str | None]],
                         timeout_s: int = 600) -> tuple[bool, str]:
    """Wait for SSH across a list of (ssh_user, key_path) candidates.

    Returns (ok, winner_or_last_user).  Tries every candidate in each pass so
    a probe can fall back (e.g. ohbsimage via the user-data key, then root via
    the platform LoginSettings key) without burning the whole budget on one
    dead user.  Keep it best-effort like _probe_ssh_ready: any transient
    failure just means another pass.
    """
    import time as _time
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        for user, key_path in candidates:
            key_args = ["-i", key_path] if key_path else []
            try:
                cp = subprocess.run(
                    ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
                     *key_args, "-p", str(ssh_port), f"{user}@{ip}",
                     "true"],
                    capture_output=True, text=True, timeout=15)
                if cp.returncode == 0:
                    return True, user
            except Exception:
                pass
        # Sleep adaptively so a short timeout_s (unit tests) doesn't stall.
        _time.sleep(min(8.0, max(0.1, deadline - _time.time())))
    return False, candidates[-1][0]

def _probe_vnc_url(r: ResolvedConfig, instance_id: str) -> str:
    """Best-effort VNC console URL for a probe instance (diagnostics only)."""
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        return ""
    try:
        resp = ohbs_image._tc3_api("cvm", "DescribeInstanceVncUrl", "2017-03-12",
                        r.region, {"InstanceId": instance_id}, sid, skey, tok or None)
        return str((resp.get("Response") or {}).get("InstanceVncUrl") or "")
    except Exception:
        return ""

def _probe_scan(r: ResolvedConfig, ip: str, ssh_port: int, ssh_user: str,
                level: int, key_path: str | None = None) -> dict[str, Any]:
    """Run the bundled engine in scan mode on the probe instance over SSH.

    The produced image ships the engine + catalog under
    /opt/ohbs-image-ansible/roles/<role>/files (cleanup.sh keeps them), so a
    fresh-boot scan needs no uploads.  Returns the parsed engine result doc.
    """
    profile = f"L{level}"
    # Prefer the benchmark-specific catalog when it exists in the image
    # (non-CIS benchmarks ship rules_<slug>.json); fall back to rules.json
    # (CIS / legacy).  The build promotes the active catalog to rules.json too,
    # so rules.json is always safe, but this makes the probe explicit.
    cat = r.catalog_basename or "rules.json"
    # Role dirs are dash-named (cis-ubuntu2204, cis-rhel8, ...).  Use the
    # configured role dir explicitly — globbing cis-*/ could pick a stale
    # role staged by an earlier build sharing the workdir.
    remote = (
        f"ENG=/opt/ohbs-image-ansible/roles/{r.role_dir}/files; "
        "[ -d \"$ENG\" ] || "
        "ENG=$(ls -d /opt/ohbs-image-ansible/roles/cis-*/files 2>/dev/null | head -1); "
        "if [ -n \"$ENG\" ] && [ -f \"$ENG/ohbs_engine.py\" ]; then "
        "CAT=\"$ENG/rules.json\"; "
        f"[ -f \"$ENG/{cat}\" ] && CAT=\"$ENG/{cat}\"; "
        "sudo /opt/ohbs-image-ansible/bin/python \"$ENG/ohbs_engine.py\" "
        f"--catalog \"$CAT\" --mode scan --profile {profile} 2>/dev/null; "
        "fi"
    )
    key_args = ["-i", key_path] if key_path else []
    try:
        cp = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
             *key_args, "-p", str(ssh_port), f"{ssh_user}@{ip}", remote],
            capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return {"error": f"remote scan timed out after 900s on {ip}"}
    except FileNotFoundError:
        return {"error": "ssh not found in PATH — cannot scan remote host"}
    try:
        return cast("dict[str, Any]", json.loads(cp.stdout))
    except json.JSONDecodeError:
        return {"error": cp.stdout[:300] or cp.stderr[:300]}

def _fetch_baseline(r: ResolvedConfig, image_id: str) -> dict[str, Any] | None:
    """Locate the baseline audit result for *image_id*.

    1) a locally saved baseline in ~/.ohbs-image/baselines/<image>.json
    2) the audit result shipped inside the image (/opt/ohbs-image-AUDIT-RESULT.json)
    """
    local = ohbs_image._lineage_path().parent / "baselines" / f"{image_id}.json"
    if local.exists():
        try:
            return cast("dict[str, Any]", json.loads(local.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            warn(f"Baseline file {local} is corrupt — ignoring")
    return None  # caller fetches the in-image one over SSH

def _share_images(r: ResolvedConfig, image_ids: list[str], accounts: list[str]) -> None:
    """Share built images with other Tencent Cloud accounts (P2#9).

    Uses cvm:ModifyImageSharePermission with the configured AccountIds
    (uin/… strings).  The API takes ONE ImageId per call and requires an
    explicit Permission ("SHARE"/"CANCEL") — there is no batch ImageIds
    parameter — so we loop over the images and warn (never fail the build)
    per image.  Credentials come from the SAME env names as the build
    itself ([cloud].secret_id_env / secret_key_env / security_token_env)
    so custom env-name configs work consistently with verify-image.
    """
    if not image_ids or not accounts:
        return
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        warn(f"{r.secret_id_env} / {r.secret_key_env} not set — "
             "cannot share images")
        return
    shared = 0
    for image_id in image_ids:
        try:
            resp = ohbs_image._tc3_api("cvm", "ModifyImageSharePermission", "2017-03-12",
                            r.region,
                            {"ImageId": image_id, "AccountIds": accounts,
                             "Permission": "SHARE"},
                            sid, skey, tok or None)
            if "Error" in resp.get("Response", {}):
                raise ConfigError(
                    f"ModifyImageSharePermission failed: "
                    f"{resp['Response']['Error']}")
            shared += 1
        except ConfigError as exc:
            warn(str(exc))
        except Exception as exc:
            warn(f"ModifyImageSharePermission failed for {image_id}: {exc}")
    if shared:
        ok(f"Shared {shared}/{len(image_ids)} image(s) with {len(accounts)} account(s) "
           f"({', '.join(accounts)})")
