from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import UTC
from typing import Any, cast

import cis_image

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


def _image_ids_still_exist(region: str, image_ids: list[str]) -> bool:
    """Best-effort: True when *any* of *image_ids* still exists in *region*.

    Fails open (returns True) on missing credentials/API errors so change
    detection never *blocks* a rebuild due to a transient API problem.
    """
    if not image_ids:
        return False
    try:
        return bool(cis_image._images_exist(region, image_ids[:5]))
    except Exception:
        return True  # fail open — let the rebuild proceed

def _tc3_api(service: str, action: str, version: str, region: str,
             params: dict[str, Any], secret_id: str, secret_key: str,
             token: str | None = None) -> dict[str, Any]:
    """Call a Tencent Cloud API v3 endpoint with TC3-HMAC-SHA256 signing."""
    import hashlib
    import hmac
    import time
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
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return cast("dict[str, Any]", json.loads(resp.read().decode("utf-8")))
    except urllib.error.URLError as exc:
        raise ConfigError(f"Tencent Cloud API {action} ({service}) request failed: {exc.reason}") from exc
    except OSError as exc:  # socket.timeout / connection reset / DNS
        raise ConfigError(f"Tencent Cloud API {action} ({service}) network error: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Tencent Cloud API {action} ({service}) returned invalid JSON") from exc

def _my_public_ip() -> str | None:
    """Best-effort discovery of the outbound public IP `cis-image` runs from.

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
                if "-" in part:
                    lo, hi = part.split("-", 1)
                    if int(lo) <= port <= int(hi):
                        ports_ok = True
                        break
                elif part and int(part) == port:
                    ports_ok = True
                    break
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
    my_ip = cis_image._my_public_ip()
    if not my_ip:
        return
    try:
        resp = cis_image._tc3_api("vpc", "DescribeSecurityGroupPolicies", "2017-03-12",
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

def _images_exist(region: str, image_ids: list[str]) -> list[str]:
    """Return which of *image_ids* still exist in *region* (via DescribeImages)."""
    if not image_ids:
        return []
    sid, skey, tok = _creds("TENCENTCLOUD_SECRET_ID",
                         "TENCENTCLOUD_SECRET_KEY",
                         "TENCENTCLOUD_SECURITY_TOKEN")
    if not sid or not skey:
        raise ConfigError("TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY not set — "
                          "cannot query images for cleanup")
    try:
        resp = cis_image._tc3_api("cvm", "DescribeImages", "2017-03-12", region,
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
        resp = cis_image._tc3_api("cvm", "DeleteImages", "2017-03-12", region,
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
        resp = cis_image._tc3_api("cvm", "DescribeImageSharePermission", "2017-03-12",
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
        resp = cis_image._tc3_api("cvm", "DescribeImages", "2017-03-12", r.region,
                        {"ImageIds": [r.source_image_id]}, sid, skey, tok or None)
    except Exception:
        return ""
    imgs = resp.get("Response", {}).get("ImageSet") or []
    if not imgs:
        return ""
    # Public images report CreatedTime as null — treat as unavailable.
    return str(imgs[0].get("CreatedTime") or "")

def _probe_launch(r: ResolvedConfig, image_id: str, instance_name: str) -> str:
    """Launch a probe instance from *image_id*; return instance-id."""
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        raise ConfigError(
            f"{r.secret_id_env} / {r.secret_key_env} not set — "
            "cannot launch verification instance")
    # TencentCloud RunInstances — the built image may be a custom image of
    # any family; we launch with the SAME placement as the build itself.
    resp = cis_image._tc3_api(
        "cvm", "RunInstances", "2017-03-12", r.region,
        {"ImageId": image_id,
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
                               "Tags": [{"Key": "purpose", "Value": "cis-image-verify"},
                                        {"Key": "ephemeral", "Value": "true"}]}]},
        sid, skey, tok or None)
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
    deadline = _time.time() + 900
    while _time.time() < deadline:
        try:
            resp = cis_image._tc3_api("cvm", "DescribeInstances", "2017-03-12", r.region,
                            {"InstanceIds": [instance_id]}, sid, skey, tok or None)
            insts = resp.get("Response", {}).get("InstanceSet") or []
            if not insts:
                _time.sleep(10)
                continue
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
        except Exception:
            pass
        _time.sleep(10)
    return ""

def _probe_terminate(r: ResolvedConfig, instance_id: str) -> None:
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    try:
        cis_image._tc3_api("cvm", "TerminateInstances", "2017-03-12", r.region,
                 {"InstanceIds": [instance_id]}, sid, skey, tok or None)
        ok(f"Verification instance terminated: {instance_id}")
    except Exception as exc:
        warn(f"Could not terminate verification instance {instance_id}: {exc}")

def _probe_ssh_ready(ip: str, ssh_port: int, ssh_user: str,
                     timeout_s: int = 600) -> bool:
    """Wait for SSH on the probe instance (best-effort BatchMode probe)."""
    import time as _time
    deadline = _time.time() + timeout_s
    while _time.time() < deadline:
        try:
            cp = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
                 "-p", str(ssh_port), f"{ssh_user}@{ip}",
                 "true"],
                capture_output=True, text=True, timeout=20)
            if cp.returncode == 0:
                return True
        except Exception:
            pass
        _time.sleep(10)
    return False

def _probe_scan(r: ResolvedConfig, ip: str, ssh_port: int, ssh_user: str,
                level: int) -> dict[str, Any]:
    """Run the bundled engine in scan mode on the probe instance over SSH.

    The produced image ships the engine + catalog under
    /opt/cis-image-ansible/roles/<role>/files (cleanup.sh keeps them), so a
    fresh-boot scan needs no uploads.  Returns the parsed engine result doc.
    """
    profile = f"L{level}"
    remote = (
        "ENG=$(ls -d /opt/cis-image-ansible/roles/cis_*/files 2>/dev/null | head -1); "
        "if [ -n \"$ENG\" ] && [ -f \"$ENG/cis_engine.py\" ]; then "
        "sudo /opt/cis-image-ansible/bin/python \"$ENG/cis_engine.py\" "
        f"--catalog \"$ENG/rules.json\" --mode scan --profile {profile} "
        "--out /tmp/cis-image-verify.json >/dev/null 2>&1 && "
        "cat /tmp/cis-image-verify.json; fi"
    )
    try:
        cp = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
             "-p", str(ssh_port), f"{ssh_user}@{ip}", remote],
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

    1) a locally saved baseline in ~/.cis-image/baselines/<image>.json
    2) the audit result shipped inside the image (/opt/cis-image-AUDIT-RESULT.json)
    """
    local = cis_image._lineage_path().parent / "baselines" / f"{image_id}.json"
    if local.exists():
        try:
            return cast("dict[str, Any]", json.loads(local.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            warn(f"Baseline file {local} is corrupt — ignoring")
    return None  # caller fetches the in-image one over SSH

def _share_images(r: ResolvedConfig, image_ids: list[str], accounts: list[str]) -> None:
    """Share built images with other Tencent Cloud accounts (P2#9).

    Uses cvm:ModifyImageSharePermission with the configured AccountIds
    (uin/… strings).  Credentials come from the SAME env names as the
    build itself ([cloud].secret_id_env / secret_key_env / security_token_env)
    so custom env-name configs work consistently with verify-image.
    """
    if not image_ids or not accounts:
        return
    sid, skey, tok = _creds(r.secret_id_env, r.secret_key_env, r.security_token_env)
    if not sid or not skey:
        warn(f"{r.secret_id_env} / {r.secret_key_env} not set — "
             "cannot share images")
        return
    try:
        resp = cis_image._tc3_api("cvm", "ModifyImageSharePermission", "2017-03-12",
                        r.region,
                        {"ImageIds": image_ids, "AccountIds": accounts},
                        sid, skey, tok or None)
        if "Error" in resp.get("Response", {}):
            raise ConfigError(
                f"ModifyImageSharePermission failed: "
                f"{resp['Response']['Error']}")
        ok(f"Shared {len(image_ids)} image(s) with {len(accounts)} account(s) "
           f"({', '.join(accounts)})")
    except ConfigError as exc:
        warn(str(exc))
    except Exception as exc:
        warn(f"ModifyImageSharePermission failed: {exc}")
