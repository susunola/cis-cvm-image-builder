#!/usr/bin/env python3
"""
ciscvm — CIS-hardened Golden Image Builder (Packer × Tencent Cloud CVM)

Spins up an ephemeral CVM, applies the bundled cis-os engine role for CIS
hardening, and captures the result as a custom image.  All configuration is
driven by ciscvm.toml — no manual template editing.

Supported OS: Ubuntu 20/22/24, RHEL 8/9/10, TencentOS 3/4,
              Windows Server 2016/2019/2022/2025

Engine:  Bundled cis_engine.py (Linux) / cis_engine.ps1 (Windows).
         In-role gate via cis_min_score (post-reboot audit must score >= 85).
         Roles ship inside the package (ciscvm/roles/) — no network at build time.

Dependencies: Python >= 3.11 (stdlib only), Packer >= 1.12, ansible-core >= 2.15.

Usage:
    ciscvm init [--target DIR]      # Generate ciscvm.toml
    ciscvm preflight [--config F]   # Pre-flight check
    ciscvm validate  [--config F]   # Render + packer init + packer validate
    ciscvm build     [--config F]   # Render + packer build (produce image)
    ciscvm clean     [--config F]   # Remove rendered working directory
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import tomllib
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any, cast

VERSION = "0.16.22"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("ciscvm")


def _setup_logging(*, verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    if logger.handlers:
        logger.setLevel(level)
        for h in logger.handlers:
            h.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)


def _color(text: str, code: int) -> str:
    if os.environ.get("NO_COLOR") or not sys.stderr.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(msg: str) -> None:
    logger.info("  %s %s", _color("\u2713", 32), msg)


def warn(msg: str) -> None:
    logger.warning("  %s %s", _color("!", 33), msg)


def fail(msg: str) -> None:
    logger.error("  %s %s", _color("\u2717", 31), msg)


def info(msg: str) -> None:
    logger.info("  %s %s", _color("\u2022", 36), msg)


def banner(title: str) -> None:
    logger.info(_color(f"\n== {title} ==", 1))


# ---------------------------------------------------------------------------
# Configuration profiles
# ---------------------------------------------------------------------------
# All roles use the bundled cis-os engine (cis_engine.py / cis_engine.ps1)
# with in-role gate (cis_fail_on_findings: true).  Roles are shipped locally
# in ciscvm/roles/ inside the package — no ansible-galaxy or network dependency.
#
# Profile keys common to Linux profiles:
#   role_dir      Bundled role directory name under roles/
#   ssh_username  Initial SSH user for Packer (ubuntu / root)
#   ssh_port              SSH port (default 22)
#   ssh_timeout           Packer SSH timeout (default "15m")
#   ssh_debug_password    (meta only) Set root password for VNC debug access
#   os_tag        CVM source image OS tag
#   benchmark     CIS benchmark version
#   pkg_update    Package index update command
#   pkg_install   Dependencies install command (must include python3-pip)
#   ansible_core_spec  pip constraint for ansible-core (default "ansible-core>=2.15")
#   pip_index_url PyPI mirror URL (empty = default PyPI; use Tencent Cloud internal mirror for VPC instances)
#   clean_cmd     Post-build package cache cleanup
#
# Windows profiles (family: "windows"):
#   role_dir       Bundled role directory name under roles/
#   winrm_username Default Administrator account
#   os_tag         CVM source image OS tag
#   benchmark      CIS benchmark version
# ── Profile factory functions (deduplicate ~100 lines of boilerplate) ──
def _ubuntu_profile(role_dir: str, os_tag: str, **kw: Any) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "ubuntu", "os_tag": os_tag,
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo apt-get -o DPkg::Lock::Timeout=600 update -y",
        "pkg_install": "sudo apt-get -o DPkg::Lock::Timeout=600 install -y python3-pip python3-venv",
        # authselect is RHEL-only; harmless under `--no-install-recommends
        # ... || true` but noisy — kept off the apt list.
        "cis_pkg_batch": "sudo apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends sudo libpam-modules firewalld chrony rsyslog cron aide systemd-journal-remote || true",
        "clean_cmd": "sudo apt-get clean", **kw,
    }

def _rhel_profile(role_dir: str, os_tag: str, **kw: Any) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "root", "os_tag": os_tag,
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip",
        "cis_pkg_batch": "sudo dnf install -y --skip-broken sudo pam authselect firewalld chrony rsyslog cronie aide systemd-journal-remote libselinux libselinux-utils || true",
        "clean_cmd": "sudo dnf clean all", **kw,
    }

def _tlinux_profile(role_dir: str, os_tag: str, **kw: Any) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "root", "ssh_port": 36000,
        "os_tag": os_tag, "benchmark": "CIS-v1.0.0",
        "pip_index_url": "https://mirrors.cloud.tencent.com/pypi/simple/",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip",
        "cis_pkg_batch": "sudo dnf install -y --skip-broken sudo pam authselect firewalld chrony rsyslog cronie aide systemd-journal-remote libselinux libselinux-utils || true",
        "clean_cmd": "sudo dnf clean all", **kw,
    }

PROFILES: dict[str, dict[str, Any]] = {
    "ubuntu2004":  _ubuntu_profile("cis_ubuntu2004", "ubuntu-20.04",
                                   # focal ships python3.8; ansible-core 2.15+
                                   # needs 3.9+ — pin to the 2.11 line (same
                                   # as rhel8/tos3, proven in production).
                                   ansible_core_spec="ansible-core>=2.11"),
    "ubuntu2204":  _ubuntu_profile("cis_ubuntu2204", "ubuntu-22.04"),
    "ubuntu2404":  _ubuntu_profile("cis_ubuntu2404", "ubuntu-24.04"),
    "rhel8":       _rhel_profile("cis_rhel8", "rhel-8", ansible_core_spec="ansible-core>=2.11"),
    "rhel9":       _rhel_profile("cis_rhel9", "rhel-9"),
    "rhel10":      _rhel_profile("cis_rhel10", "rhel-10"),
    "tencentos3":  _tlinux_profile("cis_tencentos3", "tencentos-3", ansible_core_spec="ansible-core>=2.11"),
    "tencentos4":  _tlinux_profile("cis_tencentos4", "tencentos-4"),
    # ── Windows Server (winrm + controller-side ansible) ──
    "win2016": {
        "family": "windows",
        "role_dir": "cis_win2016",
        "winrm_username": "Administrator",
        "os_tag": "windows-2016",
        "benchmark": "CIS-v4.0.0",
    },
    "win2019": {
        "family": "windows",
        "role_dir": "cis_win2019",
        "winrm_username": "Administrator",
        "os_tag": "windows-2019",
        "benchmark": "CIS-v5.0.0",
    },
    "win2022": {
        "family": "windows",
        "role_dir": "cis_win2022",
        "winrm_username": "Administrator",
        "os_tag": "windows-2022",
        "benchmark": "CIS-v5.1.0",
    },
    "win2025": {
        "family": "windows",
        "role_dir": "cis_win2025",
        "winrm_username": "Administrator",
        "os_tag": "windows-2025",
        "benchmark": "CIS-v2.1.0",
    },
}

DEFAULT_WORKDIR = ".ciscvm-build"

SAMPLE_CONFIG = """\
# ciscvm.toml — single source of truth for all build parameters
# Replace region/zone and image/network IDs with values for your account.
[build]
profile             = "tencentos3"
#   Linux profiles: ubuntu2004 | ubuntu2204 | ubuntu2404 |
#                   rhel8 | rhel9 | rhel10 |
#                   tencentos3 | tencentos4
#   Windows:        win2016 | win2019 | win2022 | win2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-3"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # replace with real public image ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = false               # set to true only if a public IP is required
# spot = true                             # use a spot instance for the build VM — up to ~90% cheaper, may be repossessed mid-build (default false)

[image]
name_prefix  = "tencentos3-cis"
# name = "my-cis-image"                  # optional: fixed image name (empty = auto prefix-level-timestamp)
copy_regions = []                         # add regions (e.g. ["ap-shanghai"]) to copy the image
# share_accounts = ["uin/1234567890"]    # optional: share the built image with other accounts
# share_org_units = ["uin/1234567890"]   # optional: org-level sharing (same ModifyImageSharePermission API as share_accounts)

[cis]
level = 1                                 # 1 or 2
# min_score = 85                          # post-reboot audit gate (0 disables; default 85)
# Rule selection (optional) — rule IDs to run / skip. Empty = all rules.
# rules_include = ["1.5.6", "5.4.3.2"]    # when set, ONLY these run
# rules_exclude = ["1.1.2.2.4"]           # always wins over rules_include
# Control-level overrides (optional) — tune individual rule parameters
# without editing the bundled catalog. Key = CIS rule ID, value = params to
# deep-merge into that rule (mirrors ansible-lockdown's per-control vars).
# [cis.overrides."5.2.2"]
# ssh_max_auth_tries = 4                  # example: tighten LoginGraceTime/MaxAuthTries

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Group-account (organization) cross-account builds: assume a CAM role in
# the target account using the local AK/SK.
# assume_role_arn      = "qcs::cam::uin/1234567890:roleName/CrossAccountBuilder"
# assume_role_session  = "ciscvm-build"   # optional, default "ciscvm"
# assume_role_duration = 3600             # optional, default 7200, range 0-43200
# OIDC / STS temporary credentials (GitHub Actions OIDC etc.):
# set security_token_env to the env var carrying the STS session token.
# Packer reads TENCENTCLOUD_SECURITY_TOKEN natively; leave this unset to
# rely on that default. Do NOT set it when using long-lived AK/SK only.
# security_token_env = "TENCENTCLOUD_SECURITY_TOKEN"
# Windows builds also require:
# winrm_password_env = "WINRM_PASSWORD"

# Build notifications (WeCom group-robot webhook). Empty webhook = off.
# on: always | success | failure (default failure)
# [notify]
# webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx"
# on      = "failure"
# deploy_webhook = "https://ci.example.com/api/images"   # optional: POST {image_id, score, profile} on build success (EventBridge-style trigger)

# SLSA-style provenance signing (GPG). Empty = provenance unsigned.
# [sign]
# gpg_key = "ABCDEF0123456789"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
# smoke_test = true   # instance-level checks before the image snapshot
# cve_scan   = false  # optional: run trivy vulnerability scan on the build VM before snapshot (gate)
# sbom       = false  # optional: emit an SBOM (syft or native rpm/dpkg) into the image + provenance
# test_components = ["scripts/app-check.sh"]   # optional: user-defined test scripts run before snapshot (Image Builder test-component style)
"""

PROFILE_NAMES_HELP = ", ".join(PROFILES)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
@dataclass
class PackerResult:
    """Normalised return from packer subprocess."""

    exit_code: int
    stdout_lines: list[str] = field(default_factory=list)


@dataclass
class ResolvedConfig:
    """Fully-resolved build configuration ready for rendering."""

    profile_name: str
    profile: dict[str, Any]
    family: str                         # "" = Linux, "windows" = Windows
    region: str
    zone: str
    instance_type: str
    source_image_id: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    associate_public_ip: bool
    ssh_port: int
    ssh_timeout: str
    ssh_username: str
    ssh_debug_password: str
    winrm_username: str
    winrm_password_env: str
    image_name_prefix: str
    image_name_override: str            # [image].name — fixed image name ("" = auto)
    image_copy_regions: list[str]
    image_share_accounts: list[str]     # [image].share_accounts — share built image with other uins
    image_share_org_units: list[str]    # [image].share_org_units — org-level sharing (same API as share_accounts)
    spot: bool                          # [build].spot — use a spot instance for the build VM (default false)
    cis_level_tag: str
    secret_id_env: str
    secret_key_env: str
    security_token_env: str         # [cloud].security_token_env — STS session token env (default "TENCENTCLOUD_SECURITY_TOKEN")
    assume_role_arn: str               # [cloud].assume_role_arn — group-account CAM role ("" = off)
    assume_role_session: str           # [cloud].assume_role_session (default "ciscvm")
    assume_role_duration: int          # [cloud].assume_role_duration (default 7200, 0-43200)
    image_os_tag: str
    image_benchmark: str
    level: int
    min_score: int                      # [cis].min_score — post-reboot audit gate, 0 disables (default 85)
    role_dir: str
    smoke_test: bool                    # [meta].smoke_test — run instance-level smoke checks before snapshot (default true)
    cve_scan: bool                      # [meta].cve_scan — trivy vulnerability scan gate before snapshot (default false)
    sbom: bool                          # [meta].sbom — emit SBOM into image + provenance (default false)
    rules_include: list[str]            # [cis].rules_include — rule-id filter (empty = all)
    rules_exclude: list[str]            # [cis].rules_exclude — rule-id filter (wins over include)
    rules_overrides: dict[str, dict[str, Any]]    # [cis.overrides] — per-rule param deep-merge (rule_id -> {param: value})
    notify_webhook: str                 # [notify].webhook — WeCom group-robot webhook URL ("" = off)
    notify_on: str                      # [notify].on — "always" | "success" | "failure" (default "failure")
    deploy_webhook: str                 # [notify].deploy_webhook — POST image metadata on build success ("" = off)
    sign_key: str                       # [sign].gpg_key — GPG key id/fingerprint for SLSA provenance signing ("" = off)
    test_components: list[str]          # [meta].test_components — user-defined test scripts run before snapshot
    verify_boot: bool                   # [meta].verify_boot — boot a probe instance from the produced image and re-audit before declaring success (default false)


# ---------------------------------------------------------------------------
# Configuration loading & validation
# ---------------------------------------------------------------------------
class ConfigError(Exception):
    """Raised when the TOML configuration is invalid or missing required fields."""


def _validate_value_present(label: str, value: Any) -> str | None:
    """Return an error message if *value* looks like a placeholder, else None."""
    if value is None or (isinstance(value, str) and not value):
        return f"{label}: cannot be empty"
    if (isinstance(value, str)
            and re.search(r"(?<![0-9a-f])x{8,}(?![0-9a-f])", value, re.IGNORECASE)):
        return f"{label}: still placeholder '{value}'"
    return None


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate ciscvm.toml.  Raises ConfigError on invalid input."""
    if not path.exists():
        raise ConfigError(
            f"Configuration file not found: {path}\n"
            f"  Run 'ciscvm init' to generate a template."
        )

    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8"))
    except Exception as exc:
        raise ConfigError(f"Failed to parse {path}: {exc}") from exc

    required: dict[str, list[str]] = {
        "build": [
            "profile", "region", "zone", "instance_type", "source_image_id",
            "vpc_id", "subnet_id", "security_group_id", "associate_public_ip",
        ],
        "image": ["name_prefix", "copy_regions"],
        "cis": ["level"],
        "cloud": ["secret_id_env", "secret_key_env"],
    }

    for section, keys in required.items():
        if section not in data:
            raise ConfigError(f"Missing [{section}] section in configuration")
        for key in keys:
            if key not in data[section]:
                raise ConfigError(f"Missing field: [{section}].{key}")

    profile_name = str(data.get("build", {}).get("profile", ""))
    if profile_name not in PROFILES:
        raise ConfigError(
            f"Unknown profile: {profile_name}\n"
            f"  Valid choices: {PROFILE_NAMES_HELP}"
        )

    level = data["cis"]["level"]
    if level not in (1, 2):
        raise ConfigError(f"[cis].level must be 1 or 2, got: {level}")

    itype = str(data["build"]["instance_type"])
    if "." not in itype:
        raise ConfigError(
            f"[build].instance_type '{itype}' is missing the CVM prefix.\n"
            f"  Use the full specifier, e.g. 'S5.MEDIUM2' (not 'S5-MEDIUM2')."
        )

    if not str(data["build"]["security_group_id"]).startswith("sg-"):
        warn(f"[build].security_group_id '{data['build']['security_group_id']}' "
             f"does not look like a security group ID (should start with 'sg-').")

    if not isinstance(data["build"]["associate_public_ip"], bool):
        raise ConfigError(
            f"[build].associate_public_ip must be a boolean, got "
            f"{type(data['build']['associate_public_ip']).__name__}. "
            f"Use true/false without quotes."
        )

    copy_regions_raw = data["image"]["copy_regions"]
    if not isinstance(copy_regions_raw, list):
        raise ConfigError(
            f"[image].copy_regions must be a list, got {type(copy_regions_raw).__name__}."
        )
    for region in copy_regions_raw:
        region_str = str(region)
        if not region_str or not all(c.isalnum() or c == "-" for c in region_str):
            warn(f"[image].copy_regions entry '{region_str}' does not look like a Tencent region code.")

    for label, key, prefix in [
        ("source image ID", "source_image_id", "img-"),
        ("VPC ID", "vpc_id", "vpc-"),
        ("subnet ID", "subnet_id", "subnet-"),
    ]:
        val = str(data["build"][key])
        if not val.startswith(prefix):
            warn(f"[build].{key} '{val}' does not look like a {label} (should start with '{prefix}').")

    return data


_CIS_REGION_DASHES = str.maketrans({
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
    "\u2015": "-",  # horizontal bar
    "\u2212": "-",  # minus sign
    "\uFF0D": "-",  # fullwidth hyphen-minus
})


def _sanitize_region_zone(value: str, label: str) -> str:
    """Replace non-ASCII dashes with regular ASCII hyphen '-'."""
    cleaned = str(value).translate(_CIS_REGION_DASHES)
    if cleaned != value:
        warn(f"{label} '{value}' contains a non-ASCII dash — "
             f"auto-corrected to '{cleaned}'")
    return cleaned


def resolve(data: dict[str, Any]) -> ResolvedConfig:
    """Flatten raw config + profile lookup into a ResolvedConfig."""
    profile_name: str = data["build"]["profile"]
    p = PROFILES[profile_name]
    meta: dict[str, Any] = data.get("meta", {})
    level: int = int(data["cis"]["level"])
    family: str = str(p.get("family", ""))

    copy_regions_raw = data["image"]["copy_regions"]
    if not isinstance(copy_regions_raw, list):
        raise ConfigError(
            f"[image].copy_regions must be a list, got {type(copy_regions_raw).__name__}. "
            f"Use [] for no copy or ['ap-shanghai'] for cross-region copy."
        )
    copy_regions: list[str] = [
        _sanitize_region_zone(str(r), "[image].copy_regions") for r in copy_regions_raw
    ]

    # Explicit None checks — `or` would silently discard a configured 0.
    _ssh_port_raw = meta.get("ssh_port")
    if _ssh_port_raw in (None, ""):
        _ssh_port_raw = p.get("ssh_port", 22)
    ssh_port = int(_ssh_port_raw)
    if not (1 <= ssh_port <= 65535):
        raise ConfigError(f"[meta].ssh_port must be 1-65535, got {ssh_port}")
    ssh_timeout = str(meta.get("ssh_timeout") or p.get("ssh_timeout") or "15m")

    # [image].name — optional fixed image name; empty means auto-generate.
    image_name_override = str(data.get("image", {}).get("name", "")).strip()
    if image_name_override:
        if len(image_name_override) < 1 or len(image_name_override) > 60:
            raise ConfigError(
                f"[image].name must be 1-60 characters, got {len(image_name_override)}")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", image_name_override):
            raise ConfigError(
                f"[image].name contains invalid characters: {image_name_override!r}. "
                "Use letters, digits, dot, dash, underscore only.")

    # [cloud].assume_role_* — group-account (organization) cross-account builds.
    # When set, Packer assumes the target account's CAM role with the local
    # AK/SK before launching the build instance.
    assume_role_arn = str(data.get("cloud", {}).get("assume_role_arn", "")).strip()
    if assume_role_arn and not re.fullmatch(r"[A-Za-z0-9:_/-]+", assume_role_arn):
        raise ConfigError(
            f"[cloud].assume_role_arn contains invalid characters: "
            f"{assume_role_arn!r}. Expected a CAM role ARN like "
            "qcs::cam::uin/12345:roleName/CrossAccountBuilder")
    assume_role_session = str(data.get("cloud", {}).get("assume_role_session", "ciscvm")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_=,.@-]+", assume_role_session):
        raise ConfigError(
            f"[cloud].assume_role_session contains invalid characters: {assume_role_session!r}")
    assume_role_duration = int(data.get("cloud", {}).get("assume_role_duration", 7200))
    if not (0 <= assume_role_duration <= 43200):
        raise ConfigError(
            f"[cloud].assume_role_duration must be 0-43200, got {assume_role_duration}")

    # [meta].smoke_test — instance-level checks before the snapshot (default on).
    smoke_test = bool(data.get("meta", {}).get("smoke_test", True))

    # [notify] — WeCom group-robot webhook; empty webhook disables notifications.
    notify_webhook = str(data.get("notify", {}).get("webhook", "")).strip()
    notify_on = str(data.get("notify", {}).get("on", "failure")).strip().lower()
    if notify_on not in ("always", "success", "failure"):
        raise ConfigError(
            f"[notify].on must be one of always|success|failure, got {notify_on!r}")

    # [sign] — GPG key for SLSA-style provenance signing ("" = off).
    sign_key = str(data.get("sign", {}).get("gpg_key", "")).strip()

    # [cis].rules_include / rules_exclude — optional rule-id filters.
    rules_include = [str(x).strip() for x in data.get("cis", {}).get("rules_include", []) if str(x).strip()]
    rules_exclude = [str(x).strip() for x in data.get("cis", {}).get("rules_exclude", []) if str(x).strip()]
    if rules_include and rules_exclude:
        overlap = sorted(set(rules_include) & set(rules_exclude))
        if overlap:
            raise ConfigError(
                f"[cis] rules_include and rules_exclude overlap: {overlap}")

    # [cis.overrides] — per-rule parameter deep-merge (rule_id -> {param: value}).
    # Mirrors ansible-lockdown's per-control vars: tune a rule's parameters
    # without editing the bundled catalog.  Keys must be dotted rule IDs.
    overrides_raw = data.get("cis", {}).get("overrides", {})
    if not isinstance(overrides_raw, dict):
        raise ConfigError(
            f"[cis].overrides must be a table of rule_id -> params, got "
            f"{type(overrides_raw).__name__}.")
    rules_overrides: dict[str, dict[str, Any]] = {}
    for rid, params in overrides_raw.items():
        rid = str(rid).strip()
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", rid):
            raise ConfigError(
                f"[cis].overrides key {rid!r} is not a dotted CIS rule ID "
                "(e.g. \"5.2.2\").")
        if not isinstance(params, dict):
            raise ConfigError(
                f"[cis].overrides.{rid} must be a table of parameter values, "
                f"got {type(params).__name__}.")
        rules_overrides[rid] = {str(k): v for k, v in params.items()}

    # [meta].cve_scan / [meta].sbom — optional supply-chain gates.
    cve_scan = bool(data.get("meta", {}).get("cve_scan", False))
    sbom = bool(data.get("meta", {}).get("sbom", False))

    # [image].share_accounts — cross-account image sharing (empty = off).
    share_accounts = [str(x).strip() for x in data.get("image", {}).get("share_accounts", []) if str(x).strip()]
    for acc in share_accounts:
        if not re.fullmatch(r"uin/[0-9]+", acc):
            raise ConfigError(
                f"[image].share_accounts entry {acc!r} is not a valid "
                "Tencent Cloud account ID (expected \"uin/1234567890\").")

    # [image].share_org_units — org-level sharing (same API as share_accounts).
    share_org_units = [str(x).strip() for x in data.get("image", {}).get("share_org_units", []) if str(x).strip()]
    for acc in share_org_units:
        if not re.fullmatch(r"uin/[0-9]+", acc):
            raise ConfigError(
                f"[image].share_org_units entry {acc!r} is not a valid "
                "Tencent Cloud account ID (expected \"uin/1234567890\").")

    # [build].spot — spot instance for the build VM (up to ~90% cheaper).
    spot = bool(data.get("build", {}).get("spot", False))

    # [meta].test_components — user-defined test scripts run before snapshot.
    test_components = [str(x).strip() for x in data.get("meta", {}).get("test_components", []) if str(x).strip()]

    # [meta].verify_boot — clean-boot verification after the snapshot.
    verify_boot = bool(data.get("meta", {}).get("verify_boot", False))

    # [cis].min_score — post-reboot audit gate (0 disables; default 85).
    min_score = int(data.get("cis", {}).get("min_score", 85))

    return ResolvedConfig(
        profile_name=profile_name,
        profile=p,
        family=family,
        region=_sanitize_region_zone(str(data["build"]["region"]), "[build].region"),
        zone=_sanitize_region_zone(str(data["build"]["zone"]), "[build].zone"),
        instance_type=str(data["build"]["instance_type"]),
        source_image_id=str(data["build"]["source_image_id"]),
        vpc_id=str(data["build"]["vpc_id"]),
        subnet_id=str(data["build"]["subnet_id"]),
        security_group_id=str(data["build"]["security_group_id"]),
        associate_public_ip=bool(data["build"]["associate_public_ip"]),
        ssh_port=ssh_port,
        ssh_timeout=ssh_timeout,
        ssh_username=str(p.get("ssh_username", "")),
        ssh_debug_password=str(meta.get("ssh_debug_password", "")),
        winrm_username=str(p.get("winrm_username", "")),
        winrm_password_env=str(data.get("cloud", {}).get("winrm_password_env", "WINRM_PASSWORD")),
        image_name_prefix=str(data["image"]["name_prefix"]),
        image_name_override=image_name_override,
        image_copy_regions=copy_regions,
        image_share_accounts=share_accounts,
        image_share_org_units=share_org_units,
        spot=spot,
        cis_level_tag=f"level{level}-server",
        secret_id_env=str(data["cloud"]["secret_id_env"]),
        secret_key_env=str(data["cloud"]["secret_key_env"]),
        security_token_env=str(data.get("cloud", {}).get("security_token_env", "TENCENTCLOUD_SECURITY_TOKEN")),
        assume_role_arn=assume_role_arn,
        assume_role_session=assume_role_session,
        assume_role_duration=assume_role_duration,
        image_os_tag=str(meta.get("os_tag", p.get("os_tag", ""))),
        image_benchmark=str(meta.get("benchmark", p.get("benchmark", ""))),
        level=level,
        role_dir=str(p["role_dir"]),
        smoke_test=smoke_test,
        cve_scan=cve_scan,
        sbom=sbom,
        rules_include=rules_include,
        rules_exclude=rules_exclude,
        rules_overrides=rules_overrides,
        min_score=min_score,
        notify_webhook=notify_webhook,
        notify_on=notify_on,
        deploy_webhook=str(data.get("notify", {}).get("deploy_webhook", "")).strip(),
        sign_key=sign_key,
        test_components=test_components,
        verify_boot=verify_boot,
    )


# ---------------------------------------------------------------------------
# Bundled role helpers
# ---------------------------------------------------------------------------
def _bundle_role(workdir: Path, role_dir: str) -> None:
    """Copy bundled role from roles/<role_dir>/ to workdir/ansible/roles/<role_dir>/."""
    project_root = Path(__file__).parent.resolve()
    src = (project_root / "roles" / role_dir).resolve()

    # Defence-in-depth: ensure the resolved path is within our project roles/ dir.
    # This prevents directory traversal via malformed or unexpected role_dir values.
    roles_root = (project_root / "roles").resolve()
    try:
        src.relative_to(roles_root)
    except ValueError as exc:
        raise ConfigError(
            f"Role directory resolves outside of {roles_root}: {src}. "
            "Refusing to bundle — check the profile's role_dir.") from exc

    if not src.is_dir():
        raise ConfigError(
            f"Bundled role directory not found: {src}. "
            f"The package may be corrupted — reinstall ciscvm."
        )
    dst = workdir / "ansible" / "roles" / role_dir
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))


def _check_bundled_role(role_dir: str) -> bool:
    """Return True if the bundled role directory exists and is under our project root."""
    project_root = Path(__file__).parent.resolve()
    src = (project_root / "roles" / role_dir).resolve()
    try:
        src.relative_to((project_root / "roles").resolve())
    except ValueError:
        return False
    return src.is_dir()


def _check_ansible_windows_collection() -> bool:
    """Return True when the ansible.windows collection is visible to ansible.

    Windows roles run controller-side with win_command/win_copy/win_file —
    without this collection the playbook dies at Gathering Facts with the
    opaque "ansible.legacy.setup was redirected ... could not be loaded".
    """
    try:
        out = subprocess.run(
            ["ansible-galaxy", "collection", "list", "ansible.windows"],
            capture_output=True, text=True, timeout=30,
        )
        return out.returncode == 0 and "ansible.windows" in out.stdout
    except (OSError, subprocess.SubprocessError):
        return False


def _check_pywinrm() -> bool:
    """Return True when pywinrm is importable (WinRM transport for ansible)."""
    try:
        out = subprocess.run(
            [sys.executable, "-c", "import winrm"],
            capture_output=True, timeout=15,
        )
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _apply_rule_overrides(workdir: Path, role_dir: str,
                          overrides: dict[str, dict[str, Any]]) -> None:
    """Deep-merge [cis].overrides into the WORKSPACE copy of rules.json.

    *overrides* maps CIS rule IDs (e.g. "5.2.2") to a dict of parameter
    values.  Each rule's `params` dict is updated in place — the bundled
    catalog file under ciscvm/roles/ is never modified.  Rule IDs that
    don't exist in the catalog are rejected loudly (typo = fail fast).
    """
    rules_path = workdir / "ansible" / "roles" / role_dir / "files" / "rules.json"
    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(
            f"[cis].overrides: cannot read bundled rules.json for {role_dir}: "
            f"{exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"[cis].overrides: bundled rules.json for {role_dir} is invalid: "
            f"{exc}") from exc

    by_id: dict[str, dict[str, Any]] = {str(r.get("id", "")): r for r in rules}
    missing = [rid for rid in overrides if rid not in by_id]
    if missing:
        raise ConfigError(
            f"[cis].overrides references unknown rule ID(s): {missing}. "
            f"Valid IDs start with e.g. '1.1.1.1' — run 'ciscvm list' and "
            f"check the catalog for the exact ID.")

    changed: list[str] = []
    for rid, params in overrides.items():
        rule = by_id[rid]
        cur = rule.get("params")
        if not isinstance(cur, dict):
            rule["params"] = {}
            cur = rule["params"]
        cur.update(params)
        changed.append(rid)
    rules_path.write_text(json.dumps(rules, ensure_ascii=False, indent=1) + "\n",
                          encoding="utf-8")
    info(f"Applied [cis].overrides to {len(changed)} rule(s): "
         f"{', '.join(sorted(changed))}")


# ---------------------------------------------------------------------------
# Packer template rendering
# ---------------------------------------------------------------------------

# ── Hostname DNS safeguard (shared snippet) ──
# TencentOS cloud images ship /etc/hosts with only "127.0.0.1 localhost".
# After CIS hardening modifies firewall / resolv.conf, internal DNS may
# become unreachable.  Every sudo call then triggers a PAM gethostbyname
# that falls through /etc/hosts (hostname not present) → DNS timeout
# (5-30s per call).  Word-exact fixed-string match on the 127.0.0.1 line:
# the naive grep "^127.0.0.1.*$(hostname)" treats hostname dots as regex
# wildcards and can false-match a longer alias containing the hostname.
# __HOSTS_FIX__ → bash scripts; __HOSTS_FIX_HCL__ → HCL inline ("-escaped).
HOSTS_FIX_SNIPPET = (
    'grep "^127.0.0.1" /etc/hosts 2>/dev/null | grep -qwF "$(hostname)" || '
    'echo "127.0.0.1 $(hostname)" | sudo tee -a /etc/hosts >/dev/null'
)

# ── Linux HCL (SSH communicator × ansible-local provisioner) ──
HCL_LINUX_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0, < 2.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("__SECRET_ID_ENV__")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("__SECRET_KEY_ENV__")
  sensitive = true
}

variable "security_token" {
  type      = string
  default   = env("__SECURITY_TOKEN_ENV__")
  sensitive = true
}

variable "region"                      { type = string }
variable "zone"                        { type = string }
variable "instance_type"               { type = string }
variable "source_image_id"             { type = string }
variable "ssh_username"                { type = string }
variable "ssh_port"                    { type = number }
variable "ssh_timeout"                 { type = string }
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
# Computed once in Python (24h UTC) and passed in — the in-image
# banner/report/motd must show the SAME name as the actual image.
variable "image_name"                  { type = string }
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }

locals {
  level_short = replace(var.cis_level, "-server", "")
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  security_token              = var.security_token
__ASSUME_ROLE_BLOCK__
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  ssh_username                = var.ssh_username
  ssh_port                    = var.ssh_port
  ssh_timeout                 = var.ssh_timeout
  ssh_handshake_attempts      = 120
  ssh_read_write_timeout      = "20m"
  ssh_keep_alive_interval     = "30s"
  image_name                  = var.image_name
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  associate_public_ip_address = var.associate_public_ip_address
__SPOT_BLOCK__
  image_copy_regions          = var.image_copy_regions
  image_tags = {
    cis_level  = local.level_short
    os         = var.image_os_tag
    benchmark  = var.image_benchmark
    built_with = "ciscvm"
  }
  run_tags = {
    purpose   = "cis-image-build"
    ephemeral = "true"
  }
__USER_DATA_BLOCK__
}

build {
  sources = ["source.tencentcloud-cvm.default"]

  # 0. Version banner — makes it trivial to confirm which ciscvm code
  #    generated this template (no more guessing from pause_before values).
  provisioner "shell" {
    remote_path = "__REMOTE_DIR__/ciscvm-banner.sh"
    inline = ["echo '==> ciscvm version: __VERSION__'"]
  }

  # 1. Install ansible-core (roles uploaded by ciscvm — no galaxy needed)
  provisioner "shell" {
    script       = "packer/scripts/install-ansible.sh"
    remote_path  = "__REMOTE_DIR__/ciscvm-install-ansible.sh"
  }

  # 2. CIS apply (gate disabled: fails don't block, re-audited after reboot)
  provisioner "ansible-local" {
    command          = "/opt/ciscvm-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site.yml"
    staging_directory = "/opt/ciscvm-ansible/staging"
    # Keep the staging dir so cleanup.sh can preserve the bundled role
    # (engine + rules.json) inside the image for later re-scans.
    clean_staging_directory = false
    # TMPDIR relocation lives in the venv wrapper (install-ansible.sh) —
    # ansible-local has no ansible_env_vars argument.
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/ciscvm-ansible/bin/python"
    ]
  }

  # 3. SSH survival guard (orchestration-layer safety net).
  #    Independent of the CIS engine: unconditionally open the live SSH
  #    port in firewalld / nftables / iptables so a DROP-target zone can
  #    never lock us (or the admin) out after reboot. Also guarantees the
  #    SSH channel itself stays usable: if a CIS rule disabled root login
  #    (PermitRootLogin no), restore key-based root login so Packer can
  #    reconnect; the dedicated build user (created by install-ansible.sh)
  #    is the primary fallback. This is a hard guarantee that no engine
  #    bug or stale install can defeat.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/ciscvm-ansible/ssh-guard.sh"
    # Packer deletes the uploaded script after running it (skip_clean=false
    # by default).  Keep it: provisioner 3.5 re-runs this same file right
    # before reboot to re-open the SSH port in the POST-apply firewall zones.
    skip_clean   = true
    inline = [
      "set +e",
      "# CIS hardening may leave the hostname unresolvable by removing its",
      "# /etc/hosts entry.  Every subsequent sudo call (PAM → DNS) hangs",
      "# 5-30s.  We write directly — Packer runs as root, so no sudo needed.",
      "__HOSTS_FIX_HCL__",
      "SSH_PORT=$(sudo sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=$(sudo awk '/^[Pp]ort[ \\t]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config)",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=22",
      "echo \"[ssh-guard] ensuring SSH port $SSH_PORT stays open\"",
      "if command -v firewall-cmd >/dev/null 2>&1; then",
      "  sudo systemctl enable firewalld >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld enable failed\"",
      "  sudo systemctl start firewalld >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld start failed\"",
      "  echo \"[ssh-guard] zones: $(sudo firewall-cmd --get-zones 2>/dev/null | tr '\\n' ' ') | default: $(sudo firewall-cmd --get-default-zone 2>/dev/null)\"",
      "  for z in $(sudo firewall-cmd --get-zones 2>/dev/null); do",
      "    sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp >/dev/null 2>&1 || echo \"[ssh-guard] WARN: runtime add-port failed for zone $z\"",
      "    sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1 || echo \"[ssh-guard] WARN: permanent add-port failed for zone $z\"",
      "  done",
      "  sudo firewall-cmd --reload >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld reload failed\"",
      "fi",
      "# nftables: open the port in EVERY table's input chain.  'nft list tables'",
      "# prints 'table <family> <name>' — read both fields so the table arg is",
      "# 'family name'.  A 'for t in $(...)' loop would split them on the space.",
      "if command -v nft >/dev/null 2>&1 && sudo systemctl is-active nftables >/dev/null 2>&1; then",
      "  sudo nft list tables 2>/dev/null | while read -r _ fam name; do",
      "    [ -n \"$name\" ] || continue",
      "    sudo nft add rule \"$fam $name\" input tcp dport $SSH_PORT accept >/dev/null 2>&1 && echo \"[ssh-guard] nft allow added to table '$fam $name'\" || echo \"[ssh-guard] WARN: nft add failed for table '$fam $name'\"",
      "  done",
      "  sudo nft list ruleset > /etc/sysconfig/nftables.conf 2>/dev/null && echo \"[ssh-guard] nftables ruleset persisted ($(sudo grep -c \"dport $SSH_PORT accept\" /etc/sysconfig/nftables.conf 2>/dev/null || echo 0) port rule(s))\" || echo \"[ssh-guard] WARN: nftables ruleset save failed\"",
      "fi",
      "if command -v iptables >/dev/null 2>&1; then",
      "  sudo iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || echo \"[ssh-guard] WARN: iptables add failed\"",
      "  sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null && echo \"[ssh-guard] iptables ruleset persisted\" || echo \"[ssh-guard] WARN: iptables save failed\"",
      "fi",
      "# /opt read-only after reboot: TencentOS 4 images may carry a ro entry for",
      "# /opt in fstab (rw while running, ro once the fstab applies at boot).  Every",
      "# post-reboot provisioner uploads to /opt/ciscvm-ansible and ansible-local",
      "# stages there too, so a ro /opt kills the whole rebuild with",
      "# 'scp: /opt/ciscvm-ansible/reconnected.sh: Read-only file system'.  Strip",
      "# ro/defaults from the /opt fstab line now and remount rw for the image.",
      "if grep -qE '(^|[[:space:]])/opt([[:space:]]|$)' /etc/fstab 2>/dev/null; then",
      "  sudo awk '{ if ($2==\"/opt\" && $1 !~ /^#/) { n=\"\"; split($4,o,\",\"); for(i in o){ if(o[i]!=\"ro\" && o[i]!=\"defaults\"){ n=(n==\"\"?o[i]:n\",\"o[i]); } } $4=(n==\"\"?\"rw\":n\",rw\"); } print }' /etc/fstab > /tmp/ciscvm-fstab.new 2>/dev/null && sudo mv /tmp/ciscvm-fstab.new /etc/fstab && echo \"[ssh-guard] fstab /opt line rewritten to rw\" || echo \"[ssh-guard] WARN: fstab /opt rewrite failed\"",
      "  sudo mount -o remount,rw /opt >/dev/null 2>&1 && echo \"[ssh-guard] /opt remounted rw\" || echo \"[ssh-guard] WARN: /opt remount rw failed (not a separate mount?)\"",
      "fi",
      "# Root read-only after reboot: the same class of problem hit the WHOLE root",
      "# fs — observed 'scp: /root/...: Read-only file system' with v0.14.18 (root",
      "# was ro, /opt ro was just a symptom).  First SELinux enable can make",
      "# systemd-remount-fs fail and leave / ro.  Strip ro from the / fstab line",
      "# (if any) so the next boot remounts rw.",
      "if grep -qE '(^|[[:space:]])/[[:space:]]' /etc/fstab 2>/dev/null; then",
      "  sudo awk '{ if ($2==\"/\" && $1 !~ /^#/) { n=\"\"; split($4,o,\",\"); for(i in o){ if(o[i]!=\"ro\" && o[i]!=\"defaults\"){ n=(n==\"\"?o[i]:n\",\"o[i]); } } $4=(n==\"\"?\"rw\":n\",rw\"); } print }' /etc/fstab > /tmp/ciscvm-fstab.new 2>/dev/null && sudo mv /tmp/ciscvm-fstab.new /etc/fstab && echo \"[ssh-guard] fstab / line rewritten to rw\" || echo \"[ssh-guard] WARN: fstab / rewrite failed\"",
      "  sudo mount -o remount,rw / >/dev/null 2>&1 && echo \"[ssh-guard] / remounted rw\" || echo \"[ssh-guard] WARN: / remount rw failed\"",
      "fi",
      "echo \"[ssh-guard] VERIFY: root options=$(findmnt -no OPTIONS / 2>/dev/null)\"",
      "# Install a post-boot oneshot that re-opens the SSH port after reboot.",
      "# Runs BEFORE sshd (Before=sshd.service) so the port is already open when",
      "# sshd accepts; logs to /var/log/ciscvm-ssh-guard.log so a still-failing",
      "# boot is diagnosable on the instance instead of a blind i/o timeout.",
      "sudo tee /etc/systemd/system/ciscvm-ssh-guard.service >/dev/null <<'UNIT'",
      "[Unit]",
      "Description=ciscvm post-boot SSH port re-open",
      "Wants=network-online.target",
      "After=network.target network-online.target firewalld.service",
      "Before=sshd.service",
      "",
      "[Service]",
      "Type=oneshot",
      "ExecStart=/opt/ciscvm-ansible/ssh-guard-boot.sh",
      "TimeoutStartSec=180",
      "RemainAfterExit=no",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "UNIT",
      "sudo tee /opt/ciscvm-ansible/ssh-guard-boot.sh >/dev/null <<'BOOT'",
      "#!/usr/bin/env bash",
      "exec >> /var/log/ciscvm-ssh-guard.log 2>&1",
      "echo \"[ssh-guard-boot] $(date -Is) start\"",
      "# First enable of SELinux (even permissive) can make systemd-remount-fs",
      "# fail, leaving / mounted ro while the rest of the boot continues: sshd",
      "# comes up, but EVERY write (scp upload, /opt staging) fails with",
      "# 'Read-only file system'.  Force rw here — this unit runs Before=sshd.",
      "mount -o remount,rw / >/dev/null 2>&1 && echo \"[ssh-guard-boot] root remounted rw\" || echo \"[ssh-guard-boot] WARN: root remount rw failed\"",
      "mount -o remount,rw /opt >/dev/null 2>&1 || true",
      "echo \"[ssh-guard-boot] root=$(findmnt -no OPTIONS / 2>/dev/null)\"",
      "SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=$(awk '/^[Pp]ort[ \\t]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config)",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=22",
      "echo \"[ssh-guard-boot] target port $SSH_PORT\"",
      "if command -v firewall-cmd >/dev/null 2>&1; then",
      "  systemctl enable firewalld >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: enable firewalld failed\"",
      "  systemctl start firewalld >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: start firewalld failed\"",
      "  for z in $(firewall-cmd --get-zones 2>/dev/null); do",
      "    firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: zone $z runtime add failed\"",
      "    firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: zone $z permanent add failed\"",
      "  done",
      "  firewall-cmd --reload >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: reload failed\"",
      "  echo \"[ssh-guard-boot] firewalld active=$(systemctl is-active firewalld 2>/dev/null)\"",
      "fi",
      "if command -v nft >/dev/null 2>&1; then",
      "  nft list tables 2>/dev/null | while read -r _ fam name; do",
      "    [ -n \"$name\" ] || continue",
      "    nft add rule \"$fam $name\" input tcp dport $SSH_PORT accept >/dev/null 2>&1 && echo \"[ssh-guard-boot] nft allow added to '$fam $name'\" || echo \"[ssh-guard-boot] WARN: nft add failed for '$fam $name'\"",
      "  done",
      "  nft list ruleset > /etc/sysconfig/nftables.conf 2>/dev/null || echo \"[ssh-guard-boot] WARN: ruleset save failed\"",
      "fi",
      "if command -v iptables >/dev/null 2>&1; then",
      "  iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || echo \"[ssh-guard-boot] WARN: iptables add failed\"",
      "  iptables-save > /etc/sysconfig/iptables 2>/dev/null || echo \"[ssh-guard-boot] WARN: iptables save failed\"",
      "fi",
      "echo \"[ssh-guard-boot] $(date -Is) done\"",
      "exit 0",
      "BOOT",
      "sudo chmod +x /opt/ciscvm-ansible/ssh-guard-boot.sh",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable ciscvm-ssh-guard.service >/dev/null 2>&1 && echo \"[ssh-guard] oneshot enabled\" || echo \"[ssh-guard] WARN: oneshot enable failed\"",
      "# VERIFY — every persistence point, printed to the build log so a",
      "# post-reboot failure is attributable instead of a mystery.",
      "echo \"[ssh-guard] VERIFY: firewalld enabled=$(sudo systemctl is-enabled firewalld 2>&1)\"",
      "echo \"[ssh-guard] VERIFY: oneshot enabled=$(sudo systemctl is-enabled ciscvm-ssh-guard.service 2>&1)\"",
      "for z in $(sudo firewall-cmd --get-zones 2>/dev/null); do if sudo firewall-cmd --zone=$z --query-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1; then echo \"[ssh-guard] VERIFY: zone $z permanent port $SSH_PORT: OK\"; else echo \"[ssh-guard] VERIFY: zone $z permanent port $SSH_PORT: MISSING\"; fi; done",
      "echo \"[ssh-guard] VERIFY: nftables.conf port rules=$(sudo grep -c \"dport $SSH_PORT accept\" /etc/sysconfig/nftables.conf 2>/dev/null || echo 0)\"",
      "echo \"[ssh-guard] VERIFY: iptables port rules=$(sudo grep -c \"dport $SSH_PORT -j ACCEPT\" /etc/sysconfig/iptables 2>/dev/null || echo 0)\"",
      "# SELinux disabled->permissive: the currently-disabled boot left a stale",
      "# /.autorelabel marker (selinux-autorelabel-mark).  On the next boot",
      "# (SELinux now permissive) the autorelabel service consumes it and runs a",
      "# full restorecon in EARLY boot, before network/sshd — observed as a",
      "# multi-minute-to-infinite i/o timeout loop after reboot.  Remove the",
      "# marker so the permissive boot needs NO relabel; with permissive the",
      "# missing file labels are tolerated, and the mark service only recreates",
      "# the marker during a SELinux-disabled boot (which this is no longer).",
      "if [ -f /.autorelabel ]; then sudo rm -f /.autorelabel && echo \"[ssh-guard] removed stale /.autorelabel (boot relabel suppressed)\" || echo \"[ssh-guard] WARN: could not remove /.autorelabel\"; else echo \"[ssh-guard] no stale /.autorelabel present\"; fi",
      "echo \"[ssh-guard] VERIFY: selinux=$(sudo getenforce 2>/dev/null) config=$(sudo grep ^SELINUX= /etc/selinux/config 2>/dev/null) autorelabel=$([ -f /.autorelabel ] && echo PRESENT || echo absent)\"",
      "# Ensure key-based root login survives CIS hardening (PermitRootLogin no)",
      "if sudo sshd -T 2>/dev/null | grep -qi '^permitrootlogin no'; then",
      "  echo \"[ssh-guard] CIS disabled root login; restoring key-based root login\"",
      "  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -f \"$f\" ] || continue; sudo sed -i 's/^[ \\t]*PermitRootLogin[ \\t].*/PermitRootLogin prohibit-password/' \"$f\"; done",
      "  sudo systemctl reload sshd",
      "fi",
      "# Build user fallback (created by install-ansible.sh) — sudoers.d already grants NOPASSWD; do NOT add to wheel (CIS 5.2.7 requires wheel to stay empty)",
      "true"
    ]
  }

  # 3.5 Re-apply the SSH guard right before reboot.  The apply playbook on
  #      TencentOS 4 can reload firewalld / shift active zones (CIS 3.4.x),
  #      which silently drops the guard's earlier rules — after reboot the
  #      build then can't reconnect (i/o timeout, not refused).  Re-running
  #      the guard here enumerates the POST-apply zones and persists the
  #      SSH port opening in all of them.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/ciscvm-ansible/ssh-guard-reapply.sh"
    inline = [
      "sudo bash /opt/ciscvm-ansible/ssh-guard.sh"
    ]
  }

  # 4. Schedule reboot. shutdown -r +1 gives Packer ~60s to finish
  #    cleanup (rm reboot.sh) while SSH is still alive.
  #    Without expect_disconnect — SSH hasn't dropped yet at this point.
  #    No `|| true`: a failed shutdown must fail loudly, otherwise the next
  #    provisioner waits for a disconnect that never comes.
  provisioner "shell" {
    pause_before = "10s"
    remote_path  = "/opt/ciscvm-ansible/reboot.sh"
    inline       = ["sudo shutdown -r +1"]
  }

  # 5. Wait for the reboot, then continue AS SOON AS SSH returns.
  #  pause_before=90s only needs to cover the shutdown delay (+60s),
  #    so Packer is already disconnected before it first probes.
  # expect_disconnect then makes Packer poll and reconnect the very
  #    moment SSH is back — no fixed 7-minute dead wait. This alone
  #    saves several minutes per build when the VM reboots faster.
  provisioner "shell" {
    pause_before      = "90s"
    expect_disconnect = true
    # A freshly hardened TOS4 may take several minutes to finish its first
    # post-enable boot (SELinux relabel / firewalld cold start) before sshd
    # accepts.  The connect window is start_retry_timeout (default "a few
    # minutes" — observed ~5 min give-up of i/o timeout retries), NOT
    # max_retries (which only retries command execution).  Raise it so a
    # slow-but-healthy boot no longer looks like a dead instance.  25m also
    # covers an unexpected single SELinux autorelabel pass + its auto-reboot.
    start_retry_timeout = "25m"
    max_retries         = 40
    # Upload to /opt (not /tmp): systemd-tmpfiles on the freshly rebooted
    # image may purge /tmp (tmp.conf D-type cleanup), which made the
    # reconnect probe fail with 'bash: script: Permission denied' (126).
    remote_path       = "__REMOTE_DIR__/ciscvm-reconnected.sh"
    inline            = ["echo reconnected"]
    valid_exit_codes  = [0, 1, -1]
  }

  # 5.5 Fix log-file permissions that were loosened by boot-time
  #     services (cloud-init, systemd-logind, …).  These files are
  #     recreated on every boot with default perms; the CIS engine
  #     flags them in the re-audit unless we fix them first.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/ciscvm-fix-logperms.sh"
    inline = [
      "set +e",
      "# Post-reboot state evidence: if SELinux autorelabel ran at boot it would",
      "# have consumed (deleted) /.autorelabel; if the marker is still here the",
      "# boot skipped relabel entirely (desired).  sshd active confirms the",
      "# instance is fully up.  Printed first so a failed build is attributable.",
      "echo \"[ciscvm] post-reboot: autorelabel=$([ -f /.autorelabel ] && echo PRESENT || echo GONE) selinux=$(sudo getenforce 2>/dev/null) sshd=$(sudo systemctl is-active sshd 2>/dev/null)\"",
      "# L2 enables auditd (4.1.1.2) and apply shows 'enabled and running', yet",
      "# after reboot it can come up inactive (audit 4.1.3.x then all fail with",
      "# 'not loaded in the running config' + smoke FAIL).  Diagnose and force a",
      "# start; the journal excerpt surfaces the real reason if start fails.",
      "echo \"[ciscvm] auditd: active=$(sudo systemctl is-active auditd 2>/dev/null) enabled=$(sudo systemctl is-enabled auditd 2>&1)\"",
      "if ! sudo systemctl is-active --quiet auditd 2>/dev/null; then",
      "  sudo systemctl start auditd >/dev/null 2>&1 && echo '[ciscvm] auditd started OK' || { echo '[ciscvm] auditd START FAILED:'; sudo journalctl -u auditd -n 8 --no-pager 2>&1 | tail -8; }",
      "  echo \"[ciscvm] auditd after start: $(sudo systemctl is-active auditd 2>/dev/null)\"",
      "fi",
      "# auditd may be active yet its rules are not in the kernel: the service's",
      "# ExecStartPost=augenrules --load can fail after the SELinux first-enable",
      "# boot while the service still reports active.  Force a reload and echo",
      "# the rule count so a missing ruleset is visible in the build log.",
      "if sudo systemctl is-active --quiet auditd 2>/dev/null; then",
      "  sudo augenrules --load >/dev/null 2>&1 && echo \"[ciscvm] audit rules reloaded: $(sudo auditctl -l 2>/dev/null | grep -c . ) rule(s)\" || { echo '[ciscvm] WARN: augenrules --load failed:'; sudo journalctl -u auditd -n 6 --no-pager 2>&1 | tail -6; }",
      "fi",
      "# Ensure hostname resolves BEFORE any sudo call.  CIS hardening may",
      "# leave /etc/hosts without the short hostname, which makes sudo PAM",
      "# hang on DNS (5-30s per call).  Packer runs as root: no sudo needed.",
      "__HOSTS_FIX_HCL__",
      "sudo find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod g-wx,o-rwx {} + 2>/dev/null",
      "# Reboot may revert ForwardToSyslog to yes (RPM / init-script overwrite).",
      "# 6.2.2.3 wants yes when rsyslog is present; but 6.2.2.1 already fails",
      "# because rsyslog is not detected, so 6.2.2.3 is not assessed. Safe to fix.",
      "sudo sed -i 's/^ForwardToSyslog=yes$/ForwardToSyslog=no/' /etc/systemd/journald.conf 2>/dev/null || true",
      "# systemd-journal-remote creates /var/lib/private/systemd/journal-upload",
      "# with unowned uid/gid; the CIS unowned-files scan flags it post-reboot.",
      "sudo chown -R root:root /var/lib/private/systemd/ 2>/dev/null || true",
      "echo fix-logperms done"
    ]
  }

  # 6. Re-audit after reboot + gate check (score >= 85%).
  #    cis_keep_remote_artifacts=true keeps /tmp/cis-*/result.json so
  #    provisioner #7.5 can persist it to /opt for the ciscvm report.
  provisioner "ansible-local" {
    command          = "/opt/ciscvm-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site-audit.yml"
    staging_directory = "/opt/ciscvm-ansible/staging"
    # Keep the staging dir so cleanup.sh can preserve the bundled role
    # (engine + rules.json) inside the image for later re-scans.
    clean_staging_directory = false
    # TMPDIR relocation lives in the venv wrapper (install-ansible.sh).
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/ciscvm-ansible/bin/python",
      "-e", "cis_keep_remote_artifacts=true"
    ]
  }

  # 7. Cleanup package cache before snapshot.
  #    Also re-lock SSH to the CIS target state: the ssh-guard step above
  #    temporarily restored key-based root login so Packer could reconnect
  #    after reboot; the final image must ship hardened (PermitRootLogin no
  #    per CIS 5.1.22/5.2.10).  The dedicated 'ciscvm' build user (sudo,
  #    same authorized_keys) remains the supported admin channel.
  provisioner "shell" {
    pause_before = "10s"
    remote_path  = "__REMOTE_DIR__/ciscvm-cleanup.sh"
    inline = [
      "__CLEAN_CMD__",
      "# Re-lock root login for the final image (CIS 5.1.22/5.2.10).  Do NOT",
      "# reload sshd here: the running daemon keeps the current policy so",
      "# Packer can still reconnect for the remaining provisioners; the new",
      "# config takes effect on the first boot of any instance from the image.",
      "for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -f \"$f\" ] || continue; sudo sed -i 's/^[ \\t]*PermitRootLogin[ \\t].*/PermitRootLogin no/' \"$f\"; done",
      "# Keep the engine + rule catalog in the image so the report's re-scan",
      "# instructions work; drop only the transient staging playbooks.",
      "sudo mv /opt/ciscvm-ansible/staging/roles /opt/ciscvm-ansible/roles 2>/dev/null || true",
      "# Shutdown safety: bound rc-local.service stop time.  On the RHEL 9/10",
      "# public images the TencentCloud security agent (secu-tcs-agent) is",
      "# started from /etc/rc.d/rc.local and lives in rc-local.service's",
      "# cgroup; the unit ships TimeoutStopSec=infinity and the agent catches",
      "# SIGTERM, so once CIS firewall rules cut its backend connection the",
      "# agent's signal handler can hang and the stop job never finishes —",
      "# the guest then cannot soft-shutdown and TencentCloud image creation",
      "# times out (CREATEFAILED).  A bounded stop lets systemd SIGKILL it.",
      "sudo mkdir -p /etc/systemd/system/rc-local.service.d",
      "printf '[Service]\\nTimeoutStopSec=15s\\n' | sudo tee /etc/systemd/system/rc-local.service.d/10-ciscvm-stop-timeout.conf > /dev/null",
      "sudo systemctl daemon-reload || true",
      "rm -rf /tmp/ansible /opt/ciscvm-ansible/staging /opt/ciscvm-ansible/reboot.sh /opt/ciscvm-ansible/ssh-guard.sh /opt/ciscvm-ansible/reconnected.sh /opt/ciscvm-ansible/fix-logperms.sh /opt/ciscvm-ansible/cleanup.sh ~/.ansible/roles 2>/dev/null || true"
    ]
  }

  # 7.5 Persist the re-audit JSON to /opt for the ciscvm report and banner,
  #     then clean up the temp workdir before the snapshot.  The re-audit
  #     role runs with cis_keep_remote_artifacts=true (provisioner #6),
  #     so /tmp/cis-*/result.json still exists when we get here.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/ciscvm-collect-audit.sh"
    inline = [
      "set +e",
      "SRC=$(ls -dt /tmp/cis-*/result.json 2>/dev/null | head -1)",
      "if [ -n \"$SRC\" ] && [ -f \"$SRC\" ]; then",
      "  sudo install -m 0600 -o root -g root \"$SRC\" /opt/ciscvm-AUDIT-RESULT.json",
      "  sudo rm -rf \"$(dirname \"$SRC\")\"",
      "  echo \"[ciscvm] saved audit result to /opt/ciscvm-AUDIT-RESULT.json\"",
      "else",
      "  echo \"[ciscvm] WARNING: no /tmp/cis-*/result.json found; banner/report will lack audit details\"",
      "  sudo install -m 0600 -o root -g root /dev/null /opt/ciscvm-AUDIT-RESULT.json 2>/dev/null || true",
      "fi",
      "true"
    ]
  }

  # 8. Upload the real ciscvm-finalize.sh (rendered by render_finalize with
  #    build metadata substituted).  The shell provisioner below is just a
  #    thin wrapper that fixes /etc/hosts first, then invokes this file.
  provisioner "file" {
    source      = "packer/scripts/ciscvm-finalize.sh"
    destination = "/opt/ciscvm-ansible/ciscvm-finalize.sh"
  }

  # 9. Run the finalize script — writes banner, motd, /opt report, and
  #    wires the SSH Banner directive.  This is the LAST user-visible step
  #    before Packer snapshots the image.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/ciscvm-run-finalize.sh"
    inline = [
      "# Fix hostname BEFORE sudo — 'sudo bash' hangs on DNS if /etc/hosts",
      "# lacks the short hostname.  We write as root (Packer is root) so",
      "# this is instant; the bash script below inherits the fix.",
      "__HOSTS_FIX_HCL__",
      "sudo bash /opt/ciscvm-ansible/ciscvm-finalize.sh '__SOURCE_IMAGE__' '__IMAGE_NAME__' '__IMAGE_OS__' '__CIS_LEVEL__' '__IMAGE_BENCHMARK__' '__CISCVM_VERSION__'",
      "# Re-scan AFTER finalize so /opt/ciscvm-AUDIT-RESULT.json describes the",
      "# final image state (finalize rewrites banner/motd/issue, which flips",
      "# CIS 1.7.x banner results).  Engine + catalog were kept under",
      "# /opt/ciscvm-ansible/roles/ by the cleanup step.",
      "ENG=$(ls -d /opt/ciscvm-ansible/roles/cis_*/files 2>/dev/null | head -1)",
      "if [ -n \"$ENG\" ] && [ -f \"$ENG/cis_engine.py\" ]; then",
      "  sudo /opt/ciscvm-ansible/bin/python \"$ENG/cis_engine.py\" --catalog \"$ENG/rules.json\" --mode scan --profile '__CIS_PROFILE_SHORT__' --out /tmp/cis-final-scan.json >/dev/null 2>&1 && sudo install -m 0600 -o root -g root /tmp/cis-final-scan.json /opt/ciscvm-AUDIT-RESULT.json && sudo rm -f /tmp/cis-final-scan.json && echo '[ciscvm] final-state audit refreshed' || echo '[ciscvm] WARNING: final-state re-scan failed; keeping pre-finalize audit'",
      "fi"
    ]
  }
__IDEMPOTENCY_BLOCK____SMOKE_TEST_BLOCK____SUPPLY_CHAIN_BLOCK____TEST_COMPONENTS_BLOCK__
}
"""

# ── Idempotency verification (Linux) ──
# ciscvm test --idempotency: re-run the apply playbook once more and assert
# the second pass makes NO changes (Applied: 0, Pending: 0 in the role's
# "Build summary" output).  A golden image builder must be idempotent — if a
# re-apply changes rules, the image drifts on every rebuild.
IDEMPOTENCY_LINUX_BLOCK = r"""  provisioner "ansible-local" {
    command          = "/opt/ciscvm-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site.yml"
    staging_directory = "/opt/ciscvm-ansible/staging"
    clean_staging_directory = false
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/ciscvm-ansible/bin/python",
      "-e", "cis_keep_remote_artifacts=true"
    ]
  }
"""

# ── Instance-level smoke test (Linux) ──
# Runs as the very last provisioner, AFTER finalize + final re-audit and
# BEFORE Packer snapshots the image.  Any failure exits non-zero → Packer
# aborts → no image is produced.  This is the "Test" leg of the
# build → test → distribute pipeline (AWS Image Builder style).
# [meta].cve_scan=true appends a trivy gate before the smoke test ends;
# [meta].sbom=true emits an SBOM into the image for provenance.
SMOKE_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    # v0.14.31: upload to /root, never /tmp — profiles where CIS 1.1.2.1
    # actually mounts /tmp as a noexec tmpfs (e.g. TencentOS 3) make packer's
    # default /tmp/script_XXXX.sh upload unexecutable (exit 126).
    remote_path = "__REMOTE_DIR__/ciscvm-smoke.sh"
    inline = [
      "echo '[ciscvm] smoke test: sshd config parses'",
      "sudo sshd -T >/dev/null 2>&1 || { echo '[ciscvm] SMOKE FAIL: sshd -T rejected config'; exit 1; }",
      "echo '[ciscvm] smoke test: sshd active'",
      "systemctl is-active --quiet sshd || { echo '[ciscvm] SMOKE FAIL: sshd not active'; exit 1; }",
      "echo '[ciscvm] smoke test: auditd active (if enabled — L1 skips auditd)'",
      "if systemctl is-enabled --quiet auditd 2>/dev/null; then",
      "  systemctl is-active --quiet auditd || { echo '[ciscvm] SMOKE FAIL: auditd inactive'; exit 1; }",
      "else",
      "  echo '[ciscvm] smoke test: auditd not enabled (L1) — skipped'",
      "fi",
      "echo '[ciscvm] smoke test: /dev/shm noexec (if hardened in fstab)'",
      "if grep -E '[[:space:]]/dev/shm[[:space:]]' /etc/fstab 2>/dev/null | grep -q noexec; then",
      "  awk '$2 == \"/dev/shm\" && $4 ~ /noexec/' /proc/mounts | grep -q . || { echo '[ciscvm] SMOKE FAIL: /dev/shm noexec applied but not live'; exit 1; }",
      "else",
      "  echo '[ciscvm] smoke test: /dev/shm noexec not applied (L1 disruptive) — skipped'",
      "fi",
      "echo '[ciscvm] smoke test: no genuinely weak SSH crypto (MD5/3DES/RC4/Blowfish)'",
      "# CIS 1.6.5/1.6.6 explicitly ALLOW hmac-sha1*, umac-64*, chacha20* and",
      "# aes*-cbc — the guard's drop-in keeps them.  Only flag algorithms CIS",
      "# actually forbids, or an L1 build can never pass this check.",
      "if sudo sshd -T 2>/dev/null | grep -Eiq 'md5|3des-cbc|arcfour|blowfish-cbc|cast128|salsa20'; then",
      "  echo '[ciscvm] SMOKE FAIL: weak SSH crypto present'; exit 1;",
      "fi",
      "echo '[ciscvm] smoke test: journal-upload (if enabled)'",
      "# v0.14.32: CIS 4.3.x only requires the forwarder configured + enabled;",
      "# it legitimately stays inactive without a reachable remote journal",
      "# server (TencentOS 3 ships it enabled-but-idle).  Assert enabled only.",
      "if systemctl is-enabled --quiet systemd-journal-upload.service 2>/dev/null; then",
      "  echo '[ciscvm] smoke test: journal-upload enabled (inactive OK without remote server)'",
      "else",
      "  echo '[ciscvm] smoke test: journal-upload not enabled — skipped'",
      "fi",
      "echo '[ciscvm] smoke test PASSED — image is buildable'"
    ]
  }
"""

# ── User test components (Linux) — [meta].test_components ──
# EC2 Image Builder "test component" style: after the built-in smoke test
# and supply-chain gates, run the user's own validation scripts (e.g.
# "agent installed and port reachable").  Scripts are uploaded from the
# controller and executed sequentially; any non-zero exit aborts the build
# before the snapshot.  #13 of the round-2 borrow list.
TEST_COMPONENTS_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "3s"
    remote_path = "__REMOTE_DIR__/ciscvm-user-tests.sh"
    inline = [
      "set +e",
      "echo '[ciscvm] user test components: running'",
      # __REMOTE_DIR__ resolves to /root (root user) or /home/<user> (e.g.
      # ubuntu) — the same mechanism as the smoke test (v0.14.33).  A
      # hardcoded /root breaks non-root profiles: the file upload to /root
      # fails with permission denied before any test even runs.
      "for t in __REMOTE_DIR__/ciscvm-test-components/*; do",
      "  [ -f \"$t\" ] || continue",
      "  echo \"[ciscvm] user-test: running $(basename \"$t\")\"",
      "  bash \"$t\"",
      "  RC=$?",
      "  if [ \"$RC\" != \"0\" ]; then",
      "    echo \"[ciscvm] USER TEST FAIL: $(basename \"$t\") exited $RC — image not produced\"",
      "    exit 1",
      "  fi",
      "  echo \"[ciscvm] user-test: PASS $(basename \"$t\")\"",
      "done",
      "echo '[ciscvm] user test components: all passed'"
    ]
  }
"""

# ── CVE scan gate (Linux) — [meta].cve_scan=true ──
# Trivy filesystem scan of the hardened rootfs, CRITICAL-severity findings
# abort the build (no image produced).  P1#6 of the benchmark borrow list:
# a vulnerability scan before the snapshot, AWS Inspector-style.  Trivy is
# installed on the build VM if missing (pinned release, no network drift).
CVE_SCAN_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    remote_path = "__REMOTE_DIR__/ciscvm-cve-scan.sh"
    inline = [
      "set +e",
      "if ! command -v trivy >/dev/null 2>&1; then",
      "  echo '[ciscvm] cve-scan: installing trivy (pinned v0.57.1)'",
      "  sudo dnf install -y wget >/dev/null 2>&1 || sudo apt-get install -y wget >/dev/null 2>&1 || true",
      "  TARCH=$(uname -m | sed -e 's/x86_64/64bit/' -e 's/aarch64/ARM64/' -e 's/arm64/ARM64/')",
      "  curl -fsSL \"https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-${TARCH}.tar.gz\" -o /tmp/trivy.tgz 2>/dev/null && sudo tar -C /usr/local/bin -xzf /tmp/trivy.tgz trivy 2>/dev/null && rm -f /tmp/trivy.tgz",
      "fi",
      "if ! command -v trivy >/dev/null 2>&1; then",
      "  echo '[ciscvm] cve-scan: WARNING trivy unavailable — skipping CVE gate (build continues)'",
      "else",
      "  echo '[ciscvm] cve-scan: trivy $(trivy --version 2>/dev/null | head -1) — scanning / (CRITICAL only)'",
      # Skip pseudo-filesystems & caches: /proc,/sys,/dev report unfixable
      # kernel findings, /run,/tmp are ephemeral — scanning them just slows
      # the gate down and pollutes the report with noise.
      "  sudo trivy fs --quiet --severity CRITICAL --exit-code 1 --no-progress --skip-dirs /proc,/sys,/dev,/run,/tmp / >/tmp/ciscvm-trivy.log 2>&1",
      "  RC=$?",
      "  tail -20 /tmp/ciscvm-trivy.log",
      "  if [ \"$RC\" = \"1\" ]; then",
      "    echo '[ciscvm] CVE GATE FAIL: CRITICAL vulnerabilities found — image not produced'",
      "    exit 1",
      "  fi",
      "  echo '[ciscvm] cve-scan: PASSED (no CRITICAL findings)'",
      "fi"
    ]
  }
"""

# ── SBOM emission (Linux) — [meta].sbom=true ──
# Zero-dependency SBOM written into the image (native package query — no
# external scanner needed, works offline) and referenced from provenance.
# Also captured on the build log so the controller can hash it (P2#10).
SBOM_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    remote_path = "__REMOTE_DIR__/ciscvm-sbom.sh"
    inline = [
      "set +e",
      "echo '[ciscvm] sbom: generating native package SBOM'",
      "if command -v rpm >/dev/null 2>&1; then",
      "  sudo rpm -qa --qf '{\"name\":\"%{NAME}\",\"version\":\"%{VERSION}-%{RELEASE}\",\"arch\":\"%{ARCH}\",\"epoch\":\"%{EPOCHNUM}\"}\\n' 2>/dev/null | sudo tee /opt/ciscvm-SBOM.jsonl >/dev/null",
      "elif command -v dpkg-query >/dev/null 2>&1; then",
      "  sudo dpkg-query -W -f='{\"name\":\"${Package}\",\"version\":\"${Version}\",\"arch\":\"${Architecture}\"}\\n' 2>/dev/null | sudo tee /opt/ciscvm-SBOM.jsonl >/dev/null",
      "else",
      "  echo '[ciscvm] sbom: WARNING no rpm/dpkg-query — SBOM empty'",
      "  sudo touch /opt/ciscvm-SBOM.jsonl",
      "fi",
      "sudo chmod 0644 /opt/ciscvm-SBOM.jsonl",
      "echo \"[ciscvm] sbom: $(sudo wc -l < /opt/ciscvm-SBOM.jsonl 2>/dev/null || echo 0) packages -> /opt/ciscvm-SBOM.jsonl\"",
      "echo \"[ciscvm] SBOM_SHA256=$(sudo sha256sum /opt/ciscvm-SBOM.jsonl 2>/dev/null | awk '{print $1}')\""
    ]
  }
"""

# ── Instance-level smoke test (Windows) ──
SMOKE_WIN_BLOCK = r"""  provisioner "powershell" {
    inline = [
      "if ((Get-Service -Name mpssvc -ErrorAction SilentlyContinue).Status -ne 'Running') { Write-Error '[ciscvm] SMOKE FAIL: Windows firewall inactive'; exit 1 }",
      "Write-Host '[ciscvm] smoke test PASSED - image is buildable'"
    ]
  }
"""

# ── User test components (Windows) — [meta].test_components ──
# PowerShell scripts run sequentially before the snapshot; a non-zero exit
# aborts the build (#13).
TEST_COMPONENTS_WIN_BLOCK = r"""  provisioner "powershell" {
    inline = [
      "Get-ChildItem 'C:/ciscvm-test-components/*.ps1' -ErrorAction SilentlyContinue | ForEach-Object {",
      "  Write-Host ('[ciscvm] user-test: running ' + $_.Name)",
      "  & $_.FullName",
      "  if ($LASTEXITCODE -ne 0) { Write-Error ('[ciscvm] USER TEST FAIL: ' + $_.Name + ' exited ' + $LASTEXITCODE); exit 1 }",
      "  Write-Host ('[ciscvm] user-test: PASS ' + $_.Name)",
      "}",
      "Write-Host '[ciscvm] user test components: all passed'"
    ]
  }
"""

# ── Windows HCL (winrm communicator × controller-side ansible provisioner) ──
HCL_WIN_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0, < 2.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("__SECRET_ID_ENV__")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("__SECRET_KEY_ENV__")
  sensitive = true
}

variable "security_token" {
  type      = string
  default   = env("__SECURITY_TOKEN_ENV__")
  sensitive = true
}

variable "region"                      { type = string }
variable "zone"                        { type = string }
variable "instance_type"               { type = string }
variable "source_image_id"             { type = string }
variable "winrm_username"              { type = string }
variable "winrm_password" {
  type      = string
  default   = env("__WINRM_PASSWORD_ENV__")
  sensitive = true
}
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
# Computed once in Python (24h UTC) and passed in — the in-image
# banner/report/motd must show the SAME name as the actual image.
variable "image_name"                  { type = string }
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }

locals {
  level_short = replace(var.cis_level, "-server", "")
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  security_token              = var.security_token
__ASSUME_ROLE_BLOCK__
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  communicator                = "winrm"
  winrm_username              = var.winrm_username
  winrm_password              = var.winrm_password
  # Stock cloud Windows images expose only an HTTP/5985 listener (or a
  # self-signed 5986 one).  Enforcing SSL with verification makes the
  # ephemeral build VM unconnectable; the build runs on an isolated subnet
  # and the VM is destroyed after snapshotting, so plain HTTP is acceptable.
  winrm_use_ssl               = false
  winrm_insecure              = true
  # Windows first boot (specialize/oobe) can take well over 10 minutes on
  # small instance types; give WinRM ample time to come up.
  winrm_timeout               = "30m"
  # Two stock-image hurdles, both handled by this cloudbase-init userdata:
  #  1. the plugin does NOT set the Administrator password from
  #     winrm_password — without this the VM boots with a random password
  #     and every WinRM attempt is a 401 ("Timeout waiting for WinRM");
  #  2. the stock image disables WinRM Basic auth, and packer's
  #     communicator cannot negotiate NTLM against it (verified: pywinrm
  #     NTLM works, packer NTLM 401s) — so Basic + unencrypted HTTP are
  #     enabled for the BUILD only; the final provisioner re-locks both
  #     before the snapshot.
  # NB: the password must not contain a single quote.
  user_data = <<-UDEOF
  <powershell>
  net user Administrator '${var.winrm_password}'
  Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
  Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
  </powershell>
  UDEOF
  image_name                  = var.image_name
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  associate_public_ip_address = var.associate_public_ip_address
__SPOT_BLOCK__
  image_copy_regions          = var.image_copy_regions
  image_tags = {
    cis_level  = local.level_short
    os         = var.image_os_tag
    benchmark  = var.image_benchmark
    built_with = "ciscvm"
  }
  run_tags = {
    purpose   = "cis-image-build"
    ephemeral = "true"
  }
}

build {
  sources = ["source.tencentcloud-cvm.default"]

  # WinRM survival guard — the Windows counterpart of the Linux ssh-guard.
  # CIS 9.x turns the firewall ON with DefaultInboundAction=Block; if no
  # enabled inbound rule covers 5985, the smoke-test and re-lock provisioners
  # (which run AFTER the apply) lose the WinRM channel and the build dies.
  # Create an explicit allow rule BEFORE the apply; the re-lock provisioner
  # removes it again so the shipped image stays clean.
  provisioner "powershell" {
    inline = [
      "Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue",
      "New-NetFirewallRule -DisplayName 'ciscvm-winrm-build-5985' -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null",
      "Write-Host '[ciscvm] winrm-guard: 5985 allow rule in place before CIS apply'"
    ]
  }

  # CIS apply via controller-side ansible (winrm — cis_engine.ps1)
  # NOTE: no --tags filter — the bundled Windows roles don't tag tasks,
  # so filtering by level would silently skip every task.
  provisioner "ansible" {
    playbook_file = "ansible/site.yml"
    user          = var.winrm_username
    use_proxy     = false
    # Controller-side ansible forks worker processes; on macOS controllers
    # the ObjC runtime kills forked children ("A worker was found in a
    # dead state") unless fork-safety is disabled.  Harmless elsewhere.
    ansible_env_vars = ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES"]
    extra_arguments = [
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_transport=basic"
    ]
  }
__SMOKE_TEST_BLOCK____TEST_COMPONENTS_BLOCK__
  # Re-lock WinRM before the snapshot: the build's userdata enabled Basic
  # auth + unencrypted HTTP so the communicator could get in; the shipped
  # image must not carry that weakening.  Runs last — nothing after this
  # needs the communicator.
  provisioner "powershell" {
    inline = [
      "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $false",
      "Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false",
      "# Randomize the Administrator password before snapshot: userdata set it",
      "# to winrm_password for the build; without this every instance launched",
      "# from the image would share that build-time password. Build a 16-char",
      "# password that guarantees one of each complexity class (upper/lower/",
      "# digit/symbol) so Windows complexity rules can never reject it.",
      "$u = 1..4 | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 91) }",
      "$l = 1..4 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) }",
      "$d = 1..4 | ForEach-Object { [char](Get-Random -Minimum 48 -Maximum 58) }",
      "$s = 1..4 | ForEach-Object { [char]@(33,35,36,37,38,42,43,45,61,63,64,95)[(Get-Random -Maximum 12)] }",
      "$newpass = -join (($u + $l + $d + $s) | Sort-Object { Get-Random })",
      "net user Administrator $newpass | Out-Null",
      "if ($LASTEXITCODE -ne 0) { Write-Error '[ciscvm] FAILED to set Administrator password (exit ' + $LASTEXITCODE + ')'; exit 1 }",
      "# Remove the build-time WinRM firewall guard rule (image ships hardened).",
      "Remove-NetFirewallRule -DisplayName 'ciscvm-winrm-build-5985' -ErrorAction SilentlyContinue",
      "Write-Host '[ciscvm] winrm re-locked: basic auth + unencrypted HTTP off; Administrator password randomized; guard rule removed'"
    ]
  }
}
"""

# ── Linux SITE_YML (ansible-local: localhost) ──
SITE_YML_TEMPLATE = r"""---
# CIS apply — bundled cis-os engine (gate disabled; re-audited after reboot)
- name: "CIS __OS_NAME__ - apply (__CIS_LEVEL__)"
  hosts: localhost
  connection: local
  become: true
  vars:
    cis_mode: __CIS_MODE__
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: 0
    cis_include: __CIS_INCLUDE__
    cis_exclude: __CIS_EXCLUDE__
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

SITE_AUDIT_TEMPLATE = r"""---
# CIS re-audit after reboot — gate active
# cis_mode is 'scan' (read-only). The engine only accepts scan|apply;
# a literal 'audit' would fail the preflight validation.
- name: "CIS __OS_NAME__ - audit after reboot (__CIS_LEVEL__)"
  hosts: localhost
  connection: local
  become: true
  vars:
    cis_mode: scan
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: __MIN_SCORE__
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

# ── Windows SITE_YML (controller-side ansible → winrm) ──
SITE_YML_WIN_TEMPLATE = r"""---
# CIS __CIS_MODE__ — bundled cis-os engine (PowerShell)
# Gate via cis_min_score (findings-only gate stays off: some controls are
# always manual/disruptive and would block every build).
- name: "CIS __OS_NAME__ - __CIS_MODE__ (__CIS_LEVEL__)"
  hosts: all
  gather_facts: true
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: basic
    cis_mode: __CIS_MODE__
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: __MIN_SCORE__
    cis_include: __CIS_INCLUDE__
    cis_exclude: __CIS_EXCLUDE__
    # Fetch result.json back to the controller (ansible/reports/) so build
    # logs don't lose the per-rule detail when the ephemeral VM is destroyed.
    cis_report_json: true
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

# ── Linux install-ansible.sh (Packer shell provisioner) ──
INSTALL_SH_TEMPLATE = r"""#!/usr/bin/env bash
# Install ansible-core inside the ephemeral CVM (Packer shell provisioner).
# CIS roles are uploaded by ciscvm — no ansible-galaxy needed.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ── Hostname DNS safeguard ──
# TencentOS cloud images ship /etc/hosts with only "127.0.0.1 localhost".
# After CIS hardening modifies firewall / resolv.conf, internal DNS may
# become unreachable.  Every sudo call then triggers a PAM gethostbyname
# that falls through /etc/hosts (hostname not present) → DNS timeout
# (5-30s per call).  We fix this ONCE here, before any sudo or hardening,
# so every downstream provisioner (ssh-guard, fix-logperms, finalize)
# inherits the fix for free.
__HOSTS_FIX__

# 1. System dependencies.
#    Refreshing package indexes (apt-get update / dnf makecache) is one of
#    the slowest steps and is pure waste when the base
#    image already ships python3 venv + pip. Probe first, only touch the
#    package manager when something is actually missing.
need_pkgs=0
# venv module + ensurepip must both work to build the ansible venv offline
python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || need_pkgs=1
if [ "$need_pkgs" = "1" ]; then
    echo "==> base deps missing, refreshing package manager"
    # Cloud-init (and other boot-time jobs) may still be running apt-get on
    # first connect — grabbing the dpkg lock races them and dies with
    # "Could not get lock /var/lib/dpkg/lock-frontend".  Wait for the lock
    # instead of failing (up to 5 min; no-op on rpm systems).
    # NB: use pgrep (procps, preinstalled everywhere) — fuser (psmisc) is
    # NOT installed on ubuntu cloud images, so a fuser-based check would
    # silently no-op and we would race the lock again.
    _dpkg_locked() {
        if pgrep -x apt-get >/dev/null 2>&1 || pgrep -x apt >/dev/null 2>&1 \
           || pgrep -x unattended-upgr >/dev/null 2>&1 || pgrep -x unattended-upgrade >/dev/null 2>&1 \
           || pgrep -x dpkg >/dev/null 2>&1; then
            return 0
        fi
        for _lk in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
            [ -e "$_lk" ] || continue
            if command -v fuser >/dev/null 2>&1; then
                if fuser "$_lk" >/dev/null 2>&1; then return 0; fi
            elif command -v flock >/dev/null 2>&1; then
                if ! flock -n "$_lk" true >/dev/null 2>&1; then return 0; fi
            fi
        done
        return 1
    }
    # Stop scheduled apt jobs BEFORE waiting; otherwise an active
    # unattended-upgrade can hold the lock for the whole timeout.
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl stop unattended-upgrades.service        >/dev/null 2>&1 || true
        sudo systemctl stop apt-daily.service apt-daily.timer   >/dev/null 2>&1 || true
        sudo systemctl stop apt-daily-upgrade.service apt-daily-upgrade.timer >/dev/null 2>&1 || true
    fi
    for _w in $(seq 1 120); do
        if ! _dpkg_locked; then
            break
        fi
        echo "==> package manager busy (cloud-init/unattended-upgrades?), waiting... ($_w/120)"
        sleep 5
    done
    __PKG_UPDATE__
    __PKG_INSTALL__
else
    echo "==> base deps (python3-venv, pip) already present — skipping pkg refresh"
fi

# 2. Pick a Python >=3.8 (ansible-core >=2.12 requires it; RHEL 8 / TencentOS 3 ship 3.6)
# NOTE: Python 3.12 has a multiprocessing atexit bug (FileNotFoundError for
# /tmp/pymp-*) that breaks ansible-local. We skip 3.12 and prefer 3.9-3.11.
PY=
for candidate in python3.11 python3.10 python3.9 python3; do
    if command -v "$candidate" &>/dev/null && \
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
        PY="$candidate"
        break
    fi
done

if [ -z "$PY" ]; then
    echo "==> No Python >=3.8 found, trying to install python39..."
    (sudo dnf install -y python39 2>/dev/null || \
     sudo yum install -y python39 2>/dev/null || \
     (sudo apt-get update -qq && sudo apt-get install -y python3.9 python3.9-venv) 2>/dev/null || true)
    for candidate in python3.9 python3.10 python3.11; do
        if command -v "$candidate" &>/dev/null && \
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    done
    # Last resort: Python 3.12 (has known multiprocessing bug, but better than nothing)
    if [ -z "$PY" ] && command -v python3.12 &>/dev/null; then
        PY=python3.12
        echo "==> WARNING: Using Python 3.12 (known multiprocessing atexit bug) — install python3.9 if builds fail" >&2
    fi
fi

if [ -z "$PY" ]; then
    echo "ERROR: Failed to find or install Python >=3.8.  Install it manually and retry." >&2
    exit 1
fi
echo "==> Using $($PY --version) for ansible venv"

# 3. Ansible in a dedicated venv so we do not mutate system pip.
#    Single pip run (no separate --upgrade pip round-trip) + disabled
#    version check keeps this to one network install pass.
VENV=/opt/ciscvm-ansible
sudo "$PY" -m venv "$VENV"
# v0.14.33: Ubuntu builds connect as the 'ubuntu' user — hand /opt/ciscvm-
# ansible over to the connecting user so the later shell provisioners
# (ssh-guard.sh, reboot.sh, ...) can scp their scripts there.
sudo chown -R "$USER" "$VENV"
# Non-/tmp scratch space for ansible (modular ansiballz payload cache via
# TMPDIR).  /tmp on TencentOS 4 can be tmpfs/swept and payload reuse then
# fails mid-run — keep it on stable root-disk storage instead.
sudo mkdir -p "$VENV/tmp"
sudo "$VENV/bin/python" -m pip install --disable-pip-version-check \
    __PIP_INDEX_FLAG__ '__ANSIBLE_CORE_SPEC__' pexpect passlib

# Wrap ansible-playbook so the controller process runs with TMPDIR off /tmp.
# ansible-core >=2.16 (modular ansiballz) caches module payloads under
# tempfile.gettempdir(); on TencentOS 4 that cache is unreliable.
sudo mv "$VENV/bin/ansible-playbook" "$VENV/bin/ansible-playbook.real"
sudo tee "$VENV/bin/ansible-playbook" > /dev/null <<'APB_EOF'
#!/usr/bin/env bash
export TMPDIR=/opt/ciscvm-ansible/tmp
exec /opt/ciscvm-ansible/bin/ansible-playbook.real "$@"
APB_EOF
sudo chmod +x "$VENV/bin/ansible-playbook"

# 4. Create a non-root build user.  CIS rules can disable root SSH login
#    (e.g. PermitRootLogin no); Packer reconnects as this user after the
#    reboot, so the build can never lock itself out.  The user inherits the
#    same authorized_keys as the current SSH user (root on TencentOS).
BUILD_USER=ciscvm
if ! id "$BUILD_USER" >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash "$BUILD_USER"
fi
# Passwordless sudo for the build user (cis role needs root on the target).
if [ ! -f /etc/sudoers.d/ciscvm-build ]; then
    echo "$BUILD_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/ciscvm-build >/dev/null
    sudo chmod 440 /etc/sudoers.d/ciscvm-build
fi
# Inherit the current user's SSH keys so Packer's keypair works after reboot.
CUR_USER=$(whoami)
if [ "$CUR_USER" != "$BUILD_USER" ] && [ -f "/home/$CUR_USER/.ssh/authorized_keys" ]; then
    sudo mkdir -p "/home/$BUILD_USER/.ssh"
    sudo cp "/home/$CUR_USER/.ssh/authorized_keys" "/home/$BUILD_USER/.ssh/authorized_keys"
    sudo chown -R "$BUILD_USER:$BUILD_USER" "/home/$BUILD_USER/.ssh"
    sudo chmod 700 "/home/$BUILD_USER/.ssh"
    sudo chmod 600 "/home/$BUILD_USER/.ssh/authorized_keys"
elif [ "$CUR_USER" = "root" ] && [ -f /root/.ssh/authorized_keys ]; then
    sudo mkdir -p "/home/$BUILD_USER/.ssh"
    sudo cp /root/.ssh/authorized_keys "/home/$BUILD_USER/.ssh/authorized_keys"
    sudo chown -R "$BUILD_USER:$BUILD_USER" "/home/$BUILD_USER/.ssh"
    sudo chmod 700 "/home/$BUILD_USER/.ssh"
    sudo chmod 600 "/home/$BUILD_USER/.ssh/authorized_keys"
fi
# Ubuntu cloud images may carry an already-expired provisioning account.
# Keep the ephemeral Packer login valid while CIS hardening runs.
if [ "$CUR_USER" != "root" ] && command -v chage >/dev/null 2>&1; then
    sudo chage -M 99999 -I -1 -E -1 "$CUR_USER" >/dev/null 2>&1 || true
fi
echo "build user '$BUILD_USER' ready (sudo + shared SSH key)"

# 4.5 Pre-install common CIS dependency packages in a single batch.
#     Without this the CIS engine installs each package via a separate
#     dnf transaction (metadata sync + download + install = 10-30s each).
#     Batching all into one call cuts many minutes from the apply phase.
#     Use --skip-broken so unavailable packages don't block the build.
__CIS_PKG_BATCH_INSTALL__

echo "ansible ready in $VENV (cis-os engine)"
"""


# ── Linux ciscvm-finalize.sh (writes banner, motd, /opt report) ──
# Runs as the last user-visible step before Packer snapshots the image.
# Reads /opt/ciscvm-AUDIT-RESULT.json (persisted by provisioner #7.5)
# and emits:
#   /etc/ciscvm/banner                              — pre-login SSH banner
#   /etc/motd                                       — post-login message
#   /etc/issue, /etc/issue.net                      — console login banner
#   /etc/ssh/sshd_config.d/99-ciscvm-banner.conf    — wires the SSH Banner
#   /opt/ciscvm-REPORT.md                           — full hardening report
#   /usr/local/bin/ciscvm-info                      — helper to view the report
#
# Banner art with REAL escape characters (the template below is a raw
# string, and the quoted heredoc performs no escape interpretation — a
# literal "\x1b" in the template would land as garbage text in the file).
_BANNER_ART = (
    "\x1b[38;5;117m              .---..---.\x1b[0m\n"
    "\x1b[38;5;117m          .-'          '-.           \x1b[1;37mSECX  SERIES\x1b[0m\n"
    "\x1b[38;5;75m        .'                '.         \x1b[38;5;75m  ___ ___  ___  ___\x1b[0m\n"
    "\x1b[1;38;5;75m      .'                    '.       \x1b[1;38;5;75m / __/ _ \\/ __|/ __|\x1b[0m\n"
    "\x1b[1;38;5;75m     /         ()    ()       \\      \x1b[1;38;5;75m| (_| (_) \\__ \\ (__ \x1b[0m\n"
    "\x1b[1;38;5;75m    |                        |      \x1b[1;38;5;75m \\___\\___/|___/\\___|\x1b[0m\n"
    "\x1b[1;38;5;33m     \\                      /       \x1b[37m  CIS-HARDENED IMAGE BUILDER\x1b[0m\n"
    "\x1b[1;38;5;33m      '.                  .'\n"
    "\x1b[1;38;5;33m        '.              .'\n"
    "\x1b[1;38;5;33m          '---.------.---'"
)

FINALIZE_SH_TEMPLATE = r"""#!/usr/bin/env bash
# ciscv finalize — banner + /opt report.
# Usage: ciscvm-finalize.sh <source_image_id> <image_name> <os_tag> <cis_level> <benchmark> <ciscvm_version>
set -euo pipefail

SRC_IMG="$1"; IMG_NAME="$2"; OS_TAG="$3"; CIS_LEVEL="$4"; BENCH="$5"; VER="$6"
AUDIT="/opt/ciscvm-AUDIT-RESULT.json"
REPORT="/opt/ciscvm-REPORT.md"
BUILD_TS="$(date -u +%FT%TZ)"

# ── Hostname DNS safeguard (belt-and-suspenders with fix-logperms) ──
__HOSTS_FIX__

# ── Progress bar: fine-grained steps with percentage ──
_TOTAL=16; _N=0
_bar() {
    _N=$((_N + 1))
    local pct=$((_N * 100 / _TOTAL)) w=$((_N * 24 / _TOTAL)) i=0 bar=""
    while [ "$i" -lt "$w" ]; do bar="${bar}█"; i=$((i+1)); done
    while [ "$i" -lt 24 ]; do bar="${bar}░"; i=$((i+1)); done
    printf "\r=== [%s] %3d%% (%2d/%2d) %s ===\n" "$bar" "$pct" "$_N" "$_TOTAL" "$*"
}

# 1. Banner
_bar "banner: /etc/ciscvm/banner"
sudo install -d -m 0755 /etc/ciscvm

sudo tee /etc/ciscvm/banner > /dev/null <<'BANNER_EOF'
__BANNER_ART__
BANNER_EOF
_bar "banner perms"
sudo chmod 0644 /etc/ciscvm/banner
_bar "motd"

# 2. /etc/motd — post-login message (with build metadata)
{
    cat /etc/ciscvm/banner
    printf '\n'
    printf '\x1b[1mImage:\x1b[0m     %s\n' "__IMAGE_NAME__"
    printf '\x1b[1mSource:\x1b[0m    %s\n' "__SOURCE_IMAGE__"
    printf '\x1b[1mOS/Level:\x1b[0m  %s / %s\n' "__IMAGE_OS__" "__CIS_LEVEL__"
    printf '\x1b[1mBenchmark:\x1b[0m %s\n' "__IMAGE_BENCHMARK__"
    printf '\x1b[1mBuilt:\x1b[0m     %s by ciscv %s\n\n' "$BUILD_TS" "__CISCVM_VERSION__"
    printf '\x1b[33m[ REPORT  ]\x1b[0m cat /opt/ciscvm-REPORT.md     (or run: ciscvm-info)\n'
    printf '\x1b[33m[ ADMIN   ]\x1b[0m ssh ciscvm@<host>            (root login disabled per CIS 5.1.22)\n'
    printf '\x1b[33m[ ESCALATE]\x1b[0m sudo -i                        (NOPASSWD via /etc/sudoers.d/ciscvm-build)\n'
} | sudo tee /etc/motd > /dev/null
_bar "motd perms"
sudo chmod 0644 /etc/motd

_bar "issue + issue.net"
# 3. /etc/issue, /etc/issue.net — console
#    colour escape sequences render as garbage on serial consoles).
{
    printf 'ciscv  CIS-HARDENED IMAGE BUILDER  --  %s\n' "__IMAGE_NAME__"
    printf 'OS/Level: %s / %s   Benchmark: %s\n' "__IMAGE_OS__" "__CIS_LEVEL__" "__IMAGE_BENCHMARK__"
    printf 'Built:    %s   by ciscv %s\n' "$BUILD_TS" "__CISCVM_VERSION__"
    printf 'Report:   /opt/ciscvm-REPORT.md  (run "ciscvm-info")\n'
    printf 'Admin:    ssh ciscvm@<host>      (root login disabled per CIS)\n'
} | sudo tee /etc/issue      > /dev/null
_bar "issue.net"
{
    printf 'ciscv  CIS-HARDENED IMAGE BUILDER  --  %s\n' "__IMAGE_NAME__"
    printf 'OS/Level: %s / %s   Built: %s by ciscv %s\n' "__IMAGE_OS__" "__CIS_LEVEL__" "$BUILD_TS" "__CISCVM_VERSION__"
    printf 'Report: /opt/ciscvm-REPORT.md\n'
} | sudo tee /etc/issue.net  > /dev/null
_bar "issue perms"
sudo chmod 0644 /etc/issue /etc/issue.net

# 3.5 Fix log-file permissions that may have been loosened by
#      cloud-init / boot-time service recreation.  The CIS engine
#      flags these in the re-audit, but they are not real hardening
#      gaps — just transient artifacts recreated on every boot.
_bar "fix boot-log perms"
_bar "  cloud-init log"
for f in /var/log/cloud-init.log /var/log/cloud-init-output.log \
         /var/log/wtmp /var/log/btmp; do
    [ -f "$f" ] && sudo chmod 0640 "$f" 2>/dev/null || true
done

# 4. Wire the banner into sshd (drop-in; survives sshd_config rewrites by CIS).
#    We write the config now but do NOT reload sshd — a reload would kill the
#    Packer SSH session, aborting the rest of the script.  The drop-in takes
#    effect on the first boot of any instance launched from this image.
_bar "sshd drop-in dir"
sudo install -d -m 0755 /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/99-ciscvm-banner.conf > /dev/null <<'SSHD_EOF'
# ciscv — show the build banner before authentication.
# Patched on top of CIS hardening by ciscvm-finalize.sh.
Banner /etc/ciscvm/banner
SSHD_EOF
_bar "sshd drop-in perms"
sudo chmod 0644 /etc/ssh/sshd_config.d/99-ciscvm-banner.conf

# 5. /opt/ciscvm-REPORT.md — what was done to the base image
_bar "generate REPORT.md"
_bar "  running Python"
sudo /opt/ciscvm-ansible/bin/python - "$SRC_IMG" "$IMG_NAME" "$OS_TAG" "$CIS_LEVEL" "$BENCH" "$VER" "$BUILD_TS" "$AUDIT" "$REPORT" <<'PY_EOF'
import json, os, shutil, subprocess, sys, tempfile
src, name, os_tag, level, bench, ver, ts, audit_p, report_p = sys.argv[1:10]
try:
    with open(audit_p) as f:
        a = json.load(f)
except Exception:
    a = {}
s = (a.get("summary") or {}).get("all") or {}
total      = s.get("total", 0)
applied    = s.get("applied", 0)
pending    = s.get("applied_pending", 0)
failed     = s.get("apply_failed", 0)
disruptive = s.get("skipped_disruptive", 0)
score      = a.get("score", "?")
mode       = a.get("mode", "scan")
results    = a.get("results") or []

def _short(r):
    return "- `{}` {}".format(r.get("id", "?"), (r.get("title") or "")[:80])
fails = [r for r in results if r.get("status") == "fail"]
pends = [r for r in results if r.get("status") == "applied_pending"]
errs  = [r for r in results if r.get("status") == "error"]
disc  = [r for r in results if (r.get("apply_status") or "") == "skipped_disruptive"
         or (r.get("risk") == "disruptive" and r.get("status") == "fail"
             and r.get("apply_status") == "not_applied")]

lines = []
# cis_level_tag is e.g. "level1-server"; the engine's --profile token is "L1".
level_num = level.replace("level", "").replace("-server", "")
level_short = "L" + level_num
lines.append("# ciscv — CIS Hardening Report")
lines.append("")
lines.append("This image was hardened by **ciscv** (CIS-hardened image builder).")
lines.append("It documents what was done to the base image and how to use the system.")
lines.append("")
lines.append("## Build metadata")
lines.append("")
lines.append("| Field        | Value |")
lines.append("|--------------|-------|")
lines.append("| Final image  | `{}` |".format(name))
lines.append("| Source image | `{}` |".format(src))
lines.append("| OS / Level   | `{}` / `{}` |".format(os_tag, level))
lines.append("| Benchmark    | `{}` |".format(bench))
lines.append("| Built at     | `{}` |".format(ts))
lines.append("| ciscv ver.   | `{}` |".format(ver))
lines.append("| Re-audit     | `{}` (score `{}%`) |".format(mode, score))
lines.append("")
lines.append("## What ciscv did")
lines.append("")
lines.append("Starting from the public source image `{}`, ciscv:".format(src))
lines.append("")
lines.append("1. **Provisioned** a dedicated non-root build user `ciscvm`")
lines.append("   (passwordless sudo via `/etc/sudoers.d/ciscvm-build`, root SSH login")
lines.append("   is disabled per CIS 5.1.22 / 5.2.10).")
lines.append("2. **Applied the CIS engine** (`cis_engine.py` + `rules.json` for `{}`)".format(os_tag))
lines.append("   against every {} rule, tagging destructive fixes as `disruptive`".format(level_short))
lines.append("   so they are NOT auto-applied.")
lines.append("3. **Rebooted** the instance to materialise kernel / audit / selinux settings.")
lines.append("4. **Re-audited** (`{}` mode) and persisted the result here.".format(mode))
lines.append("5. **Finalised**: installed the banner, motd and this report; locked the")
lines.append("   SSH channel back to the CIS target state (root key login disabled,")
lines.append("   `ciscvm` user is the supported admin channel).")
lines.append("")
lines.append("## Hardening summary")
lines.append("")
lines.append("| Metric                  | Count |")
lines.append("|-------------------------|-------|")
lines.append("| Total {} rules checked | {} |".format(level_short, total))
lines.append("| Auto-remediated         | {} |".format(applied))
lines.append("| Pending reboot / verify | {} |".format(pending))
lines.append("| Apply failed            | {} |".format(failed))
lines.append("| Skipped (disruptive)    | {} |".format(disruptive))
if errs:
    lines.append("| Errors                  | {} |".format(len(errs)))
lines.append("| **Final score**         | **{}%** |".format(score))
lines.append("")

if fails:
    lines.append("## Outstanding failures (need follow-up)")
    lines.append("")
    lines.extend(_short(r) for r in fails[:15])
    if len(fails) > 15:
        lines.append("")
        lines.append("_... and {} more._".format(len(fails) - 15))
    lines.append("")

if pends:
    lines.append("## Pending reboot / verify (already applied, will show pass next boot)")
    lines.append("")
    lines.extend(_short(r) for r in pends[:10])
    if len(pends) > 10:
        lines.append("")
        lines.append("_... and {} more._".format(len(pends) - 10))
    lines.append("")

if disc:
    lines.append("## Skipped — disruptive / known exceptions (opt-in)")
    lines.append("")
    lines.append("These rules were skipped because they would break an active service or")
    lines.append("require a manual decision. Remediate them in your own control plane.")
    lines.append("")
    lines.append("Common confirmed exceptions on this platform:")
    lines.append("")
    lines.append("- **System-wide crypto policy stays LEGACY** (CIS 1.6.1): TencentOS")
    lines.append("  ships LEGACY for legacy client compatibility. SSH-specific crypto")
    lines.append("  (CIS 1.6.3-1.6.6) is hardened via the sshd drop-in instead, so the")
    lines.append("  SSH channel is still strong without affecting other services.")
    lines.append("- **`/dev/shm` without `noexec`** (CIS 1.1.2.2.4): applications that")
    lines.append("  execute from shared memory (Java, some databases) break if it is")
    lines.append("  enabled. Track as an accepted risk, or apply `noexec` only where")
    lines.append("  workloads are known safe.")
    lines.append("- **`systemd-journal-upload` inactive** (CIS 6.2.1.2.3): the service")
    lines.append("  is enabled but needs a configured remote log server")
    lines.append("  (`UploadURL` in `/etc/systemd/journal-upload.conf`) to stay active.")
    lines.append("")
    if disruptive:
        lines.append("_({} rule(s) total skipped)_".format(disruptive))
    lines.append("")

lines.append("## How to use this image")
lines.append("")
lines.append("```bash")
lines.append("# 1. Log in as the dedicated build user (root is disabled per CIS)")
lines.append("ssh ciscvm@<host>")
lines.append("")
lines.append("# 2. View this report any time")
lines.append("cat /opt/ciscvm-REPORT.md          # this file")
lines.append("ciscvm-info                        # summary one-liner")
lines.append("")
lines.append("# 3. Escalate to root when needed")
lines.append("sudo -i")
lines.append("")
lines.append("# 4. Re-run the scan on this machine")
lines.append("sudo /opt/ciscvm-ansible/bin/python \\")
lines.append("  /opt/ciscvm-ansible/roles/cis_*/files/cis_engine.py \\")
lines.append("  --catalog /opt/ciscvm-ansible/roles/cis_*/files/rules.json \\")
lines.append("  --mode scan --profile {} --out /tmp/cis-recheck.json".format(level_short))
lines.append("```")
lines.append("")
lines.append("## Files left behind by ciscv")
lines.append("")
lines.append("| Path | Purpose |")
lines.append("|------|---------|")
lines.append("| `/etc/ciscvm/banner` | The login banner (also in `/etc/motd`, `/etc/issue`). |")
lines.append("| `/etc/ssh/sshd_config.d/99-ciscvm-banner.conf` | SSH `Banner` directive. |")
lines.append("| `/opt/ciscvm-AUDIT-RESULT.json` | Raw JSON output of the re-audit. |")
lines.append("| `/opt/ciscvm-ansible/` | The ciscv engine + bundled role (kept for re-audits). |")
lines.append("| `/etc/sudoers.d/ciscvm-build` | NOPASSWD sudo for the `ciscvm` user. |")
lines.append("")
lines.append("---")
lines.append("")
lines.append("Generated by **ciscv {}** on `{}`.".format(ver, ts))
content = "\n".join(lines) + "\n"
with tempfile.NamedTemporaryFile("w", delete=False, suffix=".md") as fh:
    fh.write(content)
    tmp = fh.name
# This heredoc already runs as root (via sudo python); install copies
# (never moves), so the temp file must be unlinked explicitly afterwards.
try:
    subprocess.run(["install", "-m", "0644", "-o", "root", "-g", "root",
                    tmp, report_p], check=True)
except (subprocess.CalledProcessError, FileNotFoundError):
    # Fallback for environments without a root group (local test runs).
    shutil.copy2(tmp, report_p)
    os.chmod(report_p, 0o644)
print("[ciscvm-finalize] _step wrote REPORT.md to /opt/")
os.unlink(tmp)
PY_EOF
_bar "install REPORT to /opt"
sudo chmod 0644 /opt/ciscvm-REPORT.md

# 6. /usr/local/bin/ciscvm-info — one-shot summary command
_bar "ciscvm-info helper"
sudo tee /usr/local/bin/ciscvm-info > /dev/null <<'INFO_EOF'
#!/usr/bin/env bash
# ciscvm-info — show a short summary of this image's CIS hardening.
set -euo pipefail
REPORT="/opt/ciscvm-REPORT.md"
if [ ! -f "$REPORT" ]; then
    echo "ciscvm-info: $REPORT not found" >&2
    exit 1
fi
awk '
    /^## Build metadata$/ {flag=1; next}
    /^## / {flag=0}
    flag && /^\|/ {print}
' "$REPORT"
echo
echo "Full report: cat $REPORT  (or 'less $REPORT')"
INFO_EOF
sudo chmod 0755 /usr/local/bin/ciscvm-info

_bar "done"
echo "[ciscvm] finalize complete: banner + motd + /opt/ciscvm-REPORT.md"
"""


def render_finalize(r: ResolvedConfig, p: dict[str, Any],
                    image_name: str | None = None) -> str:
    """Generate ciscvm-finalize.sh for Linux profiles.

    Substitutes the build's actual metadata into the finalize script.
    image_name comes from _image_name() — the same value Packer uses.
    """
    if image_name is None:
        image_name = _image_name(r)
    return (
        FINALIZE_SH_TEMPLATE
        .replace("__BANNER_ART__", _BANNER_ART)
        .replace("__HOSTS_FIX__", HOSTS_FIX_SNIPPET)
        .replace("__SOURCE_IMAGE__", r.source_image_id)
        .replace("__IMAGE_NAME__", image_name)
        .replace("__IMAGE_OS__", r.image_os_tag)
        .replace("__CIS_LEVEL__", r.cis_level_tag)
        .replace("__IMAGE_BENCHMARK__", r.image_benchmark)
        .replace("__CISCVM_VERSION__", VERSION)
    )


# ---------------------------------------------------------------------------
# Render functions
# ---------------------------------------------------------------------------
def _format_hcl_value(value: Any) -> str:
    """Format a Python value as valid HCL."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        # json.dumps escapes quotes/backslashes; valid for HCL string lists.
        return json.dumps(value, ensure_ascii=False)
    # Escape backslashes and double quotes so arbitrary strings can't break
    # out of the HCL string literal (or inject HCL).
    text = str(value)
    if "\n" in text:
        raise ConfigError("HCL string values cannot contain newlines")
    if "${" in text or "%%{" in text:
        raise ConfigError("HCL string values cannot contain interpolation sequences (${ or %%{)")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _image_name(r: ResolvedConfig) -> str:
    """Single source of truth for the image name.

    [image].name, when set, is used verbatim; otherwise the name is
    computed once in Python (24-hour UTC clock) and passed to Packer as a
    plain variable, so the name baked into the in-image banner/motd/report
    always matches the actual image name.  (Packer's own
    `formatdate("YYYYMMDD-hhmmss", timestamp())` used a 12-hour clock and
    evaluated at a different moment, so the two never agreed.)
    """
    if r.image_name_override:
        return r.image_name_override
    from datetime import datetime
    snap_ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    level_short = r.cis_level_tag.replace("-server", "")
    return f"{r.image_name_prefix}-{level_short}-{snap_ts}"


def render_pkrvars(r: ResolvedConfig, image_name: str | None = None) -> str:
    """Generate auto.pkrvars.hcl content."""
    if image_name is None:
        image_name = _image_name(r)
    flat: dict[str, Any] = {
        "region": r.region,
        "zone": r.zone,
        "instance_type": r.instance_type,
        "source_image_id": r.source_image_id,
        "vpc_id": r.vpc_id,
        "subnet_id": r.subnet_id,
        "security_group_id": r.security_group_id,
        "associate_public_ip_address": r.associate_public_ip,
        "image_name_prefix": r.image_name_prefix,
        "image_name": image_name,
        "image_copy_regions": r.image_copy_regions,
        "cis_level": r.cis_level_tag,
        "image_os_tag": r.image_os_tag,
        "image_benchmark": r.image_benchmark,
    }

    if r.family == "windows":
        flat["winrm_username"] = r.winrm_username
    else:
        flat["ssh_username"] = r.ssh_username
        flat["ssh_port"] = r.ssh_port
        flat["ssh_timeout"] = r.ssh_timeout

    return "\n".join(f"{k} = {_format_hcl_value(v)}" for k, v in flat.items()) + "\n"


def render_install(p: dict[str, Any]) -> str:
    """Generate install-ansible.sh for Linux profiles."""
    index_url = str(p.get("pip_index_url", ""))
    index_flag = f"-i {index_url}" if index_url else ""
    return (
        INSTALL_SH_TEMPLATE
        .replace("__HOSTS_FIX__", HOSTS_FIX_SNIPPET)
        .replace("__PKG_UPDATE__", str(p.get("pkg_update", "")))
        .replace("__PKG_INSTALL__", str(p.get("pkg_install", "")))
        .replace("__ANSIBLE_CORE_SPEC__", str(p.get("ansible_core_spec", "ansible-core>=2.15")))
        .replace("__CIS_PKG_BATCH_INSTALL__", str(p.get("cis_pkg_batch", "echo '(no CIS packages to pre-install)'")))
        .replace("__PIP_INDEX_FLAG__", index_flag)
    )


def render_site(p: dict[str, Any], level: int, mode: str = "apply",
                rules_include: list[str] | None = None,
                rules_exclude: list[str] | None = None,
                min_score: int = 85) -> str:
    """Generate ansible/site.yml.

    *mode* — "apply" (remediate) or "scan" (audit-only, no changes).
    *rules_include/rules_exclude* — optional rule-id filters forwarded to
    the engine's --include/--exclude (empty list = run all rules).
    *min_score* — gate threshold (Windows applies it in-role; Linux applies
    it in the post-reboot site-audit.yml via render_site_audit).
    """
    cis_level = f"L{level}"
    family = str(p.get("family", ""))

    if family == "windows":
        # Windows has no post-reboot re-audit — the gate lives in the single
        # apply/scan pass, so min_score/mode/include/exclude all land here.
        return (
            SITE_YML_WIN_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
            .replace("__CIS_MODE__", mode)
            .replace("__MIN_SCORE__", str(min_score))
            .replace("__CIS_INCLUDE__", _yaml_list(rules_include or []))
            .replace("__CIS_EXCLUDE__", _yaml_list(rules_exclude or []))
        )
    else:
        inc = rules_include or []
        exc = rules_exclude or []
        return (
            SITE_YML_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
            .replace("__CIS_MODE__", mode)
            .replace("__CIS_INCLUDE__", _yaml_list(inc))
            .replace("__CIS_EXCLUDE__", _yaml_list(exc))
        )


def _yaml_list(items: list[str]) -> str:
    """Render a Python list as an inline YAML list."""
    if not items:
        return "[]"
    return "[" + ", ".join(json.dumps(x, ensure_ascii=False) for x in items) + "]"


def render_site_audit(p: dict[str, Any], level: int, min_score: int = 85) -> str:
    """Generate ansible/site-audit.yml for post-reboot re-evaluation."""
    cis_level = f"L{level}"
    return (
        SITE_AUDIT_TEMPLATE
        .replace("__OS_NAME__", str(p["os_tag"]))
        .replace("__CIS_LEVEL__", cis_level)
        .replace("__ROLE_DIR__", str(p["role_dir"]))
        .replace("__MIN_SCORE__", str(min_score))
    )


def _assert_no_markers(content: str, filename: str) -> None:
    """Ensure no unreplaced __...__ template markers remain in rendered output."""
    markers = re.findall(r"__[A-Z_]+__", content)
    if markers:
        raise RuntimeError(
            f"Unreplaced markers in {filename}: {', '.join(sorted(set(markers)))}. "
            f"This is a bug — please report it."
        )


def _validate_env_var_name(name: str, field_label: str) -> None:
    """Env var names land inside HCL env("...") — reject anything that
    isn't a plain identifier so a malformed config can't break out of the
    string literal."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ConfigError(
            f"{field_label} must be a valid environment variable name, got {name!r}")


def _validate_shell_arg(value: str, field_label: str) -> None:
    """Values substituted into shell inline scripts must not contain shell
    metacharacters (they are embedded unquoted by design — the inline runs
    as root on the build VM)."""
    if re.search(r"['\"`$\\;|&<>(){}!\n]", value):
        raise ConfigError(
            f"{field_label} contains shell metacharacters: {value!r}. "
            "Use plain letters, digits, dot, dash, underscore only.")


def render_all(workdir: Path, r: ResolvedConfig, scan: bool = False,
               idempotency: bool = False) -> None:
    """Render the complete build directory.

    *scan* — audit-only mode: the engine runs with cis_mode=scan (no
    remediation) and the instance-level smoke test is skipped (the source
    image is not yet hardened, so hardening assertions would fail).
    *idempotency* — Linux only: re-run the apply playbook once more and
    fail the build if the second pass changes anything (Applied/Pending > 0).
    """
    p = r.profile
    family: str = r.family

    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled role into workspace
    _bundle_role(workdir, r.role_dir)

    # P1#5 — [cis].overrides: deep-merge per-rule parameter overrides into
    # the WORKSPACE copy of rules.json (the bundled catalog is never
    # mutated).  Mirrors ansible-lockdown's per-control vars without
    # touching the engine or shipping a second catalog.
    if r.rules_overrides:
        _apply_rule_overrides(workdir, r.role_dir, r.rules_overrides)

    # Computed once — pkrvars, HCL finalize args and the finalize script
    # itself all share this exact image name.
    image_name = _image_name(r)

    # Credential env var names are user-configurable ([cloud].secret_id_env);
    # validate before they land inside HCL env("...") calls.
    _validate_env_var_name(r.secret_id_env, "[cloud].secret_id_env")
    _validate_env_var_name(r.secret_key_env, "[cloud].secret_key_env")
    _validate_env_var_name(r.security_token_env, "[cloud].security_token_env")

    # Values substituted into the finalize inline shell command must be
    # shell-safe (single-quoting happens in the template).
    _validate_shell_arg(r.source_image_id, "[build].source_image_id")
    _validate_shell_arg(image_name, "image name")
    _validate_shell_arg(r.image_os_tag, "[meta].os_tag")
    _validate_shell_arg(r.cis_level_tag, "cis level")
    _validate_shell_arg(r.image_benchmark, "[meta].benchmark")

    # 2. HCL (Linux or Windows template)
    # [cloud].assume_role_arn — group-account CAM role assumption.  Renders a
    # HCL assume_role block when set; empty string renders nothing at all.
    if r.assume_role_arn:
        assume_role_block = (
            '  assume_role {\n'
            f'    role_arn         = "{r.assume_role_arn}"\n'
            f'    session_name     = "{r.assume_role_session}"\n'
            f'    session_duration = {r.assume_role_duration}\n'
            '  }\n'
        )
    else:
        assume_role_block = ""

    # Instance-level smoke test (build → test → distribute): any failure
    # aborts the build before Packer snapshots the image.
    # Linux profiles carry family == "" (only Windows sets "windows").
    # In scan (audit-only) mode the smoke test is skipped — the source image
    # is not yet hardened, so hardening assertions would falsely fail.
    if r.smoke_test and not scan:
        smoke_block = SMOKE_LINUX_BLOCK if family != "windows" else SMOKE_WIN_BLOCK
    else:
        smoke_block = ""

    # Supply-chain gates (Linux only, build mode): CVE scan + SBOM.
    # Spliced right after the smoke test, before the snapshot.
    supply_block = ""
    if not scan and family != "windows":
        if r.cve_scan:
            supply_block += CVE_SCAN_LINUX_BLOCK + "\n"
        if r.sbom:
            supply_block += SBOM_LINUX_BLOCK + "\n"

    # User test components ([meta].test_components) — build mode only.
    # Copy each script into the workdir (packer/scripts/test-components/),
    # upload via file provisioners, then run them sequentially.  A non-zero
    # exit aborts the build before the snapshot (#13).
    test_block = ""
    if not scan and r.test_components:
        tc_dir = workdir / "packer" / "scripts" / "test-components"
        tc_dir.mkdir(parents=True, exist_ok=True)
        # Non-root profiles (ubuntu) cannot write to /root — upload to the
        # ssh user's home instead, mirroring __REMOTE_DIR__ (v0.14.33).
        ssh_user = str(p.get("ssh_username", "root") or "root")
        remote_home = "/root" if ssh_user == "root" else f"/home/{ssh_user}"
        uploads: list[str] = []
        for i, script in enumerate(r.test_components):
            src = Path(script)
            if not src.is_file():
                raise ConfigError(
                    f"[meta].test_components: script not found: {script}")
            # keep the basename; prefix with an index so ordering survives
            # the copy and the packer file-upload naming.
            dest_name = f"{i:02d}-{src.name}"
            shutil.copyfile(src, tc_dir / dest_name)
            if family == "windows":
                uploads.append(
                    f'  provisioner "file" {{\n'
                    f'    source      = "packer/scripts/test-components/{dest_name}"\n'
                    f'    destination = "C:/ciscvm-test-components/{dest_name}"\n'
                    f'  }}\n')
            else:
                uploads.append(
                    f'  provisioner "file" {{\n'
                    f'    source      = "packer/scripts/test-components/{dest_name}"\n'
                    f'    destination = "{remote_home}/ciscvm-test-components/{dest_name}"\n'
                    f'  }}\n')
        test_uploads = "".join(uploads)
        runner = TEST_COMPONENTS_WIN_BLOCK if family == "windows" else TEST_COMPONENTS_LINUX_BLOCK
        test_block = test_uploads + runner
        info(f"User test components: {len(r.test_components)} script(s) will "
             f"run before the snapshot")

    # Idempotency verification (Linux only): re-run apply, fail if it changes.
    idempotency_block = IDEMPOTENCY_LINUX_BLOCK if (idempotency and family != "windows") else ""

    # [build].spot — use a spot instance for the ephemeral build VM.  The
    # build machine is short-lived and disposable, so the repossess risk is
    # acceptable and the cost saving (up to ~90% vs on-demand) is real (#15).
    # Packer's tencentcloud plugin accepts instance_charge_type = "SPOTPAID".
    spot_block = '  instance_charge_type = "SPOTPAID"\n' if r.spot else ""

    if family == "windows":
        if r.ssh_debug_password:
            warn("[meta].ssh_debug_password is ignored for Windows profiles "
                 "(it only applies to Linux user_data).")
        _validate_env_var_name(r.winrm_password_env, "[cloud].winrm_password_env")
        hcl = (HCL_WIN_TEMPLATE
               .replace("__WINRM_PASSWORD_ENV__", r.winrm_password_env)
               .replace("__SECRET_ID_ENV__", r.secret_id_env)
               .replace("__SECRET_KEY_ENV__", r.secret_key_env)
               .replace("__SECURITY_TOKEN_ENV__", r.security_token_env)
               .replace("__SMOKE_TEST_BLOCK__", smoke_block)
               .replace("__TEST_COMPONENTS_BLOCK__", test_block)
               .replace("__SPOT_BLOCK__", spot_block)
               .replace("__ASSUME_ROLE_BLOCK__", assume_role_block))
    else:
        # Substitute the build's actual metadata into the finalize provisioner
        # so the in-image banner/report show the right source/level/OS.
        hcl = (HCL_LINUX_TEMPLATE
               .replace("__CLEAN_CMD__", str(p["clean_cmd"]))
               .replace("__VERSION__", VERSION)
               .replace("__SOURCE_IMAGE__", r.source_image_id)
               .replace("__IMAGE_NAME__", image_name)
               .replace("__IMAGE_OS__", r.image_os_tag)
               .replace("__CIS_LEVEL__", r.cis_level_tag)
               .replace("__IMAGE_BENCHMARK__", r.image_benchmark)
               .replace("__CISCVM_VERSION__", VERSION)
               .replace("__CIS_PROFILE_SHORT__", f"L{r.level}")
               .replace("__HOSTS_FIX_HCL__", HOSTS_FIX_SNIPPET.replace('"', '\\"'))
               .replace("__SECRET_ID_ENV__", r.secret_id_env)
               .replace("__SECRET_KEY_ENV__", r.secret_key_env)
               .replace("__SECURITY_TOKEN_ENV__", r.security_token_env)
               .replace("__IDEMPOTENCY_BLOCK__", idempotency_block)
               .replace("__SMOKE_TEST_BLOCK__", smoke_block)
               .replace("__SUPPLY_CHAIN_BLOCK__", supply_block)
               .replace("__TEST_COMPONENTS_BLOCK__", test_block)
               .replace("__SPOT_BLOCK__", spot_block)
               .replace("__ASSUME_ROLE_BLOCK__", assume_role_block)
               # must run AFTER the smoke block is spliced in — the block
               # itself carries __REMOTE_DIR__ placeholders (v0.14.33)
               .replace("__REMOTE_DIR__",
                        "/root" if p.get("ssh_username", "root") == "root"
                        else f"/home/{p['ssh_username']}"))
        user_data = ""
        if r.ssh_debug_password:
            quoted = shlex.quote(f"root:{r.ssh_debug_password}")
            user_data = (
                '  user_data = <<EOF\n'
                '#!/bin/bash\n'
                f"echo {quoted} | chpasswd\n"
                'EOF\n'
            )
        hcl = hcl.replace("__USER_DATA_BLOCK__", user_data)
    _assert_no_markers(hcl, "main.pkr.hcl")
    hcl_path = workdir / "packer" / "main.pkr.hcl"
    hcl_path.write_text(hcl, encoding="utf-8")
    if r.ssh_debug_password:
        # The debug password is embedded in the HCL — restrict permissions.
        hcl_path.chmod(0o600)

    # 3. Vars
    (workdir / "packer" / "auto.pkrvars.hcl").write_text(
        render_pkrvars(r, image_name), encoding="utf-8")

    # 4. Ansible playbooks
    site = render_site(p, r.level, mode="scan" if scan else "apply",
                       rules_include=r.rules_include, rules_exclude=r.rules_exclude,
                       min_score=r.min_score)
    _assert_no_markers(site, "site.yml")
    (workdir / "ansible" / "site.yml").write_text(site, encoding="utf-8")

    if family != "windows":
        site_audit = render_site_audit(p, r.level, r.min_score)
        _assert_no_markers(site_audit, "site-audit.yml")
        (workdir / "ansible" / "site-audit.yml").write_text(site_audit, encoding="utf-8")

    # 5. Install script (Linux only)
    if family != "windows":
        install = render_install(p)
        _assert_no_markers(install, "install-ansible.sh")
        install_path = workdir / "packer" / "scripts" / "install-ansible.sh"
        install_path.write_text(install, encoding="utf-8")
        install_path.chmod(0o755)

    # 6. Finalize script — writes banner + /opt report (Linux only)
    if family != "windows":
        finalize = render_finalize(r, p, image_name)
        _assert_no_markers(finalize, "ciscvm-finalize.sh")
        finalize_path = workdir / "packer" / "scripts" / "ciscvm-finalize.sh"
        finalize_path.write_text(finalize, encoding="utf-8")
        finalize_path.chmod(0o755)


# ---------------------------------------------------------------------------
# Packer subprocess
# ---------------------------------------------------------------------------
PACKER_TIMEOUT_MINUTES = 120


def run_packer(
    workdir: Path,
    subcmd: str,
    quiet: bool = False,
    capture: bool = False,
    timeout: int | None = None,
    debug: bool = False,
    log_file: str | None = None,
) -> PackerResult:
    """Run `packer init` then `packer <subcmd>` inside *workdir*.

    When *log_file* is given, packer output is also written there (UTF-8,
    line-buffered).  ciscvm log messages (ok/fail/info/banner) are handled
    separately via the logger's FileHandler attached in cmd_build.
    """
    if timeout is None:
        timeout = PACKER_TIMEOUT_MINUTES * 60

    env = os.environ.copy()
    if debug:
        env["PACKER_LOG"] = "1"

    hcl_path = "packer/main.pkr.hcl"
    varfile_path = "packer/auto.pkrvars.hcl"

    # Use an ABSOLUTE cwd for every packer subprocess.  A relative cwd is
    # resolved against the parent process's cwd at spawn time; if that cwd is
    # ever removed/recreated mid-build (e.g. rebuild.sh rm -rf + clone), packer
    # inherits a stale cwd and its ansible-local prepare fails with
    # 'stat ansible/site-audit.yml: no such file or directory' even though the
    # file exists in the rendered workdir.
    workdir = Path(workdir).resolve()

    # 1. packer init
    # Plugin downloads can be tens of MB on a slow/proxied link; 60s was
    # too aggressive and produced a misleading "check network" error.
    try:
        init_res = subprocess.run(
            ["packer", "init", hcl_path],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except FileNotFoundError:
        fail("packer not found in PATH. Install from https://developer.hashicorp.com/packer/install")
        return PackerResult(exit_code=1)
    except subprocess.TimeoutExpired:
        fail("packer init timed out (300s). Check network / plugin registry access.")
        return PackerResult(exit_code=1)

    if init_res.returncode != 0:
        combined = (init_res.stdout or "") + (init_res.stderr or "")
        # init output is captured (not streamed) — surface it before failing.
        if combined.strip():
            print(combined.rstrip("\n"), file=sys.stderr)
        fail("packer init failed (see output above).")
        return PackerResult(
            exit_code=init_res.returncode,
            stdout_lines=combined.splitlines(),
        )

    # 2. packer <subcmd>
    cmd = ["packer", subcmd, f"-var-file={varfile_path}", hcl_path]
    try:
        if capture or quiet or log_file:
            # Capture output line-by-line with real-time streaming.  The
            # reader runs on a daemon thread: `for line in proc.stdout`
            # blocks until EOF, so a timeout enforced only via wait()
            # afterwards would never fire while the child keeps the pipe
            # open.  On timeout we kill() explicitly — Popen.__exit__ would
            # otherwise wait() with no timeout and hang forever.
            lines: list[str] = []
            proc = subprocess.Popen(
                cmd, cwd=str(workdir),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env,
            )

            def _reader() -> None:
                assert proc.stdout is not None
                if log_file:
                    with open(log_file, "a", encoding="utf-8") as log_fh:
                        for line in proc.stdout:
                            if not quiet:
                                print(line, end="", file=sys.stderr)
                            log_fh.write(line)
                            lines.append(line.rstrip("\n"))
                else:
                    for line in proc.stdout:
                        if not quiet:
                            print(line, end="", file=sys.stderr)
                        lines.append(line.rstrip("\n"))

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                reader.join(timeout=10)
                fail(f"packer {subcmd} timed out after {timeout // 60} minutes; "
                     "process killed.")
                return PackerResult(exit_code=1, stdout_lines=lines)
            reader.join(timeout=30)
            return PackerResult(exit_code=proc.returncode, stdout_lines=lines)
        else:
            # Inherit stdout/stderr from parent (live output, no capture).
            # subprocess.run kills the child itself on TimeoutExpired.
            cp = subprocess.run(cmd, cwd=workdir, timeout=timeout, env=env)
            return PackerResult(exit_code=cp.returncode)
    except subprocess.TimeoutExpired:
        fail(f"packer {subcmd} timed out after {timeout // 60} minutes.")
        return PackerResult(exit_code=1)
    except FileNotFoundError:
        fail("packer not found in PATH.")
        return PackerResult(exit_code=1)


# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
def run_preflight(r: ResolvedConfig) -> bool:
    """Run all pre-flight checks. Returns True if everything passes."""
    banner("preflight")
    all_ok = True
    family: str = r.family

    # Credentials
    for env_name in (r.secret_id_env, r.secret_key_env):
        if os.environ.get(env_name):
            ok(f"Credential env var {env_name} is set")
        else:
            fail(f"Credential env var {env_name} is not set (export before running)")
            all_ok = False

    if family == "windows":
        if os.environ.get(r.winrm_password_env):
            ok(f"WinRM password env var {r.winrm_password_env} is set")
        else:
            fail(f"WinRM password env var {r.winrm_password_env} is not set")
            all_ok = False
        if _check_ansible_windows_collection():
            ok("ansible.windows collection installed")
        else:
            fail("ansible.windows collection not found — install with: "
                 "ansible-galaxy collection install ansible.windows")
            all_ok = False
        if _check_pywinrm():
            ok("pywinrm importable (WinRM transport)")
        else:
            fail("pywinrm not installed for the ansible python — install with: "
                 "pip install pywinrm")
            all_ok = False

    # packer binary
    if shutil.which("packer"):
        ok("packer found in PATH")
    else:
        fail("packer not found in PATH — install from https://developer.hashicorp.com/packer/install")
        all_ok = False

    # Bundled role
    if _check_bundled_role(r.role_dir):
        ok(f"Bundled role '{r.role_dir}' ready ({Path(__file__).parent / 'roles' / r.role_dir})")
    else:
        fail(f"Bundled role directory missing: {r.role_dir}. "
             f"The package may be corrupted — reinstall ciscvm.")
        all_ok = False

    # Key parameters
    checks: list[tuple[str, Any]] = [
        ("region", r.region),
        ("zone", r.zone),
        ("instance_type", r.instance_type),
        ("source_image_id", r.source_image_id),
        ("vpc_id", r.vpc_id),
        ("subnet_id", r.subnet_id),
        ("security_group_id", r.security_group_id),
    ]
    for label, val in checks:
        err = _validate_value_present(label, val)
        if err is None:
            ok(f"{label} = {val}")
        else:
            fail(err)
            all_ok = False

    ok(f"profile={r.profile_name} (CIS Level {r.level}, {'winrm' if family == 'windows' else 'ssh'})")

    # P1#4 — benchmark pinning: warn when [meta].benchmark diverges from the
    # profile's default.  The value is embedded in image tags, the report,
    # lineage and provenance — a mismatch silently mislabels the audit.
    profile_bm = str(r.profile.get("benchmark", ""))
    if r.image_benchmark and profile_bm and r.image_benchmark != profile_bm:
        warn(f"[meta].benchmark '{r.image_benchmark}' differs from profile "
             f"default '{profile_bm}' — image tags will carry the override")
    elif not r.image_benchmark:
        warn("[meta].benchmark is empty — image tags/report will not name "
             "the CIS benchmark edition")

    if r.verify_boot and family == "windows":
        warn("[meta].verify_boot is Linux-only — it will be ignored for "
             "Windows builds")

    if all_ok:
        info("All pre-flight checks passed.")
    else:
        warn("Some pre-flight checks failed — fix before continuing.")
    return all_ok


def _is_interactive(stream: Any = sys.stdin) -> bool:
    """Check if the terminal is interactive (TTY)."""
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    """Generate a sample ciscvm.toml."""
    target = Path(args.target)
    target.mkdir(parents=True, exist_ok=True)
    cfg = target / "ciscvm.toml"

    if cfg.exists() and not args.force:
        fail(f"{cfg} already exists. Use --force to overwrite.")
        return 1

    cfg.write_text(SAMPLE_CONFIG, encoding="utf-8")

    # Add .gitignore
    gi = target / ".gitignore"
    ignore_lines = [f"{DEFAULT_WORKDIR}/", "ciscvm.toml", ""]
    if not gi.exists():
        gi.write_text("\n".join(ignore_lines), encoding="utf-8")
    else:
        existing = gi.read_text(encoding="utf-8")
        additions = [line for line in ignore_lines if line and line not in existing.splitlines()]
        if additions:
            gi.write_text(existing.rstrip() + "\n" + "\n".join(additions) + "\n", encoding="utf-8")

    banner("init")
    ok(f"Generated: {cfg}")
    info("Edit ciscvm.toml: fill in VPC/subnet/SG/source image ID.")
    info("Credentials go in environment variables, never in the config file.")
    info(f"Supported profiles: {PROFILE_NAMES_HELP}")
    info("Then run: ciscvm preflight / validate / build")
    return 0


def _load_resolve_preflight(config_path: str, workdir: str) -> tuple[ResolvedConfig, Path] | None:
    """Load config, resolve, run preflight. Returns (ResolvedConfig, workdir) or None on failure."""
    try:
        data = load_config(Path(config_path))
        r = resolve(data)
    except ConfigError as exc:
        fail(str(exc))
        return None

    if not run_preflight(r):
        return None

    # v0.16.5: resolve the render dir to an ABSOLUTE path BEFORE rendering.
    # render_all writes into it as given, and run_packer later re-resolves the
    # same Path — if the parent cwd changes between the two (rebuild.sh
    # rm -rf + clone churns the tree), a relative ".ciscvm-build" resolves to
    # a different directory and packer's ansible-local prepare fails with
    # 'stat ansible/site.yml: no such file' even though the file exists.
    wd = Path(workdir).resolve()
    wd.mkdir(parents=True, exist_ok=True)
    return r, wd


def cmd_preflight(args: argparse.Namespace) -> int:
    """Run pre-flight checks."""
    result = _load_resolve_preflight(args.config, args.workdir)
    return 0 if result is not None else 1


def cmd_validate(args: argparse.Namespace) -> int:
    """Render templates and run packer validate."""
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    render_all(workdir, r)

    banner("validate")
    info(f"Rendered working directory: {workdir}")
    info("Running packer init + packer validate ...")
    result = run_packer(workdir, "validate", quiet=args.quiet, debug=args.debug)

    # Output is already streamed live by run_packer (or surfaced on init
    # failure); do not re-print result.stdout_lines here.
    if result.exit_code == 0:
        ok("packer validate passed")
    else:
        fail("packer validate failed (see output above)")
    return result.exit_code


def cmd_build(args: argparse.Namespace) -> int:
    """Render templates and run packer build."""
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    # P1#7 — change detection: identical inputs + previous image still
    # exists → skip the rebuild entirely (scheduled-rebuild cost saver).
    if args.skip_if_unchanged:
        prev_fp, prev_images = _last_successful_fingerprint(r)
        if prev_fp is not None and prev_fp == _build_fingerprint(r):
            if _image_ids_still_exist(r.region, prev_images):
                ok(f"inputs unchanged since last build — skipping rebuild "
                   f"(images {', '.join(prev_images) or 'n/a'} still exist)")
                return 0
            warn("inputs unchanged but no prior image still exists — rebuilding")

    render_all(workdir, r)

    # Confirmation prompt (skip with -y or in non-interactive mode)
    if not args.yes:
        communicator = "winrm" if r.family == "windows" else "ssh"
        info(f"profile     = {r.profile_name}  |  CIS Level {r.level}  |  region {r.region}  |  {communicator}")
        info(f"source image = {r.source_image_id}")
        info(f"instance     = {r.instance_type}")
        if not _is_interactive():
            warn("stdin is not a TTY — assuming non-interactive, proceeding without prompt. "
                 "Use -y/--yes to suppress this message.")
        else:
            try:
                resp = input("  Confirm build? (y/N) ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return 1
            if resp not in ("y", "yes"):
                info("Cancelled.")
                return 0

    banner("build")
    info(f"Rendered working directory: {workdir}")
    info(f"Running packer build (CIS Level {r.level}, profile={r.profile_name}) ...")

    _fh: logging.FileHandler | None = None
    if args.log_file:
        _fh = logging.FileHandler(args.log_file, mode="w", encoding="utf-8")
        _fh.setLevel(logging.DEBUG)
        _fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(_fh)
        info(f"Build log → {args.log_file}")

    result = run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug,
                        log_file=args.log_file)

    # Sync file position: run_packer opened its own FD for appending,
    # so _fh's position is stale — seek to end before more logger writes.
    if _fh is not None and _fh.stream is not None:
        _fh.stream.seek(0, 2)

    # Output is already streamed live by run_packer; only scan the captured
    # lines to extract the resulting image ID (do not re-print them).
    image_ids = _extract_image_ids(result.stdout_lines)
    score = _extract_score(result.stdout_lines)
    sbom_sha = _extract_sbom_sha(result.stdout_lines)
    sbom_count = _extract_sbom_count(result.stdout_lines)
    image_name = _image_name(r)
    success = result.exit_code == 0

    if success:
        ok("packer build succeeded")
        if image_ids:
            ok(f"Output image ID(s): {', '.join(image_ids)}")
        else:
            info("Could not parse image ID from output — check the Tencent Cloud console.")
        if score is not None:
            ok(f"Re-audit score: {score:g}%")
        if sbom_sha:
            ok(f"SBOM: {sbom_count or '?'} packages, sha256 {sbom_sha[:16]}…")
        # Build → test → distribute: record lineage + signed provenance
        lin = _record_lineage(r, image_ids, image_name, score, ok=True,
                              sbom_sha=sbom_sha, sbom_count=sbom_count)
        if lin:
            info(f"Lineage recorded -> {lin}")
        prov = _write_provenance(r, image_ids, image_name, score,
                                 sbom_sha=sbom_sha, sbom_count=sbom_count)
        if prov:
            info(f"Provenance written -> {prov}")
        # P2#9 — cross-account image sharing (never fails the build).
        # [image].share_org_units (#17) merges into the same call — org
        # sharing uses the identical ModifyImageSharePermission API.
        share_targets = list(dict.fromkeys(
            r.image_share_accounts + r.image_share_org_units))
        if share_targets and image_ids:
            _share_images(r, image_ids, share_targets)
        # P0#3 — clean-boot verification (build → test → distribute).
        # Boot a probe from the produced image and re-audit on fresh boot.
        if r.verify_boot and image_ids:
            if r.family == "windows":
                warn("[meta].verify_boot is Linux-only — skipping "
                     "clean-boot verification for Windows")
            else:
                ok("Clean-boot verification: booting probe instance from "
                   f"{image_ids[0]} …")
                vrc = cmd_verify_image(args, image_id=image_ids[0])
                if vrc != 0:
                    fail("clean-boot verification FAILED — image not approved")
                    _record_lineage(r, image_ids, image_name, score, ok=False,
                                    sbom_sha=sbom_sha, sbom_count=sbom_count)
                    _send_notification(r, False, image_ids, score, image_name)
                    if _fh is not None:  # don't leak the log handler
                        logger.removeHandler(_fh)
                        _fh.close()
                    return vrc
    else:
        fail("packer build failed (see output above)")
        _record_lineage(r, image_ids, image_name, score, ok=False,
                        sbom_sha=sbom_sha, sbom_count=sbom_count)

    # [notify] — WeCom webhook; never affects the exit code.
    _send_notification(r, success, image_ids, score, image_name)

    if _fh is not None:
        logger.removeHandler(_fh)
        _fh.close()
    return result.exit_code


def _extract_image_ids(stdout_lines: list[str]) -> list[str]:
    """Extract created image IDs from captured packer build output.

    Packer's artifact line looks like:
      Tencentcloud images(ap-guangzhou: img-abc123
      ap-hongkong: img-def456) were created.
    (older builds printed "Created image ID: img-..." — keep that too).
    """
    image_ids: list[str] = []
    collecting = False
    for line in stdout_lines:
        if m := re.search(r"Created image ID:\s*(\S+)", line):
            return [m.group(1)]
        if "Tencentcloud images(" in line:
            collecting = True
        if collecting:
            image_ids += re.findall(r"img-[A-Za-z0-9]+", line)
            if ") were created" in line:
                break
    return list(dict.fromkeys(image_ids))


def _extract_score(stdout_lines: list[str]) -> float | None:
    """Extract the re-audit score (e.g. 'Score: 91.5%') from packer output."""
    for line in stdout_lines:
        if m := re.search(r"Score:\s*(\d+(?:\.\d+)?)\s*%", line):
            return float(m.group(1))
    return None


def _extract_sbom_sha(stdout_lines: list[str]) -> str | None:
    """Extract the SBOM sha256 echoed by the SBOM provisioner (P2#10)."""
    for line in stdout_lines:
        if m := re.search(r"SBOM_SHA256=([0-9a-f]{64})", line):
            return m.group(1)
    return None


def _extract_sbom_count(stdout_lines: list[str]) -> int | None:
    """Extract the SBOM package count echoed by the SBOM provisioner."""
    for line in stdout_lines:
        if m := re.search(r"sbom:\s*(\d+)\s+package", line):
            return int(m.group(1))
    return None


# ── Image lineage ────────────────────────────────────────────────────────────
# Every successful build appends a record to ~/.ciscvm/lineage.jsonl, so
# downstream tools (Terraform, ASG, scripts) can resolve "latest approved
# image" instead of hand-copying image IDs.  This is the lightweight cousin
# of HCP Packer's channels / AWS Image Builder distribution metadata.
def _lineage_path() -> Path:
    return Path.home() / ".ciscvm" / "lineage.jsonl"


def _record_lineage(r: ResolvedConfig, image_ids: list[str], image_name: str,
                    score: float | None, ok: bool,
                    sbom_sha: str | None = None,
                    sbom_count: int | None = None) -> Path | None:
    """Append one lineage record. Returns the file path, or None on failure."""
    if not isinstance(r, ResolvedConfig):
        return None  # defensive: only real resolved configs are recorded
    try:
        path = _lineage_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        rec = {
            "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "ok" if ok else "failed",
            "ciscvm_version": VERSION,
            "profile": r.profile_name,
            "cis_level": r.level,
            "region": r.region,
            "zone": r.zone,
            "source_image_id": r.source_image_id,
            "image_name": image_name,
            "image_ids": image_ids,
            "score": score,
            # P1#4/#7 — benchmark pinning + change detection: the fingerprint
            # lets 'build --skip-if-unchanged' skip rebuilds when nothing
            # changed, and the benchmark name/version anchors the audit.
            "benchmark": r.image_benchmark,
            "fingerprint": _build_fingerprint(r),
            # #20 — the source image's CreatedTime at build time, so
            # 'ciscvm check-source' can detect a vendor image refresh.
            "source_image_created": _source_image_created(r),
        }
        # P2#10 — SBOM pinning: hash + package count of the emitted SBOM.
        if sbom_sha:
            rec["sbom_sha256"] = sbom_sha
        if sbom_count is not None:
            rec["sbom_packages"] = sbom_count
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None


# ── Change detection (P1#7) ─────────────────────────────────────────────────
# A build is "unchanged" when every input that could affect the produced
# image is identical: source image, profile, level, benchmark, rule catalog
# (hashed from the bundled rules.json), rule filters and the builder itself.
# EC2 Image Builder skips scheduled rebuilds on such change detection — we
# expose the same as `ciscvm build --skip-if-unchanged` / `ciscvm pending`.
def _bundled_rules_hash(role_dir: str) -> str:
    """SHA-256 of the bundled rules.json for *role_dir* ("" if unavailable)."""
    import hashlib
    project_root = Path(__file__).parent.resolve()
    p = (project_root / "roles" / role_dir / "files" / "rules.json").resolve()
    try:
        p.relative_to((project_root / "roles").resolve())
    except ValueError:
        return ""
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""


def _build_fingerprint(r: ResolvedConfig) -> str:
    """Deterministic fingerprint of every build input that affects the image.

    Includes the source image ID (rebuilds after a vendor image refresh are
    NOT skipped), the rule catalog hash, benchmark, level, rule filters and
    the builder version.  Stable across runs of the same inputs.
    """
    import hashlib
    if not isinstance(r, ResolvedConfig):
        return ""
    parts = [
        "ciscvm", VERSION,
        "profile", r.profile_name,
        "level", str(r.level),
        "region", r.region,
        "zone", r.zone,
        "source", r.source_image_id,
        "instance", r.instance_type,
        "benchmark", r.image_benchmark,
        "os", r.image_os_tag,
        "rules", _bundled_rules_hash(r.role_dir),
        "include", ",".join(r.rules_include),
        "exclude", ",".join(r.rules_exclude),
        "overrides", json.dumps(r.rules_overrides, sort_keys=True, ensure_ascii=False),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _last_successful_fingerprint(r: ResolvedConfig) -> tuple[str | None, list[str]]:
    """Most recent 'ok' lineage record matching profile/level/region.

    Returns (fingerprint, image_ids) — None fingerprint when no match.
    Used by change detection to skip rebuilds with identical inputs.
    """
    path = _lineage_path()
    if not path.exists():
        return None, []
    match: dict[str, Any] | None = None
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if (rec.get("status") == "ok"
                    and rec.get("profile") == r.profile_name
                    and rec.get("cis_level") == r.level
                    and rec.get("region") == r.region
                    and not rec.get("retired")):
                match = rec  # last matching record wins (file is append-only)
    if not match:
        return None, []
    return match.get("fingerprint"), list(match.get("image_ids") or [])


def _image_ids_still_exist(region: str, image_ids: list[str]) -> bool:
    """Best-effort: True when *any* of *image_ids* still exists in *region*.

    Fails open (returns True) on missing credentials/API errors so change
    detection never *blocks* a rebuild due to a transient API problem.
    """
    if not image_ids:
        return False
    try:
        return bool(_images_exist(region, image_ids[:5]))
    except Exception:
        return True  # fail open — let the rebuild proceed


def cmd_images(args: argparse.Namespace) -> int:
    """List recorded builds (lineage) — most recent first."""
    path = _lineage_path()
    if not path.exists():
        info(f"No lineage records yet at {path} — run a build first.")
        return 0
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    records.reverse()  # newest first
    limit = getattr(args, "limit", 10)
    if args.latest:
        records = records[:1]
    elif limit > 0:
        records = records[:limit]
    if not records:
        info("No records.")
        return 0
    for rec in records:
        imgs = ", ".join(rec.get("image_ids") or [])
        score = rec.get("score")
        score_s = f"{score:g}%" if score is not None else "-"
        status = rec.get("status", "?")
        print(f"{rec.get('ts', '?'):s}  {status:6s}  L{rec.get('cis_level', '?')}  "
              f"score={score_s:>6s}  {rec.get('image_name', ''):s}  "
              f"src={rec.get('source_image_id', ''):s}  ->  {imgs}")
    return 0


# ── Automatic image cleanup ──────────────────────────────────────────────────
# ciscvm cleanup-images: retire old golden images by lineage age.  Uses a
# minimal TC3-HMAC-SHA256 signer (stdlib only — keeps the package zero-dep)
# against cvm:DescribeImages / cvm:DeleteImages.  Default is a dry run;
# --apply performs the deletion.  Credentials come from the standard env
# vars (TENCENTCLOUD_SECRET_ID/KEY[/TOKEN]).
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
    with urllib.request.urlopen(req, timeout=30) as resp:
        return cast("dict[str, Any]", json.loads(resp.read().decode("utf-8")))


def _images_exist(region: str, image_ids: list[str]) -> list[str]:
    """Return which of *image_ids* still exist in *region* (via DescribeImages)."""
    if not image_ids:
        return []
    sid, skey, tok = (os.environ.get("TENCENTCLOUD_SECRET_ID", ""),
                      os.environ.get("TENCENTCLOUD_SECRET_KEY", ""),
                      os.environ.get("TENCENTCLOUD_SECURITY_TOKEN", ""))
    if not sid or not skey:
        raise ConfigError("TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY not set — "
                          "cannot query images for cleanup")
    try:
        resp = _tc3_api("cvm", "DescribeImages", "2017-03-12", region,
                        {"ImageIds": image_ids}, sid, skey, tok or None)
    except Exception as exc:
        raise ConfigError(f"DescribeImages failed: {exc}") from exc
    existing = [i["ImageId"] for i in resp.get("Response", {}).get("ImageSet", [])]
    return existing


def _delete_images(region: str, image_ids: list[str]) -> None:
    sid, skey, tok = (os.environ.get("TENCENTCLOUD_SECRET_ID", ""),
                      os.environ.get("TENCENTCLOUD_SECRET_KEY", ""),
                      os.environ.get("TENCENTCLOUD_SECURITY_TOKEN", ""))
    resp = _tc3_api("cvm", "DeleteImages", "2017-03-12", region,
                    {"ImageIds": image_ids}, sid, skey, tok or None)
    if "Error" in resp.get("Response", {}):
        raise ConfigError(f"DeleteImages failed: {resp['Response']['Error']}")


def _image_is_shared(region: str, image_id: str) -> bool:
    """Return True when *image_id* is shared with other accounts (#16).

    Uses cvm:DescribeImageSharePermission.  Fails OPEN (returns True, i.e.
    "keep the image") when credentials/API are unavailable so cleanup
    never deletes an image it cannot prove is unused.
    """
    sid, skey, tok = (os.environ.get("TENCENTCLOUD_SECRET_ID", ""),
                      os.environ.get("TENCENTCLOUD_SECRET_KEY", ""),
                      os.environ.get("TENCENTCLOUD_SECURITY_TOKEN", ""))
    if not sid or not skey:
        return True  # can't prove it's unused → keep
    try:
        resp = _tc3_api("cvm", "DescribeImageSharePermission", "2017-03-12",
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
    sid, skey, tok = (os.environ.get(r.secret_id_env, ""),
                      os.environ.get(r.secret_key_env, ""),
                      os.environ.get(r.security_token_env, ""))
    if not sid or not skey:
        return ""
    try:
        resp = _tc3_api("cvm", "DescribeImages", "2017-03-12", r.region,
                        {"ImageIds": [r.source_image_id]}, sid, skey, tok or None)
    except Exception:
        return ""
    imgs = resp.get("Response", {}).get("ImageSet") or []
    if not imgs:
        return ""
    # Public images report CreatedTime as null — treat as unavailable.
    return str(imgs[0].get("CreatedTime") or "")


def cmd_check_source(args: argparse.Namespace) -> int:
    """ciscvm check-source — vendor image refresh detection (#20).

    Queries the source image's CreatedTime and compares it with the last
    build's lineage record.  Exit 0 = source unchanged (no rebuild needed);
    exit 1 = source image has been refreshed → rebuild the golden image.
    Schedule it on a timer alongside 'build --skip-if-unchanged' so a
    vendor OS image update automatically triggers a rebuild.
    """
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    now_created = _source_image_created(r)
    if not now_created:
        warn("Could not query the source image's CreatedTime — cannot "
             "detect a vendor refresh (check credentials/API access)")
        return 0  # fail open: don't force a rebuild on a transient API issue

    prev: str | None = None
    path = _lineage_path()
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if (rec.get("status") == "ok"
                        and rec.get("profile") == r.profile_name
                        and rec.get("region") == r.region):
                    prev = rec.get("source_image_created") or None

    banner("check-source")
    info(f"source image : {r.source_image_id}")
    info(f"current      : created {now_created}")
    if prev is None:
        info("no previous build record — rebuild required")
        return 1
    info(f"last build   : created {prev}")
    if prev == now_created:
        ok("source image unchanged since last build — no rebuild needed")
        return 0
    warn("source image has been refreshed — rebuild the golden image "
         "(run 'ciscvm build')")
    return 1


# ── Clean-boot verification (P0#3) ──────────────────────────────────────────
# AWS EC2 Image Builder's test phase runs on the OUTPUT image, not the build
# instance — issues like SELinux autorelabel stalls, first-boot services and
# cloud-init reconfiguration only appear on a fresh boot.  ciscvm
# verify-image boots a probe instance from the produced image, runs the
# bundled engine in scan mode (or an independent audit), and terminates it.
def _probe_launch(r: ResolvedConfig, image_id: str, instance_name: str) -> str:
    """Launch a probe instance from *image_id*; return instance-id."""
    sid, skey, tok = (os.environ.get(r.secret_id_env, ""),
                      os.environ.get(r.secret_key_env, ""),
                      os.environ.get(r.security_token_env, ""))
    if not sid or not skey:
        raise ConfigError(
            f"{r.secret_id_env} / {r.secret_key_env} not set — "
            "cannot launch verification instance")
    # TencentCloud RunInstances — the built image may be a custom image of
    # any family; we launch with the SAME placement as the build itself.
    resp = _tc3_api(
        "cvm", "RunInstances", "2017-03-12", r.region,
        {"ImageId": image_id,
         "InstanceType": r.instance_type,
         "InstanceChargeType": "POSTPAID_BY_HOUR",
         "InstanceName": instance_name,
         "VpcId": r.vpc_id,
         "SubnetId": r.subnet_id,
         "SecurityGroupIds": [r.security_group_id],
         "AssociatePublicIp": r.associate_public_ip,
         "InstanceCount": 1,
         "TagSpecification": [{"ResourceType": "instance",
                               "Tags": [{"Key": "purpose", "Value": "ciscvm-verify"},
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
    sid, skey, tok = (os.environ.get(r.secret_id_env, ""),
                      os.environ.get(r.secret_key_env, ""),
                      os.environ.get(r.security_token_env, ""))
    deadline = _time.time() + 900
    while _time.time() < deadline:
        try:
            resp = _tc3_api("cvm", "DescribeInstances", "2017-03-12", r.region,
                            {"InstanceIds": [instance_id]}, sid, skey, tok or None)
            insts = resp.get("Response", {}).get("InstanceSet") or []
            if not insts:
                _time.sleep(10)
                continue
            inst = insts[0]
            state = inst.get("InstanceState", {}).get("State", "")
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
    sid, skey, tok = (os.environ.get(r.secret_id_env, ""),
                      os.environ.get(r.secret_key_env, ""),
                      os.environ.get(r.security_token_env, ""))
    try:
        _tc3_api("cvm", "TerminateInstances", "2017-03-12", r.region,
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
    /opt/ciscvm-ansible/roles/<role>/files (cleanup.sh keeps them), so a
    fresh-boot scan needs no uploads.  Returns the parsed engine result doc.
    """
    profile = f"L{level}"
    remote = (
        "ENG=$(ls -d /opt/ciscvm-ansible/roles/cis_*/files 2>/dev/null | head -1); "
        "if [ -n \"$ENG\" ] && [ -f \"$ENG/cis_engine.py\" ]; then "
        "sudo /opt/ciscvm-ansible/bin/python \"$ENG/cis_engine.py\" "
        f"--catalog \"$ENG/rules.json\" --mode scan --profile {profile} "
        "--out /tmp/ciscvm-verify.json >/dev/null 2>&1 && "
        "cat /tmp/ciscvm-verify.json; fi"
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


def cmd_verify_image(args: argparse.Namespace, image_id: str | None = None) -> int:
    """ciscvm verify-image — clean-boot verification of a produced image.

    Boots a probe instance from *image_id*, runs the bundled engine in
    scan mode (fresh boot — NOT the build instance), gates on --min-score,
    and always terminates the probe instance (even on gate failure).
    When called from cmd_build, *image_id* is passed explicitly.
    """
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    image_id = image_id or getattr(args, "image", "") or ""
    # When driven by 'build --verify-boot', args carries no --min-score —
    # fall back to the config's [cis].min_score, not a hardcoded 85, so the
    # auto-verification gate matches the configured audit gate.
    min_score = float(getattr(args, "min_score", r.min_score or 85))
    if not image_id:
        fail("--image <img-xxx> is required")
        return 1
    info(f"Launching verification instance from {image_id} "
         f"({r.profile_name} L{r.level}, {r.region}) …")
    instance_id = None
    try:
        try:
            instance_id = _probe_launch(r, image_id, f"ciscvm-verify-{image_id}")
        except ConfigError as exc:
            fail(str(exc))
            return 1
        ok(f"Probe instance: {instance_id}")
        ip = _probe_public_ip(r, instance_id)
        if not ip:
            fail("Could not get a public IP for the probe instance (timeout)")
            return 1
        ok(f"Probe public IP: {ip}")
        ssh_user = r.ssh_username or "root"
        ssh_port = r.ssh_port or 22
        if not _probe_ssh_ready(ip, ssh_port, ssh_user):
            fail("SSH did not come up on the probe instance (timeout) — "
                 "clean-boot verification failed")
            return 1
        ok("SSH ready on fresh boot")
        doc = _probe_scan(r, ip, ssh_port, ssh_user, r.level)
        if "error" in doc and "summary" not in doc:
            fail(f"Fresh-boot scan failed: {doc.get('error', 'unknown error')}")
            return 1
        score = (doc.get("summary") or {}).get("all", {}).get("score")
        fails = (doc.get("summary") or {}).get("all", {}).get("fail", 0)
        banner("verify-image")
        if score is not None:
            info(f"Fresh-boot scan score: {score:g}% (gate >= {min_score:g}%)")
        info(f"Fresh-boot failing rules: {fails}")
        gate_ok = score is not None and score >= min_score
        if gate_ok:
            ok("clean-boot verification PASSED")
            return 0
        shown = f"{score:g}%" if score is not None else "unknown"
        fail(f"clean-boot verification FAILED: score {shown} < {min_score:g}%")
        return 1
    finally:
        if instance_id:
            _probe_terminate(r, instance_id)


# ── Drift detection (round-2 #12, Red Hat Insights Drift style) ─────────────
# A golden image is correct at build time, but instances launched from it
# drift: admins tweak configs, packages get patched, services change.
# `ciscvm drift` re-scans a LIVE instance over SSH and diffs the result
# against a baseline (the audit result shipped inside the image, or a
# saved one) — reporting what changed since the image was built.
def _extract_rule_statuses(doc: dict[str, Any]) -> dict[str, str]:
    """Flatten an engine result doc into {rule_id: status}."""
    out: dict[str, str] = {}
    for r in doc.get("results") or []:
        rid = r.get("id")
        if rid:
            out[str(rid)] = str(r.get("status", "?"))
    return out


def _drift_diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two engine result docs; return the drift summary.

    *new_failures* — rules passing (or absent) in the baseline that now fail.
    *recovered*    — rules failing in the baseline that now pass.
    *status_changed* — any other pass/fail flip.
    """
    b = _extract_rule_statuses(baseline)
    c = _extract_rule_statuses(current)
    all_ids = sorted(set(b) | set(c))
    new_failures: list[str] = []
    recovered: list[str] = []
    status_changed: list[str] = []
    for rid in all_ids:
        bst, cst = b.get(rid, "absent"), c.get(rid, "absent")
        if cst == "fail" and bst in ("pass", "absent", "manual", "notapplicable"):
            new_failures.append(rid)
        elif cst in ("pass", "manual", "notapplicable") and bst == "fail":
            recovered.append(rid)
        elif cst != bst and cst not in ("fail",) and bst not in ("fail",):
            status_changed.append(rid)
    bs = (baseline.get("summary") or {}).get("all", {})
    cs = (current.get("summary") or {}).get("all", {})
    return {
        "baseline_score": bs.get("score"),
        "current_score": cs.get("score"),
        "new_failures": new_failures,
        "recovered": recovered,
        "status_changed": status_changed,
    }


def _fetch_baseline(r: ResolvedConfig, image_id: str) -> dict[str, Any] | None:
    """Locate the baseline audit result for *image_id*.

    1) a locally saved baseline in ~/.ciscvm/baselines/<image>.json
    2) the audit result shipped inside the image (/opt/ciscvm-AUDIT-RESULT.json)
    """
    local = _lineage_path().parent / "baselines" / f"{image_id}.json"
    if local.exists():
        try:
            return cast("dict[str, Any]", json.loads(local.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            warn(f"Baseline file {local} is corrupt — ignoring")
    return None  # caller fetches the in-image one over SSH


def cmd_drift(args: argparse.Namespace) -> int:
    """ciscvm drift — detect configuration drift on a running instance.

    Scans a LIVE instance (--host) with the bundled engine and diffs the
    result against the baseline: the audit result shipped inside the
    producing image (--image), or a locally saved baseline.  Reports
    new failures / recovered rules / score delta.  Exit 0 = no drift.
    """
    if getattr(args, "save_baseline", False):
        return cmd_save_baseline(args)
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    host = args.host
    if not host:
        fail("--host <ip> is required (the running instance to check for drift)")
        return 1
    ssh_user = getattr(args, "ssh_user", "") or r.ssh_username or "root"
    ssh_port = int(getattr(args, "ssh_port", 0) or r.ssh_port or 22)

    # 1. Run a live scan on the instance (reuse the same SSH scan as
    #    verify-image — the engine ships inside the image).
    banner("drift")
    info(f"Scanning live instance {host} (profile {r.profile_name} L{r.level}) …")
    current = _probe_scan(r, host, ssh_port, ssh_user, r.level)
    if "error" in current and "summary" not in current:
        fail(f"Live scan failed: {current.get('error', 'unknown error')}")
        return 1
    cs = (current.get("summary") or {}).get("all", {})
    info(f"Live score: {cs.get('score', '?')}%  "
         f"(fail {cs.get('fail', 0)}, pass {cs.get('pass', 0)})")

    # 2. Baseline: local saved file, or fetch from the producing image.
    baseline: dict[str, Any] | None = None
    image_id = getattr(args, "image", "") or ""
    if image_id:
        baseline = _fetch_baseline(r, image_id)
        if baseline is None:
            info("Fetching baseline from the instance's shipped audit "
                 "(/opt/ciscvm-AUDIT-RESULT.json, written at build time) …")
            remote = "sudo cat /opt/ciscvm-AUDIT-RESULT.json 2>/dev/null"
            try:
                cp = subprocess.run(
                    ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15",
                     "-p", str(ssh_port), f"{ssh_user}@{host}", remote],
                    capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                baseline = None
            except FileNotFoundError:
                warn("ssh not found in PATH — cannot fetch the image baseline")
                baseline = None
            else:
                try:
                    baseline = cast("dict[str, Any]", json.loads(cp.stdout))
                except json.JSONDecodeError:
                    baseline = None
        if baseline is None:
            warn("No baseline found — try saving one with "
                 "'ciscvm drift --save-baseline' or pass --baseline <file>")

    # --baseline <file> overrides everything.
    bl_path = getattr(args, "baseline", "") or ""
    if bl_path and Path(bl_path).exists():
        try:
            baseline = cast("dict[str, Any]",
                            json.loads(Path(bl_path).read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            warn(f"Could not parse baseline file {bl_path}")
            baseline = None

    if baseline is None:
        fail("No baseline to compare against — pass --image <id>, "
             "--baseline <file>, or run 'ciscvm drift --save-baseline' first")
        return 1

    # 3. Diff + report.
    diff = _drift_diff(baseline, current)
    bs = (baseline.get("summary") or {}).get("all", {})
    bscore = diff["baseline_score"] or bs.get("score")
    cscore = diff["current_score"] or cs.get("score")
    if bscore is not None:
        info(f"Baseline score: {bscore:g}%")
    delta = ""
    if bscore is not None and cscore is not None:
        d = round(float(cscore) - float(bscore), 1)
        delta = f"  ({'+' if d > 0 else ''}{d:g} pts)"
        info(f"Score delta: {delta}")
    if diff["new_failures"]:
        warn(f"DRIFT: {len(diff['new_failures'])} rule(s) now failing that "
             f"were not before:")
        for rid in diff["new_failures"]:
            fail(f"  ✗ {rid}")
    else:
        ok("No new failing rules")
    if diff["recovered"]:
        ok(f"Recovered: {len(diff['recovered'])} rule(s) now passing")
        for rid in diff["recovered"][:10]:
            ok(f"  ✓ {rid}")

    # 4. Gate: exit 1 when there is real drift (new failures).
    if diff["new_failures"]:
        fail(f"DRIFT DETECTED — {len(diff['new_failures'])} new failing "
             f"rule(s) on {host}")
        return 1
    ok(f"No drift detected on {host}")
    return 0


def cmd_save_baseline(args: argparse.Namespace) -> int:
    """ciscvm drift --save-baseline — persist the current host scan as a baseline."""
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    host = args.host
    if not host:
        fail("--host <ip> is required to save a baseline")
        return 1
    ssh_user = getattr(args, "ssh_user", "") or r.ssh_username or "root"
    ssh_port = int(getattr(args, "ssh_port", 0) or r.ssh_port or 22)
    doc = _probe_scan(r, host, ssh_port, ssh_user, r.level)
    if "error" in doc and "summary" not in doc:
        fail(f"Scan failed: {doc.get('error', 'unknown error')}")
        return 1
    image_id = getattr(args, "image", "") or "current"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", image_id) or "current"
    out = _lineage_path().parent / "baselines" / f"{safe}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")
    ok(f"Baseline saved -> {out}")
    return 0


def cmd_cleanup_images(args: argparse.Namespace) -> int:
    """Retire old golden images by lineage age. Dry-run by default.

    *--unused-since N* (#16): additionally require the image to be
    UNshared (cvm:DescribeImageSharePermission returns no shares) — an
    image shared with other accounts is presumed in use downstream and is
    skipped, so cleanup never breaks a running consumer.  Fails open
    (keeps the image) when the share query errors.
    """
    from datetime import datetime

    path = _lineage_path()
    if not path.exists():
        info(f"No lineage records at {path} — nothing to clean.")
        return 0

    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue

    ok_recs = [r for r in records if r.get("status") == "ok" and not r.get("retired")]
    ok_recs.sort(key=lambda r: r.get("ts", ""))  # oldest first

    keep = max(0, int(getattr(args, "keep_latest", 1)))
    older_than = max(1, int(getattr(args, "older_than", 30)))
    unused_since = max(0, int(getattr(args, "unused_since", 0)))
    cutoff = datetime.now(UTC).timestamp() - older_than * 86400

    candidates: list[tuple[dict[str, Any], str]] = []  # (record, image_id)
    for i, rec in enumerate(ok_recs):
        if len(ok_recs) - i <= keep:
            continue  # keep the newest N builds
        try:
            ts = datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
        if ts > cutoff:
            continue
        for img in rec.get("image_ids", []):
            candidates.append((rec, img))

    # --unused-since: drop candidates whose image is still shared (in use).
    if unused_since:
        kept_shared = 0
        filtered: list[tuple[dict[str, Any], str]] = []
        for rec, img in candidates:
            if _image_is_shared(rec.get("region", ""), img):
                kept_shared += 1
                info(f"  {rec.get('region', '?')}: {img} is still shared "
                     "(in use downstream) — kept")
            else:
                filtered.append((rec, img))
        candidates = filtered
        if kept_shared:
            info(f"{kept_shared} shared image(s) kept (--unused-since)")

    if not candidates:
        ok(f"No images older than {older_than} days to retire (keeping {keep} latest).")
        return 0

    info(f"{len(candidates)} image(s) older than {older_than} days, keeping {keep} latest:")
    # group candidates by region for API calls
    by_region: dict[str, list[str]] = {}
    for rec, img in candidates:
        by_region.setdefault(rec.get("region", ""), []).append(img)

    total_deleted = 0
    for region, imgs in sorted(by_region.items()):
        for img in sorted(set(imgs)):
            if args.apply:
                try:
                    existing = _images_exist(region, [img])
                    if not existing:
                        info(f"  {region}: {img} already gone — marking retired")
                    else:
                        _delete_images(region, [img])
                        ok(f"  {region}: deleted {img}")
                    total_deleted += 1
                except ConfigError as exc:
                    fail(str(exc))
                    return 1
            else:
                warn(f"  [dry-run] would delete {region}: {img}")

    # mark retired in lineage (both dry-run and apply update the audit trail)
    if args.apply:
        # Per-IMAGE granularity: a lineage record can hold several image_ids
        # (cross-region copies).  Removing ONE of them must NOT retire the
        # whole record — otherwise the surviving copies are dropped from the
        # cleanup set forever (they never age out) and check-source/pending
        # treat the record as gone.  Remove the deleted ids; only mark
        # retired when the record has no images left.
        retired_ids = {img for _, img in candidates}
        lines: list[str] = []
        retired_ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                ids = list(rec.get("image_ids", []))
                if ids and not rec.get("retired"):
                    remaining = [i for i in ids if i not in retired_ids]
                    if len(remaining) != len(ids):
                        rec["image_ids"] = remaining
                        if not remaining:
                            rec["retired"] = True
                            rec["retired_ts"] = retired_ts
                lines.append(json.dumps(rec, ensure_ascii=False))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        ok(f"Retired {total_deleted} image(s); lineage updated.")

    if not args.apply:
        info("Re-run with --apply to actually delete (and mark lineage retired).")
    return 0


# ── Idempotency test + SARIF reporting ──────────────────────────────────────
def _last_num(lines: list[str], pattern: str) -> int | None:
    """Return the last integer matching *pattern* across *lines*."""
    val: int | None = None
    for line in lines:
        if m := re.search(pattern, line):
            val = int(m.group(1))
    return val


def cmd_test(args: argparse.Namespace) -> int:
    """ciscvm test --idempotency: re-run apply and assert the second pass
    makes no changes (Applied: 0 / Pending: 0 in the role summary)."""
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    if args.idempotency and r.family == "windows":
        warn("Idempotency check is Linux-only — nothing to do for Windows.")
        return 0

    render_all(workdir, r, idempotency=args.idempotency)
    banner("test")
    info(f"Idempotency — re-running apply must make 0 changes "
         f"({r.profile_name} L{r.level}, region {r.region})")

    result = run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug)
    if result.exit_code != 0:
        fail("build failed during idempotency test")
        return result.exit_code

    applied = _last_num(result.stdout_lines, r"Applied:\s+(\d+)")
    pending = _last_num(result.stdout_lines, r"Pending:\s+(\d+)")
    if applied is None:
        fail("Could not parse apply summary — idempotency test inconclusive")
        return 1
    total_changes = applied + (pending or 0)
    if total_changes > 0:
        fail(f"idempotency FAILED: second apply made {applied} change(s), "
             f"{pending or 0} pending — the image drifts on rebuild")
        return 1
    ok("idempotency OK — second apply made 0 changes (no drift)")
    return 0


def _build_sarif(stdout_lines: list[str], benchmark: str = "") -> str:
    """Build a SARIF 2.1.0 document from the engine's 'List failed rules' output.

    *benchmark* (P0#2) — official benchmark reference (e.g. "CIS TencentOS
    Linux 4 Benchmark v1.0.0") carried in the driver so GRC tooling can
    cross-reference the rule IDs against CIS-CAT / SCAP content.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    _rule_re = re.compile(r"\s*✗\s+([0-9][0-9.]+)\s*\|\s*(.*?)\s*$")
    for i, line in enumerate(stdout_lines):
        m = _rule_re.match(line)
        if not m:
            continue
        rid, title = m.group(1), m.group(2).strip()
        if rid in seen:
            continue
        seen.add(rid)
        # Collect the detail: the indented line(s) directly after this rule
        # line, stopping at the next rule line or a blank line.  (The old
        # `stdout_lines[i+1]` grabbed whatever was next — often the next
        # rule header instead of the actual failure detail.)
        detail_parts: list[str] = []
        for j in range(i + 1, min(i + 4, len(stdout_lines))):
            nxt = stdout_lines[j].strip()
            if not nxt or _rule_re.match(stdout_lines[j]):
                break
            detail_parts.append(nxt)
        detail = " ".join(detail_parts)
        rule_obj: dict[str, Any] = {"id": rid, "shortDescription": {"text": title}}
        if benchmark:
            rule_obj["properties"] = {"benchmark": benchmark}
        rules.append(rule_obj)
        results.append({
            "ruleId": rid,
            "level": "error",
            "message": {"text": detail or title},
        })
    driver: dict[str, Any] = {
        "name": "ciscvm",
        "version": VERSION,
        "informationUri": "https://github.com/susunola/cis-cvm-image-builder",
        "rules": rules,
    }
    if benchmark:
        driver["properties"] = {"benchmark": benchmark}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=1)


def _write_sarif(args: argparse.Namespace, stdout_lines: list[str], benchmark: str = "") -> None:
    if not getattr(args, "sarif", None):
        return
    try:
        Path(args.sarif).write_text(
            _build_sarif(stdout_lines, benchmark), encoding="utf-8")
        ok(f"SARIF report written -> {args.sarif}")
    except OSError as exc:
        warn(f"Could not write SARIF report: {exc}")


# ── XCCDF report (P2#8) ─────────────────────────────────────────────────────
# `ciscvm scan --xccdf out.xml` exports the engine's findings as an XCCDF
# 1.2 TestResult so enterprise GRC/compliance platforms (which consume
# SCAP/XCCDF natively) can ingest ciscvm results without a custom parser.
def _build_xccdf(stdout_lines: list[str], benchmark: str = "") -> str:
    """Build a minimal XCCDF 1.2 TestResult document from the engine output.

    Each failing rule becomes a <rule-result>; the benchmark reference is
    carried in the TestResult so the export ties back to the CIS edition.
    """
    from datetime import datetime
    from xml.sax.saxutils import escape
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    seen: set[str] = set()
    for line in stdout_lines:
        m = re.match(r"\s*✗\s+([0-9][0-9.]+)\s*\|\s*(.*?)\s*$", line)
        if not m:
            continue
        rid = m.group(1)
        if rid in seen:
            continue
        seen.add(rid)
        rows.append(
            f'  <rule-result idref="xccdf_org.ciscvm.content_rule_{rid}">\n'
            f'    <result>fail</result>\n'
            f'    <message>{escape((m.group(2) or "").strip()[:200])}</message>\n'
            f'  </rule-result>')
    bm = escape(benchmark) if benchmark else "ciscvm"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        f'id="ciscvm-{escape(benchmark) if benchmark else "benchmark"}">\n'
        f'  <TestResult id="ciscvm-scan" start-time="{now}" end-time="{now}" '
        f'benchmark-reference="{bm}">\n'
        f'    <score max="100">{100.0:.6f}</score>\n'
        + "\n".join(rows) + "\n"
        '  </TestResult>\n</Benchmark>\n')


def _write_xccdf(args: argparse.Namespace, stdout_lines: list[str], benchmark: str = "") -> None:
    if not getattr(args, "xccdf", None):
        return
    try:
        Path(args.xccdf).write_text(
            _build_xccdf(stdout_lines, benchmark), encoding="utf-8")
        ok(f"XCCDF report written -> {args.xccdf}")
    except OSError as exc:
        warn(f"Could not write XCCDF report: {exc}")


# ── Build notifications (WeCom group robot) ─────────────────────────────────
# [notify].webhook + [notify].on ("always"|"success"|"failure", default
# "failure").  Combined with an external cron / systemd timer this turns
# ciscvm build into a scheduled, self-reporting rebuild pipeline.
def cmd_pending(args: argparse.Namespace) -> int:
    """Change detection: report whether a rebuild is needed (P1#7).

    Exit 0 = build inputs unchanged since the last successful build
    (no rebuild needed).  Exit 1 = something changed or no record exists.
    The check is input-only; 'build --skip-if-unchanged' additionally
    verifies the previous image still exists before skipping.
    """
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, _workdir = prep
    fp = _build_fingerprint(r)
    prev_fp, prev_images = _last_successful_fingerprint(r)
    info(f"profile={r.profile_name} L{r.level} region={r.region}")
    info(f"current fingerprint  = {fp}")
    if prev_fp is None:
        fail("no previous successful build for this profile/level/region "
             "— rebuild required")
        return 1
    info(f"last build fingerprint = {prev_fp}")
    if prev_fp == fp:
        ok("inputs unchanged since last successful build — rebuild not required")
        if prev_images:
            ok(f"last images: {', '.join(prev_images)}")
        return 0
    warn("inputs changed — rebuild required")
    return 1


def _share_images(r: ResolvedConfig, image_ids: list[str], accounts: list[str]) -> None:
    """Share built images with other Tencent Cloud accounts (P2#9).

    Uses cvm:ModifyImageSharePermission with the configured AccountIds
    (uin/… strings).  Credentials come from the SAME env names as the
    build itself ([cloud].secret_id_env / secret_key_env / security_token_env)
    so custom env-name configs work consistently with verify-image.
    """
    if not image_ids or not accounts:
        return
    sid, skey, tok = (os.environ.get(r.secret_id_env, ""),
                      os.environ.get(r.secret_key_env, ""),
                      os.environ.get(r.security_token_env, ""))
    if not sid or not skey:
        warn(f"{r.secret_id_env} / {r.secret_key_env} not set — "
             "cannot share images")
        return
    try:
        resp = _tc3_api("cvm", "ModifyImageSharePermission", "2017-03-12",
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


# ── Independent audit tool (P0#1) ───────────────────────────────────────────
# ciscvm audit runs a THIRD-PARTY audit tool (OpenSCAP oscap or Chef InSpec)
# against a target host and gates on the score.  This is the "independent
# verification" that dev-sec (InSpec baselines) / RHEL (oscap + SCAP content)
# / ansible-lockdown (Goss profiles) all ship — the score is no longer
# self-reported by the same engine that applied the hardening.
#
#   oscap : oscap xccdf eval --profile <cis> --results-arf - <datastream>
#           (RHEL-family: scap-security-guide ships ssg-*ds.xml datastreams)
#   inspec: inspec exec <baseline> -t ssh://user@host --reporter json
#
# Runs over SSH (stdlib-only: shells out to `ssh`), parses the machine-
# readable result (ARF XML for oscap, JSON for inspec) and gates on
# --min-score like the engine gate.  Also emits SARIF / XCCDF when asked.
def _audit_ssh_args(host: str, ssh_user: str, ssh_port: int,
                    ssh_key: str | None = None) -> list[str]:
    args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15"]
    if ssh_port:
        args += ["-p", str(ssh_port)]
    if ssh_key:
        args += ["-i", ssh_key]
    args += [f"{ssh_user}@{host}"]
    return args


def _audit_oscap(host: str, ssh_user: str, ssh_port: int, ssh_key: str | None,
                 profile: str, datastream: str, timeout: int = 900) -> str:
    """Run oscap over SSH, return the ARF XML document ("" on failure)."""
    remote = (f"oscap xccdf eval --profile {profile} --results-arf - {datastream} 2>/dev/null"
              )
    try:
        cp = subprocess.run(_audit_ssh_args(host, ssh_user, ssh_port, ssh_key) + [remote],
                            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"oscap audit timed out after {timeout}s on {host}")
        return ""
    except FileNotFoundError:
        warn("ssh not found in PATH — cannot run the oscap audit")
        return ""
    return cp.stdout


def _audit_inspec(host: str, ssh_user: str, ssh_port: int, ssh_key: str | None,
                  baseline: str, timeout: int = 900) -> dict[str, Any] | None:
    """Run InSpec over SSH, return the parsed JSON report (None on failure)."""
    target = f"ssh://{ssh_user}@{host}"
    if ssh_port:
        target += f":{ssh_port}"
    cmd = ["inspec", "exec", baseline, "-t", target, "--reporter", "json"]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        warn("inspec not found in PATH — install from https://chef.io/products/chef-inspec")
        return None
    except subprocess.TimeoutExpired:
        warn(f"inspec timed out after {timeout}s")
        return None
    try:
        return cast("dict[str, Any]", json.loads(cp.stdout))
    except json.JSONDecodeError:
        warn("inspec produced no JSON report (does the target reachable?)")
        return None


def _parse_oscap_arf(xml_text: str) -> dict[str, Any]:
    """Parse an OpenSCAP ARF XML into {score, pass, fail, results[]}.

    ARF = OVAL + XCCDF results; the XCCDF TestResult holds the profile
    score and per-rule results.  stdlib xml.etree only.
    """
    import xml.etree.ElementTree as ET
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "oscap"}
    if not xml_text.strip():
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        out["error"] = 1
        out["results"] = [{"id": "_parse_error_", "status": "error",
                           "detail": str(exc)}]
        return out
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2",
          "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
          "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5"}
    # XCCDF TestResult is nested under arf:report-request/report
    test_results = root.findall(".//x:TestResult", ns)
    tr = test_results[-1] if test_results else None
    if tr is None:
        out["results"] = [{"id": "_no_result_", "status": "error",
                           "detail": "no XCCDF TestResult in ARF"}]
        return out
    score_node = tr.find("x:score", ns)
    if score_node is not None and score_node.text:
        with contextlib.suppress(ValueError):
            out["score"] = round(float(score_node.text) * 100, 1)
    for rule in tr.findall("x:rule-result", ns):
        rid = rule.get("idref", "?")
        _res_node = rule.find("x:result", ns)
        status = (_res_node.text or "notselected") if _res_node is not None else "notselected"
        st = status.lower()
        if st == "pass":
            out["pass"] += 1
        elif st == "fail":
            out["fail"] += 1
        elif st in ("notselected", "notapplicable", "informational", "fixed", "unknown"):
            out["notselected"] += 1
        elif st == "error":
            out["error"] += 1
        out["results"].append({
            "id": rid, "status": st,
            "title": rid.rsplit("_", 1)[-1].replace("_", " "),
        })
    return out


def _parse_inspec_json(data: dict[str, Any] | None) -> dict[str, Any]:
    """Parse an InSpec JSON report into the same {score, pass, fail, results} shape."""
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "inspec"}
    if not data:
        out["error"] = 1
        out["results"] = [{"id": "_no_data_", "status": "error",
                           "detail": "no InSpec JSON report"}]
        return out
    controls = data.get("controls") or []
    for c in controls:
        rid = c.get("id", "?")
        status = c.get("status", "skipped")
        st = status.lower()
        if st == "passed":
            out["pass"] += 1
            st = "pass"
        elif st in ("failed", "error"):
            out["fail"] += 1
            st = "fail" if st == "failed" else "error"
        else:
            out["notselected"] += 1
            st = "notselected"
        detail = "; ".join(
            (r.get("message") or "") for r in (c.get("results") or [])
            if r.get("status") != "passed") or (c.get("title") or "")
        out["results"].append({"id": rid, "status": st, "detail": detail[:160]})
    scored = out["pass"] + out["fail"]
    if scored:
        out["score"] = round(100.0 * out["pass"] / scored, 1)
    return out


def _audit_render(audit: dict[str, Any], min_score: float) -> int:
    """Print an audit summary; return exit code (0 = gate passed)."""
    banner("audit")
    info(f"tool       : {audit.get('tool', '?')}")
    info(f"rules      : {audit['pass'] + audit['fail'] + audit['notselected'] + audit['error']} "
         f"(pass {audit['pass']}, fail {audit['fail']}, "
         f"notselected {audit['notselected']}, error {audit['error']})")
    if audit.get("score") is not None:
        info(f"score      : {audit['score']:g}% (gate >= {min_score:g}%)")
    for r in audit["results"]:
        if r["status"] in ("fail", "error"):
            fail(f"{r['id']:s} | {r.get('detail') or r.get('title') or r['status']}")
    gate_ok = audit.get("score") is not None and audit["score"] >= min_score
    if gate_ok:
        ok(f"audit gate PASSED ({audit['score']:g}% >= {min_score:g}%)")
        return 0
    shown = f"{audit['score']:g}%" if audit.get("score") is not None else "unknown"
    fail(f"audit gate FAILED: score {shown} < {min_score:g}%")
    return 1


def _audit_results_sarif(audit: dict[str, Any]) -> str:
    """SARIF 2.1.0 document from an independent audit's findings."""
    rules, results = [], []
    seen: set[str] = set()
    for r in audit["results"]:
        if r["status"] not in ("fail", "error"):
            continue
        rid = r["id"]
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "shortDescription": {"text": r.get("title") or rid}})
        results.append({"ruleId": rid, "level": "error",
                        "message": {"text": r.get("detail") or rid}})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": f"ciscvm-audit-{audit.get('tool', '?')}",
                "version": VERSION,
                "informationUri": "https://github.com/susunola/cis-cvm-image-builder",
                "rules": rules}},
            "results": results,
        }],
    }, ensure_ascii=False, indent=1)


def cmd_audit(args: argparse.Namespace) -> int:
    """ciscvm audit — independent third-party audit (oscap / inspec / kitty)."""
    if args.tool not in ("oscap", "inspec", "kitty"):
        fail(f"Unknown audit tool: {args.tool}. Use oscap, inspec or kitty.")
        return 1
    if args.tool == "kitty":
        # HardeningKitty runs ON the Windows host (no winrm client in the
        # stdlib-only CLI); ciscvm consumes its CSV export and gates.
        if not args.parse:
            fail("--parse <kitty-audit.csv> is required for the kitty tool "
                 "(run HardeningKitty on the Windows host, export CSV, then "
                 "parse it here)")
            return 1
        try:
            csv_text = Path(args.parse).read_text(encoding="utf-8-sig")
        except OSError as exc:
            fail(f"Could not read HardeningKitty CSV {args.parse}: {exc}")
            return 1
        audit = _parse_kitty_csv(csv_text)
    elif not args.host:
        fail("--host is required (the target instance to audit)")
        return 1
    elif args.tool == "oscap":
        if not args.datastream:
            fail("--datastream is required for oscap (e.g. "
                 "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml)")
            return 1
        info(f"Running oscap xccdf eval (profile={args.profile}) on {args.host} …")
        xml_text = _audit_oscap(args.host, args.ssh_user, args.ssh_port,
                                args.ssh_key, args.profile, args.datastream)
        audit = _parse_oscap_arf(xml_text)
    else:
        baseline = args.baseline or "dev-sec/linux-baseline"
        info(f"Running InSpec ({baseline}) against {args.host} …")
        audit = _parse_inspec_json(_audit_inspec(
            args.host, args.ssh_user, args.ssh_port, args.ssh_key, baseline))
    if getattr(args, "sarif", None):
        try:
            Path(args.sarif).write_text(_audit_results_sarif(audit), encoding="utf-8")
            ok(f"SARIF report written -> {args.sarif}")
        except OSError as exc:
            warn(f"Could not write SARIF report: {exc}")
    if getattr(args, "xccdf", None):
        try:
            Path(args.xccdf).write_text(_audit_results_xccdf(audit), encoding="utf-8")
            ok(f"XCCDF report written -> {args.xccdf}")
        except OSError as exc:
            warn(f"Could not write XCCDF report: {exc}")
    return _audit_render(audit, args.min_score)


def _audit_results_xccdf(audit: dict[str, Any]) -> str:
    """Minimal XCCDF 1.2 TestResult document from an independent audit."""
    from xml.sax.saxutils import escape
    rows = []
    for r in audit["results"]:
        rid = escape(r["id"])
        status = {"pass": "pass", "fail": "fail", "error": "error"}.get(
            r["status"], "notselected")
        rows.append(
            f'  <rule-result idref="{rid}"><result>{status}</result></rule-result>')
    score = audit.get("score")
    score_f = cast(float, score)
    score_xml = f"  <score>{score_f / 100.0:.6f}</score>" if score is not None else ""
    tool_name = str(audit.get("tool", "audit"))
    now = __import__("datetime").datetime.utcnow().isoformat()
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" '
        'id="ciscvm-audit">\n'
        f'  <TestResult id="ciscvm-{tool_name}" '
        f'start-time="{now}Z" end-time="{now}Z">\n'
        f'{score_xml}\n' + "\n".join(rows) + "\n"
        "  </TestResult>\n</Benchmark>\n")


# ── HardeningKitty CSV parser (P2#11, Windows cross-check) ──────────────────
# HardeningKitty (scaledagility) is the de-facto Windows CIS/STIG audit
# script.  `ciscvm audit --tool kitty --parse file.csv` consumes its audit
# CSV export and gates on the score — independent verification for the
# Windows profiles (which today only have the bundled PS1 engine).
def _parse_kitty_csv(csv_text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"score": None, "pass": 0, "fail": 0, "notselected": 0,
                          "error": 0, "results": [], "tool": "kitty"}
    import csv as _csv
    import io as _io
    reader = _csv.DictReader(_io.StringIO(csv_text))
    if not reader.fieldnames:
        out["error"] = 1
        out["results"] = [{"id": "_no_header_", "status": "error",
                           "detail": "empty HardeningKitty CSV"}]
        return out
    for _row_no, row in enumerate(reader, start=1):
        rid = (row.get("RuleId") or row.get("Id") or row.get("Rule") or "?")
        status = (row.get("Compliant") or row.get("Status") or row.get("Result") or "").lower()
        # HardeningKitty reports "True"/"False"/"-"/"Not Applicable"
        if status in ("true", "pass", "passed", "ok", "compliant"):
            out["pass"] += 1
            st = "pass"
        elif status in ("false", "fail", "failed", "not compliant"):
            out["fail"] += 1
            st = "fail"
        elif status in ("", "-", "n/a", "not applicable", "skip", "skipped"):
            out["notselected"] += 1
            st = "notselected"
        else:
            out["error"] += 1
            st = "error"
        out["results"].append({"id": rid, "status": st,
                               "detail": (row.get("Finding") or row.get("Message") or "")[:160]})
    scored = out["pass"] + out["fail"]
    if scored:
        out["score"] = round(100.0 * out["pass"] / scored, 1)
    return out


# ── Build notifications (WeCom group robot) ─────────────────────────────────
# [notify].webhook + [notify].on ("always"|"success"|"failure", default
# "failure").  Combined with an external cron / systemd timer this turns
# ciscvm build into a scheduled, self-reporting rebuild pipeline.
def _send_notification(r: ResolvedConfig, ok: bool, image_ids: list[str],
                       score: float | None, image_name: str) -> None:
    if not isinstance(r, ResolvedConfig):
        return
    # [notify].deploy_webhook — EventBridge-style downstream trigger (#14).
    # On SUCCESS, POST the image metadata to the customer's CI/CD so the
    # "new image is ready" event drives the deployment, not a human reading
    # the WeCom message.  Independent of the WeCom notification (fires even
    # when [notify].webhook is unset); never fails the build.
    if ok and r.deploy_webhook:
        _trigger_deploy_webhook(r, image_ids, score, image_name)
    if not r.notify_webhook:
        return
    if r.notify_on == "success" and not ok:
        return
    if r.notify_on == "failure" and ok:
        return
    if ok:
        head = "✅ ciscvm build OK"
        body = (f"profile {r.profile_name} L{r.level} | image {image_name} | "
                f"score {score:g}%" if score is not None else
                f"profile {r.profile_name} L{r.level} | image {image_name}")
        if image_ids:
            body += f"\nimage-id: {', '.join(image_ids)}"
        body += f"\nregion {r.region}"
    else:
        head = "❌ ciscvm build FAILED"
        body = f"profile {r.profile_name} L{r.level} | region {r.region} — check the build log"
    payload = json.dumps({"msgtype": "text", "text": {"content": f"{head}\n{body}"}},
                         ensure_ascii=False).encode("utf-8")
    try:
        req = urllib.request.Request(
            r.notify_webhook, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                info("Notification sent to WeCom webhook")
            else:
                warn(f"Notification webhook returned HTTP {resp.status}")
    except Exception as exc:  # notifications must never fail the build
        warn(f"Notification webhook failed: {exc}")


def _trigger_deploy_webhook(r: ResolvedConfig, image_ids: list[str],
                            score: float | None, image_name: str) -> None:
    """POST image metadata to [notify].deploy_webhook on build success."""
    payload = json.dumps({
        "event": "image.ready",
        "image_id": (image_ids[0] if image_ids else ""),
        "image_ids": image_ids,
        "image_name": image_name,
        "profile": r.profile_name,
        "cis_level": r.level,
        "region": r.region,
        "benchmark": r.image_benchmark,
        "score": score,
        "ciscvm_version": VERSION,
    }, ensure_ascii=False).encode("utf-8")
    try:
        req = urllib.request.Request(
            r.deploy_webhook, data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status < 300:
                ok(f"Deploy webhook triggered ({resp.status})")
            else:
                warn(f"Deploy webhook returned HTTP {resp.status}")
    except Exception as exc:  # must never fail the build
        warn(f"Deploy webhook failed: {exc}")


# ── SLSA-style provenance + signing ─────────────────────────────────────────
# Tencent Cloud CVM images are img-* artifacts, NOT OCI images — cosign's
# container signing does not apply.  We follow the SLSA provenance model
# instead: emit a build provenance statement (SLSA v1.0-ish) and, when a GPG
# key is configured, detach-sign it.  That gives an auditable, signed
# record of exactly what produced the image (SLSA L1 + signed provenance).
def _write_provenance(r: ResolvedConfig, image_ids: list[str], image_name: str,
                      score: float | None,
                      sbom_sha: str | None = None,
                      sbom_count: int | None = None) -> Path | None:
    if not isinstance(r, ResolvedConfig):
        return None
    try:
        from datetime import datetime
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        dirp = _lineage_path().parent / "provenance"
        dirp.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", image_name) or "image"
        prov_path = dirp / f"{safe_name}.{ts.replace(':', '').replace('-', '').replace('T', '-')}.provenance.json"
        prov: dict[str, Any] = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": i, "digest": {"sha256": "n/a"}} for i in image_ids],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://ciscvm.dev/build/v1",
                    "externalParameters": {
                        "profile": r.profile_name,
                        "cis_level": r.level,
                        "region": r.region,
                        "zone": r.zone,
                        "source_image_id": r.source_image_id,
                        "instance_type": r.instance_type,
                        "benchmark": r.image_benchmark,
                        # P1#4 — pin the exact rule catalog version that was
                        # applied, so the provenance is auditable against the
                        # benchmark edition (ansible-lockdown pins per-benchmark).
                        "rules_sha256": _bundled_rules_hash(r.role_dir),
                        "fingerprint": _build_fingerprint(r),
                    },
                    "internalParameters": {"ciscvm_version": VERSION},
                },
                "runDetails": {
                    "builder": {"id": f"ciscvm@{VERSION}"},
                    "metadata": {
                        "invocationId": ts,
                        "startedOn": ts,
                        "finishedOn": ts,
                    },
                },
            },
        }
        if score is not None:
            prov["predicate"]["runDetails"]["metadata"]["reAuditScore"] = score
        # P2#10 — SBOM pinning: the provenance now references the emitted
        # SBOM (hash + package count), closing the SLSA L2-style gap of
        # "what exactly shipped inside the image".
        if sbom_sha:
            prov["predicate"]["runDetails"]["metadata"]["sbomSha256"] = sbom_sha
        if sbom_count is not None:
            prov["predicate"]["runDetails"]["metadata"]["sbomPackageCount"] = sbom_count
        prov_path.write_text(json.dumps(prov, ensure_ascii=False, indent=1) + "\n",
                             encoding="utf-8")
        if r.sign_key:
            sig = prov_path.with_suffix(prov_path.suffix + ".sig")
            try:
                rc = subprocess.run(
                    ["gpg", "--batch", "--yes", "--detach-sign", "--armor",
                     "--local-user", r.sign_key, "-o", str(sig), str(prov_path)],
                    capture_output=True, text=True, timeout=60)
                if rc.returncode == 0:
                    ok(f"Provenance signed with GPG key {r.sign_key} -> {sig.name}")
                else:
                    warn(f"GPG signing failed (key {r.sign_key}?): "
                         f"{(rc.stderr or rc.stdout).strip()[:200]}")
            except FileNotFoundError:
                warn("gpg not found — provenance written unsigned")
            except subprocess.TimeoutExpired:
                warn("gpg signing timed out — provenance written unsigned")
        return prov_path
    except OSError as exc:
        warn(f"Could not write provenance: {exc}")
        return None


def cmd_list(args: argparse.Namespace) -> int:
    """Enumerate available profiles with metadata (P1#4: benchmark shown).

    *--versions* (#19): additionally show the bundled rule-catalog sha256
    and the ciscvm version, so an audit can pin "this image was hardened
    with exactly this rule set".
    """
    show_versions = bool(getattr(args, "versions", False))
    if show_versions:
        print(f"{'profile':<12} {'benchmark':<14} {'rules_sha256':<18} engine")
        for name, meta in sorted(PROFILES.items()):
            role = str(meta.get("role_dir", ""))
            bm = str(meta.get("benchmark", ""))
            rh = _bundled_rules_hash(role)[:16] if role else "-"
            print(f"{name:<12} {bm:<14} {rh:<18} {VERSION}")
        return 0
    print(f"{'profile':<12} {'family':<8} {'os':<12} {'comm':<6} {'benchmark':<14} user")
    for name, meta in sorted(PROFILES.items()):
        family = "windows" if meta.get("family") == "windows" else "linux"
        comm = "winrm" if family == "windows" else "ssh"
        user = meta.get("ssh_username", "") or meta.get("winrm_username", "") or "-"
        bm = str(meta.get("benchmark", ""))
        print(f"{name:<12} {family:<8} {str(meta.get('os_tag', '')):<12} "
              f"{comm:<6} {bm:<14} {user}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Audit-only build: engine runs in scan mode (no remediation), gate on score.

    Runs the full ephemeral-CVM pipeline but the bundled engine only
    *evaluates* the rules — nothing is modified.  The final re-audit score
    is gated against --min-score (default 85%); below it the command fails
    (non-zero exit) so CI can block on compliance.
    """
    prep = _load_resolve_preflight(args.config, args.workdir)
    if prep is None:
        return 1
    r, workdir = prep

    render_all(workdir, r, scan=True)
    banner("scan")
    info(f"Audit-only (no remediation) — {r.profile_name} L{r.level}, region {r.region}")
    info(f"Gate: score >= {args.min_score:g}%")

    result = run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug)
    image_ids = _extract_image_ids(result.stdout_lines)
    score = _extract_score(result.stdout_lines)
    image_name = _image_name(r)

    # SARIF report (if requested) — written regardless of gate outcome so CI
    # can archive failures.  P0#2: carry the benchmark reference so rule IDs
    # cross-reference the official CIS/SCAP numbering.
    _write_sarif(args, result.stdout_lines, benchmark=r.image_benchmark)
    # XCCDF 1.2 export (if requested) — P2#8, for enterprise GRC ingestion.
    _write_xccdf(args, result.stdout_lines, benchmark=r.image_benchmark)

    if result.exit_code != 0:
        fail("packer build failed during scan")
        _record_lineage(r, image_ids, image_name, score, ok=False)
        _send_notification(r, False, image_ids, score, image_name)
        return result.exit_code

    ok("scan build succeeded")
    if score is not None:
        ok(f"Scan score: {score:g}%")

    gate_ok = score is not None and score >= args.min_score
    if not gate_ok:
        shown = f"{score:g}%" if score is not None else "unknown"
        fail(f"scan gate FAILED: score {shown} < {args.min_score:g}%")
        _record_lineage(r, image_ids, image_name, score, ok=False)
        _send_notification(r, False, image_ids, score, image_name)
        return 1

    if image_ids:
        ok(f"Output image ID(s): {', '.join(image_ids)}")
    _record_lineage(r, image_ids, image_name, score, ok=True)
    _write_provenance(r, image_ids, image_name, score)
    _send_notification(r, True, image_ids, score, image_name)
    return 0


def _find_provenance(image_id: str) -> list[Path]:
    """Locate provenance files whose subject references *image_id*."""
    dirp = _lineage_path().parent / "provenance"
    if not dirp.is_dir():
        return []
    hits: list[Path] = []
    for p in sorted(dirp.glob("*.provenance.json")):
        try:
            prov = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        subjects = [s.get("name", "") for s in prov.get("subject", [])]
        if image_id in subjects:
            hits.append(p)
    return hits


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a signed provenance statement (SLSA signing verification)."""
    paths: list[Path] = []
    if args.provenance:
        p = Path(args.provenance)
        if not p.exists():
            fail(f"Provenance file not found: {p}")
            return 1
        paths = [p]
    elif args.image:
        paths = _find_provenance(args.image)
        if not paths:
            fail(f"No provenance found for image {args.image} in "
                 f"{_lineage_path().parent / 'provenance'}")
            return 1
    else:
        fail("Specify --provenance <file> or --image <id>")
        return 1

    rc_all = 0
    for prov_path in paths:
        try:
            prov = json.loads(prov_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            fail(f"Could not read provenance {prov_path}: {exc}")
            rc_all = 1
            continue
        banner("verify")
        ok(f"provenance : {prov_path}")
        subjects = ", ".join(s.get("name", "?") for s in prov.get("subject", []))
        info(f"subject    : {subjects}")
        ext = prov.get("predicate", {}).get("buildDefinition", {}).get("externalParameters", {})
        info(f"profile    : {ext.get('profile', '?')}  |  CIS level {ext.get('cis_level', '?')}  |  region {ext.get('region', '?')}")
        info(f"source     : {ext.get('source_image_id', '?')}")
        info(f"builder    : {prov.get('predicate', {}).get('runDetails', {}).get('builder', {}).get('id', '?')}")
        score = prov.get("predicate", {}).get("runDetails", {}).get("metadata", {}).get("reAuditScore")
        if score is not None:
            info(f"re-audit   : {score:g}%")
        # signature check
        sig = prov_path.with_suffix(prov_path.suffix + ".sig")
        if sig.exists():
            try:
                rc = subprocess.run(["gpg", "--verify", str(sig), str(prov_path)],
                                    capture_output=True, text=True, timeout=30)
                if rc.returncode == 0:
                    ok(f"signature  : VALID ({prov_path.name}.sig)")
                else:
                    fail(f"signature  : INVALID — {(rc.stderr or rc.stdout).strip()[:200]}")
                    rc_all = 1
            except FileNotFoundError:
                warn("gpg not found — cannot verify signature")
            except subprocess.TimeoutExpired:
                warn("gpg verify timed out")
        else:
            warn("signature  : NONE (provenance was not signed)")
            rc_all = 1
    return rc_all


# Paths that must never be deleted by ciscvm clean.
_FORBIDDEN_CLEAN_PREFIXES: tuple[Path, ...] = (
    Path("/"),
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
    Path.home() / "Library",
    Path.home() / "Pictures",
    Path.home() / "Music",
    Path.home() / "Movies",
)


def _clean_is_safe(workdir: Path) -> str | None:
    """Return an error message if *workdir* is unsafe to delete, else None."""
    wd = workdir.resolve()

    # 1. Require at least one ciscvm marker file (guard against accidental path)
    markers = [
        wd / "packer" / "main.pkr.hcl",
        wd / "ansible" / "site.yml",
    ]
    if not any(m.exists() for m in markers):
        return f"Not a ciscvm working directory (no packer/main.pkr.hcl or ansible/site.yml): {wd}"

    # 2. Reject known system / home root directories
    for forbidden in _FORBIDDEN_CLEAN_PREFIXES:
        try:
            fr = forbidden.resolve()
        except OSError:
            continue
        if wd == fr or str(wd).startswith(str(fr) + os.sep):
            return f"Refusing to clean system/home path: {wd}"

    return None


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove the rendered working directory."""
    workdir = Path(args.workdir)
    if not workdir.exists():
        info(f"Working directory does not exist: {workdir}")
        return 0

    err = _clean_is_safe(workdir)
    if err:
        fail(err)
        return 1

    shutil.rmtree(workdir)
    ok(f"Removed: {workdir}")
    return 0


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="ciscvm.toml",
                        help="Path to config file (default ./ciscvm.toml)")
    common.add_argument("--workdir", default=DEFAULT_WORKDIR,
                        help=f"Rendered working directory (default ./{DEFAULT_WORKDIR})")

    parser = argparse.ArgumentParser(
        prog="ciscvm",
        description="CIS-hardened Golden Image Builder (Packer × Tencent Cloud CVM)",
        epilog=f"Supported profiles: {PROFILE_NAMES_HELP}",
    )
    parser.add_argument("--version", action="version", version=f"ciscvm {VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Generate sample ciscvm.toml")
    p_init.add_argument("--target", default=".", help="Output directory (default: current)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    p_init.set_defaults(func=cmd_init)

    p_pre = sub.add_parser("preflight", parents=[common], help="Run pre-flight checks")
    p_pre.set_defaults(func=cmd_preflight)

    p_val = sub.add_parser("validate", parents=[common], help="Render + packer validate")
    p_val.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ciscvm summary)")
    p_val.add_argument("--debug", action="store_true",
                       help="Enable Packer debug logging (PACKER_LOG=1)")
    p_val.set_defaults(func=cmd_validate)

    p_bld = sub.add_parser("build", parents=[common], help="Render + packer build (produce image)")
    p_bld.add_argument("--quiet", action="store_true",
                       help="Suppress packer output (show only the ciscvm summary)")
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
                       help="Suppress packer output (show only the ciscvm summary)")
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
                       help="Suppress packer output (show only the ciscvm summary)")
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
    parser = build_parser()
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


if __name__ == "__main__":
    sys.exit(main())
