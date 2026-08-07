#!/usr/bin/env python3
"""
ciscvm — CIS-hardened Golden Image Builder (Packer × Tencent Cloud CVM)

Spins up an ephemeral CVM, applies the bundled cis-os engine role for CIS
hardening, and captures the result as a custom image.  All configuration is
driven by ciscvm.toml — no manual template editing.

Supported OS: Ubuntu 20/22/24, RHEL 8/9/10, TencentOS 3/4, SLES 15/16,
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
from pathlib import Path
from typing import Any

VERSION = "0.14.0"

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
def _ubuntu_profile(role_dir: str, os_tag: str, **kw) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "ubuntu", "os_tag": os_tag,
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv",
        # authselect is RHEL-only; harmless under `--no-install-recommends
        # ... || true` but noisy — kept off the apt list.
        "cis_pkg_batch": "sudo apt-get install -y --no-install-recommends sudo libpam-modules firewalld chrony rsyslog cron aide systemd-journal-remote || true",
        "clean_cmd": "sudo apt-get clean", **kw,
    }

def _rhel_profile(role_dir: str, os_tag: str, **kw) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "root", "os_tag": os_tag,
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip",
        "cis_pkg_batch": "sudo dnf install -y --skip-broken sudo pam authselect firewalld chrony rsyslog cronie aide systemd-journal-remote libselinux libselinux-utils || true",
        "clean_cmd": "sudo dnf clean all", **kw,
    }

def _tlinux_profile(role_dir: str, os_tag: str, **kw) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "root", "ssh_port": 36000,
        "os_tag": os_tag, "benchmark": "CIS-v1.0.0",
        "pip_index_url": "https://mirrors.cloud.tencent.com/pypi/simple/",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip",
        "cis_pkg_batch": "sudo dnf install -y --skip-broken sudo pam authselect firewalld chrony rsyslog cronie aide systemd-journal-remote libselinux libselinux-utils || true",
        "clean_cmd": "sudo dnf clean all", **kw,
    }

def _sles_profile(role_dir: str, os_tag: str, **kw) -> dict[str, Any]:
    return {
        "role_dir": role_dir, "ssh_username": "root", "os_tag": os_tag,
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo zypper refresh",
        "pkg_install": "sudo zypper install -y python3-pip python3-venv",
        "cis_pkg_batch": "sudo zypper --non-interactive install -y sudo pam authselect firewalld chrony rsyslog cronie aide systemd-journal-remote || true",
        "clean_cmd": "sudo zypper clean --all", **kw,
    }

PROFILES: dict[str, dict[str, Any]] = {
    "ubuntu2004":  _ubuntu_profile("cis_ubuntu2004", "ubuntu-20.04"),
    "ubuntu2204":  _ubuntu_profile("cis_ubuntu2204", "ubuntu-22.04"),
    "ubuntu2404":  _ubuntu_profile("cis_ubuntu2404", "ubuntu-24.04"),
    "rhel8":       _rhel_profile("cis_rhel8", "rhel-8", ansible_core_spec="ansible-core>=2.11"),
    "rhel9":       _rhel_profile("cis_rhel9", "rhel-9"),
    "rhel10":      _rhel_profile("cis_rhel10", "rhel-10"),
    "tencentos3":  _tlinux_profile("cis_tencentos3", "tencentos-3", ansible_core_spec="ansible-core>=2.11"),
    "tencentos4":  _tlinux_profile("cis_tencentos4", "tencentos-4"),
    "sles15":      _sles_profile("cis_sles15", "sles-15"),
    "sles16":      _sles_profile("cis_sles16", "sles-16"),
    # ── Windows Server (winrm + controller-side ansible) ──
    "win2016": {
        "family": "windows",
        "role_dir": "cis_win2016",
        "winrm_username": "Administrator",
        "os_tag": "windows-2016",
        "benchmark": "CIS-v1.0.0",
    },
    "win2019": {
        "family": "windows",
        "role_dir": "cis_win2019",
        "winrm_username": "Administrator",
        "os_tag": "windows-2019",
        "benchmark": "CIS-v1.0.0",
    },
    "win2022": {
        "family": "windows",
        "role_dir": "cis_win2022",
        "winrm_username": "Administrator",
        "os_tag": "windows-2022",
        "benchmark": "CIS-v1.0.0",
    },
    "win2025": {
        "family": "windows",
        "role_dir": "cis_win2025",
        "winrm_username": "Administrator",
        "os_tag": "windows-2025",
        "benchmark": "CIS-v1.0.0",
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
#                   tencentos3 | tencentos4 |
#                   sles15 | sles16
#   Windows:        win2016 | win2019 | win2022 | win2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-3"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # replace with real public image ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = false               # set to true only if a public IP is required

[image]
name_prefix  = "tencentos3-cis"
# name = "my-cis-image"                  # optional: fixed image name (empty = auto prefix-level-timestamp)
copy_regions = []                         # add regions (e.g. ["ap-shanghai"]) to copy the image

[cis]
level = 1                                 # 1 or 2

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

# SLSA-style provenance signing (GPG). Empty = provenance unsigned.
# [sign]
# gpg_key = "ABCDEF0123456789"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
# smoke_test = true   # instance-level checks before the image snapshot
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
    role_dir: str
    smoke_test: bool                    # [meta].smoke_test — run instance-level smoke checks before snapshot (default true)
    notify_webhook: str                 # [notify].webhook — WeCom group-robot webhook URL ("" = off)
    notify_on: str                      # [notify].on — "always" | "success" | "failure" (default "failure")
    sign_key: str                       # [sign].gpg_key — GPG key id/fingerprint for SLSA provenance signing ("" = off)


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
    if assume_role_arn:
        if not re.fullmatch(r"[A-Za-z0-9:_/-]+", assume_role_arn):
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
        notify_webhook=notify_webhook,
        notify_on=notify_on,
        sign_key=sign_key,
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
    except ValueError:
        raise ConfigError(
            f"Role directory resolves outside of {roles_root}: {src}. "
            "Refusing to bundle — check the profile's role_dir.")

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
    'echo "127.0.0.1 $(hostname)" >> /etc/hosts'
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
    inline = ["echo '==> ciscvm version: __VERSION__'"]
  }

  # 1. Install ansible-core (roles uploaded by ciscvm — no galaxy needed)
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
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
      "if command -v firewall-cmd >/dev/null 2>&1 && sudo systemctl is-active firewalld >/dev/null 2>&1; then for z in $(sudo firewall-cmd --get-active-zones 2>/dev/null | grep -v '^ '); do sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp; sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp --permanent; done; sudo firewall-cmd --reload; fi",
      "if command -v nft >/dev/null 2>&1 && sudo systemctl is-active nftables >/dev/null 2>&1; then for t in $(sudo nft list tables 2>/dev/null | awk '{print $2}'); do sudo nft add rule $t input tcp dport $SSH_PORT accept 2>/dev/null || true; done; fi",
      "if command -v iptables >/dev/null 2>&1; then sudo iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || true; fi",
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
    # Upload to /opt (not /tmp): systemd-tmpfiles on the freshly rebooted
    # image may purge /tmp (tmp.conf D-type cleanup), which made the
    # reconnect probe fail with 'bash: script: Permission denied' (126).
    remote_path       = "/opt/ciscvm-ansible/reconnected.sh"
    inline            = ["echo reconnected"]
    valid_exit_codes  = [0, 1, -1]
  }

  # 5.5 Fix log-file permissions that were loosened by boot-time
  #     services (cloud-init, systemd-logind, …).  These files are
  #     recreated on every boot with default perms; the CIS engine
  #     flags them in the re-audit unless we fix them first.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/ciscvm-ansible/fix-logperms.sh"
    inline = [
      "set +e",
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
    remote_path  = "/opt/ciscvm-ansible/cleanup.sh"
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
      "rm -rf /tmp/ansible /opt/ciscvm-ansible/staging /opt/ciscvm-ansible/reboot.sh /opt/ciscvm-ansible/ssh-guard.sh /opt/ciscvm-ansible/reconnected.sh /opt/ciscvm-ansible/fix-logperms.sh /opt/ciscvm-ansible/cleanup.sh ~/.ansible/roles 2>/dev/null || true"
    ]
  }

  # 7.5 Persist the re-audit JSON to /opt for the ciscvm report and banner,
  #     then clean up the temp workdir before the snapshot.  The re-audit
  #     role runs with cis_keep_remote_artifacts=true (provisioner #6),
  #     so /tmp/cis-*/result.json still exists when we get here.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/ciscvm-ansible/collect-audit.sh"
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
    remote_path  = "/opt/ciscvm-ansible/run-finalize.sh"
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
__SMOKE_TEST_BLOCK__
}
"""

# ── Instance-level smoke test (Linux) ──
# Runs as the very last provisioner, AFTER finalize + final re-audit and
# BEFORE Packer snapshots the image.  Any failure exits non-zero → Packer
# aborts → no image is produced.  This is the "Test" leg of the
# build → test → distribute pipeline (AWS Image Builder style).
SMOKE_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    inline = [
      "echo '[ciscvm] smoke test: sshd config parses'",
      "sudo sshd -T >/dev/null 2>&1 || { echo '[ciscvm] SMOKE FAIL: sshd -T rejected config'; exit 1; }",
      "echo '[ciscvm] smoke test: sshd active'",
      "systemctl is-active --quiet sshd || { echo '[ciscvm] SMOKE FAIL: sshd not active'; exit 1; }",
      "echo '[ciscvm] smoke test: auditd active'",
      "systemctl is-active --quiet auditd || { echo '[ciscvm] SMOKE FAIL: auditd not active'; exit 1; }",
      "echo '[ciscvm] smoke test: /dev/shm noexec'",
      "awk '$2 == \"/dev/shm\" && $4 ~ /noexec/' /proc/mounts | grep -q . || { echo '[ciscvm] SMOKE FAIL: /dev/shm lacks noexec'; exit 1; }",
      "echo '[ciscvm] smoke test: no weak SSH crypto'",
      "if sudo sshd -T 2>/dev/null | tr ',' '\\n' | grep -Eiq 'hmac-sha1|hmac-md5|umac-64|chacha20|aes128-cbc|aes192-cbc|aes256-cbc'; then",
      "  echo '[ciscvm] SMOKE FAIL: weak SSH crypto present'; exit 1;",
      "fi",
      "echo '[ciscvm] smoke test: journal-upload (if configured)'",
      "if systemctl list-unit-files systemd-journal-upload.service >/dev/null 2>&1; then",
      "  systemctl is-active --quiet systemd-journal-upload || { echo '[ciscvm] SMOKE FAIL: journal-upload inactive'; exit 1; }",
      "fi",
      "echo '[ciscvm] smoke test PASSED — image is buildable'"
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
  winrm_timeout               = "10m"
  image_name                  = var.image_name
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  associate_public_ip_address = var.associate_public_ip_address
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

  # CIS apply via controller-side ansible (winrm — cis_engine.ps1)
  # NOTE: no --tags filter — the bundled Windows roles don't tag tasks,
  # so filtering by level would silently skip every task.
  provisioner "ansible" {
    playbook_file = "ansible/site.yml"
    user          = var.winrm_username
    use_proxy     = false
    extra_arguments = [
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_transport=basic"
    ]
  }
__SMOKE_TEST_BLOCK__
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
    cis_mode: apply
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: 0
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
    cis_min_score: 85
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

# ── Windows SITE_YML (controller-side ansible → winrm) ──
SITE_YML_WIN_TEMPLATE = r"""---
# CIS apply — bundled cis-os engine (PowerShell)
# Gate via cis_min_score (findings-only gate stays off: some controls are
# always manual/disruptive and would block every build).
- name: "CIS __OS_NAME__ - apply (__CIS_LEVEL__)"
  hosts: all
  gather_facts: true
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: basic
    cis_mode: apply
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: 85
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
#    Refreshing package indexes (apt-get update / dnf makecache / zypper
#    refresh) is one of the slowest steps and is pure waste when the base
#    image already ships python3 venv + pip. Probe first, only touch the
#    package manager when something is actually missing.
need_pkgs=0
# venv module + ensurepip must both work to build the ansible venv offline
python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || need_pkgs=1
if [ "$need_pkgs" = "1" ]; then
    echo "==> base deps missing, refreshing package manager"
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
     (sudo apt-get update -qq && sudo apt-get install -y python3.9 python3.9-venv) 2>/dev/null || \
     sudo zypper --non-interactive install -y python39 2>/dev/null || true)
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
sudo "$VENV/bin/python" -m pip install --disable-pip-version-check \
    __PIP_INDEX_FLAG__ '__ANSIBLE_CORE_SPEC__' pexpect passlib

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
    from datetime import datetime, timezone
    snap_ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
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


def render_site(p: dict[str, Any], level: int) -> str:
    """Generate ansible/site.yml."""
    cis_level = f"L{level}"
    family = str(p.get("family", ""))

    if family == "windows":
        return (
            SITE_YML_WIN_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
        )
    else:
        return (
            SITE_YML_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
        )


def render_site_audit(p: dict[str, Any], level: int) -> str:
    """Generate ansible/site-audit.yml for post-reboot re-evaluation."""
    cis_level = f"L{level}"
    return (
        SITE_AUDIT_TEMPLATE
        .replace("__OS_NAME__", str(p["os_tag"]))
        .replace("__CIS_LEVEL__", cis_level)
        .replace("__ROLE_DIR__", str(p["role_dir"]))
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


def render_all(workdir: Path, r: ResolvedConfig) -> None:
    """Render the complete build directory."""
    p = r.profile
    family: str = r.family

    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled role into workspace
    _bundle_role(workdir, r.role_dir)

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
    if r.smoke_test:
        smoke_block = SMOKE_LINUX_BLOCK if family != "windows" else SMOKE_WIN_BLOCK
    else:
        smoke_block = ""

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
               .replace("__SMOKE_TEST_BLOCK__", smoke_block)
               .replace("__ASSUME_ROLE_BLOCK__", assume_role_block))
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
    site = render_site(p, r.level)
    _assert_no_markers(site, "site.yml")
    (workdir / "ansible" / "site.yml").write_text(site, encoding="utf-8")

    if family != "windows":
        site_audit = render_site_audit(p, r.level)
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
                log_fh = open(log_file, "a", encoding="utf-8") if log_file else None
                try:
                    for line in proc.stdout:
                        if not quiet:
                            print(line, end="", file=sys.stderr)
                        if log_fh:
                            log_fh.write(line)
                        lines.append(line.rstrip("\n"))
                finally:
                    if log_fh:
                        log_fh.close()

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

    wd = Path(workdir)
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
        # Build → test → distribute: record lineage + signed provenance
        lin = _record_lineage(r, image_ids, image_name, score, ok=True)
        if lin:
            info(f"Lineage recorded -> {lin}")
        prov = _write_provenance(r, image_ids, image_name, score)
        if prov:
            info(f"Provenance written -> {prov}")
    else:
        fail("packer build failed (see output above)")
        _record_lineage(r, image_ids, image_name, score, ok=False)

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


# ── Image lineage ────────────────────────────────────────────────────────────
# Every successful build appends a record to ~/.ciscvm/lineage.jsonl, so
# downstream tools (Terraform, ASG, scripts) can resolve "latest approved
# image" instead of hand-copying image IDs.  This is the lightweight cousin
# of HCP Packer's channels / AWS Image Builder distribution metadata.
def _lineage_path() -> Path:
    return Path.home() / ".ciscvm" / "lineage.jsonl"


def _record_lineage(r: ResolvedConfig, image_ids: list[str], image_name: str,
                    score: float | None, ok: bool) -> Path | None:
    """Append one lineage record. Returns the file path, or None on failure."""
    if not isinstance(r, ResolvedConfig):
        return None  # defensive: only real resolved configs are recorded
    try:
        path = _lineage_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        from datetime import datetime, timezone
        rec = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return path
    except OSError:
        return None


def cmd_images(args: argparse.Namespace) -> int:
    """List recorded builds (lineage) — most recent first."""
    path = _lineage_path()
    if not path.exists():
        info(f"No lineage records yet at {path} — run a build first.")
        return 0
    records: list[dict] = []
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


# ── Build notifications (WeCom group robot) ─────────────────────────────────
# [notify].webhook + [notify].on ("always"|"success"|"failure", default
# "failure").  Combined with an external cron / systemd timer this turns
# ciscvm build into a scheduled, self-reporting rebuild pipeline.
def _send_notification(r: ResolvedConfig, ok: bool, image_ids: list[str],
                       score: float | None, image_name: str) -> None:
    if not isinstance(r, ResolvedConfig):
        return
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
                info(f"Notification sent to WeCom webhook")
            else:
                warn(f"Notification webhook returned HTTP {resp.status}")
    except Exception as exc:  # notifications must never fail the build
        warn(f"Notification webhook failed: {exc}")


# ── SLSA-style provenance + signing ─────────────────────────────────────────
# Tencent Cloud CVM images are img-* artifacts, NOT OCI images — cosign's
# container signing does not apply.  We follow the SLSA provenance model
# instead: emit a build provenance statement (SLSA v1.0-ish) and, when a GPG
# key is configured, detach-sign it.  That gives an auditable, signed
# record of exactly what produced the image (SLSA L1 + signed provenance).
def _write_provenance(r: ResolvedConfig, image_ids: list[str], image_name: str,
                      score: float | None) -> Path | None:
    if not isinstance(r, ResolvedConfig):
        return None
    try:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dirp = _lineage_path().parent / "provenance"
        dirp.mkdir(parents=True, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", image_name) or "image"
        prov_path = dirp / f"{safe_name}.{ts.replace(':', '').replace('-', '').replace('T', '-')}.provenance.json"
        prov = {
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

    sub = parser.add_subparsers(dest="command", required=True)

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
    p_bld.set_defaults(func=cmd_build)

    p_cln = sub.add_parser("clean", parents=[common], help="Remove working directory")
    p_cln.set_defaults(func=cmd_clean)

    p_img = sub.add_parser("images", help="List recorded builds (image lineage)")
    p_img.add_argument("--latest", action="store_true", help="Show only the newest record")
    p_img.add_argument("-n", "--limit", type=int, default=10,
                       help="Max records to show (default 10; 0 = all)")
    p_img.set_defaults(func=cmd_images)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point — parse args, dispatch to subcommand, return exit code."""
    _setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(verbose=args.verbose)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
