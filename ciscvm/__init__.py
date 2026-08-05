#!/usr/bin/env python3
"""
ciscvm — CIS-hardened Golden Image Builder (Packer × Tencent Cloud CVM)

Spins up an ephemeral CVM, applies the bundled cis-os engine role for CIS
hardening, and captures the result as a custom image.  All configuration is
driven by ciscvm.toml — no manual template editing.

Supported OS: Ubuntu 20/22/24, RHEL 8/9/10, TencentOS 3/4, SLES 15/16,
              Windows Server 2016/2019/2022/2025

Engine:  Bundled cis_engine.py (Linux) / cis_engine.ps1 (Windows).
         In-role gate via cis_fail_on_findings — no external audit.
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
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = "0.5.0"

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
#   ssh_timeout           Packer SSH timeout (default "10m")
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
PROFILES: dict[str, dict[str, Any]] = {
    # ── Ubuntu ──
    "ubuntu2004": {
        "role_dir": "cis_ubuntu2004",
        "ssh_username": "ubuntu",
        "os_tag": "ubuntu-20.04",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
        "clean_cmd": "sudo apt-get clean",
    },
    "ubuntu2204": {
        "role_dir": "cis_ubuntu2204",
        "ssh_username": "ubuntu",
        "os_tag": "ubuntu-22.04",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
        "clean_cmd": "sudo apt-get clean",
    },
    "ubuntu2404": {
        "role_dir": "cis_ubuntu2404",
        "ssh_username": "ubuntu",
        "os_tag": "ubuntu-24.04",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
        "clean_cmd": "sudo apt-get clean",
    },
    # ── RHEL ──
    "rhel8": {
        "role_dir": "cis_rhel8",
        "ssh_username": "root",
        "os_tag": "rhel-8",
        "benchmark": "CIS-v1.0.0",
        "ansible_core_spec": "ansible-core>=2.11",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
    },
    "rhel9": {
        "role_dir": "cis_rhel9",
        "ssh_username": "root",
        "os_tag": "rhel-9",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
    },
    "rhel10": {
        "role_dir": "cis_rhel10",
        "ssh_username": "root",
        "os_tag": "rhel-10",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
    },
    # ── TencentOS Server ──
    "tencentos3": {
        "role_dir": "cis_tencentos3",
        "ssh_username": "root",
        "ssh_port": 36000,
        "os_tag": "tencentos-3",
        "benchmark": "CIS-v1.0.0",
        "ansible_core_spec": "ansible-core>=2.11",
        "pip_index_url": "https://mirrors.cloud.tencent.com/pypi/simple/",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
    },
    "tencentos4": {
        "role_dir": "cis_tencentos4",
        "ssh_username": "root",
        "ssh_port": 36000,
        "os_tag": "tencentos-4",
        "benchmark": "CIS-v1.0.0",
        "pip_index_url": "https://mirrors.cloud.tencent.com/pypi/simple/",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
    },
    # ── SLES ──
    "sles15": {
        "role_dir": "cis_sles15",
        "ssh_username": "root",
        "os_tag": "sles-15",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo zypper refresh",
        "pkg_install": "sudo zypper install -y python3-pip git",
        "clean_cmd": "sudo zypper clean --all",
    },
    "sles16": {
        "role_dir": "cis_sles16",
        "ssh_username": "root",
        "os_tag": "sles-16",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo zypper refresh",
        "pkg_install": "sudo zypper install -y python3-pip git",
        "clean_cmd": "sudo zypper clean --all",
    },
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
[build]
profile             = "tencentos3"
#   Linux profiles: ubuntu2004 | ubuntu2204 | ubuntu2404 |
#                   rhel8 | rhel9 | rhel10 |
#                   tencentos3 | tencentos4 |
#                   sles15 | sles16
#   Windows:        win2016 | win2019 | win2022 | win2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-7"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # replace with real public image ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # empty [] to skip cross-region copy

[cis]
level = 1                                 # 1 or 2

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Windows builds also require:
# winrm_password_env = "WINRM_PASSWORD"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
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
    image_copy_regions: list[str]
    cis_level_tag: str
    secret_id_env: str
    secret_key_env: str
    image_os_tag: str
    image_benchmark: str
    level: int
    role_dir: str


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
        ssh_port=int(p.get("ssh_port", 22)),
        ssh_timeout=str(p.get("ssh_timeout", "10m")),
        ssh_username=str(p.get("ssh_username", "")),
        ssh_debug_password=str(meta.get("ssh_debug_password", "")),
        winrm_username=str(p.get("winrm_username", "")),
        winrm_password_env=str(data.get("cloud", {}).get("winrm_password_env", "WINRM_PASSWORD")),
        image_name_prefix=str(data["image"]["name_prefix"]),
        image_copy_regions=copy_regions,
        cis_level_tag=f"level{level}-server",
        secret_id_env=str(data["cloud"]["secret_id_env"]),
        secret_key_env=str(data["cloud"]["secret_key_env"]),
        image_os_tag=str(meta.get("os_tag", p.get("os_tag", ""))),
        image_benchmark=str(meta.get("benchmark", p.get("benchmark", ""))),
        level=level,
        role_dir=str(p["role_dir"]),
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
        warn(f"Role directory resolves outside of {roles_root}: {src}. Skipping.")
        return

    if not src.is_dir():
        raise ConfigError(
            f"Bundled role directory not found: {src}. "
            f"The package may be corrupted — reinstall ciscvm."
        )
    dst = workdir / "ansible" / "roles" / role_dir
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git"))


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

# ── Linux HCL (SSH communicator × ansible-local provisioner) ──
HCL_LINUX_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_ID")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_KEY")
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
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }

locals {
  level_short = replace(var.cis_level, "-server", "")
  image_name  = "${var.image_name_prefix}-${local.level_short}-${formatdate("YYYYMMDD", timestamp())}"
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  ssh_username                = var.ssh_username
  ssh_port                    = var.ssh_port
  ssh_timeout                 = var.ssh_timeout
  image_name                  = local.image_name
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

  # 1. Install ansible-core (roles uploaded by ciscvm — no galaxy needed)
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
  }

  # 2. CIS apply (ansible-local: gate inside role via cis_fail_on_findings)
  provisioner "ansible-local" {
    playbook_dir    = "ansible"
    playbook_file   = "ansible/site.yml"
    extra_arguments = []
  }

  # 3. Cleanup package cache before snapshot
  provisioner "shell" {
    pause_before = "10s"
    inline = [
      "__CLEAN_CMD__",
      "rm -rf /tmp/ansible ~/.ansible/roles 2>/dev/null || true"
    ]
  }
}
"""

# ── Windows HCL (winrm communicator × controller-side ansible provisioner) ──
HCL_WIN_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_ID")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_KEY")
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
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }

locals {
  level_short = replace(var.cis_level, "-server", "")
  image_name  = "${var.image_name_prefix}-${local.level_short}-${formatdate("YYYYMMDD", timestamp())}"
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  communicator                = "winrm"
  winrm_username              = var.winrm_username
  winrm_password              = var.winrm_password
  winrm_use_ssl               = true
  winrm_insecure              = true
  winrm_timeout               = "10m"
  image_name                  = local.image_name
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
  provisioner "ansible" {
    playbook_file = "ansible/site.yml"
    user          = var.winrm_username
    use_proxy     = false
    extra_arguments = [
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_server_cert_validation=ignore",
      "-e", "ansible_winrm_transport=basic",
      "--tags", var.cis_level
    ]
  }
}
"""

# ── Linux SITE_YML (ansible-local: localhost) ──
SITE_YML_TEMPLATE = r"""---
# CIS apply — bundled cis-os engine
# Gate inside role: cis_fail_on_findings: true → ansible exits non-zero on failures
- name: "CIS __OS_NAME__ - apply (__CIS_LEVEL__)"
  hosts: localhost
  connection: local
  become: true
  vars:
    cis_mode: apply
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: true
    cis_min_score: 0
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

# ── Windows SITE_YML (controller-side ansible → winrm) ──
SITE_YML_WIN_TEMPLATE = r"""---
# CIS apply — bundled cis-os engine (PowerShell)
# Gate inside role: cis_fail_on_findings: true
- name: "CIS __OS_NAME__ - apply (__CIS_LEVEL__)"
  hosts: all
  gather_facts: true
  vars:
    ansible_connection: winrm
    ansible_winrm_server_cert_validation: ignore
    ansible_winrm_transport: basic
    cis_mode: apply
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_fail_on_findings: true
    cis_min_score: 0
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

# 1. System dependencies
__PKG_UPDATE__
__PKG_INSTALL__

# 2. Ansible
sudo python3 -m pip install --upgrade pip __PIP_INDEX_FLAG__
sudo python3 -m pip install __PIP_INDEX_FLAG__ '__ANSIBLE_CORE_SPEC__' pexpect passlib

echo "ansible ready (cis-os engine)"
"""


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
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_pkrvars(r: ResolvedConfig) -> str:
    """Generate auto.pkrvars.hcl content."""
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
        .replace("__PKG_UPDATE__", str(p.get("pkg_update", "")))
        .replace("__PKG_INSTALL__", str(p.get("pkg_install", "")))
        .replace("__ANSIBLE_CORE_SPEC__", str(p.get("ansible_core_spec", "ansible-core>=2.15")))
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


def _assert_no_markers(content: str, filename: str) -> None:
    """Ensure no unreplaced __...__ template markers remain in rendered output."""
    markers = re.findall(r"__[A-Z_]+__", content)
    if markers:
        raise RuntimeError(
            f"Unreplaced markers in {filename}: {', '.join(sorted(set(markers)))}. "
            f"This is a bug — please report it."
        )


def render_all(workdir: Path, r: ResolvedConfig) -> None:
    """Render the complete build directory."""
    p = r.profile
    family: str = r.family

    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled role into workspace
    _bundle_role(workdir, r.role_dir)

    # 2. HCL (Linux or Windows template)
    if family == "windows":
        hcl = HCL_WIN_TEMPLATE.replace("__WINRM_PASSWORD_ENV__", r.winrm_password_env)
    else:
        hcl = HCL_LINUX_TEMPLATE.replace("__CLEAN_CMD__", str(p["clean_cmd"]))
        user_data = ""
        if r.ssh_debug_password:
            user_data = (
                '  user_data = <<EOF\n'
                '#!/bin/bash\n'
                f"echo 'root:{r.ssh_debug_password}' | chpasswd\n"
                'EOF\n'
            )
        hcl = hcl.replace("__USER_DATA_BLOCK__", user_data)
    _assert_no_markers(hcl, "main.pkr.hcl")
    (workdir / "packer" / "main.pkr.hcl").write_text(hcl, encoding="utf-8")

    # 3. Vars
    (workdir / "packer" / "auto.pkrvars.hcl").write_text(render_pkrvars(r), encoding="utf-8")

    # 4. Ansible playbook
    site = render_site(p, r.level)
    _assert_no_markers(site, "site.yml")
    (workdir / "ansible" / "site.yml").write_text(site, encoding="utf-8")

    # 5. Install script (Linux only)
    if family != "windows":
        install = render_install(p)
        _assert_no_markers(install, "install-ansible.sh")
        install_path = workdir / "packer" / "scripts" / "install-ansible.sh"
        install_path.write_text(install, encoding="utf-8")
        install_path.chmod(0o755)


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
) -> PackerResult:
    """Run `packer init` then `packer <subcmd>` inside *workdir*."""
    if timeout is None:
        timeout = PACKER_TIMEOUT_MINUTES * 60

    env = os.environ.copy()
    if debug:
        env["PACKER_LOG"] = "1"

    hcl_path = "packer/main.pkr.hcl"
    varfile_path = "packer/auto.pkrvars.hcl"

    # 1. packer init
    try:
        init_res = subprocess.run(
            ["packer", "init", hcl_path],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
    except FileNotFoundError:
        fail("packer not found in PATH. Install from https://developer.hashicorp.com/packer/install")
        return PackerResult(exit_code=1)
    except subprocess.TimeoutExpired:
        fail("packer init timed out (60s). Check network / plugin registry access.")
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
        if capture or quiet:
            # Capture output line-by-line with real-time streaming.
            lines: list[str] = []
            with subprocess.Popen(
                cmd, cwd=str(workdir),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, env=env,
            ) as proc:
                assert proc.stdout is not None
                for line in proc.stdout:
                    if not quiet:
                        print(line, end="", file=sys.stderr)
                    lines.append(line.rstrip("\n"))
                proc.wait(timeout=timeout)
            return PackerResult(exit_code=proc.returncode, stdout_lines=lines)
        else:
            # Inherit stdout/stderr from parent (live output, no capture).
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
    ignore_line = f"{DEFAULT_WORKDIR}/\n"
    if not gi.exists():
        gi.write_text(ignore_line, encoding="utf-8")
    elif ignore_line.strip() not in gi.read_text(encoding="utf-8"):
        gi.write_text(gi.read_text(encoding="utf-8").rstrip() + "\n" + ignore_line, encoding="utf-8")

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
        banner("build")
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

    result = run_packer(workdir, "build", quiet=args.quiet, capture=True, debug=args.debug)

    # Output is already streamed live by run_packer; only scan the captured
    # lines to extract the resulting image ID (do not re-print them).
    image_id: str | None = None
    for line in result.stdout_lines:
        if m := re.search(r"Created image ID:\s*(\S+)", line):
            image_id = m.group(1)
            break

    if result.exit_code == 0:
        ok("packer build succeeded")
        if image_id:
            ok(f"Output image ID: {image_id}")
        else:
            info("Could not parse image ID from output — check the Tencent Cloud console.")
    else:
        fail("packer build failed (see output above)")
    return result.exit_code


# Paths that must never be deleted by ciscvm clean.
_FORBIDDEN_CLEAN_PREFIXES: tuple[Path, ...] = (
    Path("/"),
    Path("/bin"),
    Path("/boot"),
    Path("/dev"),
    Path("/etc"),
    Path("/lib"),
    Path("/lib64"),
    Path("/opt"),
    Path("/proc"),
    Path("/root"),
    Path("/run"),
    Path("/sbin"),
    Path("/srv"),
    Path("/sys"),
    Path("/usr"),
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
    p_bld.set_defaults(func=cmd_build)

    p_cln = sub.add_parser("clean", parents=[common], help="Remove working directory")
    p_cln.set_defaults(func=cmd_clean)

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
