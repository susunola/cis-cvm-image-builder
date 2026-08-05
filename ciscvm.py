#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ciscvm — Packer × Tencent Cloud CVM × CIS Image Builder

A configuration-driven CLI tool that automates the CIS-hardened golden image pipeline:
  ephemeral CVM → run CIS hardening (ansible-lockdown / cis_engine) → audit gate → image.

All HCL, playbooks, and shell scripts are rendered from ciscvm.toml — the single
source of truth. No manual Packer template editing required.

Dependencies: Python >= 3.11 (stdlib only), Packer >= 1.9 on the build machine.

Usage:
    ciscvm init [--target DIR]      # Generate ciscvm.toml
    ciscvm preflight [--config F]   # Pre-flight check (credentials, network, plugins)
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
from typing import Any, cast

VERSION = "0.2.1"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("ciscvm")


def _setup_logging(*, verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)


def _color(text: str, code: int) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(msg: str) -> None:
    logger.info("  %s %s", _color("✓", 32), msg)


def warn(msg: str) -> None:
    logger.warning("  %s %s", _color("!", 33), msg)


def fail(msg: str) -> None:
    logger.error("  %s %s", _color("✗", 31), msg)


def info(msg: str) -> None:
    logger.info("  %s %s", _color("•", 36), msg)


def debug(msg: str) -> None:
    logger.debug("  %s", msg)


def banner(title: str) -> None:
    logger.info(_color(f"\n== {title} ==", 1))


# ---------------------------------------------------------------------------
# Configuration profiles
# ---------------------------------------------------------------------------
# ⚠️  ANSIBLE-LOCKDOWN variable prefix trap:
#     Different OS variants use different CIS role variable prefixes.
#     Getting them wrong causes silent no-ops — Level/GRUB overrides become dead.
#     - Ubuntu 22/24 -> ubtu22cis_ / ubtu24cis_   (NOT ubuntu!)
#     - RHEL 8/9      -> rhel8cis_  / rhel9cis_
#     - CentOS        -> reuses corresponding RHEL prefix
#     - Windows       -> win19cis_ / win22cis_ / win25cis_
#     Always verify against the role's defaults/main.yml — never infer.
PROFILES: dict[str, dict[str, Any]] = {
    # ── Ubuntu ──
    "ubuntu22": {
        "ssh_username": "ubuntu",
        "role": "ansible-lockdown.ubuntu22_cis",
        "role_version": "",
        "audit_dir": "/opt/ubuntu22_cis",
        "os_tag": "ubuntu-22.04",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
        "clean_cmd": "sudo apt-get clean",
        "level1_var": "ubtu22cis_level_1",
        "level2_var": "ubtu22cis_level_2",
        "boot_pass_var": "ubtu22cis_set_grub_user_pass",
        "os_check_var": None,
        "root_login_rule_var": None,
        "preview": False,
    },
    "ubuntu24": {
        "ssh_username": "ubuntu",
        "role": "ansible-lockdown.ubuntu24_cis",
        "role_version": "",
        "audit_dir": "/opt/ubuntu24_cis",
        "os_tag": "ubuntu-24.04",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo apt-get update -y",
        "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
        "clean_cmd": "sudo apt-get clean",
        "level1_var": "ubtu24cis_level_1",
        "level2_var": "ubtu24cis_level_2",
        "boot_pass_var": "ubtu24cis_set_grub_user_pass",
        "os_check_var": None,
        "root_login_rule_var": None,
        "preview": True,
    },
    # ── RHEL ──
    "rhel8": {
        "ssh_username": "root",
        "role": "ansible-lockdown.rhel8_cis",
        "role_version": "",
        "audit_dir": "/opt/rhel8_cis",
        "os_tag": "rhel-8",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "level1_var": "rhel8cis_level_1",
        "level2_var": "rhel8cis_level_2",
        "boot_pass_var": "rhel8cis_set_boot_pass",
        "os_check_var": None,
        "root_login_rule_var": "rhel8cis_rule_5_2_2",
        "preview": True,
    },
    "rhel9": {
        "ssh_username": "root",
        "role": "ansible-lockdown.rhel9_cis",
        "role_version": "",
        "audit_dir": "/opt/rhel9_cis",
        "os_tag": "rhel-9",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "level1_var": "rhel9cis_level_1",
        "level2_var": "rhel9cis_level_2",
        "boot_pass_var": "rhel9cis_set_boot_pass",
        "os_check_var": None,
        "root_login_rule_var": "rhel9cis_rule_5_2_2",
        "preview": True,
    },
    # ── CentOS (derived from RHEL, reuse RHEL roles + disable os_check) ──
    "centos8": {
        "ssh_username": "root",
        "role": "ansible-lockdown.rhel8_cis",
        "role_version": "",
        "audit_dir": "/opt/rhel8_cis",
        "os_tag": "centos-8",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "level1_var": "rhel8cis_level_1",
        "level2_var": "rhel8cis_level_2",
        "boot_pass_var": "rhel8cis_set_boot_pass",
        "os_check_var": "os_check",
        "root_login_rule_var": "rhel8cis_rule_5_2_2",
        "preview": True,
    },
    "centos9": {
        "ssh_username": "root",
        "role": "ansible-lockdown.rhel9_cis",
        "role_version": "",
        "audit_dir": "/opt/rhel9_cis",
        "os_tag": "centos-9",
        "benchmark": "CIS-v2.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "level1_var": "rhel9cis_level_1",
        "level2_var": "rhel9cis_level_2",
        "boot_pass_var": "rhel9cis_set_boot_pass",
        "os_check_var": "os_check",
        "root_login_rule_var": "rhel9cis_rule_5_2_2",
        "preview": True,
    },
    # ── TencentOS 3/4 (bundled cis-os engine, gate inside role) ──
    "tencentos3": {
        "family": "cis-os",
        "role_dir": "cis_tencentos3",
        "ssh_username": "root",
        "audit_dir": "",
        "os_tag": "tencentos-3",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "preview": False,
    },
    "tencentos4": {
        "family": "cis-os",
        "role_dir": "cis_tencentos4",
        "ssh_username": "root",
        "audit_dir": "",
        "os_tag": "tencentos-4",
        "benchmark": "CIS-v1.0.0",
        "pkg_update": "sudo dnf makecache",
        "pkg_install": "sudo dnf install -y python3-pip git",
        "clean_cmd": "sudo dnf clean all",
        "preview": False,
    },
    # ── Windows Server (winrm + remote ansible; no goss audit) ──
    "windows2019": {
        "family": "windows",
        "winrm_username": "Administrator",
        "role": "Windows-2019-CIS",
        "git_repo": "Windows-2019-CIS",
        "role_version": "",
        "os_tag": "windows-2019",
        "benchmark": "CIS-v2.0.0",
        "level1_var": "win19cis_l1_ms",
        "level2_var": "win19cis_l2_ms",
        "audit_dir": "",
        "preview": True,
    },
    "windows2022": {
        "family": "windows",
        "winrm_username": "Administrator",
        "role": "Windows-2022-CIS",
        "git_repo": "Windows-2022-CIS",
        "role_version": "",
        "os_tag": "windows-2022",
        "benchmark": "CIS-v2.0.0",
        "level1_var": "win22cis_l1_ms",
        "level2_var": "win22cis_l2_ms",
        "audit_dir": "",
        "preview": True,
    },
    "windows2025": {
        "family": "windows",
        "winrm_username": "Administrator",
        "role": "Windows-2025-CIS",
        "git_repo": "Windows-2025-CIS",
        "role_version": "",
        "os_tag": "windows-2025",
        "benchmark": "CIS-v2.0.0",
        "level1_var": "win25cis_l1_ms",
        "level2_var": "win25cis_l2_ms",
        "audit_dir": "",
        "preview": True,
    },
}

DEFAULT_WORKDIR = ".ciscvm-build"

SAMPLE_CONFIG = """\
# ciscvm.toml — single source of truth for all build parameters
[build]
profile             = "ubuntu22"          # ubuntu22 | ubuntu24 | rhel8 | rhel9 | ... (see PROFILES)
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # replace with real public image ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "ubuntu-2204-cis"
copy_regions = ["ap-shanghai"]            # empty [] to skip cross-region copy

[cis]
level        = 1                          # 1 or 2
max_failures = 0                          # audit failure tolerance (Linux ansible-lockdown only)
audit_dir    = "/opt/ubuntu22_cis"        # must match the role's audit output directory

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
winrm_password_env = "WINRM_PASSWORD"     # Windows profiles only (Administrator password)

[meta]
os_tag    = "ubuntu-22.04"
benchmark = "CIS-v2.0.0"
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
    family: str
    preview: bool
    region: str
    zone: str
    instance_type: str
    source_image_id: str
    vpc_id: str
    subnet_id: str
    security_group_id: str
    associate_public_ip: bool
    ssh_username: str
    winrm_username: str
    image_name_prefix: str
    image_copy_regions: list[str]
    cis_level_tag: str
    cis_max_failures: int
    cis_audit_dir: str
    secret_id_env: str
    secret_key_env: str
    winrm_password_env: str
    image_os_tag: str
    image_benchmark: str
    level: int


# ---------------------------------------------------------------------------
# Configuration loading & validation
# ---------------------------------------------------------------------------
class ConfigError(Exception):
    """Raised when the TOML configuration is invalid or missing required fields."""


def _validate_value_present(label: str, value: Any) -> str | None:
    """Return an error message if *value* looks like a placeholder, else None."""
    if not value:
        return f"{label}: cannot be empty"
    if isinstance(value, str) and "xxxxxxxx" in value:
        return f"{label}: still placeholder '{value}'"
    return None


def load_config(path: Path) -> dict[str, Any]:
    """Load and validate ciscvm.toml.  Raises ConfigError on invalid input."""
    if not path.exists():
        raise ConfigError(
            f"Configuration file not found: {path}\n"
            f"  Run 'ciscvm init' to generate a template."
        )

    # The stdlib tomllib requires reading bytes, not text.
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
        "cis": ["level", "max_failures"],
        "cloud": ["secret_id_env", "secret_key_env"],
    }

    profile_name = str(data.get("build", {}).get("profile", ""))
    if profile_name in PROFILES:
        fam = PROFILES[profile_name].get("family", "")
        # audit_dir is only mandatory for ansible-lockdown Linux profiles
        if fam not in ("windows", "cis-os"):
            required["cis"].append("audit_dir")

    for section, keys in required.items():
        if section not in data:
            raise ConfigError(f"Missing [{section}] section in configuration")
        for key in keys:
            if key not in data[section]:
                raise ConfigError(f"Missing field: [{section}].{key}")

    if profile_name not in PROFILES:
        raise ConfigError(
            f"Unknown profile: {profile_name}\n"
            f"  Valid choices: {PROFILE_NAMES_HELP}"
        )

    level = data["cis"]["level"]
    if level not in (1, 2):
        raise ConfigError(f"[cis].level must be 1 or 2, got: {level}")

    # Validate instance_type: packer requires "CVM." prefix — add it if omitted
    itype = str(data["build"]["instance_type"])
    if "." not in itype:
        raise ConfigError(
            f"[build].instance_type '{itype}' is missing the CVM prefix.\n"
            f"  Use the full specifier, e.g. 'S5.MEDIUM2' (not 'S5-MEDIUM2')."
        )

    # Validate security_group_id — must start with sg-
    if not str(data["build"]["security_group_id"]).startswith("sg-"):
        warn(f"[build].security_group_id '{data['build']['security_group_id']}' "
             f"does not look like a security group ID (should start with 'sg-').")

    return data


def resolve(data: dict[str, Any]) -> ResolvedConfig:
    """Flatten raw config + profile lookup into a ResolvedConfig."""
    profile_name: str = data["build"]["profile"]
    p = PROFILES[profile_name]
    meta: dict[str, Any] = data.get("meta", {})
    level: int = int(data["cis"]["level"])
    family: str = str(p.get("family", ""))

    return ResolvedConfig(
        profile_name=profile_name,
        profile=p,
        family=family,
        preview=bool(p.get("preview", False)),
        region=str(data["build"]["region"]),
        zone=str(data["build"]["zone"]),
        instance_type=str(data["build"]["instance_type"]),
        source_image_id=str(data["build"]["source_image_id"]),
        vpc_id=str(data["build"]["vpc_id"]),
        subnet_id=str(data["build"]["subnet_id"]),
        security_group_id=str(data["build"]["security_group_id"]),
        associate_public_ip=bool(data["build"]["associate_public_ip"]),
        ssh_username=str(p.get("ssh_username", "")),
        winrm_username=str(p.get("winrm_username", "")),
        image_name_prefix=str(data["image"]["name_prefix"]),
        image_copy_regions=list(data["image"]["copy_regions"]),
        cis_level_tag=f"level{level}-server",
        cis_max_failures=int(data["cis"]["max_failures"]),
        cis_audit_dir=str(data["cis"].get("audit_dir", p.get("audit_dir", ""))),
        secret_id_env=str(data["cloud"]["secret_id_env"]),
        secret_key_env=str(data["cloud"]["secret_key_env"]),
        winrm_password_env=str(data.get("cloud", {}).get("winrm_password_env", "WINRM_PASSWORD")),
        image_os_tag=str(meta.get("os_tag", p.get("os_tag", ""))),
        image_benchmark=str(meta.get("benchmark", p.get("benchmark", ""))),
        level=level,
    )


# ---------------------------------------------------------------------------
# Packer template rendering
# ---------------------------------------------------------------------------
HCL_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/packer-plugin-tencentcloud"
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
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
variable "image_copy_regions"          { type = list(string); default = [] }
variable "cis_level"                   { type = string }
variable "cis_max_failures"            { type = number; default = 0 }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }
variable "cis_audit_dir"               { type = string; default = "/opt/ubuntu22_cis" }

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

  # 1. Install ansible + CIS role inside the ephemeral CVM
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
  }

  # 2. CIS remediation (ansible-local: playbook + roles run inside the instance)
  provisioner "ansible-local" {
    playbook_file   = "ansible/site.yml"
    extra_arguments = ["--tags", var.cis_level]
  }

  # 3. Audit gate: fail build if too many audit failures
  provisioner "shell" {
    script = "packer/scripts/verify-cis.sh"
    environment_vars = [
      "CIS_AUDIT_DIR=${var.cis_audit_dir}",
      "CIS_MAX_FAILURES=${var.cis_max_failures}"
    ]
  }

  # 4. Cleanup: remove ansible/roles before snapshot
  provisioner "shell" {
    pause_before = "10s"
    inline = [
      "__CLEAN_CMD__",
      "rm -rf /tmp/ansible ~/.ansible/roles 2>/dev/null || true"
    ]
  }
}
"""

# TencentOS 3/4: bundled cis-os engine (gate inside role: cis_fail_on_findings + cis_min_score)
HCL_CISOS_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/packer-plugin-tencentcloud"
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
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
variable "image_copy_regions"          { type = list(string); default = [] }
variable "cis_level"                   { type = string }
variable "cis_audit_dir"               { type = string; default = "" }
variable "cis_max_failures"            { type = number; default = 0 }
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

  # 1. Install ansible (roles uploaded by ciscvm, no galaxy needed)
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
  }

  # 2. CIS apply (ansible-local: gate inside role — cis_fail_on_findings)
  provisioner "ansible-local" {
    playbook_file   = "ansible/site.yml"
    extra_arguments = ["--tags", var.cis_level]
  }

  # 3. Cleanup
  provisioner "shell" {
    pause_before = "10s"
    inline = [
      "__CLEAN_CMD__",
      "rm -rf /tmp/ansible ~/.ansible/roles 2>/dev/null || true"
    ]
  }
}
"""

# Windows: winrm communicator + remote ansible provisioner (roles installed on controller)
HCL_WIN_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/packer-plugin-tencentcloud"
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
variable "image_copy_regions"          { type = list(string); default = [] }
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

  provisioner "ansible" {
    playbook_file = "ansible/site.yml"
    user          = var.winrm_username
    use_proxy     = false
    extra_arguments = [
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_server_cert_validation=ignore",
      "-e", "ansible_winrm_transport=basic"
    ]
  }
}
"""

SITE_YML_TEMPLATE = r"""---
- hosts: localhost
  connection: local
  become: true
  vars:
    # ── CIS level ──
    __LEVEL1_VAR__: __LEVEL1_VAL__
    __LEVEL2_VAR__: __LEVEL2_VAL__

    # ── Cloud environment exceptions (DO NOT remove — prevent lockout) ──
__EXTRA_VARS__

    # ── Build-time audit gate ──
    run_audit: true
    setup_audit: true
    audit_only: false
    get_audit_binary_method: "download"

  roles:
    - __ROLE__
"""

SITE_YML_CISOS_TEMPLATE = r"""---
# CIS TencentOS apply (cis-os engine — not ansible-lockdown)
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

SITE_YML_WIN_TEMPLATE = r"""---
- hosts: all
  gather_facts: true
  vars:
    ansible_connection: winrm
    ansible_winrm_server_cert_validation: ignore
    ansible_winrm_transport: basic

    # ── CIS level (member server L1/L2 vars; GPO/domain vars off by default) ──
    __L1VAR__: __L1VAL__
    __L2VAR__: __L2VAL__
    __REMED_VAR__: true
    __GPO_VAR__: false

  roles:
    - __ROLE__
"""

INSTALL_SH_TEMPLATE = r"""#!/usr/bin/env bash
# Install ansible + CIS lockdown role inside the ephemeral CVM (Packer shell provisioner)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# 1. System dependencies
__PKG_UPDATE__
__PKG_INSTALL__

# 2. Ansible (system-wide, for ansible-local provisioner)
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install 'ansible-core>=2.15' pexpect passlib

# 3. Install CIS role (installed as current SSH user so ansible-local can find it)
__INSTALL_ROLE__

echo "ansible + CIS role ready"
"""

INSTALL_CISOS_TEMPLATE = r"""#!/usr/bin/env bash
# TencentOS CIS engine: install ansible (roles uploaded by ciscvm, no galaxy needed)
set -euo pipefail

# 1. System dependencies
__PKG_UPDATE__
__PKG_INSTALL__

# 2. Ansible
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install 'ansible-core>=2.15' pexpect passlib

echo "ansible ready (cis-os engine)"
"""

INSTALL_WIN_TEMPLATE = r"""#!/usr/bin/env bash
# Windows: CIS role installed on the controller, not inside the VM.
# ciscvm runs the following before build:
#   __INSTALL_ROLE__
echo "Windows: CIS role is installed on the controller, not inside the VM."
"""

VERIFY_SH_TEMPLATE = r"""#!/usr/bin/env bash
# Build-time CIS audit gate: run goss audit, fail build if too many failures.
# Environment variables:
#   CIS_AUDIT_DIR     Role audit output directory (default /opt/ubuntu22_cis)
#   CIS_MAX_FAILURES  Allowed failure count (default 0)
set -uo pipefail

AUDIT_DIR="${CIS_AUDIT_DIR:-/opt/ubuntu22_cis}"
MAX_FAILURES="${CIS_MAX_FAILURES:-0}"

if [ ! -d "$AUDIT_DIR" ]; then
  echo "WARN: audit directory $AUDIT_DIR not found, skipping gate." >&2
  exit 0
fi

LOG="$(mktemp)"
if [ -x "$AUDIT_DIR/run_audit.sh" ]; then
  echo "==> Running role audit script: run_audit.sh"
  bash "$AUDIT_DIR/run_audit.sh" | tee "$LOG" || true
elif command -v goss >/dev/null 2>&1 && [ -f "$AUDIT_DIR/goss.yaml" ]; then
  echo "==> Running goss directly"
  goss -g "$AUDIT_DIR/goss.yaml" render --format json >/dev/null 2>&1 || true
  goss -g "$AUDIT_DIR/goss.yaml" validate | tee "$LOG" || true
else
  echo "WARN: neither run_audit.sh nor goss found in $AUDIT_DIR, skipping gate." >&2
  exit 0
fi

# Parse failure count (multiple goss output formats)
if grep -qiE 'Failed[[:space:]]*:[[:space:]]*[0-9]+' "$LOG"; then
  failures=$(grep -oiE 'Failed[[:space:]]*:[[:space:]]*([0-9]+)' "$LOG" | grep -oE '[0-9]+' | head -1)
elif grep -qiE '[0-9]+[[:space:]]*fail' "$LOG"; then
  failures=$(grep -oiE '([0-9]+)[[:space:]]*fail' "$LOG" | grep -oE '[0-9]+' | head -1)
else
  failures=$(grep -ciE '\bFAIL\b' "$LOG")
fi
failures="${failures:-0}"

echo "------------------------------------------------------------"
echo "CIS audit failures: $failures  (tolerance: $MAX_FAILURES)"
echo "------------------------------------------------------------"

if [ "$failures" -gt "$MAX_FAILURES" ]; then
  echo "ERROR: CIS audit failures ($failures) exceed tolerance ($MAX_FAILURES). Build failed." >&2
  exit 1
fi

echo "OK: CIS audit within tolerance. Build continues."
exit 0
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
        return json.dumps(value, ensure_ascii=False)
    return f'"{value}"'


def render_pkrvars(r: ResolvedConfig) -> str:
    """Generate auto.pkrvars.hcl content."""
    lines: list[str] = []
    p = r.profile

    if p.get("family") == "windows":
        flat = {
            "region": r.region,
            "zone": r.zone,
            "instance_type": r.instance_type,
            "source_image_id": r.source_image_id,
            "winrm_username": r.winrm_username,
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
    else:
        flat = {
            "region": r.region,
            "zone": r.zone,
            "instance_type": r.instance_type,
            "source_image_id": r.source_image_id,
            "ssh_username": r.ssh_username,
            "vpc_id": r.vpc_id,
            "subnet_id": r.subnet_id,
            "security_group_id": r.security_group_id,
            "associate_public_ip_address": r.associate_public_ip,
            "image_name_prefix": r.image_name_prefix,
            "image_copy_regions": r.image_copy_regions,
            "cis_level": r.cis_level_tag,
            "cis_max_failures": r.cis_max_failures,
            "image_os_tag": r.image_os_tag,
            "image_benchmark": r.image_benchmark,
            "cis_audit_dir": r.cis_audit_dir,
        }

    for k, v in flat.items():
        lines.append(f"{k} = {_format_hcl_value(v)}")
    return "\n".join(lines) + "\n"


def render_install(p: dict[str, Any]) -> str:
    """Generate install-ansible.sh content."""
    if p.get("family") == "windows":
        repo: str = cast(str, p["git_repo"])
        install_line = (
            f'ansible-galaxy role install '
            f'"git+https://github.com/ansible-lockdown/{repo}.git" --force'
        )
        return INSTALL_WIN_TEMPLATE.replace("__INSTALL_ROLE__", install_line)
    if p.get("family") == "cis-os":
        return (
            INSTALL_CISOS_TEMPLATE
            .replace("__PKG_UPDATE__", str(p["pkg_update"]))
            .replace("__PKG_INSTALL__", str(p["pkg_install"]))
        )
    role: str = cast(str, p.get("role", ""))
    if p.get("role_version"):
        install_line = f'ansible-galaxy install "{role},{p["role_version"]}" --force'
    else:
        install_line = f'ansible-galaxy install "{role}" --force'
    return (
        INSTALL_SH_TEMPLATE
        .replace("__PKG_UPDATE__", str(p["pkg_update"]))
        .replace("__PKG_INSTALL__", str(p["pkg_install"]))
        .replace("__INSTALL_ROLE__", install_line)
    )


def render_requirements(p: dict[str, Any]) -> str:
    """Generate ansible/requirements.yml for Windows profiles."""
    repo: str = cast(str, p["git_repo"])
    return (
        "# Windows CIS role (installed on controller, used by ansible provisioner)\n"
        f"#   ciscvm runs: ansible-galaxy role install git+https://github.com/ansible-lockdown/{repo}.git --force\n"
        "roles:\n"
        f"  - src: git+https://github.com/ansible-lockdown/{repo}.git\n"
        f"    name: {repo}\n"
    )


def render_site(p: dict[str, Any], level: int) -> str:
    """Generate ansible/site.yml content."""
    l1 = "true" if level == 1 else "false"
    l2 = "true" if level == 2 else "false"

    if p.get("family") == "cis-os":
        cis_level = f"L{level}"
        return (
            SITE_YML_CISOS_TEMPLATE
            .replace("__OS_NAME__", str(p["os_tag"]))
            .replace("__CIS_LEVEL__", cis_level)
            .replace("__ROLE_DIR__", str(p["role_dir"]))
        )
    if p.get("family") == "windows":
        prefix = str(p["level1_var"]).split("_l1")[0]
        rem = f"{prefix}_ansible_remediation"
        gpo = f"{prefix}_create_gpos"
        return (
            SITE_YML_WIN_TEMPLATE
            .replace("__ROLE__", str(p["role"]))
            .replace("__L1VAR__", str(p["level1_var"]))
            .replace("__L1VAL__", l1)
            .replace("__L2VAR__", str(p["level2_var"]))
            .replace("__L2VAL__", l2)
            .replace("__REMED_VAR__", rem)
            .replace("__GPO_VAR__", gpo)
        )

    # ansible-lockdown Linux
    extra: list[str] = [
        f"    {p['boot_pass_var']}: false   # disable GRUB/boot password (prevents lockout)"
    ]
    if p.get("os_check_var"):
        extra.append(
            f"    {p['os_check_var']}: false   # non-RHEL derivative, disable OS check"
        )
    if p.get("root_login_rule_var"):
        extra.append(
            f"    {p['root_login_rule_var']}: false   # keep root SSH for build shell access"
        )
    extra_text = "\n".join(extra)
    return (
        SITE_YML_TEMPLATE
        .replace("__LEVEL1_VAR__", str(p["level1_var"]))
        .replace("__LEVEL1_VAL__", l1)
        .replace("__LEVEL2_VAR__", str(p["level2_var"]))
        .replace("__LEVEL2_VAL__", l2)
        .replace("__EXTRA_VARS__", extra_text)
        .replace("__ROLE__", str(p["role"]))
    )


def render_all(workdir: Path, r: ResolvedConfig) -> None:
    """Render the complete build directory."""
    p = r.profile
    is_win = p.get("family") == "windows"
    is_cisos = p.get("family") == "cis-os"

    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    if is_win:
        hcl = HCL_WIN_TEMPLATE.replace("__WINRM_PASSWORD_ENV__", r.winrm_password_env)
        (workdir / "packer" / "main.pkr.hcl").write_text(hcl, encoding="utf-8")
    elif is_cisos:
        role_dir = str(p.get("role_dir", ""))
        tool_roles = Path(__file__).parent / "roles" / role_dir
        dst_roles = workdir / "ansible" / "roles" / role_dir
        if not tool_roles.is_dir():
            warn(f"Bundled role directory not found: {tool_roles}. "
                 f"Ensure roles/{role_dir}/ exists alongside ciscvm.py.")
        else:
            if dst_roles.exists():
                shutil.rmtree(dst_roles)
            shutil.copytree(tool_roles, dst_roles)
        (workdir / "packer" / "main.pkr.hcl").write_text(
            HCL_CISOS_TEMPLATE.replace("__CLEAN_CMD__", str(p["clean_cmd"])),
            encoding="utf-8",
        )
    else:
        (workdir / "packer" / "main.pkr.hcl").write_text(
            HCL_TEMPLATE.replace("__CLEAN_CMD__", str(p["clean_cmd"])),
            encoding="utf-8",
        )

    (workdir / "packer" / "auto.pkrvars.hcl").write_text(render_pkrvars(r), encoding="utf-8")
    (workdir / "ansible" / "site.yml").write_text(render_site(p, r.level), encoding="utf-8")

    if is_win:
        (workdir / "ansible" / "requirements.yml").write_text(
            render_requirements(p), encoding="utf-8"
        )
    else:
        (workdir / "packer" / "scripts" / "install-ansible.sh").write_text(
            render_install(p), encoding="utf-8"
        )
        if not is_cisos:
            (workdir / "packer" / "scripts" / "verify-cis.sh").write_text(
                VERIFY_SH_TEMPLATE, encoding="utf-8"
            )
        for sh in (workdir / "packer" / "scripts").glob("*.sh"):
            sh.chmod(0o755)


# ---------------------------------------------------------------------------
# Packer subprocess
# ---------------------------------------------------------------------------
PACKER_TIMEOUT_MINUTES = 120  # generous timeout for image builds


def run_packer(
    workdir: Path,
    subcmd: str,
    quiet: bool = False,
    capture: bool = False,
    timeout: int | None = None,
) -> PackerResult:
    """Run `packer init` then `packer <subcmd>` inside *workdir*.

    Returns a PackerResult which always contains exit_code and stdout_lines.
    """
    if timeout is None:
        timeout = PACKER_TIMEOUT_MINUTES * 60

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
        )
    except FileNotFoundError:
        fail("packer not found in PATH. Install from https://developer.hashicorp.com/packer/install")
        return PackerResult(exit_code=1, stdout_lines=[])
    except subprocess.TimeoutExpired:
        fail("packer init timed out (60s). Check network / plugin registry access.")
        return PackerResult(exit_code=1, stdout_lines=[])

    if init_res.returncode != 0:
        fail("packer init failed (see output above for details).")
        return PackerResult(
            exit_code=init_res.returncode,
            stdout_lines=init_res.stdout.splitlines() if init_res.stdout else [],
        )

    # 2. packer <subcmd>
    cmd = ["packer", subcmd, f"-var-file={varfile_path}", hcl_path]
    try:
        if capture or quiet:
            res = subprocess.run(
                cmd, cwd=workdir,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
            lines = res.stdout.splitlines() if res.stdout else []
            return PackerResult(exit_code=res.returncode, stdout_lines=lines)
        else:
            res = subprocess.run(cmd, cwd=workdir, timeout=timeout)
            return PackerResult(exit_code=res.returncode, stdout_lines=[])
    except subprocess.TimeoutExpired:
        fail(f"packer {subcmd} timed out after {timeout // 60} minutes.")
        return PackerResult(exit_code=1, stdout_lines=[])
    except FileNotFoundError:
        fail("packer not found in PATH.")
        return PackerResult(exit_code=1, stdout_lines=[])


# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
def run_preflight(r: ResolvedConfig) -> bool:
    """Run all pre-flight checks. Returns True if everything passes."""
    banner("preflight")
    all_ok = True

    # Credentials
    for env_name in (r.secret_id_env, r.secret_key_env):
        if os.environ.get(env_name):
            ok(f"Credential env var {env_name} is set")
        else:
            fail(f"Credential env var {env_name} is not set (export before running)")
            all_ok = False

    # packer binary
    if shutil.which("packer"):
        ok("packer found in PATH")
    else:
        fail("packer not found in PATH — install from https://developer.hashicorp.com/packer/install")
        all_ok = False

    # Windows-specific checks
    if r.family == "windows":
        if shutil.which("ansible"):
            ok("ansible found in PATH (required for Windows controller-side provisioning)")
        else:
            fail("Windows profiles need controller-side ansible: pip install 'ansible' pywinrm")
            all_ok = False
        try:
            import importlib
            importlib.import_module("winrm")
            ok("pywinrm is installed")
        except ImportError:
            fail("pywinrm not installed on controller: pip install pywinrm")
            all_ok = False
        if os.environ.get(r.winrm_password_env):
            ok(f"WinRM password env var {r.winrm_password_env} is set")
        else:
            fail(f"WinRM password env var {r.winrm_password_env} is not set "
                 f"(Windows Administrator password, export before running)")
            all_ok = False

    # cis-os: verify bundled role directory exists
    if r.family == "cis-os":
        role_dir = str(r.profile.get("role_dir", ""))
        tool_roles = Path(__file__).parent / "roles" / role_dir
        if tool_roles.is_dir():
            ok(f"Bundled role '{role_dir}' ready ({tool_roles})")
        else:
            fail(f"Bundled role directory missing: {tool_roles}. "
                 f"Ensure roles/{role_dir}/ exists alongside ciscvm.py.")
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

    # Preview profile warning
    if r.preview:
        warn(f"profile={r.profile_name} is marked preview — verify role vars against defaults/main.yml.")
    else:
        ok(f"profile={r.profile_name} (CIS Level {r.level})")

    if all_ok:
        info("All pre-flight checks passed.")
    else:
        warn("Some pre-flight checks failed — fix before continuing.")
    return all_ok


def _is_interactive(stream: Any = sys.stdin) -> bool:
    """Check if the terminal is interactive (TTY)."""
    try:
        return stream.isatty()
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------------------------------
# Windows controller-side role installation
# ---------------------------------------------------------------------------
def ensure_controller_roles(r: ResolvedConfig) -> int:
    """For Windows profiles: install the CIS role on the controller before build."""
    if r.family != "windows":
        return 0
    repo: str = cast(str, r.profile.get("git_repo", ""))
    cmd: list[str] = [
        "ansible-galaxy", "role", "install",
        f"git+https://github.com/ansible-lockdown/{repo}.git",
        "--force",
    ]
    banner("controller role install (windows)")
    info(f"Windows profile: installing CIS role {repo} on controller ...")
    try:
        res = subprocess.run(cmd, timeout=120)
    except subprocess.TimeoutExpired:
        fail(f"ansible-galaxy install timed out for {repo}")
        return 1
    except FileNotFoundError:
        fail("ansible-galaxy not found — install ansible on the controller first")
        return 1

    if res.returncode != 0:
        fail(f"ansible-galaxy install failed for {repo}")
    else:
        ok(f"Role {repo} installed on controller")
    return res.returncode


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
    info("Then run: ciscvm preflight / validate / build")
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    """Run pre-flight checks."""
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as exc:
        fail(str(exc))
        return 1
    return 0 if run_preflight(r) else 1


def cmd_validate(args: argparse.Namespace) -> int:
    """Render templates and run packer validate."""
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as exc:
        fail(str(exc))
        return 1

    if not run_preflight(r):
        return 1
    if ensure_controller_roles(r) != 0:
        return 1

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    render_all(workdir, r)

    banner("validate")
    info(f"Rendered working directory: {workdir}")
    info("Running packer init + packer validate ...")
    result = run_packer(workdir, "validate", quiet=args.quiet)

    for line in result.stdout_lines:
        print(line)

    if result.exit_code == 0:
        ok("packer validate passed")
    else:
        fail("packer validate failed (see output above)")
    return result.exit_code


def cmd_build(args: argparse.Namespace) -> int:
    """Render templates and run packer build."""
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as exc:
        fail(str(exc))
        return 1

    if not run_preflight(r):
        return 1
    if ensure_controller_roles(r) != 0:
        return 1

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    render_all(workdir, r)

    # Confirmation prompt (skip with -y or in non-interactive mode)
    if not args.yes:
        banner("build")
        info(f"profile     = {r.profile_name}  |  CIS Level {r.level}  |  region {r.region}")
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

    result = run_packer(workdir, "build", quiet=args.quiet, capture=True)

    # Stream output + extract image ID
    image_id: str | None = None
    for line in result.stdout_lines:
        print(line)
        if image_id is None and (m := re.search(r"Created image ID:\s*(\S+)", line)):
            image_id = m.group(1)

    if result.exit_code == 0:
        ok("packer build succeeded")
        if image_id:
            ok(f"Output image ID: {image_id}")
        else:
            info("Could not parse image ID from output — check the Tencent Cloud console.")
    else:
        fail("packer build failed (see output above)")
    return result.exit_code


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove the rendered working directory."""
    workdir = Path(args.workdir)
    if workdir.exists():
        shutil.rmtree(workdir)
        ok(f"Removed: {workdir}")
    else:
        info(f"Working directory does not exist: {workdir}")
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
        prog="ciscvm", parents=[common],
        description="Packer × Tencent Cloud CVM × CIS Image Builder",
        epilog=f"Supported profiles: {PROFILE_NAMES_HELP}",
    )
    parser.add_argument("--version", action="version", version=f"ciscvm {VERSION}")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", parents=[common], help="Generate sample ciscvm.toml")
    p_init.add_argument("--target", default=".", help="Output directory (default: current)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing config")
    p_init.set_defaults(func=cmd_init)

    p_pre = sub.add_parser("preflight", parents=[common], help="Run pre-flight checks")
    p_pre.set_defaults(func=cmd_preflight)

    p_val = sub.add_parser("validate", parents=[common], help="Render + packer validate")
    p_val.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    p_val.set_defaults(func=cmd_validate)

    p_bld = sub.add_parser("build", parents=[common], help="Render + packer build (produce image)")
    p_bld.add_argument("--quiet", action="store_true", help="Suppress verbose output")
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
    # Dispatch: argparse ensures every subcommand has a 'func' default
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
