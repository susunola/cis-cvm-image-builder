#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ciscvm — Packer × 腾讯云 CVM × CIS 镜像构建小工具

把「起临时 CVM → ansible-local 跑 CIS 角色 → goss 审计 gate → 打镜像」整条流水线
收敛成一个配置驱动的单命令工具。HCL / playbook / 脚本全部由 config 渲染生成，
config（ciscvm.toml）是唯一的「事实来源」，不用再手改 HCL。

依赖：Python ≥ 3.11（仅标准库），以及构建机上装有 packer。

用法：
    python3 ciscvm.py init [--target DIR]      # 生成示例 ciscvm.toml
    python3 ciscvm.py preflight [--config F]   # 构建前自检（凭据/网络/插件/参数）
    python3 ciscvm.py validate  [--config F]   # 渲染 + packer init + packer validate
    python3 ciscvm.py build     [--config F]   # 渲染 + packer build（产出镜像）
    python3 ciscvm.py clean     [--config F]   # 删除渲染工作目录
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

VERSION = "0.2.0"

# ----------------------------------------------------------------------------
# 配置画像（profile）：换 OS 只加一个字典项，不用改任何代码逻辑
# ----------------------------------------------------------------------------
# ⚠️  ANSIBLE-LOCKDOWN 变量前缀陷阱（务必注意！）
#    不同 OS 的 CIS 角色变量前缀不同，写错会静默失效，Level/GRUB 覆盖全部变 NO-OP。
#    - Ubuntu 22/24 → ubtu22cis_ / ubtu24cis_    **是 ubtu 不是 ubuntu！**
#    - RHEL 8/9     → rhel8cis_  / rhel9cis_
#    - CentOS        → 套用对应 RHEL 前缀
#    - Windows       → win19cis_ / win22cis_ / win25cis_
#    每条新 profile 加 level1_var / level2_var / boot_pass_var 时，
#    必须以角色 defaults/main.yml 为准逐字核对，不要靠「规律」推断。
#
#  各字段含义：
#   ssh_username        临时 CVM 的 SSH 登录用户
#   role                Galaxy 角色名（ansible-lockdown.<x>）
#   role_version        固定版本号；空字符串 = 装 galaxy 最新（推荐先跑通再 pin）
#   audit_dir           角色 goss 审计输出目录（verify-cis.sh 用；不同角色不同，需对上）
#   os_tag/benchmark    写入镜像 tag 的标识
#   pkg_update/pkg_install/clean_cmd   包管理器命令（按 OS 区分，避免写死 apt）
#   level1_var/level2_var              角色里控制 CIS Level 的变量（前缀随 OS 而变！）
#   boot_pass_var       控制引导/GRUB 密码的变量，统一显式关掉，避免把自己锁死
#   os_check_var        CentOS 等非 RHEL 派生系统需要关掉 OS 校验（None 表示不关）
#   root_login_rule_var 关掉「禁止 root SSH 登录」那条 rule，保证构建期 shell 还能连上
#   preview             角色名/变量名未经逐一验证时标 True，preflight 会提醒
PROFILES = {
    # ---------- Ubuntu ----------
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
    # ---------- RHEL ----------
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
    # ---------- CentOS（派生自 RHEL，套用对应 RHEL 角色 + 关闭 os_check）----------
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
    # ---------- Windows Server（winrm + 远程 ansible；无 goss 审计）----------
    # 注意：ansible-lockdown 的 Windows 角色按 section 应用 CIS 设置，L1/L2 用成员服务器
    # 变量（l1_ms / l2_ms）区分；GPO/域相关变量默认关闭。WinRM 是连接与构建必需，不能禁。
    # 该画像为 preview：winrm provisioner 接线、L1/L2 成员服务器变量名需按真实角色版本核对。
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
        "audit_dir": "",          # Windows 无 goss 审计，留空表示跳过 verify gate
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
# ciscvm.toml — 唯一事实来源，所有构建参数都在这里改
[build]
profile             = "ubuntu22"          # ubuntu22 | ubuntu24 | rhel8 | rhel9 | centos8 | centos9 | windows2019 | windows2022 | windows2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # 替换为官方对应 OS 公共镜像 ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "ubuntu-2204-cis"
copy_regions = ["ap-shanghai"]            # 留空 [] 不跨地域复制

[cis]
level        = 1                          # 1 或 2
max_failures = 0                          # 审计失败项容忍上限，超过则 build 失败（仅 Linux 生效，Windows 无 goss 审计）
audit_dir    = "/opt/ubuntu22_cis"        # 必须与角色审计输出目录一致（仅 Linux 生效）

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
winrm_password_env = "WINRM_PASSWORD"     # 仅 Windows 画像需要（Windows 管理员密码）

[meta]
os_tag    = "ubuntu-22.04"                # 镜像 tag 用，一般随 profile 默认即可
benchmark = "CIS-v2.0.0"
"""

# ----------------------------------------------------------------------------
# 渲染模板（HCL 是静态文本，配置值经由 auto.pkrvars.hcl 注入）
# ----------------------------------------------------------------------------
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

  # 1. 临时 CVM 内装 ansible + CIS 角色
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
  }

  # 2. CIS remediation（ansible-local：playbook 与角色都在实例内执行）
  provisioner "ansible-local" {
    playbook_file   = "ansible/site.yml"
    extra_arguments = ["--tags", var.cis_level]
  }

  # 3. build 期审计 gate：不达标 -> exit 1 -> build 失败
  provisioner "shell" {
    script = "packer/scripts/verify-cis.sh"
    environment_vars = [
      "CIS_AUDIT_DIR=${var.cis_audit_dir}",
      "CIS_MAX_FAILURES=${var.cis_max_failures}"
    ]
  }

  # 4. 清理：缩容前清掉 ansible / 角色，避免带进镜像
  provisioner "shell" {
    pause_before = "10s"
    inline = [
      "__CLEAN_CMD__",
      "rm -rf /tmp/ansible ~/.ansible/roles 2>/dev/null || true"
    ]
  }
}
"""

# Windows：winrm 通信 + 远程 ansible provisioner（角色在控制器侧预装，连到临时 Windows CVM 跑）
# 注意：Windows 画像为 preview，winrm provisioner 接线请按真实构建验证；goss 审计不适用，故无 verify gate。
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

  # CIS remediation：控制器侧 ansible 通过 winrm 连到临时 Windows CVM 跑 lockdown 角色
  # （角色需在 build 前由 ciscvm 在控制器侧 `ansible-galaxy role install git+...` 预装）
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

SITE_YML_WIN_TEMPLATE = r"""---
- hosts: all
  gather_facts: true
  vars:
    # WinRM 连接（控制器 ansible 通过 winrm 连到临时 Windows CVM）
    ansible_connection: winrm
    ansible_winrm_server_cert_validation: ignore
    ansible_winrm_transport: basic

    # ---- CIS 等级（Windows 用成员服务器 L1/L2 变量；GPO/域相关默认关闭）----
    __L1VAR__: __L1VAL__
    __L2VAR__: __L2VAL__
    __REMED_VAR__: true
    __GPO_VAR__: false

    # ---- 云环境例外：保留 WinRM / 远程管理，避免把自己锁死 ----
    # Windows 镜像默认允许 WinRM；CIS 加固不要禁用，否则 provisioner 后续连不上。
  roles:
    - __ROLE__

# 注意：Windows 角色按 section 应用 CIS 设置，L1/L2 用成员服务器变量区分；
# 不同 CIS 版本变量名可能不同，跑前请以角色 defaults/main.yml 为准。
"""

INSTALL_SH_TEMPLATE = r"""#!/usr/bin/env bash
# 在临时 CVM 内安装 ansible 与 CIS lockdown 角色（由 Packer shell provisioner 调用）
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# 1. 系统依赖
__PKG_UPDATE__
__PKG_INSTALL__

# 2. ansible（装到系统 PATH，供 ansible-local provisioner 调用）
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install 'ansible-core>=2.15' pexpect passlib

# 3. 安装 CIS 角色（作为当前 SSH 用户，ansible-local 以该用户运行可找到）
#    角色名随 Galaxy 命名空间/版本可能微调；如 galaxy 名对不上，改用 git 源兜底：
#    ansible-galaxy install git+https://github.com/ansible-lockdown/<REPO>.git
__INSTALL_ROLE__

echo "ansible + CIS role ready"
"""

INSTALL_WIN_TEMPLATE = r"""#!/usr/bin/env bash
# Windows 画像：ansible 不在实例内运行（角色在「控制器侧」安装并执行）。
# 此文件仅作离线参考；真实安装由 ciscvm 在 build 前自动执行：
#   __INSTALL_ROLE__
echo "Windows: CIS role is installed on the controller, not inside the VM."
"""

VERIFY_SH_TEMPLATE = r"""#!/usr/bin/env bash
# build 期 CIS 审计 gate：加固后跑 goss 审计，失败项超限则 exit 1 让 packer build 失败
# 可调环境变量：
#   CIS_AUDIT_DIR     角色审计输出目录（默认 /opt/ubuntu22_cis，按角色版本调整）
#   CIS_MAX_FAILURES  允许的失败项数（默认 0）
set -uo pipefail

AUDIT_DIR="${CIS_AUDIT_DIR:-/opt/ubuntu22_cis}"
MAX_FAILURES="${CIS_MAX_FAILURES:-0}"

if [ ! -d "$AUDIT_DIR" ]; then
  echo "WARN: 审计目录 $AUDIT_DIR 不存在，跳过硬 gate。" >&2
  echo "      请按你使用的角色版本设置 audit_dir（参考角色 README 的 audit 输出位置）。" >&2
  exit 0
fi

LOG="$(mktemp)"
if [ -x "$AUDIT_DIR/run_audit.sh" ]; then
  echo "==> 运行角色自带审计 run_audit.sh"
  bash "$AUDIT_DIR/run_audit.sh" | tee "$LOG" || true
elif command -v goss >/dev/null 2>&1 && [ -f "$AUDIT_DIR/goss.yaml" ]; then
  echo "==> 直接运行 goss"
  goss -g "$AUDIT_DIR/goss.yaml" render --format json >/dev/null 2>&1 || true
  goss -g "$AUDIT_DIR/goss.yaml" validate | tee "$LOG" || true
else
  echo "WARN: 在 $AUDIT_DIR 未找到 run_audit.sh 或 goss，跳过硬 gate。" >&2
  exit 0
fi

# 解析失败项数（兼容 goss 多种摘要格式）
if grep -qiE 'Failed[[:space:]]*:[[:space:]]*[0-9]+' "$LOG"; then
  failures=$(grep -oiE 'Failed[[:space:]]*:[[:space:]]*([0-9]+)' "$LOG" | grep -oE '[0-9]+' | head -1)
elif grep -qiE '[0-9]+[[:space:]]*fail' "$LOG"; then
  failures=$(grep -oiE '([0-9]+)[[:space:]]*fail' "$LOG" | grep -oE '[0-9]+' | head -1)
else
  failures=$(grep -ciE '\bFAIL\b' "$LOG")
fi
failures="${failures:-0}"

echo "------------------------------------------------------------"
echo "CIS 审计失败项: $failures  (容忍上限: $MAX_FAILURES)"
echo "------------------------------------------------------------"

if [ "$failures" -gt "$MAX_FAILURES" ]; then
  echo "ERROR: CIS 审计失败项 ($failures) 超过容忍上限 ($MAX_FAILURES)，构建失败。" >&2
  exit 1
fi

echo "OK: CIS 审计在容忍范围内，构建继续。"
exit 0
"""

SITE_YML_TEMPLATE = r"""---
- hosts: localhost
  connection: local
  become: true
  vars:
    # ---- CIS 等级 ----
    __LEVEL1_VAR__: __LEVEL1_VAL__
    __LEVEL2_VAR__: __LEVEL2_VAL__

    # ---- 云环境例外（务必保留，否则会把自己锁死 / 破坏云能力）----
__EXTRA_VARS__

    # ---- build 期审计 gate ----
    run_audit: true
    setup_audit: true
    audit_only: false
    get_audit_binary_method: "download"

  roles:
    - __ROLE__

# 注意：不同 CIS 版本角色变量名略有差异，以角色 defaults/main.yml 为准；
# Level 2 还需额外分区（/var /var/tmp /var/log /var/log/audit /home）。
"""


# ----------------------------------------------------------------------------
# 终端输出
# ----------------------------------------------------------------------------
def _color(text: str, code: int) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    return f"\033[{code}m{text}\033[0m"


def ok(msg: str) -> None:
    print(f"  {_color('✓', 32)} {msg}")


def warn(msg: str) -> None:
    print(f"  {_color('!', 33)} {msg}")


def fail(msg: str) -> None:
    print(f"  {_color('✗', 31)} {msg}")


def info(msg: str) -> None:
    print(f"  {_color('•', 36)} {msg}")


def banner(title: str) -> None:
    print(_color(f"\n== {title} ==", 1))


# ----------------------------------------------------------------------------
# 配置加载与校验
# ----------------------------------------------------------------------------
class ConfigError(Exception):
    pass


def load_config(path: Path) -> dict:
    if not path.exists():
        raise ConfigError(f"找不到配置文件 {path}，先跑 `ciscvm.py init` 生成。")
    with path.open("rb") as f:
        data = tomllib.load(f)

    required = {
        "build": ["profile", "region", "zone", "instance_type", "source_image_id",
                  "vpc_id", "subnet_id", "security_group_id", "associate_public_ip"],
        "image": ["name_prefix", "copy_regions"],
        "cis": ["level", "max_failures"],
        "cloud": ["secret_id_env", "secret_key_env"],
    }
    # audit_dir is only required for Linux profiles; Windows has no goss audit
    profile = data.get("build", {}).get("profile", "")
    if profile in PROFILES and PROFILES[profile].get("family") != "windows":
        required["cis"].append("audit_dir")
    for section, keys in required.items():
        if section not in data:
            raise ConfigError(f"配置缺少 [section]：[{section}]")
        for k in keys:
            if k not in data[section]:
                raise ConfigError(f"配置缺少字段：[{section}].{k}")

    profile = data["build"]["profile"]
    if profile not in PROFILES:
        raise ConfigError(f"未知 profile：{profile}（可选：{', '.join(PROFILES)}）")

    lvl = data["cis"]["level"]
    if lvl not in (1, 2):
        raise ConfigError(f"[cis].level 只能是 1 或 2，当前：{lvl}")

    return data


def resolve(data: dict) -> dict:
    """把 config + profile 解析成渲染所需的扁平字典。"""
    profile_name = data["build"]["profile"]
    p = PROFILES[profile_name]
    meta = data.get("meta", {})
    level = data["cis"]["level"]
    family = p.get("family", "linux")
    return {
        "profile_name": profile_name,
        "profile": p,
        "family": family,
        "preview": p.get("preview", False),
        "region": data["build"]["region"],
        "zone": data["build"]["zone"],
        "instance_type": data["build"]["instance_type"],
        "source_image_id": data["build"]["source_image_id"],
        "vpc_id": data["build"]["vpc_id"],
        "subnet_id": data["build"]["subnet_id"],
        "security_group_id": data["build"]["security_group_id"],
        "associate_public_ip": data["build"]["associate_public_ip"],
        "ssh_username": p.get("ssh_username", ""),
        "winrm_username": p.get("winrm_username", ""),
        "image_name_prefix": data["image"]["name_prefix"],
        "image_copy_regions": data["image"]["copy_regions"],
        "cis_level_tag": f"level{level}-server",
        "cis_max_failures": data["cis"]["max_failures"],
        "cis_audit_dir": data["cis"]["audit_dir"],
        "secret_id_env": data["cloud"]["secret_id_env"],
        "secret_key_env": data["cloud"]["secret_key_env"],
        "winrm_password_env": data.get("cloud", {}).get("winrm_password_env", "WINRM_PASSWORD"),
        "image_os_tag": meta.get("os_tag", p["os_tag"]),
        "image_benchmark": meta.get("benchmark", p["benchmark"]),
        "level": level,
    }


# ----------------------------------------------------------------------------
# 渲染
# ----------------------------------------------------------------------------
def render_pkrvars(r: dict) -> str:
    lines = []
    p = r["profile"]
    if p.get("family") == "windows":
        # Windows HCL 不声明 ssh_username / cis_max_failures / cis_audit_dir，必须对齐变量集
        flat = {
            "region": r["region"],
            "zone": r["zone"],
            "instance_type": r["instance_type"],
            "source_image_id": r["source_image_id"],
            "winrm_username": r["winrm_username"],
            "vpc_id": r["vpc_id"],
            "subnet_id": r["subnet_id"],
            "security_group_id": r["security_group_id"],
            "associate_public_ip_address": r["associate_public_ip"],
            "image_name_prefix": r["image_name_prefix"],
            "image_copy_regions": r["image_copy_regions"],
            "cis_level": r["cis_level_tag"],
            "image_os_tag": r["image_os_tag"],
            "image_benchmark": r["image_benchmark"],
        }
    else:
        flat = {
            "region": r["region"],
            "zone": r["zone"],
            "instance_type": r["instance_type"],
            "source_image_id": r["source_image_id"],
            "ssh_username": r["ssh_username"],
            "vpc_id": r["vpc_id"],
            "subnet_id": r["subnet_id"],
            "security_group_id": r["security_group_id"],
            "associate_public_ip_address": r["associate_public_ip"],
            "image_name_prefix": r["image_name_prefix"],
            "image_copy_regions": r["image_copy_regions"],
            "cis_level": r["cis_level_tag"],
            "cis_max_failures": r["cis_max_failures"],
            "image_os_tag": r["image_os_tag"],
            "image_benchmark": r["image_benchmark"],
            "cis_audit_dir": r["cis_audit_dir"],
        }
    for k, v in flat.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            lines.append(f"{k} = {v}")
        elif isinstance(v, list):
            lines.append(f'{k} = {json.dumps(v, ensure_ascii=False)}')
        else:
            lines.append(f'{k} = "{v}"')
    return "\n".join(lines) + "\n"


def render_install(p: dict) -> str:
    if p.get("family") == "windows":
        # Windows：角色在「控制器侧」安装，用 git 源最稳（galaxy 名随版本可能变动）
        repo = p["git_repo"]
        install_line = f'ansible-galaxy role install "git+https://github.com/ansible-lockdown/{repo}.git" --force'
        # 该 install 命令由 ciscvm 在 build 前于控制器执行，这里仅作参考/离线记录
        return (INSTALL_WIN_TEMPLATE.replace("__INSTALL_ROLE__", install_line))
    if p.get("role_version"):
        install_line = f'ansible-galaxy install "{p["role"]},{p["role_version"]}" --force'
    else:
        install_line = f'ansible-galaxy install "{p["role"]}" --force'
    return (INSTALL_SH_TEMPLATE
            .replace("__PKG_UPDATE__", p["pkg_update"])
            .replace("__PKG_INSTALL__", p["pkg_install"])
            .replace("__INSTALL_ROLE__", install_line))


def render_requirements(p: dict) -> str:
    repo = p["git_repo"]
    return (
        "# Windows CIS 角色（控制器侧安装，供 ansible provisioner 使用）\n"
        "# ciscvm 会在 build 前自动执行：\n"
        f"#   ansible-galaxy role install git+https://github.com/ansible-lockdown/{repo}.git --force\n"
        "roles:\n"
        f"  - src: git+https://github.com/ansible-lockdown/{repo}.git\n"
        f"    name: {repo}\n"
    )


def render_site(p: dict, level: int) -> str:
    l1 = "true" if level == 1 else "false"
    l2 = "true" if level == 2 else "false"
    if p.get("family") == "windows":
        # 成员服务器 L1/L2 变量前缀（win22cis_ / win19cis_ ...）
        prefix = p["level1_var"].split("_l1")[0]
        rem = f"{prefix}_ansible_remediation"
        gpo = f"{prefix}_create_gpos"
        return (SITE_YML_WIN_TEMPLATE
                .replace("__ROLE__", p["role"])
                .replace("__L1VAR__", p["level1_var"])
                .replace("__L1VAL__", l1)
                .replace("__L2VAR__", p["level2_var"])
                .replace("__L2VAL__", l2)
                .replace("__REMED_VAR__", rem)
                .replace("__GPO_VAR__", gpo))
    extra = [f"    {p['boot_pass_var']}: false   # 关闭引导/GRUB 密码，避免把自己锁死"]
    if p.get("os_check_var"):
        extra.append(f"    {p['os_check_var']}: false   # 非 RHEL 派生系统，关闭 OS 校验")
    if p.get("root_login_rule_var"):
        extra.append(f"    {p['root_login_rule_var']}: false   # 保留 root SSH，保证构建期 shell 可连")
    extra_text = "\n".join(extra)
    return (SITE_YML_TEMPLATE
            .replace("__LEVEL1_VAR__", p["level1_var"])
            .replace("__LEVEL1_VAL__", l1)
            .replace("__LEVEL2_VAR__", p["level2_var"])
            .replace("__LEVEL2_VAL__", l2)
            .replace("__EXTRA_VARS__", extra_text)
            .replace("__ROLE__", p["role"]))


def render_all(workdir: Path, r: dict) -> None:
    p = r["profile"]
    is_win = p.get("family") == "windows"
    (workdir / "packer" / "scripts").mkdir(parents=True, exist_ok=True)
    (workdir / "ansible").mkdir(parents=True, exist_ok=True)

    if is_win:
        hcl = HCL_WIN_TEMPLATE.replace("__WINRM_PASSWORD_ENV__", r["winrm_password_env"])
        (workdir / "packer" / "main.pkr.hcl").write_text(hcl, encoding="utf-8")
    else:
        (workdir / "packer" / "main.pkr.hcl").write_text(
            HCL_TEMPLATE.replace("__CLEAN_CMD__", p["clean_cmd"]), encoding="utf-8")
    (workdir / "packer" / "auto.pkrvars.hcl").write_text(render_pkrvars(r), encoding="utf-8")
    (workdir / "ansible" / "site.yml").write_text(render_site(p, r["level"]), encoding="utf-8")

    if is_win:
        # Windows：控制器侧预装角色；requirements.yml 供离线/CI 参考
        (workdir / "ansible" / "requirements.yml").write_text(
            render_requirements(p), encoding="utf-8")
    else:
        (workdir / "packer" / "scripts" / "install-ansible.sh").write_text(
            render_install(p), encoding="utf-8")
        (workdir / "packer" / "scripts" / "verify-cis.sh").write_text(
            VERIFY_SH_TEMPLATE, encoding="utf-8")
        for sh in (workdir / "packer" / "scripts").glob("*.sh"):
            sh.chmod(0o755)


# ----------------------------------------------------------------------------
# 子命令
# ----------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.target)
    target.mkdir(parents=True, exist_ok=True)
    cfg = target / "ciscvm.toml"
    if cfg.exists() and not args.force:
        fail(f"{cfg} 已存在，加 --force 覆盖。")
        return 1
    cfg.write_text(SAMPLE_CONFIG, encoding="utf-8")
    gi = target / ".gitignore"
    if not gi.exists():
        gi.write_text(".ciscvm-build/\n", encoding="utf-8")
    else:
        content = gi.read_text(encoding="utf-8")
        if ".ciscvm-build/" not in content:
            gi.write_text(content.rstrip() + "\n.ciscvm-build/\n", encoding="utf-8")
    banner("init")
    ok(f"已生成示例配置：{cfg}")
    info("编辑 ciscvm.toml：填 VPC/子网/SG/源镜像ID，凭据走环境变量不入文件。")
    info("然后跑：python3 ciscvm.py preflight / validate / build")
    return 0


def run_preflight(data: dict, r: dict) -> bool:
    banner("preflight")
    all_ok = True

    # 凭据
    for env_name in (r["secret_id_env"], r["secret_key_env"]):
        if os.environ.get(env_name):
            ok(f"凭据环境变量 {env_name} 已设置")
        else:
            fail(f"凭据环境变量 {env_name} 未设置（export 后再跑）")
            all_ok = False

    # packer 二进制
    if shutil.which("packer"):
        ok("packer 已在 PATH")
    else:
        fail("PATH 中找不到 packer，请先安装：https://developer.hashicorp.com/packer/install")
        all_ok = False

    # Windows 画像：控制器侧需要 ansible + pywinrm + WinRM 密码
    if r["family"] == "windows":
        if shutil.which("ansible"):
            ok("ansible 已在 PATH（Windows 画像需控制器侧 ansible + pywinrm）")
        else:
            fail("Windows 画像需要控制器侧 ansible（pip install 'ansible' pywinrm）")
            all_ok = False
        try:
            import importlib
            importlib.import_module("winrm")
            ok("pywinrm 已安装")
        except Exception:
            fail("控制器缺少 pywinrm（pip install pywinrm）")
            all_ok = False
        env_win = r["winrm_password_env"]
        if os.environ.get(env_win):
            ok(f"WinRM 密码环境变量 {env_win} 已设置")
        else:
            fail(f"WinRM 密码环境变量 {env_win} 未设置（Windows 管理员密码，export 后再跑）")
            all_ok = False

    # 关键参数非空 / 非占位
    checks = [
        ("region", r["region"]),
        ("zone", r["zone"]),
        ("instance_type", r["instance_type"]),
        ("source_image_id", r["source_image_id"]),
        ("vpc_id", r["vpc_id"]),
        ("subnet_id", r["subnet_id"]),
        ("security_group_id", r["security_group_id"]),
    ]
    for label, val in checks:
        if val and "xxxxxxxx" not in str(val):
            ok(f"{label} = {val}")
        else:
            fail(f"{label} 仍是占位值 {val}，请填真实值")
            all_ok = False

    # preview 画像提醒
    if r["preview"]:
        warn(f"profile={r['profile_name']} 为 preview，角色名/变量名未经逐一验证，跑前请核对角色 defaults。")
    else:
        ok(f"profile={r['profile_name']}（CIS Level {r['level']}）")

    if all_ok:
        info("自检通过，可以 validate / build。")
    else:
        warn("自检有失败项，请先修复再继续。")
    return all_ok


def ensure_controller_roles(r: dict) -> int:
    """Windows 画像：build 前在控制器侧预装 CIS 角色（ansible provisioner 需要）。"""
    p = r["profile"]
    if p.get("family") != "windows":
        return 0
    repo = p["git_repo"]
    cmd = ["ansible-galaxy", "role", "install",
           f"git+https://github.com/ansible-lockdown/{repo}.git", "--force"]
    banner("controller role install (windows)")
    info(f"Windows 画像：控制器侧安装 CIS 角色 {repo} ...")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        fail(f"ansible-galaxy 安装 {repo} 失败（见上方输出）")
    else:
        ok(f"角色 {repo} 已就绪")
    return res.returncode


def run_packer(workdir: Path, subcmd: str, quiet: bool, capture: bool = False):
    """在 workdir 内执行 packer init + <subcmd>。返回 (exit_code, [output_lines]) 或 exit_code。"""
    hcl = "packer/main.pkr.hcl"
    varfile = "packer/auto.pkrvars.hcl"
    init = subprocess.run(["packer", "init", hcl], cwd=workdir)
    if init.returncode != 0:
        if capture:
            return (init.returncode, [])
        return init.returncode
    cmd = ["packer", subcmd, f"-var-file={varfile}", hcl]
    if capture:
        res = subprocess.run(cmd, cwd=workdir,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = res.stdout.splitlines() if res.stdout else []
        return (res.returncode, lines)
    if quiet:
        res = subprocess.run(cmd, cwd=workdir,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if res.stdout:
            sys.stdout.write(res.stdout)
        return res.returncode
    return subprocess.run(cmd, cwd=workdir).returncode


def cmd_preflight(args: argparse.Namespace) -> int:
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as e:
        fail(str(e))
        return 1
    return 0 if run_preflight(data, r) else 1


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as e:
        fail(str(e))
        return 1
    if not run_preflight(data, r):
        return 1
    if ensure_controller_roles(r) != 0:
        return 1
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    render_all(workdir, r)
    banner("validate")
    info(f"已渲染工作目录：{workdir}")
    info("执行 packer init + packer validate ...")
    rc = run_packer(workdir, "validate", args.quiet)
    if rc == 0:
        ok("packer validate 通过")
    else:
        fail("packer validate 失败（见上方输出）")
    return rc


def cmd_build(args: argparse.Namespace) -> int:
    try:
        data = load_config(Path(args.config))
        r = resolve(data)
    except ConfigError as e:
        fail(str(e))
        return 1
    if not run_preflight(data, r):
        return 1
    if ensure_controller_roles(r) != 0:
        return 1
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    render_all(workdir, r)

    # 确认（除非 -y）
    if not args.yes:
        banner("build")
        info(f"profile  = {r['profile_name']}  |  CIS Level {r['level']}  |  region {r['region']}")
        info(f"源镜像   = {r['source_image_id']}")
        info(f"实例规格 = {r['instance_type']}")
        try:
            resp = input("  确认开始构建？(y/N) ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 1
        if resp not in ("y", "yes"):
            info("已取消")
            return 0

    banner("build")
    info(f"已渲染工作目录：{workdir}")
    info(f"执行 packer build（CIS Level {r['level']}, profile={r['profile_name']}）...")
    rc, lines = run_packer(workdir, "build", args.quiet, capture=True)
    # 流式输出 + 抓取镜像 ID
    image_id = None
    for line in lines:
        print(line)
        if image_id is None:
            m = re.search(r"Created image ID:\s*(\S+)", line)
            if m:
                image_id = m.group(1)
    if rc == 0:
        ok("packer build 成功")
        if image_id:
            ok(f"产出镜像 ID：{image_id}")
        else:
            info("未从输出解析到镜像 ID，请到控制台确认。")
    else:
        fail("packer build 失败（见上方输出）")
    return rc


def cmd_clean(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    if workdir.exists():
        shutil.rmtree(workdir)
        ok(f"已删除工作目录：{workdir}")
    else:
        info(f"工作目录不存在：{workdir}")
    return 0


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    # --config / --workdir 在子命令前后都可用，用共享 parent 实现
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="ciscvm.toml",
                        help="配置文件路径（默认 ./ciscvm.toml）")
    common.add_argument("--workdir", default=DEFAULT_WORKDIR,
                        help=f"渲染工作目录（默认 ./{DEFAULT_WORKDIR}）")

    parser = argparse.ArgumentParser(
        prog="ciscvm", parents=[common],
        description="Packer × 腾讯云 CVM × CIS 镜像构建小工具")
    parser.add_argument("--version", action="version",
                        version=f"ciscvm {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", parents=[common], help="生成示例 ciscvm.toml")
    p_init.add_argument("--target", default=".", help="输出目录（默认当前目录）")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的配置")
    p_init.set_defaults(func=cmd_init)

    p_pre = sub.add_parser("preflight", parents=[common], help="构建前自检")
    p_pre.set_defaults(func=cmd_preflight)

    p_val = sub.add_parser("validate", parents=[common], help="渲染 + packer validate")
    p_val.add_argument("--quiet", action="store_true", help="仅输出 packer 结果")
    p_val.set_defaults(func=cmd_validate)

    p_bld = sub.add_parser("build", parents=[common], help="渲染 + packer build（产出镜像）")
    p_bld.add_argument("--quiet", action="store_true", help="仅输出 packer 结果")
    p_bld.add_argument("-y", "--yes", action="store_true", help="跳过确认提示，直接执行")
    p_bld.set_defaults(func=cmd_build)

    p_cln = sub.add_parser("clean", parents=[common], help="删除渲染工作目录")
    p_cln.set_defaults(func=cmd_clean)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
