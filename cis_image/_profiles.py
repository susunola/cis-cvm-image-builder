from __future__ import annotations

from typing import Any


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

DEFAULT_WORKDIR = ".cis-image-build"

SAMPLE_CONFIG = """\
# cis-image.toml — single source of truth for all build parameters
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
# instance_name = "my-build-cvm"          # optional explicit name for the temporary build CVM ("" = plugin auto)
# # [build.packer] — passthrough of arbitrary packer tencentcloud-cvm builder
# # args (inherits the full packer capability set). E.g. some SA-series
# # instance types do not support the default CLOUD_PREMIUM root disk:
# #   [build.packer]
# #   disk_type = "CLOUD_SSD"
# #   disk_size = 100

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
# assume_role_session  = "cisimage-build"   # optional, default "cis-image"
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
