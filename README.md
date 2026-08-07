<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@7203244/docs/ciscvm-logo.png" alt="ciscvm — SecX Series" width="520">
</p>

<p align="center">
  <a href="README.zh-CN.md">简体中文</a> &nbsp;|&nbsp;
  <a href="README.ja.md">日本語</a> &nbsp;|&nbsp;
  <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.10.5-blue?logo=pypi&logoColor=white" alt="Version 0.10.5">
  <img src="https://img.shields.io/badge/python-3.11_|_3.12_|_3.13-blue?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/profiles-14-orange" alt="14 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <a href="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ciscvm

**Config-driven CLI that spins up an ephemeral CVM, applies CIS hardening via the bundled cis-os engine, and captures the result as a custom image.** Built for DevOps and security teams who need repeatable, auditable hardened base images — CI pipelines, Auto Scaling launch templates, or Terraform image references.

Zero pip dependencies. 14 OS profiles across Linux and Windows. Build-time gate with configurable score threshold. All roles ship inside the package — no Galaxy, no network drift.

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder
pip install .

# 2. Generate and edit configuration
ciscvm init
# Edit ciscvm.toml — fill in VPC, subnet, security group, and source_image_id

# 3. Build
ciscvm preflight   # validate credentials and prerequisites
ciscvm validate    # dry-run: render templates + packer validate
ciscvm build       # produce the hardened custom image
ciscvm clean       # remove build artifacts
```

```bash
# Set credentials (environment variables only — never in config files)
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
export WINRM_PASSWORD=xxxx   # Windows builds only
```

**Example output (`build`)**

```
══════════════════════════════════════════════════════════
  ciscvm 0.5.0 — tencentos3 (L1) → ap-guangzhou-4
══════════════════════════════════════════════════════════
[packer]  tencentcloud-cvm: Launching instance (S5.MEDIUM2)...
[packer]  tencentcloud-cvm: Provisioning with ansible-local...
[packer]      tencentcloud-cvm: TASK [cis_tencentos3 : apply CIS Level 1] ***
[packer]      tencentcloud-cvm: ok: 142  changed: 38  failed: 0
[packer]      tencentcloud-cvm: TASK [cis_tencentos3 : reboot] ************
[packer]      tencentcloud-cvm: Instance rebooted — re-auditing pending items
[packer]      tencentcloud-cvm: TASK [cis_tencentos3 : gate] **************
[packer]      tencentcloud-cvm:
[packer]      tencentcloud-cvm: ═══ CIS Hardening Results ═══
[packer]      tencentcloud-cvm: Mode:      apply
[packer]      tencentcloud-cvm: Profile:   L1
[packer]      tencentcloud-cvm: Total:     142
[packer]      tencentcloud-cvm: Passed:    138
[packer]      tencentcloud-cvm: Failed:    4
[packer]      tencentcloud-cvm: Score:     97.2% ≥ 85%  ✓ PASS
[packer]  ==> tencentcloud-cvm: Creating custom image...
[packer]  ==> tencentcloud-cvm: Image created: img-abc123def456
[packer]  ==> tencentcloud-cvm: Terminating build instance...

✔  Build complete — image-id: img-abc123def456
```

> **Not installed?** Replace `ciscvm` with `python3 -m ciscvm` in any command.

---

## Installation

### Prerequisites

| Requirement | Details |
|---|---|
| **Python** | 3.11+ (stdlib only — zero pip dependencies) |
| **Packer** | 1.12+ |
| **ansible-core** | 2.15+ (controller — required for Windows builds) |
| **ansible.windows** | `ansible-galaxy collection install ansible.windows` (Windows builds only) |
| **Tencent Cloud** | Sub-account with `cvm:RunInstances`, `cvm:CreateImage`, `cvm:DescribeImages`; `cvm:CopyImage` for cross-region copy |
| **Network** | Dedicated VPC + subnet + security group — SSH/22 (Linux) or WinRM/5986 (Windows), source-restricted to build machine egress IP |
| **Source Image** | Public image ID for the target OS |

### Install from source

```bash
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder
pip install .
ciscvm --version
```

---

## Commands

```bash
ciscvm                                    # show help
ciscvm init                               # generate ciscvm.toml
ciscvm preflight                          # validate config, credentials, prerequisites
ciscvm validate                           # render templates + packer validate
ciscvm build                              # render + packer build → custom image
ciscvm clean                              # remove .ciscvm-build/
```

| Flag | Applies to | Description |
|---|---|---|
| `--config <path>` | all | Config file path (default `./ciscvm.toml`) |
| `--workdir <dir>` | all | Build output directory (default `./.ciscvm-build`) |
| `--quiet` | validate, build | Suppress packer output |
| `--debug` | validate, build | Enable `PACKER_LOG=1` |
| `-y` / `--yes` | build | Skip confirmation prompt |
| `--log-file <path>` | build | Write full build log to file |

---

## Configuration

`ciscvm.toml` is the single source of truth — no manual template editing.

```toml
[build]
profile             = "tencentos3"
#   Linux: ubuntu2004 | ubuntu2204 | ubuntu2404 |
#          rhel8 | rhel9 | rhel10 |
#          tencentos3 | tencentos4 |
#          sles15 | sles16
#   Windows: win2016 | win2019 | win2022 | win2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # [] to disable cross-region copy

[cis]
level = 1                                 # 1 or 2

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# winrm_password_env = "WINRM_PASSWORD"   # Windows only

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### Full reference

| Section | Field | Type | Notes |
|---|---|---|---|
| `[build]` | `profile` | string | Profile name from supported list |
| | `region` | string | e.g. `ap-guangzhou` |
| | `zone` | string | e.g. `ap-guangzhou-4` |
| | `instance_type` | string | e.g. `S5.MEDIUM2` |
| | `source_image_id` | string | OS public image ID |
| | `vpc_id` | string | VPC identifier |
| | `subnet_id` | string | Subnet identifier |
| | `security_group_id` | string | Must start with `sg-` |
| | `associate_public_ip` | bool | Assign public IP |
| `[image]` | `name_prefix` | string | Output image name prefix |
| | `copy_regions` | []string | Regions to replicate (empty = skip) |
| `[cis]` | `level` | int | `1` (Level 1) or `2` (Level 2) |
| `[cloud]` | `secret_id_env` | string | Env var for Secret ID |
| | `secret_key_env` | string | Env var for Secret Key |
| | `winrm_password_env` | string | Windows admin password env var |
| `[meta]` | `os_tag` | string | Tag value for output image |
| | `benchmark` | string | CIS benchmark version tag |
| | `ssh_port` | int | SSH port (default `22`; TencentOS: `36000`) |
| | `ssh_timeout` | string | Packer SSH timeout (default `"10m"`) |
| | `ssh_debug_password` | string | Root password for VNC debug (default empty) |

---

## Architecture

### Linux pipeline

```
Build Machine                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ Ephemeral CVM    │
│             │                           │   (SSH port 22)  │
│ ciscvm.toml │                           │                  │
│             │                           │ 1. Install       │
│ roles/      │── uploaded to CVM ───────▶│    ansible-core  │
│   cis_*     │      (bundled roles)      │                  │
│             │                           │ 2. CIS apply     │
│             │                           │    (cis_engine)  │
│             │                           │                  │
│             │                           │ 3. Reboot        │
│             │                           │    + re-audit    │
│             │                           │    (pending      │
│             │                           │     items)       │
│             │                           │                  │
│             │                           │ 4. Gate          │
│             │                           │    score ≥ 85%   │
│             │◀── image-id ──────────────│ 5. CreateImage   │
└─────────────┘                           └──────────────────┘
```

Four phases executed inside the ephemeral CVM via `ansible-local`:

1. **Install** — provisions `ansible-core` via the OS package manager + pip.
2. **Harden** — runs the bundled cis-os engine (`cis_engine.py` + `rules.json`). Variables: `cis_mode: apply`, `cis_profile: L1/L2`.
3. **Reboot + re-audit** — reboots the instance and re-runs only the rules that were pending a reboot. Catches kernel parameters, audit daemon configs, and other settings that only take effect after restart.
4. **Gate** — final score check against a configurable threshold (default 85%). If the score falls below, `ansible-playbook` exits non-zero and Packer fails the build — the image is never created.

#### SSH access safety net

CIS rules can disable root SSH login (`PermitRootLogin no` — TencentOS 3 rule
5.1.22 / TencentOS 4 rule 5.2.10). Because the builder itself connects as
`root`, this would lock the build out after the reboot. ciscvm therefore
adds two orchestration-layer guarantees that are regenerated on every build
(they can never go stale):

1. **Dedicated build user `ciscvm`** — created by `install-ansible.sh` with
   passwordless sudo and the same `authorized_keys` as the current SSH user,
   so it can reconnect even if root login is fully disabled.
2. **SSH guard** — opens the live SSH port in firewalld / nftables /
   iptables, and if a CIS rule set `PermitRootLogin no`, temporarily restores
   key-based root login so Packer can reconnect.

The **final image ships hardened**: the cleanup provisioner re-applies
`PermitRootLogin no` before the snapshot is taken. To administer a built
image, use the `ciscvm` user (`sudo -i` for root), or create your own user —
root password login is disabled by design per CIS.

#### What ships in the image (Linux)

Every Linux build leaves a ciscv paper trail inside the image so admins know
exactly what was done and which admin channel to use:

| Path | Purpose |
|------|---------|
| `/etc/ciscvm/banner` | ASCII banner with the ciscv logo + image metadata (colored). |
| `/etc/motd` | The same banner + build summary, shown after SSH login. |
| `/etc/issue`, `/etc/issue.net` | Plain-text version for serial / network console. |
| `/etc/ssh/sshd_config.d/99-ciscvm-banner.conf` | Wires the SSH `Banner` directive. |
| `/opt/ciscvm-REPORT.md` | Full hardening report (what was done, score, follow-ups). |
| `/opt/ciscvm-AUDIT-RESULT.json` | Raw re-audit JSON (the gate result). |
| `/usr/local/bin/ciscvm-info` | One-shot summary command: `ciscvm-info`. |

```bash
$ ssh ciscvm@<host>
              .---..---.
          .-'          '-.           SECX  SERIES
        .'                '.           ___ ___  ___  ___
      .'                    '.       / __/ _ \/ __|/ __|
     /         ()    ()       \      | (_| (_) \__ \ (__ 
    |                        |       \___\___/|___/\___|
     \                      /         CIS-HARDENED IMAGE BUILDER
      '.                  .'
        '.              .'
          '---.------.---'

Image:    t3-cis-level1-20260806-173729
Source:   img-test-abc123
OS/Level: tencentos-3 / level1-server
Built:    2026-08-06T17:37:29Z by ciscv 0.10.0

[ REPORT  ] cat /opt/ciscvm-REPORT.md     (or run: ciscvm-info)
[ ADMIN   ] ssh ciscvm@<host>            (root login disabled per CIS 5.1.22)
[ ESCALATE] sudo -i                        (NOPASSWD via /etc/sudoers.d/ciscvm-build)
```

The report at `/opt/ciscvm-REPORT.md` documents what ciscv did to the base
image (per-rule counts, outstanding failures, how to re-run the scan) so
the next admin does not have to guess.

### Windows pipeline

```
Build Machine                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ Ephemeral CVM    │
│             │                           │   (WinRM 5986)   │
│ ciscvm.toml │                           │                  │
│             │                           │                  │
│ roles/      │── ansible provisioner ───▶│ CIS apply         │
│   cis_win*  │   (controller-side,       │ (cis_engine.ps1)  │
│             │    WinRM connection)      │                  │
│             │                           │ Reboot +         │
│             │                           │ re-audit         │
│             │                           │                  │
│             │                           │ Gate: score≥85%  │
│             │◀── image-id ──────────────│ CreateImage      │
└─────────────┘                           └──────────────────┘
```

Windows builds use the Packer `ansible` provisioner (controller-side) over WinRM. The bundled role includes `cis_engine.ps1` (PowerShell). The controller requires `ansible-core` locally.

### Design

**Bundled roles.** All 14 cis-os engine roles ship inside `ciscvm/roles/`. At build time the tool copies the selected role into the workspace. No Galaxy, no network dependency, no version drift.

**ansible-local (Linux).** Playbooks and roles execute inside the build instance — the Packer controller does not need SSH access into the cloud VPC.

**ansible (Windows).** Controller-driven over WinRM. The controller must have `ansible-core` installed locally.

**Build-time gate.** The gate runs inside the Ansible role (`cis_fail_on_findings`). Configurable score threshold ensures the image is good enough to ship, or no image is produced.

**Credentials.** AK/SK via environment variables only (`sensitive = true` in HCL). Ephemeral instances are tagged and auto-recycled. Image tags record CIS level, OS, and benchmark.

---

## Profiles

### Linux (SSH × ansible-local)

| Profile | OS | SSH User | Pkg Manager | Role |
|---|---|---|---|---|
| `ubuntu2004` | Ubuntu 20.04 LTS | ubuntu | apt | `roles/cis_ubuntu2004/` |
| `ubuntu2204` | Ubuntu 22.04 LTS | ubuntu | apt | `roles/cis_ubuntu2204/` |
| `ubuntu2404` | Ubuntu 24.04 LTS | ubuntu | apt | `roles/cis_ubuntu2404/` |
| `rhel8` | RHEL 8 | root | dnf | `roles/cis_rhel8/` |
| `rhel9` | RHEL 9 | root | dnf | `roles/cis_rhel9/` |
| `rhel10` | RHEL 10 | root | dnf | `roles/cis_rhel10/` |
| `tencentos3` | TencentOS Server 3 | root | dnf | `roles/cis_tencentos3/` |
| `tencentos4` | TencentOS Server 4 | root | dnf | `roles/cis_tencentos4/` |
| `sles15` | SLES 15 | root | zypper | `roles/cis_sles15/` |
| `sles16` | SLES 16 | root | zypper | `roles/cis_sles16/` |

### Windows (WinRM × controller-side ansible)

| Profile | OS | User | Role |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/cis_win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/cis_win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/cis_win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/cis_win2025/` |

To switch profiles, change `[build].profile` and `source_image_id` in `ciscvm.toml`.

---

## CI/CD Integration

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx
ciscvm build --log-file build.log
```

Point downstream CVM / Auto Scaling / Terraform at the output `image_id`. Pin the build machine to a dedicated VPC and security group.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `preflight` fails with credential error | AK/SK not exported | `export TENCENTCLOUD_SECRET_ID=...` |
| `validate` fails with plugin download | `packer init` failed (offline?) | Run with internet access — Packer caches plugins after first download |
| Packer times out waiting for SSH | SG doesn't allow TCP/22 from build IP | Add inbound rule for your egress IP |
| `ansible-playbook` can't find python3 | Source image has no Python | Python 3.6+ must be pre-installed |
| Windows build WinRM error | Password not set or TCP/5986 blocked | Export `WINRM_PASSWORD` + open inbound rule |
| Build passes but score below 85% | Gate threshold too strict for this OS | Adjust `cis_min_score` in the role, or use Level 1 |

---

## Roadmap

- [x] CI pipeline (GitHub Actions)
- [ ] PyPI package (`pip install ciscvm`)
- [ ] `ciscvm list` — enumerate available profiles with metadata
- [ ] `ciscvm scan` — audit-only mode (no remediation, gate on findings)
- [ ] Custom rule selection (`rules_include` / `rules_exclude` in `ciscvm.toml`)

## Contributing

Bug reports and pull requests are welcome. Run the test suite before submitting:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## CIS Benchmarks Disclaimer

This tool applies hardening rules from CIS Benchmark recommendations. CIS Benchmarks are developed and maintained by the [Center for Internet Security](https://www.cisecurity.org/) (CIS). The cis-os engine roles bundled in this repository are derived from [susunola/cis-os](https://github.com/susunola/cis-os) and are provided under their respective licenses.

**Running CIS hardening in `apply` mode modifies system configuration and may affect application compatibility.** Always test hardened images in a staging environment before production use. Neither the CIS organization nor the authors of this tool guarantee complete compliance — official audit requires independent assessment using CIS-CAT or equivalent tools.
