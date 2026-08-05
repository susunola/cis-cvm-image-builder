<p align="center">
  <b>English</b> | <a href="README.zh-CN.md">简体中文</a> | <a href="README.ja.md">日本語</a> | <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python&logoColor=white" alt="Python >= 3.11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/profiles-14-orange" alt="14 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@main/docs/ciscvm-icon.png" alt="ciscvm icon" width="96">
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@main/docs/ciscvm-logo.png" alt="ciscvm — SecX Series" width="520">
</p>

# ciscvm — CIS-hardened Golden Image Builder

> Build CIS-hardened images on Tencent Cloud from `ciscvm.toml`.

**What it does:** spins up an ephemeral CVM, applies the bundled
[cis-os](https://github.com/susunola/cis-os) engine for CIS hardening, runs an
in-role gate, and captures the result as a custom image. If any finding survives
remediation, the build fails before the image is created.

**Who it's for:** DevOps and security engineers who need repeatable, auditable
CIS-hardened base images for CVM workloads — on-prem CI, Auto Scaling launch
templates, or Terraform image references.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Profiles](#profiles)
- [CI/CD Integration](#cicd-integration)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [CIS Benchmarks Disclaimer](#cis-benchmarks-disclaimer)

## Installation

**Prerequisites**

| Requirement | Details |
|---|---|
| **Python** | >= 3.11 (stdlib only — zero pip dependencies) |
| **Packer** | >= 1.12 |
| **ansible-core** | >= 2.15 (controller, required for Windows builds) |
| **ansible.windows** | `ansible-galaxy collection install ansible.windows` (controller, required for Windows builds) |
| **Tencent Cloud** | Sub-account with `cvm:RunInstances`, `cvm:CreateImage`, `cvm:DescribeImages`, `cvm:CopyImage`* |
| **Network** | Dedicated VPC + subnet + security group (Linux: SSH/22, Windows: WinRM/5986). Source-restricted to build machine egress IP. |
| **Source Image** | Public image ID for the target OS |

\* `cvm:CopyImage` only needed with cross-region copy.

**Install**

```bash
# Recommended: install from the repository (provides the `ciscvm` command)
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder
pip install .

ciscvm --version

# Or run without installing (from the repo root)
python3 -m ciscvm --version
```

**Set credentials** (environment variables only — never in config files)

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx

# Windows builds additionally require:
export WINRM_PASSWORD=xxxx
```

## Quick Start

```bash
# 1. Generate configuration
ciscvm init

# 2. Edit ciscvm.toml — fill in VPC, subnet, security group, and source image ID

# 3. Pre-flight check (validates config, credentials, and prerequisites)
ciscvm preflight

# 4. Dry-run (render templates + packer validate)
ciscvm validate

# 5. Build the hardened image
ciscvm build

# Optional: clean up rendered files
ciscvm clean
```

> Not installed? Replace `ciscvm` with `python3 -m ciscvm` in any command below.

**Example output (`build`)**

```
════════════════════════════════════════════════════════
  ciscvm 0.5.0 — tencentos3 (L1) → ap-guangzhou-4
════════════════════════════════════════════════════════
[packer]  tencentcloud-cvm: output will be in this color
[packer]  ==> tencentcloud-cvm: Creating temporary keypair...
[packer]  ==> tencentcloud-cvm: Launching instance (S5.MEDIUM2)...
[packer]  ==> tencentcloud-cvm: Provisioning with ansible-local...
[packer]      tencentcloud-cvm: TASK [cis_tencentos3 : apply CIS Level 1] ***
[packer]      tencentcloud-cvm: ok: 142  changed: 38  failed: 0
[packer]      tencentcloud-cvm: TASK [cis_tencentos3 : gate] **************
[packer]      tencentcloud-cvm: PASS — 0 remaining findings
[packer]      tencentcloud-cvm:
[packer]      tencentcloud-cvm: ═══ CIS Hardening Results ═══
[packer]      tencentcloud-cvm: Mode:      apply
[packer]      tencentcloud-cvm: Profile:   L1
[packer]      tencentcloud-cvm: Total:     142
[packer]      tencentcloud-cvm: Passed:    142
[packer]      tencentcloud-cvm: Failed:    0
[packer]      tencentcloud-cvm: Score:     100%
[packer]  ==> tencentcloud-cvm: Creating custom image...
[packer]  ==> tencentcloud-cvm: Image created: img-abc123def456
[packer]  ==> tencentcloud-cvm: Terminating build instance...

✔  Build complete — image-id: img-abc123def456
```

## Commands

| Command | Description |
|---|---|
| `ciscvm init` | Generate `ciscvm.toml` in the current directory |
| `ciscvm preflight` | Validate config, credentials, and prerequisites |
| `ciscvm validate` | Render templates and run `packer validate` |
| `ciscvm build` | Render + `packer build` (produce the image) |
| `ciscvm clean` | Remove the `.ciscvm-build/` working directory |

All commands accept these flags:

| Flag | Default | Applies to | Description |
|---|---|---|---|
| `--config <path>` | `./ciscvm.toml` | all | Configuration file |
| `--workdir <dir>` | `./.ciscvm-build` | all | Rendered output directory |
| `--quiet` | — | validate / build | Suppress packer output |
| `--debug` | — | validate / build | Enable Packer debug logging (`PACKER_LOG=1`) |
| `-y` / `--yes` | — | build | Skip confirmation prompt |
| `--log-file <path>` | — | build | Write full build log to file |

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
source_image_id     = "img-xxxxxxxx"       # Replace with actual OS image ID
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
# Windows builds also require:
# winrm_password_env = "WINRM_PASSWORD"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### Config Reference

| Section | Field | Type | Description |
|---|---|---|---|
| `[build]` | `profile` | string | One of the 14 supported profiles |
| | `region` | string | Tencent Cloud region, e.g. `ap-guangzhou` |
| | `zone` | string | Availability zone, e.g. `ap-guangzhou-4` |
| | `instance_type` | string | CVM instance spec, e.g. `S5.MEDIUM2` |
| | `source_image_id` | string | OS public image ID |
| | `vpc_id` / `subnet_id` | string | Network identifiers |
| | `security_group_id` | string | Must start with `sg-` |
| | `associate_public_ip` | bool | Assign public IP to build instance |
| `[image]` | `name_prefix` | string | Prefix for the output image name |
| | `copy_regions` | []string | Regions to replicate to (empty = skip) |
| `[cis]` | `level` | int | 1 (Level 1) or 2 (Level 2) |
| `[cloud]` | `secret_id_env` | string | Env var for Tencent Cloud Secret ID |
| | `secret_key_env` | string | Env var for Tencent Cloud Secret Key |
| | `winrm_password_env` | string | Env var for Windows Admin password (Windows only) |
| `[meta]` | `os_tag` | string | Tag value for the output image |
| | `benchmark` | string | CIS benchmark version tag |
| | `ssh_port` | int | SSH port (default 22; TencentOS profiles: 36000) |
| | `ssh_timeout` | string | Packer SSH timeout (default "10m") |
| | `ssh_debug_password` | string | Set root password for VNC debug access (default empty) |

## Architecture

### Linux Build Pipeline (SSH × ansible-local)

```
Build Machine                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ Ephemeral CVM    │
│             │                           │   (SSH port 22)  │
│ ciscvm.toml │                           │ 1. Install ansible│
│             │                           │    (dnf/apt/zypp)│
│ roles/      │── uploaded to CVM ───────▶│ 2. CIS apply      │
│   cis_*     │      (bundled roles)      │    (cis_engine.py)│
│             │                           │ 3. Gate:          │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Three phases executed by Packer inside the ephemeral CVM via `ansible-local`:

1. **Install** — provisions ansible-core via the OS package manager + pip.
2. **Harden** — runs the bundled cis-os engine (`cis_engine.py` + `rules.json`).
   Variables: `cis_mode: apply`, `cis_profile: L1/L2`, `cis_platform: server`.
3. **Gate** — in-role: `cis_fail_on_findings: true` + `cis_min_score: 0`.
   If any findings remain, `ansible-playbook` exits non-zero and Packer fails the build.

### Windows Build Pipeline (WinRM × controller-side ansible)

```
Build Machine                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ Ephemeral CVM    │
│             │                           │  (WinRM 5986)    │
│ ciscvm.toml │                           │                  │
│             │                           │                  │
│ roles/      │── ansible provisioner ───▶│ CIS apply         │
│   cis_win*  │   (controller-side,       │ (cis_engine.ps1)  │
│             │    winrm connection)      │                  │
│             │                           │ Gate inside role  │
│             │◀── image-id ──────────────│ CreateImage      │
└─────────────┘                           └──────────────────┘
```

Windows builds use the Packer `ansible` provisioner (controller-side) over WinRM.
The bundled role includes `cis_engine.ps1` (PowerShell). No software installation
is needed inside the instance — the controller requires `ansible-core` locally.

### Design Decisions

**Bundled roles, no Galaxy.**
All 14 cis-os engine roles are shipped inside the package at `ciscvm/roles/`. At build
time the tool copies the selected role into the workspace. No network dependency,
no version drift.

**`ansible-local` (Linux) — self-contained inside the instance.**
The Packer controller does not need SSH access into the cloud VPC. Playbooks and
roles execute inside the build instance.

**`ansible` (Windows) — controller-driven over WinRM.**
Windows images use the Packer `ansible` provisioner from the controller, connecting
via WinRM. The controller must have `ansible-core` installed locally.

**Build-time gate, no external audit.**
The gate is inside the Ansible role (`cis_fail_on_findings`). The hardened image
is guaranteed to pass, or not be created.

**Credentials and governance.**
AK/SK via environment variables only (`sensitive = true` in HCL). Ephemeral instances
are tagged and auto-recycled. Image tags record CIS level, OS, and benchmark.

## Profiles

### Linux (SSH × ansible-local)

| Profile | OS | SSH User | Package Manager | Role |
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

## CI/CD Integration

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows builds:
# export WINRM_PASSWORD=xxx

ciscvm build --log-file build.log
```

Point downstream CVM / Auto Scaling / Terraform at the output `image_id`.
Pin the build machine to a dedicated VPC and security group.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `preflight` fails with credential error | `TENCENTCLOUD_SECRET_ID` / `_KEY` not exported | `export TENCENTCLOUD_SECRET_ID=...` in your shell |
| `validate` fails with plugin download error | `packer init` failed (e.g. offline build machine) | Re-run `ciscvm validate` with internet access — Packer caches plugins after first download |
| Packer times out waiting for SSH | Security group doesn't allow port 22 from build machine | Add inbound rule: TCP/22 from your egress IP |
| `ansible-playbook` fails with "python3 not found" | Build instance OS doesn't have Python pre-installed | Ensure source image includes Python >= 3.6 |
| Windows build fails with WinRM connection error | `WINRM_PASSWORD` not set or network blocked | Export password + ensure TCP/5986 inbound from build IP |
| Build succeeds but has CIS findings | Remediation didn't cover all rules for this OS | Re-run with `level: 1` (Level 1 covers most common findings) |

## Roadmap

- [ ] CI pipeline (GitHub Actions) for automated image builds
- [ ] PyPI package (`pip install ciscvm`)
- [ ] `ciscvm list` — enumerate available profiles with metadata
- [ ] Custom rule selection (`rules_include` / `rules_exclude` in `ciscvm.toml`)

## Contributing

Bug reports and pull requests are welcome. Run the test suite before submitting:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE).

## CIS Benchmarks Disclaimer

This tool applies hardening rules from CIS Benchmark recommendations. CIS Benchmarks
are developed and maintained by the [Center for Internet Security](https://www.cisecurity.org/)
(CIS). The cis-os engine roles bundled in this repository are derived from the
[susunola/cis-os](https://github.com/susunola/cis-os) project and are provided under
their respective licenses.

**Important:** Running CIS hardening in `apply` mode modifies system configuration
and may affect application compatibility. Always test hardened images in a staging
environment before production use. Neither the CIS organization nor the authors of
this tool guarantee that the applied rules result in complete compliance — official
audit requires independent assessment using CIS-CAT or equivalent tools.
