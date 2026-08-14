<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@7203244/docs/ciscvm-logo.png" alt="ciscvm — SecX Series" width="520">
</p>

<p align="center">
  <b>English</b> &nbsp;|&nbsp;
  <a href="README.zh-CN.md">简体中文</a> &nbsp;|&nbsp;
  <a href="README.ja.md">日本語</a> &nbsp;|&nbsp;
  <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.12.4-blue?logo=pypi&logoColor=white" alt="Version 0.12.4">
  <img src="https://img.shields.io/badge/python-3.11_|_3.12_|_3.13-blue?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/profiles-12-orange" alt="12 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <a href="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ciscvm

**Config-driven CLI that spins up an ephemeral CVM, applies CIS hardening via the bundled cis-os engine, and captures the result as a custom image.** Built for DevOps and security teams who need repeatable, auditable hardened base images — CI pipelines, Auto Scaling launch templates, or Terraform image references.

Zero pip dependencies. 12 OS profiles across Linux and Windows. Build-time gate with configurable score threshold. All roles ship inside the package — no Galaxy, no network drift.

Beyond the build itself, ciscvm covers the full **build → test → distribute** governance loop:

- **Instance-level smoke test** before the snapshot — a broken image never ships
- **Image lineage** (`ciscvm images`) — source → image IDs, score, version history
- **WeCom notifications** — pair with cron/systemd timer for scheduled rebuilds
- **SLSA-style signed provenance** (`ciscvm verify`) — tamper-evident build records
- **OIDC / STS credentials** — zero long-lived AK/SK in CI; `assume_role` for group accounts

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
  ciscvm 0.14.1 — tencentos3 (L1) → ap-guangzhou-4
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
[packer]  ==> tencentcloud-cvm: smoke test: sshd config parses ... ok
[packer]  ==> tencentcloud-cvm: smoke test: /dev/shm noexec ... ok
[packer]  ==> tencentcloud-cvm: smoke test PASSED — image is buildable
[packer]  ==> tencentcloud-cvm: Creating custom image...
[packer]  ==> tencentcloud-cvm: Image created: img-abc123def456
[packer]  ==> tencentcloud-cvm: Terminating build instance...

✔  Build complete — image-id: img-abc123def456
✔  Output image ID(s): img-abc123def456
✔  Re-audit score: 97.2%
✔  Lineage recorded -> ~/.ciscvm/lineage.jsonl
✔  Provenance signed with GPG key 0123ABCD -> ...provenance.json.sig
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
ciscvm build --skip-if-unchanged          # ... skip when inputs are unchanged (change detection)
ciscvm scan [--min-score 85]              # audit-only build (no remediation) + score gate
ciscvm scan --sarif out.sarif             # ... plus a SARIF 2.1.0 failure report
ciscvm scan --xccdf out.xml               # ... plus an XCCDF 1.2 TestResult (GRC ingestion)
ciscvm test --idempotency                 # re-run apply, fail if 2nd pass changes anything
ciscvm list                               # enumerate available profiles with metadata
ciscvm images [--latest] [-n N]           # list recorded builds (lineage)
ciscvm pending                            # change detection: is a rebuild required? (exit 0/1)
ciscvm cleanup-images [--older-than 30]   # retire old images by lineage age
ciscvm cleanup-images --apply             # actually delete (default = dry run)
ciscvm verify --provenance <file>         # verify a SLSA provenance signature
ciscvm verify --image <img-id>            # ... or locate provenance by image ID
ciscvm verify-image --image <img-id>      # clean-boot verification of a produced image
ciscvm drift --host <ip> [--image <id>]   # config drift on a running instance vs image baseline
ciscvm drift --host <ip> --save-baseline  # save the current host scan as a drift baseline
ciscvm check-source                       # vendor image refresh detection (rebuild needed?)
ciscvm audit --tool oscap ...             # independent audit: OpenSCAP (RHEL-family SCAP content)
ciscvm audit --tool inspec ...            # independent audit: Chef InSpec (dev-sec baselines)
ciscvm audit --tool kitty --parse out.csv # independent audit: HardeningKitty (Windows) CSV
ciscvm clean                              # remove .ciscvm-build/
```

| Flag | Applies to | Description |
|---|---|---|
| `--config <path>` | all | Config file path (default `./ciscvm.toml`) |
| `--workdir <dir>` | all | Build output directory (default `./.ciscvm-build`) |
| `--quiet` | validate, build, scan | Suppress packer output |
| `--debug` | validate, build, scan | Enable `PACKER_LOG=1` |
| `-y` / `--yes` | build | Skip confirmation prompt |
| `--log-file <path>` | build | Write full build log to file |
| `--skip-if-unchanged` | build | Skip when inputs (source image, rules, benchmark, level) are unchanged |
| `--min-score <pct>` | scan, audit, verify-image | Gate threshold (default `85`; below it → exit 1) |
| `--sarif <path>` | scan, audit | Write findings as SARIF 2.1.0 |
| `--xccdf <path>` | scan, audit | Write findings as XCCDF 1.2 (enterprise GRC ingestion) |
| `--host <ip>` | audit | Target host to audit (oscap/inspec) |
| `--datastream <path>` | audit | oscap SCAP datastream on the target (e.g. `/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`) |
| `--baseline <name>` | audit | inspec baseline (default `dev-sec/linux-baseline`) |
| `--parse <csv>` | audit --tool kitty | HardeningKitty audit CSV export to parse |
| `--older-than <days>` | cleanup-images | Retire builds older than N days (default `30`) |
| `--keep-latest <n>` | cleanup-images | Always keep the newest N builds (default `1`) |
| `--unused-since <days>` | cleanup-images | Only delete images NOT shared with other accounts (in-use guard; `0` = off) |
| `--apply` | cleanup-images | Actually delete (default is a dry run) |

---

## Configuration

`ciscvm.toml` is the single source of truth — no manual template editing.

```toml
[build]
profile             = "tencentos3"
#   Linux: ubuntu2004 | ubuntu2204 | ubuntu2404 |
#          rhel8 | rhel9 | rhel10 |
#          tencentos3 | tencentos4
#   Windows: win2016 | win2019 | win2022 | win2025
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true
# spot = true                             # use a spot instance for the build VM (up to ~90% cheaper)

[image]
name_prefix  = "tencentos3-cis"
# name = "my-cis-image"                  # optional: fixed image name (empty = auto prefix-level-timestamp)
copy_regions = ["ap-shanghai"]            # [] to disable cross-region copy
# share_accounts = ["uin/1234567890"]    # optional: share the built image with other accounts
# share_org_units = ["uin/1234567890"]   # optional: org-level sharing (same API)

[cis]
level = 1                                 # 1 or 2
# min_score = 85                          # post-reboot audit gate (0 disables; default 85)
# rules_include = ["1.5.6"]               # run only these rules
# rules_exclude = ["1.1.2.2.4"]           # always wins over rules_include
# Per-control parameter overrides (deep-merged into the catalog at render):
# [cis.overrides."5.2.2"]
# ssh_max_auth_tries = 4

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# winrm_password_env = "WINRM_PASSWORD"   # Windows only
# Group-account (organization) cross-account builds — assume a CAM role in
# the target account using the local AK/SK:
# assume_role_arn      = "qcs::cam::uin/1234567890:roleName/CrossAccountBuilder"
# assume_role_session  = "ciscvm-build"   # optional, default "ciscvm"
# assume_role_duration = 3600             # optional, default 7200, range 0-43200
# OIDC / STS temporary credentials (CI, no long-lived AK/SK):
# security_token_env = "TENCENTCLOUD_SECURITY_TOKEN"   # Packer default

# Build notifications (WeCom group-robot webhook). Empty webhook = off.
# [notify]
# webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx"
# on      = "failure"        # always | success | failure
# deploy_webhook = "https://ci.example.com/api/images"  # POST image metadata on success (EventBridge-style)

# SLSA-style provenance signing (GPG). Empty = provenance unsigned.
# [sign]
# gpg_key = "ABCDEF0123456789"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
# smoke_test = true           # instance-level checks before the image snapshot
# cve_scan   = false          # optional: trivy vulnerability gate before the snapshot
# sbom       = false          # optional: emit an SBOM into the image + provenance
# verify_boot = false         # optional: boot a probe from the produced image and re-audit
# test_components = ["scripts/app-check.sh"]  # optional: user test scripts run before snapshot
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
| | `spot` | bool | Use a spot instance for the build VM (`instance_charge_type=SPOTPAID`; up to ~90% cheaper, may be repossessed mid-build, default `false`) |
| `[image]` | `name_prefix` | string | Output image name prefix |
| | `name` | string | Fixed image name (empty = auto `prefix-level-timestamp`) |
| | `copy_regions` | []string | Regions to replicate (empty = skip) |
| | `share_accounts` | []string | Share the built image with other accounts (`uin/…`) after build (empty = off) |
| | `share_org_units` | []string | Org-level sharing — same `ModifyImageSharePermission` API, merged with `share_accounts` (empty = off) |
| `[cis]` | `level` | int | `1` (Level 1) or `2` (Level 2) |
| | `min_score` | int | Post-reboot audit gate (default `85`; `0` disables) |
| | `rules_include` | []string | Rule-ID filter — when set, ONLY these rules run (empty = all) |
| | `rules_exclude` | []string | Rule-ID filter — always wins over `rules_include` |
| | `overrides` | table | Per-control parameter overrides, keyed by rule ID — deep-merged into the catalog at render time (e.g. `[cis.overrides."5.2.2"]`) |
| `[cloud]` | `secret_id_env` | string | Env var for Secret ID |
| | `secret_key_env` | string | Env var for Secret Key |
| | `security_token_env` | string | STS session-token env var (default `TENCENTCLOUD_SECURITY_TOKEN`; used with OIDC/STS credentials) |
| | `winrm_password_env` | string | Windows admin password env var |
| | `assume_role_arn` | string | Group-account CAM role ARN (empty = off). e.g. `qcs::cam::uin/12345:roleName/X` |
| | `assume_role_session` | string | AssumeRole session name (default `ciscvm`) |
| | `assume_role_duration` | int | Session seconds, 0-43200 (default 7200) |
| `[meta]` | `os_tag` | string | Tag value for output image |
| | `benchmark` | string | CIS benchmark version tag (pinned in lineage/provenance for auditability) |
| | `ssh_port` | int | SSH port (default `22`; TencentOS: `36000`) |
| | `ssh_timeout` | string | Packer SSH timeout (default `"15m"`) |
| | `ssh_debug_password` | string | Root password for VNC debug (default empty) |
| | `smoke_test` | bool | Instance-level checks before snapshot (default `true`) |
| | `cve_scan` | bool | Trivy CRITICAL-severity vulnerability gate before the snapshot (default `false`) |
| | `sbom` | bool | Emit an SBOM (`/opt/ciscvm-SBOM.jsonl`) into the image, hash it and pin it in lineage + provenance (default `false`) |
| | `verify_boot` | bool | After the snapshot, boot a probe instance from the produced image, re-audit on fresh boot and gate (Linux only, default `false`) |
| | `test_components` | []string | User-defined test scripts run sequentially before the snapshot (Image Builder test-component style); non-zero exit aborts the build (empty = off) |
| `[notify]` | `webhook` | string | WeCom group-robot webhook URL (empty = off) |
| | `on` | string | `always` \| `success` \| `failure` (default `failure`) |
| | `deploy_webhook` | string | POST `{image_id, score, profile}` on build success to trigger downstream CI/CD (EventBridge-style; empty = off) |
| `[sign]` | `gpg_key` | string | GPG key id/fingerprint for provenance signing (empty = unsigned) |

---

## Architecture

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@main/docs/ciscvm-architecture.png" alt="ciscvm build architecture — TOML config to hardened golden image" width="720">
</p>

### Linux pipeline

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

Windows builds use the Packer `ansible` provisioner (controller-side) over WinRM. The bundled role includes `cis_engine.ps1` (PowerShell). The controller requires `ansible-core` locally.

| | Linux | Windows |
|---|---|---|
| Communicator | SSH | WinRM |
| Packer provisioner | `ansible-local` (runs in the CVM) | `ansible` (controller-side) |
| Engine | `cis_engine.py` | `cis_engine.ps1` |
| Controller requirement | none — engine runs on the instance | `ansible-core` on the build machine |
| Reboot safety net | `ciscvm` build user + SSH guard | WinRM direct (no reboot lockout risk) |

### Design

**Bundled roles.** All 12 cis-os engine roles ship inside `ciscvm/roles/`. At build time the tool copies the selected role into the workspace. No Galaxy, no network dependency, no version drift.

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

### Windows (WinRM × controller-side ansible)

| Profile | OS | User | Role |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/cis_win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/cis_win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/cis_win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/cis_win2025/` |

To switch profiles, change `[build].profile` and `source_image_id` in `ciscvm.toml`.

---

## Test Matrix

Validated CIS-hardened images across the supported OS × level grid.
All builds ran on Tencent Cloud Guangzhou region with `cis_allow_disruptive: false`;
every image below was re-verified in the console as `NORMAL` on 2026-08-14.

| OS | L1 | L2 |
|---|---|---|
| **RHEL 8** | `img-8zfwvl9g` (93.5%) | `img-4d6jxfe2` (93.3%) |
| **RHEL 9** | `img-25hwnzl8` (95.3%) | `img-8mjw35cy` (95.2%) |
| **RHEL 10** | `img-1idroc9y` (96.3%) | `img-lzha2io2` (95.3%) |
| **Ubuntu 20.04** | `img-9xyvohdy` (92.0%) | `img-gut6728y` (90.0%) |
| **Ubuntu 22.04** | `img-jd3gct8o` (91.5%) | `img-rx4n84w4` (92.1%) |
| **Ubuntu 24.04** | `img-7ncjcq10` (95.9%) | `img-j9m1fn0u` (96.5%) |
| **TencentOS 3** | `img-ip62dj1k` (95.7%) | `img-joo4xcis` (94.2%) |
| **TencentOS 4** | `img-ipw57gea` (96.9%) | `img-fs0hh75w` (96.7%) |
| **Windows Server 2016** | EN `img-lw9onsqo` (99.7%) · CN `img-bm2kusug` (99.7%) | EN `img-gnedt90i` (99.7%) · CN `img-4t7nd0ne` (99.7%) |
| **Windows Server 2019** | EN `img-9dfarngo` (99.6%) · CN `img-2h1qdi5c` (99.6%) | EN `img-5gfx1ybo` (99.7%) · CN `img-8u7us60c` (99.7%) |
| **Windows Server 2022** | EN `img-b9iwlu30` (99.7%) · CN `img-5fwbryp2` (99.7%) | EN `img-8r09mpwq` (99.7%) · CN `img-q5zih0bo` (99.7%) |
| **Windows Server 2025** | EN `img-4obl2vj4` (99.7%) · CN `img-pqx9opsw` (99.7%) | EN `img-cvoolqiu` (99.7%) · CN `img-2e5x3xhg` (99.7%) |

> Scores are the post-reboot re-audit results (all assessed rules, gate ≥ 85).
> kmod rules are applied via persistent modprobe install-overrides — no rule
> exclusions are needed at build time.
> Windows images are member-server builds from the Tencent Cloud Datacenter
> EN/CN public images, built and re-audited on 2026-08-14; WinRM is
> re-locked (Basic/unencrypted off, Administrator password randomized) before snapshot.
> The single remaining Windows fail on every build is "Deny access to this
> computer from the network → include S-1-5-114" (2.2.2x), which is deliberately
> skipped as disruptive: applying it would cut off the very WinRM session the
> build runs on. Enable it post-boot with `cis_allow_disruptive: true`.

---

## CI/CD Integration

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx
ciscvm build --log-file build.log
```

Point downstream CVM / Auto Scaling / Terraform at the output `image_id`. Pin the build machine to a dedicated VPC and security group.

---

## Group accounts (organization)

ciscvm supports the Tencent Cloud group-account (企业组织) pattern for
**cross-account golden image builds** — build once from a central account,
distribute everywhere:

- **Build as a target account**: set `[cloud].assume_role_arn` to a CAM
  role created in the target account. Packer assumes that role with the
  local AK/SK (STS `AssumeRole`), so the instance and image are created
  *in the target account* while credentials stay in the central account.

  ```toml
  [cloud]
  assume_role_arn      = "qcs::cam::uin/1234567890:roleName/CrossAccountBuilder"
  assume_role_session  = "ciscvm-build"   # optional
  assume_role_duration = 3600             # optional, default 7200
  ```

  The role needs the same CAM permissions the builder requires
  (`cvm:RunInstances`, `cvm:CreateImage`, `cvm:DescribeImages`) plus a
  trust policy allowing the central account to assume it.

- **Build then share**: keep `assume_role_arn` empty, build in the central
  account, and share the resulting image to business accounts via the
  Tencent Cloud console or the `image_share_accounts` Packer option.

When `assume_role_arn` is empty (the default) builds behave exactly as
before — no group-account setup required.

### OIDC / STS credentials (no long-lived AK/SK)

For CI pipelines (GitHub Actions etc.) you can build **without storing any
AK/SK**: the runner obtains short-lived STS credentials via OIDC federation,
and ciscvm hands the session token straight to Packer.

1. **CAM side (one-time)**: create an OIDC identity provider pointing at
   `https://token.actions.githubusercontent.com`, then create a CAM role
   whose trust conditions pin `oidc:iss`, `oidc:aud` (the client ID you
   configured) and `oidc:sub` (e.g. `repo:susunola/cis-cvm-image-builder:
   ref:refs/heads/main`). Attach the builder permissions
   (`cvm:RunInstances`, `cvm:CreateImage`, `cvm:DescribeImages`, ...).

2. **Workflow**: exchange the OIDC token for STS credentials with
   `everpcpc/tencentcloud-oidc-auth@v1`, which exports
   `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY` and
   `TENCENTCLOUD_SECURITY_TOKEN` — Packer reads all three natively:

   ```yaml
   permissions:
     id-token: write          # required for OIDC
   steps:
     - uses: everpcpc/tencentcloud-oidc-auth@v1
       with:
         role-arn: qcs::cam::uin/1234567890:roleName/ci-builder
         oidc-provider-id: github
         region: ap-guangzhou
     - run: ciscvm build --config ciscvm.toml
   ```

3. **ciscvm side**: nothing to configure — the default
   `security_token_env = "TENCENTCLOUD_SECURITY_TOKEN"` is picked up
   automatically. Override it only if your CI exports the token under a
   different name:

   ```toml
   [cloud]
   security_token_env = "MY_CI_STS_TOKEN"
   ```

Note: `security_token` and `assume_role` are independent — STS credentials
can themselves be scoped to the OIDC role, so you typically do not need
both at once.

### Build → test → distribute (image governance)

Beyond building the image, ciscvm covers the governance loop that Packer
itself leaves to you (mirroring AWS Image Builder's build → test →
distribute pipeline):

- **Test (before snapshot)** — after finalize + re-audit, an instance-level
  smoke test runs on the live VM *before* Packer snapshots it: `sshd -T`
  parses, sshd/auditd active, `/dev/shm` carries `noexec`, no weak SSH
  crypto, journal-upload active (when configured). Any failure aborts the
  build — **no image is produced**. Disable with `[meta].smoke_test = false`.

- **Lineage (distribute metadata)** — every build appends a record
  (`~/.ciscvm/lineage.jsonl`): source image → output image IDs, level,
  region, score, version, timestamp. Query it with:

  ```bash
  ciscvm images            # recent builds, newest first
  ciscvm images --latest   # the most recent record
  ciscvm cleanup-images --older-than 30   # dry-run: what would be retired
  ciscvm cleanup-images --older-than 30 --apply   # actually delete
  ```

  `cleanup-images` retires golden images older than N days (default 30),
  always keeping the newest build (`--keep-latest`, default 1). It uses the
  lineage records to find the image IDs, verifies them via
  `cvm:DescribeImages`, deletes via `cvm:DeleteImages` (stdlib TC3-signed —
  no extra dependencies), and marks the lineage entries `retired`. Credentials
  come from `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY`
  (optionally `TENCENTCLOUD_SECURITY_TOKEN`). Pair with cron/systemd timer
  for fully automatic retirement.

- **Notify (scheduling companion)** — post build results to a WeCom group
  robot. Combine with cron / systemd timer / SCF for scheduled rebuilds:

  ```toml
  [notify]
  webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx"
  on      = "failure"     # always | success | failure
  ```

  ```bash
  # systemd timer / cron example — rebuild monthly, only notify on failure
  0 3 1 * *  ciscvm build --config /etc/ciscvm/ciscvm.toml -y
  ```

- **SLSA-style provenance** — after a successful build ciscvm writes a
  signed provenance statement (`~/.ciscvm/provenance/…provenance.json`)
  describing exactly what produced the image (source image, profile, level,
  region, ciscvm version, score). Tencent CVM images are `img-*` artifacts,
  not OCI images, so cosign container signing does not apply — instead the
  provenance file is GPG-detached-signed (`[sign].gpg_key`), giving an
  auditable, tamper-evident record (SLSA L1 + signed provenance). Verified
  end-to-end with a real GPG key — tampering with the provenance makes
  verification fail (`gpg: BAD signature`).

  ```toml
  [sign]
  gpg_key = "ABCDEF0123456789"   # your GPG key id/fingerprint
  ```

  Verify any signed provenance (audit / compliance):

  ```bash
  ciscvm verify --provenance ~/.ciscvm/provenance/xxx.provenance.json
  ciscvm verify --image img-ekny61ig        # auto-locate by image ID
  ```

  Output shows subject (image IDs), profile/level/region/source, builder
  version, re-audit score, and the GPG signature status (VALID / INVALID /
  NONE). Exit code is non-zero when the signature is missing or invalid.

- **SBOM + change detection (supply chain)** — with `[meta].sbom = true` the
  build emits a zero-dependency SBOM (`/opt/ciscvm-SBOM.jsonl`, native
  rpm/dpkg query) into the image, and its SHA-256 + package count are pinned
  in lineage and the provenance statement (`sbomSha256` /
  `sbomPackageCount`) — SLSA L2-style evidence of what exactly shipped.
  `ciscvm build --skip-if-unchanged` / `ciscvm pending` compare a
  deterministic input fingerprint (source image, rule catalog hash,
  benchmark, level, filters) against the last successful lineage record and
  skip the rebuild when nothing changed — a scheduled-pipeline cost saver.

  ```bash
  ciscvm build --skip-if-unchanged    # skip if inputs unchanged
  ciscvm pending                      # exit 0 = no rebuild needed, 1 = rebuild
  ```

- **Clean-boot verification (`verify-image`)** — AWS Image Builder runs its
  test phase on the *output* image, not the build instance. `ciscvm
  verify-image --image img-xxx` boots a probe instance from the produced
  image, runs the bundled engine in scan mode on the FRESH boot (catching
  SELinux relabel stalls, first-boot services, cloud-init reconfiguration),
  gates on the score, and always terminates the probe. `[meta].verify_boot
  = true` chains it automatically after every successful build (Linux only).

  ```bash
  ciscvm verify-image --image img-ekny61ig --min-score 85
  ```

- **Independent audit (`audit`)** — the score is no longer only self-
  reported by the engine that applied the hardening. `ciscvm audit` runs a
  third-party tool and gates on the result, exactly like dev-sec (InSpec) /
  RHEL (oscap + SCAP content) / ansible-lockdown (Goss):

  ```bash
  # OpenSCAP — RHEL-family: use the scap-security-guide datastream on target
  ciscvm audit --tool oscap --host 1.2.3.4 --ssh-user root \
    --datastream /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
    --profile xccdf_org.ssgproject.content_profile_cis --min-score 85

  # Chef InSpec — dev-sec baselines (Linux)
  ciscvm audit --tool inspec --host 1.2.3.4 --ssh-user root \
    --baseline dev-sec/linux-baseline --min-score 85

  # HardeningKitty — Windows cross-check (audit runs on the Windows host,
  # export the CSV, parse it here)
  ciscvm audit --tool kitty --parse kitty-audit.csv --min-score 85
  ```

  Every audit can emit SARIF / XCCDF for GRC ingestion
  (`--sarif out.sarif --xccdf out.xml`).

### Post-delivery lifecycle (drift / refresh / deploy trigger)

- **Drift detection** — an image is correct at build time, but instances
  launched from it drift (configs tweaked, packages patched, services
  changed). `ciscvm drift` re-scans a LIVE instance over SSH and diffs the
  result against the baseline — the audit result shipped inside the image
  (`/opt/ciscvm-AUDIT-RESULT.json`) or a saved one:

  ```bash
  ciscvm drift --host 1.2.3.4 --image img-ekny61ig --min-score 85
  # reports: new failing rules / recovered rules / score delta; exit 1 = drift
  ciscvm drift --host 1.2.3.4 --save-baseline   # persist a custom baseline
  ```

- **Vendor image refresh** — when the upstream OS image is updated, the
  golden image should be rebuilt. `ciscvm check-source` compares the
  source image's `CreatedTime` against the last build's lineage record
  (exit 0 = unchanged, 1 = refreshed); schedule it on a timer ahead of
  `build --skip-if-unchanged`:

  ```bash
  ciscvm check-source && echo "source unchanged" || ciscvm build -y
  ```

- **Deploy trigger** — `[notify].deploy_webhook` POSTs
  `{event: "image.ready", image_id, score, profile, region}` on build
  success, so a new image automatically drives the downstream release
  (ASG launch-template update, Terraform, CI pipeline) instead of waiting
  for a human to read the WeCom message.

- **Cost control** — `[build].spot = true` launches the ephemeral build VM
  as a spot (竞价) instance (`instance_charge_type=SPOTPAID`, up to ~90%
  cheaper); repossess risk is acceptable for a short-lived build machine.

- **Safe cleanup** — `cleanup-images --unused-since N` only deletes images
  that are NOT shared with other accounts (via
  `DescribeImageSharePermission`), so an image still referenced downstream
  is never accidentally retired. Fails open (keeps the image) on API errors.

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
| TencentOS 4 apply fails: `Module result deserialization failed` + missing `/tmp/ansible_...payload.zip` | ansible-core ≥ 2.16 (modular ansiballz) caches module payloads in `/tmp`, which TencentOS 4 sweeps / backs with tmpfs; the reused payload vanishes mid-run | Fixed in v0.14.4 — the venv wrapper exports `TMPDIR=/opt/ciscvm-ansible/tmp` so payloads live on stable root-disk storage |
| TencentOS 4 reboot → Packer reconnect `i/o timeout` for 5+ min | ssh-guard runs *before* apply; CIS firewall rules (3.4.x) reload firewalld / switch the active zone, and the new zone has no SSH allow rule → port 22 is DROPped after reboot | Fixed in v0.14.8 — ssh-guard is re-run right before the reboot provisioner, and rules are persisted (`nft list ruleset > /etc/sysconfig/nftables.conf`, `iptables-save > /etc/sysconfig/iptables`) |
| `packer build` fails at prepare: `Unsupported argument "ansible_env_vars"` | `ansible_env_vars` only exists on the `ansible` (non-local) provisioner, not `ansible-local` | Fixed in v0.14.4 — TMPDIR is injected via the ansible-playbook venv wrapper instead of an HCL argument |
| `packer build` fails at parse: `Missing item separator` in `main.pkr.hcl` | A missing comma between `inline = [...]` items — Python silently concatenates the two adjacent strings, HCL then sees one unterminated item | Fixed in v0.14.14 — comma restored; regression test scans every rendered inline list for missing separators |
| TencentOS 4 reboot → `i/o timeout` even with all-zone firewall rules | `/.autorelabel` left by the SELinux-disabled boot; once `SELINUX=permissive` is written the next boot runs a full early-boot relabel (before sshd) — a multi-minute-to-infinite stall | Fixed in v0.14.17 — the guard deletes the stale `/.autorelabel` before reboot (permissive needs no relabel; the mark service only recreates it during a disabled boot) |
| Post-reboot `scp: /opt/...: Read-only file system` (then `/root/...`) | TencentOS 4 ships ro entries in fstab; first SELinux enable also makes `systemd-remount-fs` fail, leaving the whole root fs ro while sshd still comes up | Fixed in v0.14.18/19 — guard strips `ro` from `/opt` and `/` fstab lines + remounts rw; the boot oneshot force-remounts `/` before sshd; post-reboot uploads moved to `/root` |
| Smoke test `SMOKE FAIL: auditd / /dev/shm / weak SSH crypto` on L1 | Assertions gated on file/unit *existence* (TOS4 ships many units) or a hand-written "weak" blacklist that contradicts CIS 1.6.5/1.6.6 (hmac-sha1/umac-64/chacha20/aes\*-cbc are allowed) | Fixed in v0.14.20-22 — assertions now gate on `is-enabled` / fstab-applied; crypto check only flags CIS-forbidden algorithms (md5/3des/rc4/blowfish/cast/salsa20) |

---

## Roadmap

- [x] CI pipeline (GitHub Actions + OIDC, zero long-lived AK/SK)
- [x] Image governance loop: smoke test / lineage / notifications / SLSA signing
- [x] `ciscvm list` — enumerate available profiles with metadata
- [x] `ciscvm scan` — audit-only mode (no remediation, gate on findings)
- [x] Custom rule selection (`rules_include` / `rules_exclude` in `ciscvm.toml`)
- [x] PyPI package (`pip install ciscvm`) — publish workflow included
- [x] Automatic image cleanup (retire old images by lineage age)
- [x] Independent audit tool (`ciscvm audit` — oscap / inspec / kitty)
- [x] Benchmark-pinned rule IDs in engine output + SARIF (CIS-CAT cross-reference)
- [x] Clean-boot verification (`ciscvm verify-image` / `[meta].verify_boot`)
- [x] Per-control overrides (`[cis].overrides` in `ciscvm.toml`)
- [x] CVE scan gate + SBOM emission (`[meta].cve_scan` / `[meta].sbom`)
- [x] Change detection (`ciscvm pending` / `build --skip-if-unchanged`)
- [x] XCCDF 1.2 report export (`scan --xccdf`, audit `--xccdf`)
- [x] Cross-account image sharing (`[image].share_accounts`)
- [x] SBOM pinning in provenance + lineage (SLSA L2-style evidence)
- [x] Windows cross-check via HardeningKitty CSV (`audit --tool kitty`)
- [x] Config drift detection (`ciscvm drift` vs the image baseline)
- [x] User test components (`[meta].test_components`, Image Builder style)
- [x] Deploy trigger webhook (`[notify].deploy_webhook`, EventBridge style)
- [x] Spot-instance build VM (`[build].spot`, up to ~90% cheaper)
- [x] Safe cleanup (`cleanup-images --unused-since`, shared images kept)
- [x] Org-level sharing (`[image].share_org_units`)
- [x] Rule-set versioning (`ciscvm list --versions`)
- [x] Vendor image refresh detection (`ciscvm check-source`)
- [ ] SLSA L2: fully reproducible builds (pinned build environment)
- [ ] STIG benchmark profiles (same engine, DISA content — roadmap)

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
