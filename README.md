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
  <img src="https://img.shields.io/badge/profiles-14-orange" alt="14 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <a href="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ciscvm

**Config-driven CLI that spins up an ephemeral CVM, applies CIS hardening via the bundled cis-os engine, and captures the result as a custom image.** Built for DevOps and security teams who need repeatable, auditable hardened base images — CI pipelines, Auto Scaling launch templates, or Terraform image references.

Zero pip dependencies. 14 OS profiles across Linux and Windows. Build-time gate with configurable score threshold. All roles ship inside the package — no Galaxy, no network drift.

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
ciscvm scan [--min-score 85]              # audit-only build (no remediation) + score gate
ciscvm list                               # enumerate available profiles with metadata
ciscvm images [--latest] [-n N]           # list recorded builds (lineage)
ciscvm cleanup-images [--older-than 30]   # retire old images by lineage age
ciscvm cleanup-images --apply             # actually delete (default = dry run)
ciscvm verify --provenance <file>         # verify a SLSA provenance signature
ciscvm verify --image <img-id>            # ... or locate provenance by image ID
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
| `--min-score <pct>` | scan | Gate threshold (default `85`; below it → exit 1) |
| `--older-than <days>` | cleanup-images | Retire builds older than N days (default `30`) |
| `--keep-latest <n>` | cleanup-images | Always keep the newest N builds (default `1`) |
| `--apply` | cleanup-images | Actually delete (default is a dry run) |

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
# name = "my-cis-image"                  # optional: fixed image name (empty = auto prefix-level-timestamp)
copy_regions = ["ap-shanghai"]            # [] to disable cross-region copy

[cis]
level = 1                                 # 1 or 2

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

# SLSA-style provenance signing (GPG). Empty = provenance unsigned.
# [sign]
# gpg_key = "ABCDEF0123456789"

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
| | `name` | string | Fixed image name (empty = auto `prefix-level-timestamp`) |
| | `copy_regions` | []string | Regions to replicate (empty = skip) |
| `[cis]` | `level` | int | `1` (Level 1) or `2` (Level 2) |
| | `rules_include` | []string | Rule-ID filter — when set, ONLY these rules run (empty = all) |
| | `rules_exclude` | []string | Rule-ID filter — always wins over `rules_include` |
| `[cloud]` | `secret_id_env` | string | Env var for Secret ID |
| | `secret_key_env` | string | Env var for Secret Key |
| | `security_token_env` | string | STS session-token env var (default `TENCENTCLOUD_SECURITY_TOKEN`; used with OIDC/STS credentials) |
| | `winrm_password_env` | string | Windows admin password env var |
| | `assume_role_arn` | string | Group-account CAM role ARN (empty = off). e.g. `qcs::cam::uin/12345:roleName/X` |
| | `assume_role_session` | string | AssumeRole session name (default `ciscvm`) |
| | `assume_role_duration` | int | Session seconds, 0-43200 (default 7200) |
| `[meta]` | `os_tag` | string | Tag value for output image |
| | `benchmark` | string | CIS benchmark version tag |
| | `ssh_port` | int | SSH port (default `22`; TencentOS: `36000`) |
| | `ssh_timeout` | string | Packer SSH timeout (default `"15m"`) |
| | `ssh_debug_password` | string | Root password for VNC debug (default empty) |
| | `smoke_test` | bool | Instance-level checks before snapshot (default `true`) |
| `[notify]` | `webhook` | string | WeCom group-robot webhook URL (empty = off) |
| | `on` | string | `always` \| `success` \| `failure` (default `failure`) |
| `[sign]` | `gpg_key` | string | GPG key id/fingerprint for provenance signing (empty = unsigned) |

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@main/docs/ciscvm-pipeline-dark.png">
    <img src="https://cdn.jsdelivr.net/gh/susunola/cis-cvm-image-builder@main/docs/ciscvm-pipeline-light.png" alt="ciscvm build pipeline — TOML config to hardened golden image" width="720">
  </picture>
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

- [x] CI pipeline (GitHub Actions + OIDC, zero long-lived AK/SK)
- [x] Image governance loop: smoke test / lineage / notifications / SLSA signing
- [x] `ciscvm list` — enumerate available profiles with metadata
- [x] `ciscvm scan` — audit-only mode (no remediation, gate on findings)
- [x] Custom rule selection (`rules_include` / `rules_exclude` in `ciscvm.toml`)
- [x] PyPI package (`pip install ciscvm`) — publish workflow included
- [x] Automatic image cleanup (retire old images by lineage age)
- [ ] SLSA L2: reproducible builds (pinned build environment)

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
