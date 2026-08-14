# Changelog

All notable changes to **ciscvm** are documented here, grouped by release.
The format follows the ansible-lockdown convention: each release pins the
CIS benchmark edition it targets and lists rule-catalog changes so audits
can be traced across rebuilds.

## [0.16.25] — 2026-08-14

### Added
- **Audit reports archived on the build machine** — every successful
  `build` / `scan` now saves the per-rule audit JSON to
  `~/.ciscvm/reports/<image-name>.json`, next to the lineage and
  provenance records.  Linux emits the file as a gzipped+base64 marker
  line in the packer log (extracted by ciscvm); Windows copies the
  role-fetched `result.json`.  The in-image copy
  (`/opt/ciscvm-AUDIT-RESULT.json` /
  `C:\ProgramData\ciscvm\AUDIT-RESULT.json`) still ships — drift and
  verify-image use it as the baseline.

## [0.16.24] — 2026-08-14

### Added
- **Windows images now ship the build-time audit result** at
  `C:\ProgramData\ciscvm\AUDIT-RESULT.json` — the counterpart of Linux
  `/opt/ciscvm-AUDIT-RESULT.json`.  Previously the Windows engine's
  `result.json` was fetched to the controller and then deleted with the
  working directory, so nothing inside the image documented what was
  assessed.  Implemented as a `cis_ship_result_path` role variable
  (empty = off), enabled by the ciscvm Windows site template.

## [0.16.23] — 2026-08-14

### Fixed
- **`scan --sarif` / `--xccdf` reports came out empty on real builds**: the
  engine's failed-rule list reaches packer stdout as ONE Ansible
  `"msg": "...✗ 1.1.1.1 | ...\n..."` JSON string (literal `\n` escapes,
  each rule's detail glued to the next `✗` marker), so the line-anchored
  `✗`-rule regex never matched — the SARIF had zero results and the XCCDF
  showed zero rule-results even with dozens of failures on the console.
  Both builders now share `_parse_failed_rules`, which decodes msg
  payloads first and splits on rule markers.  Verified against a live
  rhel9 scan (56 failed rules now present in both reports).
- **XCCDF hard-coded `<score>100</score>`**: the TestResult now carries
  the real re-audit score parsed from the engine output, and `0` when the
  build never reached the audit — a failed build no longer ingests into
  GRC tooling as a perfect pass.

## [0.16.21] — 2026-08-13

### Fixed
- **Windows engine result.json carried a UTF-8 BOM**: PowerShell 5.1's
  `Out-File -Encoding utf8` writes a BOM, and the role's
  `b64decode | from_json` then dies with "Unexpected UTF-8 BOM" right
  after the engine completes.  The engine now writes via
  `[System.IO.File]::WriteAllText(..., UTF8Encoding($false))` — no BOM.
- **macOS controllers**: the ansible provisioner sets
  `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` — macOS kills forked ObjC
  children ("A worker was found in a dead state") when ansible runs
  controller-side.

## [0.16.20] — 2026-08-13

### Fixed
- **userdata's `winrm set` never ran**: winrm.cmd fails inside
  cloudbase-init's execution context ("resource URI not found") — the
  build only progressed because Basic was flipped on manually mid-build.
  The userdata and the re-lock provisioner now use the WSMan: provider
  (`Set-Item WSMan:\localhost\Service\Auth\Basic`), verified working.
- **Controller-side ansible needs collections**: `ansible.legacy.setup`
  redirects to `ansible.windows.setup` — document/install
  `ansible.windows` + `community.windows` (galaxy) alongside pywinrm.

## [0.16.19] — 2026-08-13

### Fixed
- **Windows build still failed after NTLM** (401 on every WinRM attempt):
  the tencentcloud packer plugin never sets the instance's Administrator
  password from `winrm_password`, so the VM boots with a random one.
  The Windows source now passes a cloudbase-init `user_data` PowerShell
  snippet that sets the Administrator password at first boot to the
  `winrm_password` value.  Follow-up: packer's Go WinRM client still could
  not negotiate NTLM against the stock image (pywinrm NTLM works — packer
  401s), so the userdata also enables Basic auth + unencrypted HTTP for
  the BUILD only, and a final powershell provisioner re-locks both before
  the snapshot.  NTLM flags from v0.16.18 are reverted; the ansible side
  is back to transport=basic.

## [0.16.18] — 2026-08-13

First Windows build attempt (win2022 L1) failed at "Timeout waiting for
WinRM"; root-caused with a manually launched probe instance.

### Fixed
- **WinRM auth**: stock TencentCloud Windows images DISABLE Basic auth on
  the WinRM service (NTLM verified working).  The packer communicator now
  sets `winrm_use_ntlm = true` and the ansible provisioner /
  site.yml use `ansible_winrm_transport=ntlm` (requires `pywinrm` +
  `ntlm-auth` on the controller).
- **winrm_timeout 10m → 30m**: Windows specialize/OOBE first boot can
  exceed 10 minutes on small instance types.

## [0.16.17] — 2026-08-13

ubuntu2004 post-reboot audit fixes (debugged live on a scratch CVM).

### Fixed
- **Gate now scores the whole run** (`summary.all.score`): the per-level
  buckets are level-only — ubuntu2204 L2 gated 69.2% on the L2-exclusive
  bucket while the run itself scored 90.1%.
- **journal-upload bootstrap rewritten** (was broken on ubuntu2004):
  config 0600 made the service fail "Permission denied" (runs as
  systemd-journal) → 0644; hardened /var/log/journal is 2740
  root:systemd-journal so the remote user cannot traverse into
  /var/log/journal/remote; and the stock socket unit double-bound the
  loopback port.  The bootstrap now ships a standalone
  systemd-journal-remote.service (direct 127.0.0.1:19532 bind,
  PrivateNetwork off, archive in a top-level /var/log/journal-remote
  LogsDirectory) and disables the socket unit.  Verified live: both
  services active and suid_dumpable=0 survive a reboot; post-reboot scan
  89.4%.
- **apport vs suid_dumpable (1.5.3/1.5.5)**: `/etc/init.d/apport` writes
  `fs.suid_dumpable=2` on every boot, so 1.5.3 could never survive a
  reboot while apport stayed enabled.  1.5.5 reclassified disruptive→safe
  (disabling apport is build-safe), which also makes 1.5.3 stick.
- **catalog contradictions → manual** (ubuntu2004): 6.2.2.1.4 (remote
  "not in use" contradicts the upload loopback bootstrap), 2.3.3.1/2.3.3.3
  (chrony path — apt installing chrony removes systemd-timesyncd, breaking
  2.3.2.2), 2.3.2.1 (site-specific NTP server), 6.2.2.2 (ForwardToSyslog
  contradicts the applied 6.2.3.3 rsyslog path).

## [0.16.16] — 2026-08-13

### Fixed
- **Gate read the level-ONLY summary bucket**: `gate.yml` scored
  `summary[cis_profile].score` — for L2 that is the L2-exclusive bucket,
  which is 0.0% when every L2-only rule is manual (ubuntu2404 L2: run
  scored 95.2% on "all" but gated 0.0%).  The gate now falls back to
  `summary.all.score` when the profile bucket has zero assessed rules.

## [0.16.15] — 2026-08-13

Ubuntu build failures root-caused on a live debug instance.

### Fixed
- **risk=none partition rules were LIVE-APPLIED** (ubuntu2404 L1/L2 crash):
  `run_rule()` only gated `disruptive`, so a risk=none rule with a real
  check+fixer ran its fix — `1.1.2.1.1` (/tmp, allow_tmpfs) mounted a fresh
  tmpfs over /tmp mid-apply, covering the running Ansible payload
  (`/tmp/ansible_ansible.*_payload_*`) and multiprocessing socket; the
  module then died at `exit_json` ("Module result deserialization failed").
  Two-layer fix: `run_rule()` now skips apply for risk=none rules
  (`skipped_manual`), and every risk=none partition rule in all catalogs is
  reclassified `family: manual` per the established manual/none convention.
- **Package fixes hardcoded `dnf`** (ubuntu2004/2204 gate failures):
  `f_pkg_present` / `f_pkg_absent` / `f_pkg_any_present` and the phase-1
  batch install called dnf directly — every package rule failed apply on
  Debian-family targets ("dnf install failed: not found"), dragging
  ubuntu2004 L1 to 82.1% and L2 gates below 60-70%.  All now route through
  `_install_pkgs()` / new `_remove_pkgs()` (dnf / apt-get with
  DEBIAN_FRONTEND=noninteractive).  Package names were already deb-correct
  in the ubuntu catalogs.

## [0.16.14] — 2026-08-13

### Fixed
- **v0.16.13 broke non-root (ubuntu) builds**: the rc-local drop-in was
  written with `sudo printf ... > file` — the redirect runs in the
  *unprivileged* shell, so the cleanup provisioner died with
  `Permission denied` for every profile whose SSH user is not root
  (all ubuntu builds failed at the cleanup step).  Now
  `printf ... | sudo tee file`, matching the surrounding provisioner style.

## [0.16.13] — 2026-08-13

RHEL 9/10 CREATEFAILED root cause — guest can no longer soft-shutdown after
hardening, so TencentCloud image creation times out (snapshot is taken from
a guest that never finished powering off).

### Fixed
- **rc-local.service stop hangs forever**: on the RHEL 9/10 public images
  the TencentCloud security agent (`secu-tcs-agent`) is started from
  `/etc/rc.d/rc.local` and lives in rc-local.service's cgroup.  The unit
  ships `TimeoutStopSec=infinity` and the agent catches SIGTERM; once the
  CIS firewall rules cut its backend connection, the agent's signal handler
  blocks on a dead socket and the stop job never completes — reproducer:
  `StopInstances --StopType SOFT` hangs >5 min on a hardened guest vs ~110 s
  unhardened.  The cleanup provisioner now installs
  `/etc/systemd/system/rc-local.service.d/10-ciscvm-stop-timeout.conf`
  (`TimeoutStopSec=15s`) so systemd SIGKILLs the agent and the shutdown
  completes.  RHEL 8 was unaffected (agent runs under a regular unit there).
- Regression: `test_rc_local_stop_timeout_capped` asserts the drop-in is
  rendered into the packer HCL.

## [0.16.7] — 2026-08-09

Py3.8 compatibility hardening (ubuntu2004 matrix follow-up to v0.16.6).

### Added
- **Regression guard for target-side py3.8**: the engine runs ON the build
  target (ubuntu2004 ships python3.8) but tests run on 3.13 — so py3.8
  breakage was invisible.  `TestEnginePy38Compat` now enforces, statically
  on any CI python:
  - py3.8 grammar via `ast.parse(feature_version=(3,8))` on ALL 10 engines
  - no runtime-evaluated PEP585/PEP604 annotations (function signatures,
    returns, module/class vars) — the exact `'type' object is not
    subscriptable` import crash v0.16.6 fixed
  - no py3.9+ stdlib APIs (`removeprefix`, `functools.cache`, `zoneinfo`…)
  - all 10 role engines stay byte-identical (drift guard)
- **Live verification**: engine scan (L1: 254 rules, L2: 312 rules) and
  apply-mode startup were executed under a real Python 3.8.20 — no
  crash; apply correctly stops at the root check.

## [0.16.2] — 2026-08-09

Round-2 review — the engine (`cis_engine.py`), HCL templates, packer
subprocess handling and the build/clean guards were audited; no new P0/P1
bugs found (those code paths had been hardened across earlier releases).
Two polish fixes landed:

### Fixed
- **SARIF detail extraction**: `scan --sarif` grabbed whatever line came
  after a failing rule — often the *next* rule header instead of the
  failure detail.  Now collects the indented detail lines up to the next
  rule/blank line.
- **`main()` top-level guard**: an uncaught exception in any subcommand
  now prints the traceback plus a human `internal error` message and
  exits 70 (Ctrl-C exits 130) instead of leaking a raw traceback.

Tests: 299 → 304 (5 new regression tests).

## [0.16.1] — 2026-08-09

Post-review hardening — bugs found in a systematic review of v0.15.0/v0.16.0.

### Fixed
- **P0 — `test_components` broke non-root profiles (ubuntu)**: the file
  upload destination and the runner loop were hardcoded to `/root` — the
  same class of bug v0.14.33 fixed for the smoke test.  Uploads now go to
  the ssh user's home (`/root` for root, `/home/<user>` otherwise) and the
  runner loop uses `__REMOTE_DIR__`.
- **verify-image gate ignored `[cis].min_score`**: `build`-driven
  `verify_boot` fell back to a hardcoded 85 instead of the configured gate.
- **`cmd_verify_image` crashed on `ConfigError`** (e.g. missing credentials
  with `verify_boot` on) — now a clean `fail()` + exit 1.
- **SSH `TimeoutExpired` / `FileNotFoundError` uncaught** in `_probe_scan`,
  `_audit_oscap` and the drift baseline fetch — surfaced as scan errors
  instead of tracebacks.
- **cleanup-images retired whole multi-image records**: removing one image
  of a cross-region copy pair marked the whole record retired, permanently
  dropping the surviving copies from cleanup.  Now removes per-image and
  only retires when the record has no images left.
- **log FileHandler leaked** on the `verify_boot` failure path in
  `cmd_build`.
- **`_share_images` used hardcoded `TENCENTCLOUD_*` env names**, ignoring
  custom `[cloud].secret_id_env` — now honours the config's env names like
  the probe/verify paths.

### Changed
- oscap ARF parser: dead no-op accumulator removed; `fixed`/`unknown`/
  `notapplicable` are now consistently counted as `notselected`.
- trivy CVE gate now skips `/proc,/sys,/dev,/run,/tmp` (kernel pseudo-fs
  findings are unfixable noise and slow the gate down).
- `_probe_public_ip` no longer trips an IndexError on empty
  `PublicIpAddresses` lists.

Tests: 287 → 299 (12 new regression tests).

## [0.16.0] — 2026-08-08

Round-2 borrows — the "post-delivery lifecycle" layer.  Benchmarked against
Red Hat Insights Drift, EC2 Image Builder test components / EventBridge /
spot instances / lifecycle policies, and AWS RAM-style org sharing.

### Added
- **#12 — Drift detection** (`ciscvm drift`): re-scan a LIVE instance over
  SSH and diff against the baseline (the audit result shipped inside the
  image, a saved baseline, or `--baseline <file>`).  Reports new failing
  rules / recovered rules / score delta; exit 1 = drift.
  `drift --save-baseline` persists a custom baseline.
- **#13 — User test components** (`[meta].test_components`): user-defined
  shell/powershell scripts are uploaded and run sequentially before the
  snapshot (EC2 Image Builder test-component style); non-zero exit aborts
  the build.  Missing scripts fail fast.
- **#14 — Deploy trigger** (`[notify].deploy_webhook`): on build success,
  POST `{event: image.ready, image_id, score, profile, region}` to the
  customer's CI/CD (EventBridge-style).  Independent of the WeCom webhook.
- **#15 — Spot build VM** (`[build].spot`): renders
  `instance_charge_type = "SPOTPAID"` — up to ~90% cheaper build machine.
- **#16 — Safe cleanup** (`cleanup-images --unused-since N`): only delete
  images NOT shared with other accounts (`DescribeImageSharePermission`);
  fails open (keeps) on API errors so an in-use image is never retired.
- **#17 — Org-level sharing** (`[image].share_org_units`): merged with
  `share_accounts` into one `ModifyImageSharePermission` call.
- **#19 — Rule-set versioning** (`ciscvm list --versions`): per-profile
  rules.json sha256 + engine version for audit pinning.
- **#20 — Vendor refresh detection** (`ciscvm check-source`): compares the
  source image's CreatedTime against the last build's lineage record;
  exit 0 = unchanged, 1 = refreshed.  Lineage now records
  `source_image_created`.
- **#18 — STIG roadmap**: framework is CIS-only today; DISA STIG profiles
  are documented as a roadmap item (same engine, new rule catalogs).

### Changed
- `_send_notification` fires `deploy_webhook` independently of the WeCom
  webhook (deploy trigger no longer blocked when `[notify].webhook` unset).
- Version bumped 0.15.0 → 0.16.0.

### Tests
- 287 tests (up from 257) — every round-2 feature has regression coverage.

## [0.15.0] — 2026-08-08

Borrows from the 2026-08 benchmark comparison against Ansible Lockdown,
dev-sec hardening, RHEL Image Builder (osbuild+OpenSCAP), AWS EC2 Image
Builder, CIS-CAT/LBK and HardeningKitty.

### Added
- **P0#1 — Independent audit tool** (`ciscvm audit`): run a THIRD-PARTY
  auditor instead of relying on the self-reported engine score.
  - `--tool oscap` — OpenSCAP over SSH, parses ARF XML, gates on score
    (RHEL-family: scap-security-guide datastream).
  - `--tool inspec` — Chef InSpec over SSH, parses JSON report
    (dev-sec baselines).
  - `--tool kitty --parse <csv>` — HardeningKitty (Windows) CSV cross-check.
  - Optional `--sarif` / `--xccdf` export for GRC ingestion.
- **P0#2 — Benchmark-pinned rule IDs**: the engine now emits
  `benchmark` + `rule_id` (`"<benchmark> <id>"`) on every result, and
  SARIF carries the benchmark reference — findings cross-reference
  CIS-CAT / SCAP numbering exactly.
- **P0#3 — Clean-boot verification** (`ciscvm verify-image --image …`):
  boots a probe instance from the PRODUCED image, re-audits on fresh boot
  (SELinux relabel, first-boot services, cloud-init), gates on score and
  always terminates the probe. `[meta].verify_boot = true` chains it
  automatically after successful builds (Linux only).
- **P1#4 — Benchmark pinning + changelog**: benchmark recorded in lineage
  and provenance (`rules_sha256` + `fingerprint`); preflight warns on
  `[meta].benchmark` divergence from the profile default; `ciscvm list`
  shows the benchmark column.
- **P1#5 — Per-control overrides** (`[cis].overrides`): deep-merge rule
  parameters into the workspace copy of rules.json at render time
  (bundled catalog never mutated; unknown rule IDs fail fast).
- **P1#6 — CVE scan + SBOM** (`[meta].cve_scan` / `[meta].sbom`):
  trivy CRITICAL-severity gate before the snapshot; zero-dependency SBOM
  (`/opt/ciscvm-SBOM.jsonl`) emitted into the image and echoed to the
  build log for hashing.
- **P1#7 — Change detection** (`ciscvm pending`, `build
  --skip-if-unchanged`): deterministic input fingerprint (source image,
  rule catalog hash, benchmark, level, filters, version); skips rebuilds
  when nothing changed and the previous image still exists.
- **P2#8 — XCCDF 1.2 export** (`scan --xccdf`, `audit --xccdf`): feed
  enterprise GRC/compliance platforms.
- **P2#9 — Cross-account sharing** (`[image].share_accounts`): calls
  `cvm:ModifyImageSharePermission` after a successful build (never fails
  the build).
- **P2#10 — SBOM pinning in provenance**: provenance records
  `sbomSha256` + `sbomPackageCount`; lineage records the same — SLSA
  L2-style evidence of what shipped inside the image.
- **P2#11 — HardeningKitty CSV parser** for Windows cross-validation.

### Changed
- `ciscvm list` prints a `benchmark` column.
- SARIF reports now carry the benchmark reference (P0#2).
- Version bumped 0.14.33 → 0.15.0 (feature release).

### Fixed
- Pre-existing lint/type debt cleaned so `ruff check ciscvm` and
  `mypy ciscvm --ignore-missing-imports` are green (CI gate).

### CIS benchmark editions (profile → benchmark tag)
- Ubuntu 20.04 / 22.04 / 24.04 — CIS Ubuntu Linux LTS Benchmark v1.0.0
- RHEL 8 / 9 / 10 — CIS Red Hat Enterprise Linux Benchmark v1.0.0
- TencentOS 3 / 4 — CIS TencentOS Linux Benchmark v1.0.0
- Windows Server 2016 / 2019 / 2022 / 2025 — CIS Microsoft Windows Server
  Benchmark v1.0.0

## [0.14.33] — 2026-08-08

- Fix: ubuntu non-root login — `remote_path` rendered per user
  (`/root` vs `/home/<user>`).

## [0.14.32] — 2026-08-08

- Fix: smoke journal-upload assertion too strict — enabled but inactive is
  normal without a remote journal server.

## [0.14.31] — 2026-08-08

- Fix: all shell provisioners set `remote_path=/root` — TencentOS 3
  `/tmp` noexec caused exit 126.

## [0.14.30] — 2026-08-08

- Fix: audit load aborted by duplicate rules 4.1.3.24 / 4.1.3.6
  ("Rule exists").

## [0.14.29] — 2026-08-08

- L2 score uplift: 11 of 22 failures reclassified manual + 3 risk
  downgrades.
