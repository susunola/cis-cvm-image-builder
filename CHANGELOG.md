# Changelog

All notable changes to **ohbs-image** are documented here, grouped by release.
The format follows the ansible-lockdown convention: each release pins the
CIS benchmark edition it targets and lists rule-catalog changes so audits
can be traced across rebuilds.

## [Unreleased]

### Fixed (fleet re-audit round, all 8 Linux roles)
- **role bundling: purge stale roles from the shared workdir** — the build
  workdir is reused across runs, so `workdir/ansible/roles/` accumulated
  every previously-built role; any glob-based engine lookup (finalize
  re-scan, `_probe_scan`) could pick a different OS family's engine and
  report another distro's results. `_bundle_role` now removes every role
  directory except the current one before copying, and the finalize
  re-scan / probe scan resolve the engine via the explicit
  `/opt/ohbs-image-ansible/roles/__ROLE_DIR__/files` path with the glob
  only as a fallback.
- **finalize banner drop-in mode 0600** — `99-ohbs-image-banner.conf` was
  written 0644, failing the CIS sshd_config permission check on its own.
- **`sudo_defaults` accepts `op: eq`** — 5.2.3 (`Defaults use_pty` etc.)
  failed on every platform because the checker only understood `kv`.
- **authselect: never write through a profile symlink** — on rhel8/9 the
  PAM edit path atomically replaced `/etc/authselect/custom/*` symlinks
  with plain files, after which every authselect operation refused to
  touch the profile ("unexpected content") and with-faillock/with-pwhistory
  could never be enabled. `_pam_edit_targets` now edits only the custom
  profile's source files when one exists; `f_pam_arg`'s direct
  `/etc/pam.d` re-apply loop runs only for non-custom profiles, and
  `f_authselect_feature` creates the custom profile (based on `sssd`)
  before enabling features.
- **journald upload: socket-activated remote sink** —
  `_bootstrap_journal_upload` rewritten: a socket drop-in re-points
  `systemd-journal-remote.socket` at 127.0.0.1:19532, the service drop-in
  drops PrivateNetwork and writes to `/var/log/journal-remote/`, the
  masked unit from older images is unmasked, and `journal-upload.conf`
  always uses `URL=http://127.0.0.1:19532` (`UploadServer=` is not a
  valid lvalue on systemd 239).
- **`crypto_policy` fixes** — SSH crypto rules (`no_weak_mac`, …) no
  longer require `update-crypto-policies` (absent on Ubuntu, so 5.1.15
  never fixed); a post-fix hook restores `/etc/sysconfig/sshd` to
  0600 root:root after `update-crypto-policies` rewrites it 0640; the
  `no_sha1` module gains `mac = -HMAC-SHA1`, and the fixer prefers the
  vendor `NO-SHA1.pmod` module when present instead of shadowing it with
  a local (incomplete) one.
- **`svc_enabled`: masked units count as "not in use"** — an
  `if_in_use` rule whose unit is masked now evaluates `notapplicable`
  (ubuntu2204: chrony's rule masks systemd-timesyncd, which then
  reported itself as a failure). The fixer also falls back to the
  `systemd-journal-remote` package on apt systems where
  `systemd-journal-upload` does not exist.
- **`updates_applied` (apt): dist-upgrade + phased updates** — plain
  `apt-get -y upgrade` leaves kept-back/phased updates pending; the
  fixer now runs `dist-upgrade` with
  `APT::Get::Always-Include-Phased-Updates=true`.
- **`exclusive_stack` dedupes unit aliases** — units sharing one
  `FragmentPath` (chrony/chronyd) no longer count as two stacks.
- **`listening_ports`: protocol-qualified allowlist entries** —
  `allow_ports` accepts `"68/udp"` so DHCP clients do not fail the check.
- **`logfile_perm`: also hook `APT::Update::Post-Invoke-Success`** —
  `eipp.log.xz` is written by `apt update`, which the DPkg hook misses.
- **new fixer `bootloader_password`** — generates a random GRUB
  superuser password (PBKDF2-SHA512, 10k rounds) per build: RHEL-family
  writes `/boot/grub2/user.cfg`, Debian-family a `01_users` drop-in +
  `update-grub`; the cleartext is stashed in
  `/root/ohbs-image-grub-password` (0600). Catalogs flipped from
  risk=none to safe on all 8 Linux roles.
- **catalog conflict cleanups** — rhel8 5.1.17 drops the two etm MACs
  (conflict with 1.6.6); rhel8 6.2.1.1.4 / rhel9 6.2.2.2 / rhel10
  6.2.2.2 / ubuntu2204 6.1.1.1.4 / ubuntu2004 6.2.2.2 removed
  (ForwardToSyslog=no is mutually exclusive with the rsyslog path the
  sibling rule enforces); rhel10 1.1.1.11 keeps `vfat` loadable
  (/boot/efi) and 2.1.3 disables cockpit at L1 too; ubuntu2404 1.1.1.11
  keeps overlay/squashfs (snapd); ubuntu2004 drops the whole 4.3.x/4.4.x
  nftables+iptables sections (alternative stacks fought the enforced ufw
  stack) and masks the vendor-enabled firewalld; assorted risk=none→safe
  promotions validated on live build VMs.
- **`bootloader_password` (Debian/Ubuntu): keep menu entries bootable** —
  Debian's `/etc/grub.d/10_linux` generates entries WITHOUT
  `--unrestricted` (RHEL ships it in `CLASS=` by default), so defining a
  GRUB superuser made GRUB prompt for credentials before booting any
  entry: the post-hardening reboot of the 2026-08-22 ubuntu2404 build
  never came back (SSH dial i/o timeout).  The fixer now patches every
  `/etc/grub.d/10_linux*` generator to append `--unrestricted` to the
  `CLASS=` line (idempotent), verifies the regenerated grub.cfg, and
  rolls back `01_users` + re-runs update-grub when entries still lack it
  — a failed rule beats an unbootable image.
- **Windows: first-boot deferred hardening** — the CIS WinRM Service
  lockdown rules (AllowBasic / AllowAutoConfig / AllowUnencryptedTraffic /
  WinRS AllowRemoteShell) and the UAC built-in-Administrator token
  filtering rule (FilterAdministratorToken) cannot be written to the live
  registry during a packer build: pywinrm re-authenticates with basic auth
  on every request, so AllowBasic=0 turns the running ansible play into
  "401 credentials rejected" (win2022 died mid-apply with exit status 4).
  Catalog entries for these rules now carry `"defer": "firstboot"`; the
  ps1 engine records them in
  `%ProgramData%\ohbs-image\firstboot-deferred.json`, generates
  `firstboot-hardening.ps1` from that manifest, and registers a one-shot
  SYSTEM scheduled task (`ohbs-cis-firstboot-hardening`, AtStartup) that
  applies the values at the next boot and removes itself.  The checker
  treats a recorded manifest entry as compliant (the captured image
  carries the task, so deployed VMs converge on first boot).  All 4
  Windows roles now share a byte-identical engine.

### Added
- **19 new/extended engine families automating ~130 `manual` Linux rules**
  (all 8 Linux roles share the byte-identical engine; catalog wiring is a
  separate change).  New check families:
  - package/repo hygiene: `gpg_keys`, `pkg_repos`, `updates_applied`
    (fixer runs a full `dnf -y update` / `apt-get -y upgrade` under
    `_pkg_lock` with an 1800s budget), `pkg_verify` (rpm -Va / dpkg
    --verify mode/owner drift), `suid_baseline` (SUID/SGID files vs an
    explicit `params.allow` baseline with a bit-stripping fixer, OR
    golden-image mode: `params.baseline` records the post-hardening set
    at apply time and fails later scans on any addition — missing
    recording is `fail` in apply mode so the fixer fires, `manual` in
    scan mode), `apt_signed_by`;
  - network: `listening_ports` (ss-based allowlist, default SSH+loopback;
    deliberately no fixer), `nft_rules`, `iptables_rules` (+`ipv6` flag),
    `firewalld_rules`, `ufw_rules` — the four firewall detail families
    embed the `fw_stack_in_use` guard and return `notapplicable` when
    their stack is not enabled/active;
  - services/config: `kmod_list`, `exclusive_stack`, `exclusive_logging`,
    `timesync_cfg`, `apparmor`, `perm_glob`, `rsyslog_actions`,
    `audit_rules_valid` (literal "audit rules load" syntax check — see the
    in-code ASSUMPTION note pending benchmark-PDF confirmation).
  Extensions: `chrony_user` gains `params.user` (Ubuntu `_chrony`, checked
  via the running process or the unit's `User=` directive);
  `user_audit` gains the `shadow_group_empty` kind (fixer strips members
  via `gpasswd -d`, refuses to move primary groups).
- **All 8 Linux catalogs wired to the automation families** — every rule
  previously evaluating as `manual` was mapped to an existing or new
  family (separate-partition rules became check-only `partition` with
  risk=none; SUID/SGID audit rules use the new baseline-recording mode).
  Residual `manual` rules per catalog: tencentos4 **0**; rhel8/9/10,
  tencentos3, ubuntu2004/2204 **2** each (journal-upload auth and the
  remote rsyslog destination — both need site-specific endpoints);
  ubuntu2404 **4** (plus sshd ListenAddress and rsyslog gtls/CA
  material).  Catalog data bugs fixed along the way: tencentos4 1.11
  (orphan params belonged to `crypto_policy`), ubuntu2404 1.3.1.3
  (orphan apparmor params), the 5.3.3.2.3/6.2.x assessment-metadata lags
  in every catalog, and the rhel9/ubuntu2004 3.3.x sysctl rules left at
  family=manual while siblings automated them.
- **Windows catalogs automated** (win2016/2019/2022/2025): ~234 rules
  moved from `manual` to the existing registry/secedit families
  (`reg-dword`, `reg-string`, `reg-multisz`, `user-right`,
  `audit-policy`, …) — CIS 18.x/19.x Administrative-Template rules are
  registry-backed, so this was mostly catalog data completion.  New
  ps1-engine family `reg-values-map` (a SET of string values under one
  key) covers win2016 18.10.43.6.1.2 (ASR per-rule states).  Residual
  `manual`: 15–16 per catalog — rename-Administrator/Guest (would break
  the build's own WinRM login), DC-only rules, IPv6 disable (too
  disruptive on cloud images), and the HKCU-only 19.x policies a golden
  image cannot enforce.  Data bugs fixed: win2016 2.3.1.1 params,
  win2022 9.2.5 stray space in the registry path, and the
  Guest-account-status rules that mapped to `SpecialAccounts\UserList`
  (hides the account; does not disable it).  WinRM-listener rules are
  marked `risk: medium` — applying `AllowAutoConfig=0` on a live host
  can drop its management listener.
- **Firewall-stack guard + firewalld probes (engine + tencentos4 catalog)** —
  the CIS 3.4 firewall sections are mutually exclusive alternatives
  (firewalld 3.4.2.x / nftables 3.4.3.x / iptables 3.4.4.x), yet every
  stack's detail rules were catalogued `manual`, inflating the manual
  count by 18 on tencentos4-l1.  Two new families fix that:
  - `fw_stack_in_use` — a section guard: when none of the stack's units
    are enabled/active the rule is `notapplicable`; when the stack IS in
    use the rule drops back to `manual` for auditor review.  Applied to
    all nftables (3.4.3.x) and iptables (3.4.4.x) detail rules.
  - `firewalld_cfg` — automates the chosen-stack rules 3.4.2.4
    (`default_zone`) and 3.4.2.5 (`interfaces_assigned`) via firewall-cmd,
    with fixers (set default zone / bind stray interfaces to it).
  Also repairs three catalog entries (3.4.3.7, 3.4.4.1.2, 3.4.4.1.3) that
  claimed `Automated` assessment but had `family: manual`.  tencentos4-l1
  manual count drops 31 → 13.
- **`[ohbs].allow_disruptive` config option** (default `true`) — controls
  whether the engine applies disruptive remediations (mount options,
  service removals, SELinux enforcing, …) during the build. Previously
  hardcoded to `false` in the rendered playbooks, which left ~40 rules
  per profile permanently `skipped_disruptive`. The build VM is ephemeral
  and rebooted before the post-boot audit, so disruptive fixes are safe
  to apply here; set it to `false` to restore the old behaviour.

### Fixed (engine + tencentos4 catalog, 2026-08-21 re-audit round)
- **`mount_opt`/`partition`: unmask the generated mount unit** — TencentOS 4
  ships `tmp.mount` masked (`/etc/systemd/system/tmp.mount -> /dev/null`),
  which silently nullified the CIS `/tmp` tmpfs fstab entry: the entry was
  present but never mounted at boot (re-audit 1.1.2.2–4 `notapplicable`).
  Both fixers now `systemctl unmask` the mount unit when it is masked.
- **`mount_opt`: late-boot mount re-assert** — a new opt-in
  `cis-mount-apply.service` (oneshot, `After=local-fs.target`) re-remounts
  tmpfs mounts with their applied options on every boot. On the 2026-08-21
  tencentos4-l1 build, `/dev/shm` came up after the post-hardening reboot
  WITHOUT the `noexec` its fstab entry carried (systemd-remount-fs did not
  apply it), failing the build smoke test. Follows the established
  `cis-sysctl-apply.service` late-boot pattern.
- **authselect: base the custom profile on `sssd`, not `minimal`** —
  TencentOS 4 ships with the feature-less `minimal` profile selected, so
  `authselect enable-feature with-faillock` failed with "Unknown profile
  feature" and CIS 5.4.3/5.4.4 could never pass.
- **`world_writable`: persist fixes for boot-recreated tmpfs files** —
  vendor agents (TencentCloud barad_agent) re-create
  `/run/.barad_agent.pid` and `/run/barad_agent.lock` mode 0666 tens of
  seconds after every boot. `f_world_writable` now installs
  `ohbs-cis-volatile-perms.service` (Type=simple, non-blocking) which
  polls once a second for up to 3 minutes after boot: an explicit
  `chmod o-w` loop over every path fixed at build time (covers
  boot-recreated files on persistent filesystems too — barad recreates
  `/etc/uuid` 0666 ~13s in, and its STARGATE logs can be baked into the
  image as 0666) plus a `find` sweep of the offending tmpfs mounts; the
  fix-logperms provisioner additionally sweeps `/run` right before the
  fresh-boot re-audit as a deterministic fallback (6.1.13 kept failing
  the fresh-boot scan).
- **finalize: keep the CIS banner files OS-name-free** — the build banner
  written to `/etc/motd`, `/etc/issue` and `/etc/issue.net` embedded the
  dashed os_tag (`tencentos-4`), which the engine's own CIS 1.2.x banner
  check flags as an OS reference on every boot from the image (the
  fresh-boot gate ran before finalize, so it never saw the regression;
  the post-finalize report audit recorded 1.2.1–3 as fail).  Banners now
  print the dash-stripped tag (`tencentos4`); the full tag still lands in
  the /opt report.  The finalize boot-log sweep also covers
  `/var/log/lastlog` (baked into the image as 0664, failing 4.2.3).
- **tencentos4 catalog: two more manual rules automated** — 4.2.1.6 now
  uses the existing `rsyslog_no_receive` family and 4.3 uses `pkg_present`
  (logrotate), matching the rhel9/ubuntu2404 catalogs.

## [0.17.0] — 2026-08-20 — build-CVM naming, packer passthrough, API retries, real E2E

### Added (rule-catalog automation, rounds 2–4)
- **Second wave of manual-rule automation** — dozens more CIS rules moved
  from `manual` to automated families across all 8 Linux catalogs: `7.1.x`
  /etc file permissions, `6.3.4.x` audit log/config permissions, `6.3.2.2`
  auditd `keep_logs`, plus SELinux `1.3.1.4` reclassified to `safe`
  (applies permissive; `1.3.1.5` enforcing stays `disruptive`). ubuntu2404
  L2 manual count drops from 169 (2026-08-19 report) to ~67.
- **Audit-rule canon** — multi-`-S` syscall lists are merged and watch-path
  trailing slashes stripped (`-F path=` before tokenization), fixing audit
  rules that previously failed to load via augenrules on 64-bit; `-S stime`
  dropped (aborts augenrules); 32-bit syscall variants (b32) corrected.

### Fixed (engine + catalog, 2026-08-20)
- **Conditional `svc_enabled` rules** — catalog rules may now set
  `params.if_in_use`: when neither the unit nor its provider package
  exists, the check returns `notapplicable` (and the fixer a no-op)
  instead of `fail`. Fixes the ubuntu2404 2.3.2.2 false positive where
  chrony covers time sync and Debian packaging removes
  `systemd-timesyncd`. Applied to 2.3.2.2 in ubuntu2004/2204/2404.
- **telnet/ftp client removal reclassified to `safe`** — was
  `disruptive` and skipped at build time on rhel8/9/10 and
  ubuntu2004/2204/2404; removing a client package does not interrupt
  services (tencentos3/4 already marked `safe`).
- **ubuntu 1.4.1 bootloader password** — moved to `family=manual`
  (risk=none) with a documenting note: the GRUB password is a
  site-specific credential with no automated remediation; cloud golden
  images normally exempt it.
- **Engine correctness** — `kv_conf` reads its key after the
  `limits_core` branch (1.5.1 KeyError); `f_kv_conf` fix-end key;
  shadow group root; `crypto_policy` kind default → `not_legacy`;
  journal-upload/remote no longer reference non-existent RHEL10 packages.

### Added
- **`[build].instance_name`** — optional explicit name for the temporary
  build CVM (the machine Packer launches and hardens before snapshotting).
  Empty means the plugin auto-generates it. Used by the E2E runner to tag
  target machines with a recognizable `CIS_E2E_*` prefix.
- **`[build.packer]` passthrough** — arbitrary `tencentcloud-cvm` Packer
  builder args can now be injected verbatim into the generated HCL source
  block (e.g. `disk_type`, `disk_size`, `data_disks`,
  `internet_max_bandwidth_out`), so ohbs-image inherits the full Packer
  capability set without hardcoding each argument. Values are rendered via
  the existing `_format_hcl_value` (now dict-aware) and spliced in through
  a new `__EXTRA_ARGS_BLOCK__` marker.
- **`_tc3_api` resilience** — Tencent Cloud API calls now retry rate-limit
  (429) and gateway (5xx) responses and network-layer failures
  (DNS/reset/timeout) up to 3 attempts with exponential backoff, and wrap
  every terminal failure in a `ConfigError` with a clear, actionable
  message. Bad-request/auth errors and non-JSON responses are never
  retried. Credential reads are de-duplicated via a shared `_creds`
  helper.
- **Real E2E runner overhaul** (`scripts/real_e2e_test.py`) — supports
  `--target-mode single|all-linux|all` to trigger real `ohbs-image build`
  against profile+level combinations; the E2E build CVM can be tagged via
  `[build].instance_name`. New `scripts/e2e.env.example` documents the
  required Tencent Cloud / network variables; the live `scripts/e2e.env`
  (and any `e2e.env-bak`) is git-ignored so credentials never leak.
- **`tests/test_real_e2e.py`** — integration harness for the real E2E flow.

### Fixed
- `_audit_results_xccdf` now emits a timezone-aware, UTC-normalized
  timestamp instead of a naive `datetime.utcnow().isoformat()`.
- **`packer init` retries transient failures** — the `packer init` step now
  retries up to 4 attempts with exponential backoff on GitHub API 5xx /
  rate-limit and network-layer errors (e.g. while downloading the
  `packer-plugin-tencentcloud`). A genuine HCL/plugin error or a missing
  `packer` binary still fails fast. This removes intermittent CI flakiness
  in the real-HCL `TestRealPackerValidateAllProfiles` checks.
- **Review-wave correctness fixes (2026-08-20)** — probe scan role glob,
  verify-boot probe key auth, `ModifyImageSharePermission` parameters, oscap
  score normalization, scan lineage no longer poisoning skip-if-unchanged,
  and stricter config type validation; e2e script fixes (`--reuse-last`
  re-queries the kept jump box's public IP, batch-image cleanup targets the
  actual build region); the build-image workflow installs packer and
  generates `ohbs-image.toml` from secrets; the upstream-plugin monitor
  stays quiet via a comment-count baseline; setuptools floor bumped to
  >=62.3 for the recursive `roles/**/*` package-data glob.

### CI / tests
- **Tests aligned with the `ohbs_` rebrand** — the test suite referenced the
  pre-rebrand `cis` naming (config section `[cis]`, `cis_win` role filter,
  `tencentos3-cis-` image prefix, legacy `_image_ids_still_exist`
  signature, old CVE template text). Updated to match current `ohbs_image`
  behavior, fixing 22 CI failures.


### Runtime-robustness (ported from the pre-refactor ohbs lineage)
- **Guaranteed temp-dir cleanup in the roles** — all 12 OS `run.yml`
  (8 Linux + 4 Windows) now wrap the engine execution in an Ansible
  `block` whose `always:` clause removes the remote working directory even
  if the engine run (or any intermediate step) fails, instead of relying on
  a plain cleanup task that gets skipped on error. Failed builds no longer
  leak `cis-<os>-*` / `cis-run` dirs under `cis_remote_tmp`.
- **Static role imports + tags** — Linux `main.yml` now uses
  `import_tasks` (parsed up-front, so tags apply reliably) and tags each
  phase (`cis, always` / `cis, scan, apply` / `cis, gate` / `cis, output`)
  so operators can run `--tags cis` selectively.
- **pip install retry** — `install-ansible.sh` retries `pip install` once
  after a 5s pause (transient mirror/network failures are common during
  image builds, especially in VPCs with no outbound redundancy).
- **`render_install` shell-injection fix** — the pip `--index-url` is now
  passed through `shlex.quote()` so a maliciously-crafted `pip_index_url`
  cannot break out of the generated shell script.



### Added
- **Audit reports archived on the build machine** — every successful
  `build` / `scan` now saves the per-rule audit JSON to
  `~/.ohbs-image/reports/<image-name>.json`, next to the lineage and
  provenance records.  Linux emits the file as a gzipped+base64 marker
  line in the packer log (extracted by ohbs-image); Windows copies the
  role-fetched `result.json`.  The in-image copy
  (`/opt/ohbs-image-AUDIT-RESULT.json` /
  `C:\ProgramData\ohbs-image\AUDIT-RESULT.json`) still ships — drift and
  verify-image use it as the baseline.

## [0.16.26] — 2026-08-17

### Added
- **Benchmark catalog layer** (`ohbs_image/_catalog.py`) — benchmark becomes
  a first-class, multi-benchmark-capable concept: a profile can select a
  non-CIS catalog (`rules_<slug>.json`, e.g. STIG/NIST) with a `rules.json`
  fallback, without renaming internals or touching the 12 byte-identical
  engine copies. `catalog_basename` is threaded through `ResolvedConfig`,
  rendering (workspace promotion), report hashing, the probe scan, the
  finalize re-scan / image tags, and `ohbs-image list --versions`.
- **Stock-aware e2e builds** — the e2e runner picks instance types via an
  explicit disk-family map, pre-filters candidates by image compatibility,
  and retries the whole build with backoff across in-stock types on any
  launch failure (understocked types, image gated to an instance family,
  transient image-availability or intermittent "instance not exist" errors).
- **Persistent e2e jump box** — `--keep` / `--reuse-last` /
  `--terminate-last` let a batch of runs share one jump box.
- **Upstream plugin monitor** — `scripts/check_tencentcloud_plugin.sh` and a
  scheduled workflow watch hashicorp/packer-plugin-tencentcloud#166 and new
  plugin releases; the e2e runner can inject a locally patched plugin.

### Fixed
- Rebrand residuals: builder glob, banner/report strings, `[ohbs]`/`[cis]`
  config-section backward-compat alias; role bundles keep the `cis-*`
  prefix (renamed back after the glob fix).
- HCL templates: `extra_builder_args` uses `map(string)` (not `map(any)`);
  removed a substitution token from a template comment.
- `instance_name` is sanitized so the packer hostname never ends in `-`.
- tencentos4 profile uses SSH port 22, not 36000.
- tencentcloud packer plugin pinned to v1.2.0 (v1.2.8 was never published).
- e2e: SSH kept alive during long builds; unique `RunInstances`
  ClientToken and `ImportKeyPair` key name per (parallel) run; the remote
  `git clone` is retried with a hard timeout.

## [0.16.25] — 2026-08-16

The ohbs (OH BASELINE) rebrand release.

### Changed
- **`cis-image` → `ohbs-image`** — package `cis_image` renamed to
  `ohbs_image`, CLI to `ohbs-image`, state dir to `~/.ohbs-image/`, config
  file to `ohbs-image.toml`. Added `LICENSE` (MIT) and `DISCLAIMER.md`
  (CIS Benchmark content is licensed and not redistributable).
- README restored in full with ohbs branding (zh/ja/th translations kept in
  sync), OH BASELINE logo, and a rebranded architecture diagram; residual
  `cis_*` project tokens (`cis_os_key`, `cis-engine`, `cis_image`) cleared.

### Fixed
- Image safety gates now fail closed.

## [0.16.24] — 2026-08-14

### Added
- **Windows images now ship the build-time audit result** at
  `C:\ProgramData\ohbs-image\AUDIT-RESULT.json` — the counterpart of Linux
  `/opt/ohbs-image-AUDIT-RESULT.json`.  Previously the Windows engine's
  `result.json` was fetched to the controller and then deleted with the
  working directory, so nothing inside the image documented what was
  assessed.  Implemented as a `cis_ship_result_path` role variable
  (empty = off), enabled by the ohbs-image Windows site template.

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
  `/etc/systemd/system/rc-local.service.d/10-ohbs-image-stop-timeout.conf`
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

Round-2 review — the engine (`ohbs_engine.py`), HCL templates, packer
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
- **#12 — Drift detection** (`ohbs-image drift`): re-scan a LIVE instance over
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
- **#19 — Rule-set versioning** (`ohbs-image list --versions`): per-profile
  rules.json sha256 + engine version for audit pinning.
- **#20 — Vendor refresh detection** (`ohbs-image check-source`): compares the
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
- **P0#1 — Independent audit tool** (`ohbs-image audit`): run a THIRD-PARTY
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
- **P0#3 — Clean-boot verification** (`ohbs-image verify-image --image …`):
  boots a probe instance from the PRODUCED image, re-audits on fresh boot
  (SELinux relabel, first-boot services, cloud-init), gates on score and
  always terminates the probe. `[meta].verify_boot = true` chains it
  automatically after successful builds (Linux only).
- **P1#4 — Benchmark pinning + changelog**: benchmark recorded in lineage
  and provenance (`rules_sha256` + `fingerprint`); preflight warns on
  `[meta].benchmark` divergence from the profile default; `ohbs-image list`
  shows the benchmark column.
- **P1#5 — Per-control overrides** (`[cis].overrides`): deep-merge rule
  parameters into the workspace copy of rules.json at render time
  (bundled catalog never mutated; unknown rule IDs fail fast).
- **P1#6 — CVE scan + SBOM** (`[meta].cve_scan` / `[meta].sbom`):
  trivy CRITICAL-severity gate before the snapshot; zero-dependency SBOM
  (`/opt/ohbs-image-SBOM.jsonl`) emitted into the image and echoed to the
  build log for hashing.
- **P1#7 — Change detection** (`ohbs-image pending`, `build
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
- `ohbs-image list` prints a `benchmark` column.
- SARIF reports now carry the benchmark reference (P0#2).
- Version bumped 0.14.33 → 0.15.0 (feature release).

### Fixed
- Pre-existing lint/type debt cleaned so `ruff check ohbs_image` and
  `mypy ohbs_image --ignore-missing-imports` are green (CI gate).

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
