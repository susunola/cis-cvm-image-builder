# Changelog

All notable changes to **ciscvm** are documented here, grouped by release.
The format follows the ansible-lockdown convention: each release pins the
CIS benchmark edition it targets and lists rule-catalog changes so audits
can be traced across rebuilds.

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
- SLES 15 / 16 — CIS SUSE Linux Enterprise Server Benchmark v1.0.0
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
