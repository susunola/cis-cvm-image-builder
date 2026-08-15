# Contributing to cis-image

Bug reports and pull requests are welcome. This document covers the
development workflow, coding constraints, and how to add a new CIS profile.

## Development setup

```bash
git clone https://github.com/susunola/cis-image.git
cd cis-image
pip install -e ".[dev]"
```

This installs `cis-image` in editable mode plus the dev toolchain (`pytest`,
`pytest-cov`, `mypy`, `ruff`, `tomli_w`, `pywinrm`).

## Before opening a PR

Run the same checks CI runs (`.github/workflows/ci.yml`), in this order:

```bash
ruff check cis_image
mypy cis_image --ignore-missing-imports
pytest -v --tb=short
```

- `ruff` and `mypy` only lint/type-check `cis_image/` — `cis_image/roles/` is
  the vendored cis-os engine and is excluded (see `[tool.ruff]` /
  `[tool.mypy]` in `pyproject.toml`).
- CI runs the matrix on Python 3.11–3.13; keep changes compatible with 3.11+
  (no 3.12-only syntax).
- Add a test for every bug fix and every new flag/command. Regressions in
  this project have repeatedly come from untested edges in the Tencent
  Cloud API responses (e.g. `CreatedTime: null` on public images,
  `InstanceState` returned as a plain string instead of a dict) — mock at
  the `cis_image._tc3_api` boundary and assert both the happy path and the
  edge case that broke before.

## Running the real end-to-end test

`tests/test_cis_image.py` mocks the `cis_image._tc3_api` boundary — it's
fast, free, and catches API-response edge cases well (null fields, wrong
nesting, etc.), but it can never prove that `pip install -e .` actually
works on a clean box, that the real network path is reachable, or that we
haven't drifted from the real Tencent Cloud API contract. For that,
`scripts/real_e2e_test.py` boots a real, billed CVM instance, SSHes in,
clones the repo, and runs the same `ruff` / `mypy` / `pytest` sequence as
CI — then tears the instance and its temporary SSH key pair back down
automatically (success, failure, or Ctrl-C).

This is **not** a CI-required step — it's a manual/optional check to run
when you suspect an environment-specific issue, or before a larger release.
By default (no `--target-mode`, or `--target-mode toolchain`) it only
validates that the checkout itself installs and tests cleanly on a real
machine — it does **not** run a real `cis-image build`/`verify-image`/
`cleanup-images` against a profile.

To additionally trigger a REAL `cis-image build` against one or more
profile+level combinations (e.g. "RHEL 8, CIS Level 1"), pass
`--target-mode single|all-linux|all` — see "Triggering a real profile
build" below.

```bash
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
python3 scripts/real_e2e_test.py \
    --region ap-guangzhou --zone ap-guangzhou-3 \
    --vpc-id vpc-xxxxxxxx --subnet-id subnet-xxxxxxxx \
    --security-group-id sg-xxxxxxxx
```

To avoid retyping credentials/IDs every run, copy `scripts/e2e.env.example`
to `scripts/e2e.env` (gitignored — never commit it), fill in real values,
then:

```bash
source scripts/e2e.env
python3 scripts/real_e2e_test.py \
    --region "$E2E_REGION" --zone "$E2E_ZONE" \
    --vpc-id "$E2E_VPC_ID" --subnet-id "$E2E_SUBNET_ID" \
    --security-group-id "$E2E_SG_ID" --yes
```

- `--region` and `--zone` are **required**, with no default — they must
  match the region/zone your `--vpc-id`/`--subnet-id`/`--security-group-id`/
  `--image-id` actually live in. There used to be an `ap-guangzhou` default
  here; it silently broke runs against resources in other regions with a
  confusing "security group id is `None`" error from the CVM API, so it was
  removed in favor of an explicit, required flag.
- Defaults to image `img-31d8ynuj` (an AlmaLinux 10.2 build) — override with
  `--image-id` / `--instance-type` as needed. Confirm the image is actually
  available in your target region first (`cis-image images --region ...`
  or `DescribeImages`) since custom images don't automatically replicate
  across regions.
- The security group you pass must already allow inbound TCP/22 from this
  machine's public IP; the script does not modify security group rules.
- Requires `cis-image` to already be installed in editable mode on the
  machine running the script (it imports `cis_image._tc3_api` directly
  rather than re-implementing TC3-HMAC-SHA256 signing).
- Creates one real CVM instance for the duration of the run (roughly
  5-10 minutes) — this incurs real cloud cost, however small.
- Pass `--keep-on-failure` to leave a failed instance running for
  debugging; otherwise it's always destroyed, even on `Ctrl-C`. After
  teardown the script verifies the jump box is actually gone
  (`DescribeInstances`) and warns if it may still be incurring cost.
- Tune the boot/SSH wait with `--timeout` / `--ssh-timeout` (default 900s /
  360s). A sustained network outage during the IP poll aborts early rather
  than waiting out the full timeout.
- Tencent Cloud API calls (`ImportKeyPair`, `RunInstances`,
  `TerminateInstances`, `DeleteKeyPairs`, `DeleteImages`) are retried with
  exponential backoff on transient failures (throttling codes, network
  blips); deterministic errors (auth / bad params) surface immediately.
- Installs `python3.12` on the remote box (AlmaLinux 10's default Python —
  RHEL 10 dropped the `python3.11` package name entirely). If you change the
  default `--image-id` to a different OS family, update the `python3.12`
  references in `REMOTE_SCRIPT` accordingly.
- Every remote step (Python/git check, clone, venv + install, `ruff`,
  `mypy`, `pytest`) runs independently and records its own exit code — an
  early failure (e.g. a missing package) does **not** abort the remaining
  steps, so you always get a complete picture instead of just "the first
  thing that broke".
- After the run, in addition to the plain-text `logs/e2e-<timestamp>.log`,
  the script writes a self-contained `logs/e2e-<timestamp>.html` report
  (no external assets, safe to open offline) showing the PASS/FAIL status
  of every step plus the full `pytest` results (including per-test
  failure/error messages parsed from the JUnit XML). This is the report to
  check first — "did it run" and "did everything pass" are two different
  questions, and the HTML report answers both.

### Triggering a real profile build

`--target-mode` (default `toolchain`) opts into triggering a REAL
`cis-image build` for one or more profile+level combinations, each on its
own temporary build CVM (with a public IP) reached from the jump box over
the public internet:

- `single` — one combination, e.g.
  `--target-mode single --profile rhel8 --level 1`.
- `all-linux` — every Linux profile x the configured CIS Levels (default
  Level 1 + Level 2, up to 16 real builds).
- `all` — every Linux **and** Windows profile x the configured levels (up
  to 24 real builds).

In matrix mode (`single`/`all-linux`/`all`) the jump box skips
`ruff`/`mypy`/`pytest` (that's the `toolchain` mode's job) and instead
installs `packer` + `ansible-core` (+ `ansible.windows` if any Windows
profile is in scope), then drives up to `--max-parallel-builds` (default 4)
concurrent `cis-image build` subprocesses. The HTML report gets an
additional "Profile Build Matrix" section (profile, level, status, score,
image ID(s)) alongside the existing step table.

Two batch-mode knobs can be set either on the CLI or in `scripts/e2e.env`:

- **Which levels to build** — `--levels {1,2,both}` or `E2E_LEVELS`
  (default `both`). For example `--target-mode all-linux --levels 1` runs
  only the Level-1 combination of every Linux profile (8 builds instead of
  16). This only applies to `all-linux`/`all`; `single` mode always uses
  `--level`.
- **How many concurrent builds** — `--max-parallel-builds` or
  `E2E_MAX_PARALLEL_BUILDS` (default `4`).

Additional requirements for matrix mode:

- Set `E2E_TARGET_IMAGE_<PROFILE>` in `scripts/e2e.env` for every profile
  you want built (see `scripts/e2e.env.example`) — this is the **target**
  image for that profile's build CVM, a **different** image than
  `E2E_IMAGE_ID` (which is only the AlmaLinux jump box). In `single` mode a
  missing image for the chosen `--profile` is a hard error; in
  `all-linux`/`all` mode an unconfigured profile is skipped and reported as
  "skipped: no image configured" — the rest of the batch still runs.
- All profile **target** build CVMs share ONE uniform placement
  (`E2E_TARGET_REGION` / `E2E_TARGET_ZONE` / `E2E_TARGET_VPC_ID` /
  `E2E_TARGET_SUBNET_ID` / `E2E_TARGET_SG_ID`), not a per-profile one — only
  the image is per-profile. Any of these left unset falls back to the jump
  box's `--region`/`--zone`/`--vpc-id`/`--subnet-id`/`--security-group-id`,
  so the target machines use the jump box's placement unless overridden
  (e.g. when the target images only exist in another region).
- The security group used for a profile must allow inbound TCP/22 (Linux
  builds) and TCP/5986 (Windows builds) from the jump box's **public** IP —
  each build CVM gets a public IP and is reached from the jump box over the
  public internet. The jump box and targets may live in different
  regions/VPCs (e.g. jump box in ap-hongkong, targets in ap-guangzhou).
  This script does not modify security group rules, same as the existing
  public-IP TCP/22 requirement for the jump box itself.
- `WINRM_PASSWORD` must be set if any Windows profile is in scope
  (`single --profile winXXXX`, or `--target-mode all`).
- Every combination is a REAL, billed CVM (auto-destroyed by packer at the
  end of its own build). The image(s) produced are ALWAYS deleted by this
  script right after the batch finishes — it never leaves a billed golden
  image behind.

## Hard constraints

- **Zero third-party runtime dependencies.** `cis-image` itself only imports
  the Python 3.11+ standard library — `urllib.request`, `hashlib`, `hmac`,
  `tomllib`, etc. Do not add a `requirements.txt` entry or a new import from
  PyPI to `cis_image/__init__.py`. Packer and Ansible remain external
  system-level tools, not Python dependencies. Dev-only tooling
  (`pytest`, `ruff`, `mypy`, `tomli_w`, `pywinrm`) belongs in
  `[project.optional-dependencies].dev`, never in the base install.
- **No long-lived credentials in code or config.** Secrets come from
  `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` (and optionally
  `TENCENTCLOUD_SECURITY_TOKEN` for STS) via environment variables only.
  Never read them from `cis-image.toml` or write them to disk.
- **Bundled roles ship inside the package.** Every profile's role directory
  lives under `cis_image/roles/<role_dir>/` (next to `__init__.py`), not
  outside the package — otherwise a built wheel omits it and `cis-image
  build` fails after a clean install. `tests/test_cis_image.py::TestPackaging`
  guards this; don't remove or weaken it.
- **Fail open on read-only/advisory checks.** Anything that inspects cloud
  state before taking a destructive action (image cleanup, security-group
  ingress preflight checks, share-permission checks) must treat API errors,
  missing credentials, or ambiguous responses as "cannot verify" and take
  the safe path — never turn an API hiccup into a false failure or an
  unintended deletion.

## Adding or updating a CIS profile

There are 12 bundled profiles (8 Linux via `ansible-local` + SSH, 4 Windows
via controller-side Ansible + WinRM). Each lives at
`cis_image/roles/cis_<profile>/` and needs, at minimum:

```
cis_image/roles/cis_<profile>/
├── files/
│   ├── cis_engine.py       # Linux: the rule check/fix engine (or cis_engine.ps1 for Windows)
│   ├── rules.json          # rule catalog: id, title, section, levels, family, params, risk, page
│   ├── guidance.json       # optional: human-readable remediation notes per rule
│   └── sections.json       # chapter/subsection titles for report headers
├── tasks/                  # main.yml, preflight.yml, run.yml, gate.yml, output.yml
├── defaults/
├── meta/
└── templates/
```

Then register the profile in `PROFILES` in `cis_image/__init__.py` (family,
`role_dir`, `os_tag`, `benchmark`, and for Windows `winrm_username`; for
Linux the SSH username/port defaults come from the `_ubuntu_profile` /
`_rhel_profile` / `_tlinux_profile` helpers).

Rule entries in `rules.json` follow this shape:

```json
{
  "id": "1.1.1.1",
  "title": "Ensure cramfs kernel module is not available",
  "section": "1.1.1",
  "levels": [1],
  "platforms": ["Server", "Workstation"],
  "assessment": "Automated",
  "family": "kmod",
  "params": {"module": "cramfs", "mtype": "fs"},
  "risk": "safe",
  "page": 24
}
```

- `family` maps to a `c_<family>` (check) / `f_<family>` (fix) handler pair
  in `cis_engine.py`, registered via the `@check(...)` / `@fix(...)`
  decorators. Reuse an existing family where the check/fix logic already
  fits (`kmod`, `sysctl`, `mount_opt`, `file_perm`, `svc_disabled`,
  `svc_enabled`, `pkg_absent`, `pkg_present`, `sshd_param`, ...) — only add
  a new family when none of the ~20 existing ones apply.
  - `family: "manual"` marks a rule as assessment-only / not auto-remediable
    (e.g. it needs a site-specific value like a remote log server URL).
    Any rule with `risk: "none"` that touches partitioning/mounts **must**
    be `family: "manual"` — it is never safe to auto-apply a partition
    layout change on a live disk (see
    `test_none_risk_partition_rules_are_manual`).
- `risk` is `"safe"` (apply freely) or a stronger label gated by
  `[cis].allow_disruptive` in `cis-image.toml` — don't downgrade a
  legitimately disruptive rule to `"safe"` to make a benchmark score look
  better.
- Keep the benchmark edition and page numbers accurate — they're surfaced
  in the report, SARIF/XCCDF output, and image tags, and per-control
  overrides (`[cis].overrides."<id>"`) are matched by `id`.

After adding/changing rules, run the full suite — several tests iterate
every bundled role and assert catalog-wide invariants (rule ID format,
family/handler pairing, `manual` on `risk: none` partition rules, page
numbers present, etc.), so a malformed entry in any profile fails fast.

## Reporting bugs

Include:
- The exact `cis-image` command and relevant `cis-image.toml` fields
  (redact secrets — there shouldn't be any in the file, but redact anything
  you're unsure about).
- Full output with `-v`/`--verbose`, or the contents of `--log-file` if you
  used one.
- The profile name and CIS level.

If the bug reproduces during `build`, check the
[Troubleshooting table](README.md#troubleshooting) first — several
TencentOS/RHEL boot and SELinux/firewalld interactions are already
documented there with the fix version.
