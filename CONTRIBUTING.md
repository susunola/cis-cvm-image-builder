# Contributing to ciscvm

Bug reports and pull requests are welcome. This document covers the
development workflow, coding constraints, and how to add a new CIS profile.

## Development setup

```bash
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder
pip install -e ".[dev]"
```

This installs `ciscvm` in editable mode plus the dev toolchain (`pytest`,
`pytest-cov`, `mypy`, `ruff`, `tomli_w`, `pywinrm`).

## Before opening a PR

Run the same checks CI runs (`.github/workflows/ci.yml`), in this order:

```bash
ruff check ciscvm
mypy ciscvm --ignore-missing-imports
pytest -v --tb=short
```

- `ruff` and `mypy` only lint/type-check `ciscvm/` — `ciscvm/roles/` is the
  vendored cis-os engine and is excluded (see `[tool.ruff]` /
  `[tool.mypy]` in `pyproject.toml`).
- CI runs the matrix on Python 3.11–3.13; keep changes compatible with 3.11+
  (no 3.12-only syntax).
- Add a test for every bug fix and every new flag/command. Regressions in
  this project have repeatedly come from untested edges in the Tencent
  Cloud API responses (e.g. `CreatedTime: null` on public images,
  `InstanceState` returned as a plain string instead of a dict) — mock at
  the `ciscvm._tc3_api` boundary and assert both the happy path and the
  edge case that broke before.

## Running the real end-to-end test

`tests/test_ciscvm.py` mocks the `ciscvm._tc3_api` boundary — it's fast,
free, and catches API-response edge cases well (null fields, wrong
nesting, etc.), but it can never prove that `pip install -e .` actually
works on a clean box, that the real network path is reachable, or that we
haven't drifted from the real Tencent Cloud API contract. For that,
`scripts/real_e2e_test.py` boots a real, billed CVM instance, SSHes in,
clones the repo, and runs the same `ruff` / `mypy` / `pytest` sequence as
CI — then tears the instance and its temporary SSH key pair back down
automatically (success, failure, or Ctrl-C).

This is **not** a CI-required step — it's a manual/optional check to run
when you suspect an environment-specific issue, or before a larger release.
It does **not** run a real `ciscvm build`/`verify-image`/`cleanup-images`
against a profile; it only validates that the checkout itself installs and
tests cleanly on a real machine.

```bash
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
python3 scripts/real_e2e_test.py \
    --vpc-id vpc-xxxxxxxx --subnet-id subnet-xxxxxxxx \
    --security-group-id sg-xxxxxxxx
```

- Defaults to image `img-31d8ynuj` in `ap-guangzhou` — override with
  `--image-id` / `--region` / `--zone` / `--instance-type` as needed.
- The security group you pass must already allow inbound TCP/22 from this
  machine's public IP; the script does not modify security group rules.
- Requires `ciscvm` to already be installed in editable mode on the machine
  running the script (it imports `ciscvm._tc3_api` directly rather than
  re-implementing TC3-HMAC-SHA256 signing).
- Creates one real CVM instance for the duration of the run (roughly
  5-10 minutes) — this incurs real cloud cost, however small.
- Pass `--keep-on-failure` to leave a failed instance running for
  debugging; otherwise it's always destroyed, even on `Ctrl-C`.

## Hard constraints

- **Zero third-party runtime dependencies.** `ciscvm` itself only imports
  the Python 3.11+ standard library — `urllib.request`, `hashlib`, `hmac`,
  `tomllib`, etc. Do not add a `requirements.txt` entry or a new import from
  PyPI to `ciscvm/__init__.py`. Packer and Ansible remain external
  system-level tools, not Python dependencies. Dev-only tooling
  (`pytest`, `ruff`, `mypy`, `tomli_w`, `pywinrm`) belongs in
  `[project.optional-dependencies].dev`, never in the base install.
- **No long-lived credentials in code or config.** Secrets come from
  `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY` (and optionally
  `TENCENTCLOUD_SECURITY_TOKEN` for STS) via environment variables only.
  Never read them from `ciscvm.toml` or write them to disk.
- **Bundled roles ship inside the package.** Every profile's role directory
  lives under `ciscvm/roles/<role_dir>/` (next to `__init__.py`), not
  outside the package — otherwise a built wheel omits it and `ciscvm build`
  fails after a clean install. `tests/test_ciscvm.py::TestPackaging` guards
  this; don't remove or weaken it.
- **Fail open on read-only/advisory checks.** Anything that inspects cloud
  state before taking a destructive action (image cleanup, security-group
  ingress preflight checks, share-permission checks) must treat API errors,
  missing credentials, or ambiguous responses as "cannot verify" and take
  the safe path — never turn an API hiccup into a false failure or an
  unintended deletion.

## Adding or updating a CIS profile

There are 12 bundled profiles (8 Linux via `ansible-local` + SSH, 4 Windows
via controller-side Ansible + WinRM). Each lives at
`ciscvm/roles/cis_<profile>/` and needs, at minimum:

```
ciscvm/roles/cis_<profile>/
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

Then register the profile in `PROFILES` in `ciscvm/__init__.py` (family,
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
  `[cis].allow_disruptive` in `ciscvm.toml` — don't downgrade a
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
- The exact `ciscvm` command and relevant `ciscvm.toml` fields (redact
  secrets — there shouldn't be any in the file, but redact anything you're
  unsure about).
- Full output with `-v`/`--verbose`, or the contents of `--log-file` if you
  used one.
- The profile name and CIS level.

If the bug reproduces during `build`, check the
[Troubleshooting table](README.md#troubleshooting) first — several
TencentOS/RHEL boot and SELinux/firewalld interactions are already
documented there with the fix version.
