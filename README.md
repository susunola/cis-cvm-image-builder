> ⚠️ **Not affiliated with, endorsed by, or sponsored by the Center for Internet
> Security (CIS).** See [DISCLAIMER.md](./DISCLAIMER.md). `ohbs-image`
> implements hardening *aligned with* the CIS Benchmarks™; it references CIS as
> a standard only.

# oh baseline image

> **Repository / CLI / package:** `ohbs-image`
> Full name: **oh baseline image** — part of the **oh baseline** (ohbs) family,
> **Open Source Hardened Baseline**.

A **config-driven golden-image builder for Tencent Cloud CVM**. It launches a
short-lived CVM, applies hardening from the bundled `ohbs-os` engine, re-audits
against a configurable score gate, and captures the result as a custom image.

- Fully repeatable / auditable builds; **zero pip dependencies**
- 12 OS profiles (Linux + Windows)
- Build-time gate with configurable score threshold
- Bundled Ansible roles (no Galaxy / network drift)
- Build → test → distribute governance: smoke test, lineage, WeCom
  notifications, SLSA-style signed provenance, OIDC / STS credentials

## Install (from source)

```bash
git clone https://github.com/susunola/ohbs-image.git
cd ohbs-image
pip install .
ohbs-image --version
```

Prerequisites: Python 3.11+, Packer 1.12+, ansible-core 2.15+
(controller; required for Windows), `ansible.windows` collection (Windows only),
and a Tencent Cloud sub-account with CVM permissions. Credentials are set via
environment variables only:

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
export WINRM_PASSWORD=xxxx   # Windows builds only
```

## Commands

| Command | Purpose |
|---------|---------|
| `ohbs-image init` | generate `ohbs-image.toml` |
| `ohbs-image preflight` | validate config, credentials, prerequisites |
| `ohbs-image validate` | render templates + packer validate |
| `ohbs-image build` | render + packer build → custom image |
| `ohbs-image scan` | audit-only build (no remediation) + score gate |
| `ohbs-image test --idempotency` | re-run apply, fail if 2nd pass changes |
| `ohbs-image list` | enumerate available profiles with metadata |
| `ohbs-image images` | list recorded builds (lineage) |
| `ohbs-image pending` | change detection: is rebuild required? |
| `ohbs-image cleanup-images` | retire old images by lineage age |
| `ohbs-image verify` | verify SLSA provenance signature |
| `ohbs-image verify-image` | clean-boot verification of produced image |
| `ohbs-image drift` | config drift on running instance vs baseline |
| `ohbs-image check-source` | vendor image refresh detection |
| `ohbs-image audit` | independent audit (oscap / inspec / kitty) |
| `ohbs-image clean` | remove `.ohbs-image-build/` |

Global flags: `--config`, `--workdir`, `--quiet`, `--debug`, `-y/--yes`,
`--log-file`, `--skip-if-unchanged`, `--min-score`, `--sarif`, `--xccdf`,
`--host`, `--datastream`, `--baseline`, `--parse`, `--older-than`,
`--min-score`, `--keep-latest`, `--unused-since`, `--apply`.

## Usage

```bash
# quick start
ohbs-image init
# edit ohbs-image.toml
ohbs-image preflight
ohbs-image validate
ohbs-image build
ohbs-image clean

# scan with reports
ohbs-image scan --min-score 85 --sarif out.sarif --xccdf out.xml

# cleanup old images
ohbs-image cleanup-images --older-than 30 --apply

# verify provenance
ohbs-image verify --image img-ekny61ig

# drift detection
ohbs-image drift --host 1.2.3.4 --image img-ekny61ig --min-score 85
```

Build output example:

```
ohbs-image 0.14.1 — tencentos3 (L1) → ap-guangzhou-4
[packer] tencentcloud-cvm: Launching instance (S5.MEDIUM2)...
Score: 97.2% ≥ 85%  ✓ PASS
✔ Build complete — image-id: img-abc123def456
```

## License

MIT — see [LICENSE](./LICENSE).
