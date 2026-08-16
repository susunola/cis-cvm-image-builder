# Test Matrix

Validated CIS-hardened images across the supported OS × level grid.
All builds ran on Tencent Cloud Guangzhou region with `cis_allow_disruptive: false`;
every image below was re-verified in the console as `NORMAL` on 2026-08-14.

Build instance types: Linux profiles used `S5.MEDIUM2` (2 vCPU / 4 GB);
Windows profiles used `S5.LARGE4` (4 vCPU / 8 GB).

| OS | Instance type | Source image | L1 | L2 |
|---|---|---|---|---|
| **RHEL 8** | `S5.MEDIUM2` | `img-kp3mv36j` | `img-8zfwvl9g` (93.5%) | `img-4d6jxfe2` (93.3%) |
| **RHEL 9** | `S5.MEDIUM2` | `img-02j8jprl` | `img-25hwnzl8` (95.3%) | `img-8mjw35cy` (95.2%) |
| **RHEL 10** | `S5.MEDIUM2` | `img-29guuzjp` | `img-1idroc9y` (96.3%) | `img-lzha2io2` (95.3%) |
| **Ubuntu 20.04** | `S5.MEDIUM2` | `img-22trbn9x` | `img-9xyvohdy` (92.0%) | `img-gut6728y` (90.0%) |
| **Ubuntu 22.04** | `S5.MEDIUM2` | `img-487zeit5` | `img-jd3gct8o` (91.5%) | `img-rx4n84w4` (92.1%) |
| **Ubuntu 24.04** | `S5.MEDIUM2` | `img-mmytdhbn` | `img-7ncjcq10` (95.9%) | `img-j9m1fn0u` (96.5%) |
| **TencentOS 3** | `S5.MEDIUM2` | `img-eb30mz89` | `img-ip62dj1k` (95.7%) | `img-joo4xcis` (94.2%) |
| **TencentOS 4** | `S5.MEDIUM2` | `img-9qrfy1xt` | `img-ipw57gea` (96.9%) | `img-fs0hh75w` (96.7%) |
| **Windows Server 2016** | `S5.LARGE4` | EN `img-1eckhm4t` · CN `img-9id7emv7` | EN `img-lw9onsqo` (99.7%) · CN `img-bm2kusug` (99.7%) | EN `img-gnedt90i` (99.7%) · CN `img-4t7nd0ne` (99.7%) |
| **Windows Server 2019** | `S5.LARGE4` | EN `img-bhvhr6pr` · CN `img-mmy6qctz` | EN `img-9dfarngo` (99.6%) · CN `img-2h1qdi5c` (99.6%) | EN `img-5gfx1ybo` (99.7%) · CN `img-8u7us60c` (99.7%) |
| **Windows Server 2022** | `S5.LARGE4` | EN `img-9tzezztj` · CN `img-m07ny34j` | EN `img-b9iwlu30` (99.7%) · CN `img-5fwbryp2` (99.7%) | EN `img-8r09mpwq` (99.7%) · CN `img-q5zih0bo` (99.7%) |
| **Windows Server 2025** | `S5.LARGE4` | EN `img-eb87lxi3` · CN `img-6jb5wacd` | EN `img-4obl2vj4` (99.7%) · CN `img-pqx9opsw` (99.7%) | EN `img-cvoolqiu` (99.7%) · CN `img-2e5x3xhg` (99.7%) |

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
