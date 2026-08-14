<p align="center">
  <a href="README.md">English</a> | <a href="README.zh-CN.md">简体中文</a> | <a href="README.ja.md">日本語</a> | <b>ภาษาไทย</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python&logoColor=white" alt="Python >= 3.11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/profiles-12-orange" alt="12 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-cvm-image-builder/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ciscvm — เครื่องมือสร้าง Golden Image ที่ผ่านการ Hardened ตามมาตรฐาน CIS

> สร้าง Golden Image ที่ผ่านการ Hardened ตามมาตรฐาน CIS บน Tencent Cloud
> ด้วย 5 คำสั่ง ไม่ต้องใช้ Galaxy, ไม่มี dependency ด้าน network ตอน build,
> ไม่ต้องแก้ไข template เอง — ทุกอย่างขับเคลื่อนด้วย `ciscvm.toml`

**ฟีเจอร์:** ปั่น CVM ชั่วคราวขึ้นมา, ใช้ [cis-os](https://github.com/susunola/cis-os)
engine ที่ให้มาด้วยทำการ CIS hardened, รัน gate ภายใน role, แล้วแคปเป็น custom image
ถ้าหลัง hardened แล้วยังมี finding ค้างอยู่ build จะ fail ก่อนที่ image จะถูกสร้าง

**กลุ่มเป้าหมาย:** DevOps และ security engineer ที่ต้องการ base image
ที่ผ่าน CIS hardened แบบ reproducible และ auditable สำหรับ CVM workloads —
ใช้ใน CI, Auto Scaling launch template, หรือ Terraform image reference

## สารบัญ

- [การติดตั้ง](#การติดตั้ง)
- [เริ่มต้นใช้งาน](#เริ่มต้นใช้งาน)
- [คำสั่ง](#คำสั่ง)
- [การตั้งค่า](#การตั้งค่า)
- [สถาปัตยกรรม](#สถาปัตยกรรม)
- [Profile ที่รองรับ](#profile-ที่รองรับ)
- [เชื่อมต่อ CI/CD](#เชื่อมต่อ-cicd)
- [การแก้ไขปัญหา](#การแก้ไขปัญหา)
- [Roadmap](#roadmap)
- [การมีส่วนร่วม](#การมีส่วนร่วม)
- [ลิขสิทธิ์](#ลิขสิทธิ์)
- [ข้อสงวนสิทธิ์เกี่ยวกับ CIS Benchmarks](#ข้อสงวนสิทธิ์เกี่ยวกับ-cis-benchmarks)

## การติดตั้ง

**ข้อกำหนดเบื้องต้น**

| รายการ | รายละเอียด |
|---|---|
| **Python** | >= 3.11 (stdlib ล้วน — ไม่ต้อง pip install อะไรเพิ่ม) |
| **Packer** | >= 1.12 |
| **ansible-core** | >= 2.15 (Windows build ต้องติดตั้งที่ controller) |
| **Tencent Cloud** | Sub-account ที่มีสิทธิ์ `cvm:RunInstances`, `cvm:CreateImage`, `cvm:DescribeImages`, `cvm:CopyImage`* |
| **เครือข่าย** | VPC + subnet + security group เฉพาะ (Linux: SSH/22, Windows: WinRM/5986) จำกัด source เฉพาะ egress IP ของเครื่อง build |
| **Source Image** | Public image ID ของ OS เป้าหมาย |

\* `cvm:CopyImage` ต้องใช้เฉพาะตอน copy ข้าม region

**ดาวน์โหลดเครื่องมือ**

```bash
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder

# แนะนำ: ติดตั้งจาก repository (ได้คำสั่ง `ciscvm`)
pip install .

ciscvm --version

# หรือรันโดยไม่ติดตั้ง (ที่ root ของ repo)
python3 -m ciscvm --version

# หรือติดตั้งเป็น package
pip install -e ".[dev]"
```

**ตั้งค่า credential** (ใช้ environment variable เท่านั้น — ไม่เก็บใน config file)

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx

# Windows build ต้องตั้งเพิ่ม:
export WINRM_PASSWORD=xxxx
```

## เริ่มต้นใช้งาน

```bash
# 1. สร้างไฟล์ตั้งค่า
ciscvm init

# 2. แก้ ciscvm.toml ใส่ค่า VPC, subnet, security group และ source image ID

# 3. ตรวจก่อน build (ตรวจ config, credential และข้อกำหนดเบื้องต้น)
ciscvm preflight

# 4. Dry-run (render template + packer validate)
ciscvm validate

# 5. Build image ที่ hardened แล้ว
ciscvm build

# ไม่บังคับ: ล้างไฟล์ที่ render ออก
ciscvm clean
```

**ตัวอย่างผลลัพธ์ (`build`)**

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
[packer]  ==> tencentcloud-cvm: Creating custom image...
[packer]  ==> tencentcloud-cvm: Image created: img-abc123def456
[packer]  ==> tencentcloud-cvm: Terminating build instance...

✔  Build complete — image-id: img-abc123def456
```

## คำสั่ง

| คำสั่ง | คำอธิบาย |
|---|---|
| `ciscvm init` | สร้าง `ciscvm.toml` ในไดเรกทอรีปัจจุบัน |
| `ciscvm preflight` | ตรวจ config, credential และข้อกำหนดเบื้องต้น |
| `ciscvm validate` | Render template และรัน `packer validate` |
| `ciscvm build` | Render + `packer build` (สร้าง image) |
| `ciscvm clean` | ลบไดเรกทอรี `.ciscvm-build/` |

| Flag | ค่าเริ่มต้น | คำอธิบาย |
|---|---|---|
| `--config <path>` | `./ciscvm.toml` | ไฟล์ตั้งค่า |
| `--workdir <dir>` | `./.ciscvm-build` | ไดเรกทอรีสำหรับ render ผลลัพธ์ |
| `--quiet` | — | ลด output ของเครื่องมือ (validate / build) |
| `-y` / `--yes` | — | ข้ามข้อความยืนยันก่อน build |

## การตั้งค่า

`ciscvm.toml` เป็น single source of truth — ไม่ต้องแก้ไข Packer template เอง

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
source_image_id     = "img-xxxxxxxx"       # แทนที่ด้วย image ID จริงของ OS
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # ใส่ [] เพื่อไม่ copy ข้าม region

[cis]
level = 1                                 # 1 หรือ 2

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Windows build ต้องตั้งเพิ่ม:
# winrm_password_env = "WINRM_PASSWORD"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### อ้างอิงฟิลด์ตั้งค่า

| Section | Field | Type | คำอธิบาย |
|---|---|---|---|
| `[build]` | `profile` | string | หนึ่งใน 12 profile ที่รองรับ |
| | `region` | string | Region ของ Tencent Cloud เช่น `ap-guangzhou` |
| | `zone` | string | Availability zone เช่น `ap-guangzhou-4` |
| | `instance_type` | string | สเปก CVM เช่น `S5.MEDIUM2` |
| | `source_image_id` | string | Public image ID ของ OS |
| | `vpc_id` / `subnet_id` | string | identifier ของ network |
| | `security_group_id` | string | ต้องขึ้นต้นด้วย `sg-` |
| | `associate_public_ip` | bool | กำหนด public IP ให้ instance build หรือไม่ |
| `[image]` | `name_prefix` | string | prefix ของชื่อ image ที่ออกมา |
| | `copy_regions` | []string | region ปลายทางที่จะ replicate (ว่าง = ข้าม) |
| `[cis]` | `level` | int | 1 (Level 1) หรือ 2 (Level 2) |
| `[cloud]` | `secret_id_env` | string | ชื่อ env var สำหรับ Tencent Cloud Secret ID |
| | `secret_key_env` | string | ชื่อ env var สำหรับ Tencent Cloud Secret Key |
| | `winrm_password_env` | string | ชื่อ env var สำหรับรหัสผ่าน Windows Administrator (เฉพาะ Windows) |
| `[meta]` | `os_tag` | string | ค่า tag ของ image ที่ออกมา |
| | `benchmark` | string | tag เวอร์ชันของ CIS benchmark |
| | `ssh_port` | int | พอร์ต SSH (ค่าเริ่มต้น 22; TencentOS: 36000) |
| | `ssh_timeout` | string | เวลาหมดอายุ SSH ของ Packer (ค่าเริ่มต้น "10m") |
| | `ssh_debug_password` | string | ตั้งรหัสผ่าน root สำหรับดีบัก VNC (ค่าเริ่มต้น: ไม่ตั้ง) |

## สถาปัตยกรรม

### Linux Build Pipeline (SSH × ansible-local)

```
เครื่อง Build                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ CVM ชั่วคราว       │
│             │                           │   (SSH port 22)  │
│ ciscvm.toml │                           │ 1. ติดตั้ง ansible│
│             │                           │    (dnf/apt/zypp)│
│ roles/      │── อัปโหลดไป CVM ─────────▶│ 2. ใช้ CIS        │
│   cis_*     │      (role ที่ให้มาด้วย)      │    (cis_engine.py)│
│             │                           │ 3. Gate:         │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer รัน 3 เฟสบน CVM ชั่วคราวผ่าน `ansible-local`:

1. **Install** — ใช้ package manager ของ OS + pip ติดตั้ง ansible-core
2. **Harden** — รัน cis-os engine ที่ให้มาด้วย (`cis_engine.py` + `rules.json`)
   ตัวแปร: `cis_mode: apply`, `cis_profile: L1/L2`, `cis_platform: server`
3. **Gate** — ภายใน role: `cis_fail_on_findings: true` + `cis_min_score: 0`
   ถ้าหลังจาก remediate แล้วยังมี finding เหลืออยู่ `ansible-playbook` จะ exit
   แบบ non-zero และ Packer จะ fail build

### Windows Build Pipeline (WinRM × controller-side ansible)

```
เครื่อง Build                              Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ CVM ชั่วคราว       │
│             │                           │  (WinRM 5986)    │
│             │                           │                  │
│ roles/      │── ansible provisioner ───▶│ ใช้ CIS            │
│   cis_win*  │   (ฝั่ง controller,       │ (cis_engine.ps1)  │
│             │    ต่อผ่าน winrm)         │                  │
│             │                           │ Gate ภายใน role  │
│             │◀── image-id ──────────────│ CreateImage      │
└─────────────┘                           └──────────────────┘
```

Windows build ใช้ Packer `ansible` provisioner (ฝั่ง controller) ต่อผ่าน WinRM
Role ที่ให้มาด้วยมี `cis_engine.ps1` (PowerShell) อยู่ในนั้น ไม่ต้องติดตั้งซอฟต์แวร์อะไร
ใน instance เลย — ที่ controller ต้องมี `ansible-core` ติดตั้งอยู่

### การตัดสินใจด้านดีไซน์

**role ที่ให้มาด้วย, ไม่ใช้ Galaxy**
cis-os engine role ทั้ง 12 ตัวถูกรวมไว้ในแพ็กเกจที่ `ciscvm/roles/` ตอน build
เครื่องมือจะคัดลอก role ที่เลือกไปยัง workspace ไม่มี dependency ด้าน network
ไม่มี version drift

**`ansible-local` (Linux) — self-contained ภายใน instance**
Packer controller ไม่จำเป็นต้อง SSH เข้าไปใน cloud VPC เลย playbook และ role
รันอยู่ใน build instance

**`ansible` (Windows) — controller-driven ผ่าน WinRM**
Windows image ใช้ Packer `ansible` provisioner จาก controller ต่อผ่าน WinRM
ที่ controller ต้องติดตั้ง `ansible-core` ไว้ก่อน

**Gate ตอน build, ไม่ตรวจภายนอก**
Gate อยู่ใน Ansible role (`cis_fail_on_findings`) image ที่ hardened แล้วจะ
"ผ่านแล้วสร้าง" หรือ "ไม่ผ่านก็ไม่สร้าง" เท่านั้น

**Credential และ governance**
AK/SK ผ่าน environment variable เท่านั้น (HCL `sensitive = true`) instance
ชั่วคราวถูก tag ไว้และ recycle อัตโนมัติ tag ของ image จะบันทึกระดับ CIS, OS
และ benchmark

## Profile ที่รองรับ

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

### Windows (WinRM × controller-side ansible)

| Profile | OS | User | Role |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/cis_win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/cis_win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/cis_win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/cis_win2025/` |

การสลับ profile ทำได้โดยแก้ `[build].profile` และ `source_image_id` ใน `ciscvm.toml`

## ตารางผลการทดสอบ

อิมเมจที่ผ่านการ harden ตาม CIS แล้ว ครบทุกชุด OS × level
build ทั้งหมดทำบน Tencent Cloud รีเจี้ยน Guangzhou ด้วย `cis_allow_disruptive: false`
และอิมเมจด้านล่างทุกตัวได้รับการตรวจสอบซ้ำในคอนโซลว่าเป็น `NORMAL` เมื่อ 2026-08-14

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
| **Windows Server 2022** | EN `img-b9iwlu30` (99.7%) · CN `img-5fwbryp2` (99.7%) | — |
| **Windows Server 2025** | EN `img-4obl2vj4` (99.7%) · CN `img-pqx9opsw` (99.7%) | EN `img-cvoolqiu` (99.7%) · CN `img-2e5x3xhg` (99.7%) |

> คะแนนเป็นผล re-audit หลังรีบูต (กฎที่ถูกประเมินทั้งหมด เกณฑ์ผ่าน ≥ 85)
> กฎกลุ่ม kmod ถูก apply ผ่าน modprobe install-override แบบถาวร
> ไม่จำเป็นต้อง exclude กฎใด ๆ ตอน build
> อิมเมจ Windows เป็นบิลด์แบบ member server จากอิมเมจสาธารณะ
> ของ Tencent Cloud (EN/CN) สร้างและ re-audit เมื่อ 2026-08-14; WinRM ถูก re-lock
> ก่อนสร้าง snapshot (ปิด Basic/HTTP ไม่เข้ารหัส และสุ่มรหัสผ่าน Administrator ใหม่)
> fail เดียวที่เหลือในทุกบิลด์ Windows คือ "Deny access to this computer from the
> network → รวม S-1-5-114" (2.2.2x) ซึ่งถูกข้ามโดยเจตนาเพราะเป็น disruptive:
> หาก apply จะตัด session WinRM ที่ใช้ build อยู่ สามารถเปิดหลังบูตด้วย
> `cis_allow_disruptive: true`

## เชื่อมต่อ CI/CD

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows build:
# export WINRM_PASSWORD=xxx

ciscvm build
```

ให้ CVM / Auto Scaling / Terraform ฝั่ง downstream ชี้ไปที่ `image_id` ที่ออกมา
ล็อกเครื่อง build ไว้กับ VPC และ SG เฉพาะ

## การแก้ไขปัญหา

| อาการ | สาเหตุที่เป็นไปได้ | วิธีแก้ไข |
|---|---|---|
| `preflight` แจ้ง credential error | ยังไม่ได้ export `TENCENTCLOUD_SECRET_ID` / `_KEY` | `export TENCENTCLOUD_SECRET_ID=...` ใน shell |
| `validate` แจ้ง plugin download error | `packer init` ล้มเหลว (เช่นเครื่อง build offline) | รัน `ciscvm validate` อีกครั้งเมื่อมีอินเทอร์เน็ต — Packer cache plugin หลังจากดาวน์โหลดครั้งแรก |
| Packer timeout ตอนรอ SSH | security group ไม่อนุญาต port 22 จากเครื่อง build | เพิ่ม inbound rule: TCP/22 จาก egress IP ของเครื่อง build |
| `ansible-playbook` fail แจ้ง "python3 not found" | OS ของ build instance ไม่มี Python ติดตั้ง | ตรวจสอบว่า source image มี Python >= 3.6 |
| Windows build fail ด้วย WinRM connection error | ยังไม่ได้ตั้ง `WINRM_PASSWORD` หรือ network ไม่ผ่าน | export password + ตรวจสอบว่า TCP/5986 เปิดจาก build IP |
| Build สำเร็จแต่ยังมี CIS finding | บาง rules ของ OS นี้ยังไม่ครอบคลุม | ลองรันด้วย `level: 1` (Level 1 ครอบคลุม finding ส่วนใหญ่) |

## Roadmap

- [ ] CI pipeline (GitHub Actions) สำหรับ automated image build
- [ ] PyPI package (`pip install ciscvm`)
- [ ] `ciscvm list` — แสดงรายการ profile พร้อม metadata
- [ ] `ciscvm report` — ดึงและแสดง audit report จาก build ที่เสร็จแล้ว
- [ ] Custom rule selection (`rules_include` / `rules_exclude` ใน `ciscvm.toml`)

## การมีส่วนร่วม

ยินดีรับ bug report และ pull request กรุณารัน test suite ก่อนส่ง:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## ลิขสิทธิ์

MIT — ดู [LICENSE](LICENSE)

## ข้อสงวนสิทธิ์เกี่ยวกับ CIS Benchmarks

เครื่องมือนี้ใช้ hardening rules ที่อ้างอิงจากคำแนะนำของ CIS Benchmark
CIS Benchmarks พัฒนาและดูแลโดย [Center for Internet Security](https://www.cisecurity.org/)
(CIS) cis-os engine roles ที่ให้มาด้วยใน repository นี้พัฒนาต่อยอดมาจากโปรเจกต์
[susunola/cis-os](https://github.com/susunola/cis-os) และให้บริการภายใต้ลิขสิทธิ์ของแต่ละ role

**สำคัญ:** การรัน CIS hardening ในโหมด `apply` จะแก้ไขการตั้งค่าระบบและอาจส่งผล
ต่อความเข้ากันได้ของแอปพลิเคชัน ควรทดสอบ hardened image ใน staging environment
ก่อนใช้งาน production เสมอ องค์กร CIS และผู้พัฒนาเครื่องมือนี้ไม่รับประกันว่า
rules ที่ใช้จะทำให้เกิด compliance ที่สมบูรณ์ — การตรวจสอบอย่างเป็นทางการ
ต้องใช้ CIS-CAT หรือเครื่องมือเทียบเท่าในการประเมินอิสระ
