<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b> | <a href="README.ja.md">日本語</a> | <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python&logoColor=white" alt="Python >= 3.11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/profiles-12-orange" alt="12 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/ohbs-image/actions/workflows/ci.yml"><img src="https://github.com/susunola/ohbs-image/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ohbs-image — CIS 加固黄金镜像构建

> 属于 cis-* 家族:ohbs-image(镜像源头)、ohbs-host(主机加固)、ohbs-cloud(云上合规)

> 五条命令在腾讯云上构建 CIS 加固黄金镜像。无需 Galaxy，构建时零网络依赖，
> 不用手写模板 — 一切由 `ohbs-image.toml` 驱动。

**做什么：** 起一台临时 CVM，应用捆绑的 [ohbs-os](https://github.com/susunola/ohbs-os)
引擎执行 CIS 加固，跑内建门禁，产出自定义镜像。加固后仍有残留发现项则构建失败，镜像不入库。

**给谁用：** 需要可重复、可审计的 CIS 加固基础镜像的 DevOps 和安全工程师 —
用于私有 CI、弹性伸缩启动模板或 Terraform 镜像引用。

## 目录

- [安装](#安装)
- [快速开始](#快速开始)
- [命令](#命令)
- [配置文件](#配置文件)
- [架构](#架构)
- [画像](#画像)
- [对接 CI/CD](#对接-cicd)
- [故障排查](#故障排查)
- [路线图](#路线图)
- [参与贡献](#参与贡献)
- [许可证](#许可证)
- [CIS Benchmarks 声明](#cis-benchmarks-声明)

## 安装

**前置条件**

| 条件 | 说明 |
|---|---|
| **Python** | >= 3.11，仅用标准库，零 pip 依赖 |
| **Packer** | >= 1.12 |
| **ansible-core** | >= 2.15（Windows 构建需在控制器本地安装） |
| **腾讯云** | 子账号，最少权限：`cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* |
| **网络** | 专用构建 VPC + 子网 + 安全组（Linux: SSH/22，Windows: WinRM/5986），来源限定构建机出口 IP |
| **源镜像** | 目标 OS 的公共镜像 ID |

\* 跨地域复制才需要 `cvm:CopyImage`。

**获取工具**

```bash
git clone https://github.com/susunola/ohbs-image.git
cd ohbs-image

# 推荐：从仓库安装（提供 `ohbs-image` 命令）
pip install .

ohbs-image --version

# 或免安装直接运行（在仓库根目录）
python3 -m ohbs-image --version
```

**设置凭据**（仅通过环境变量，不写入配置文件）

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx

# Windows 构建额外需要：
export WINRM_PASSWORD=xxxx
```

## 快速开始

```bash
# 1. 生成配置文件
ohbs-image init

# 2. 编辑 ohbs-image.toml，填入 VPC、子网、安全组和源镜像 ID

# 3. 构建前自检（校验配置、凭据和前置条件）
ohbs-image preflight

# 4. 干跑校验（渲染模板 + packer validate）
ohbs-image validate

# 5. 构建加固镜像
ohbs-image build

# 可选：清理渲染产物
ohbs-image clean
```

**构建输出示例（`build`）**

```
════════════════════════════════════════════════════════
  ohbs-image 0.5.0 — tencentos3 (L1) → ap-guangzhou-4
════════════════════════════════════════════════════════
[packer]  tencentcloud-cvm: output will be in this color
[packer]  ==> tencentcloud-cvm: Creating temporary keypair...
[packer]  ==> tencentcloud-cvm: Launching instance (S5.MEDIUM2)...
[packer]  ==> tencentcloud-cvm: Provisioning with ansible-local...
[packer]      tencentcloud-cvm: TASK [ohbs-tencentos3 : apply CIS Level 1] ***
[packer]      tencentcloud-cvm: ok: 142  changed: 38  failed: 0
[packer]      tencentcloud-cvm: TASK [ohbs-tencentos3 : gate] **************
[packer]      tencentcloud-cvm: PASS — 0 remaining findings
[packer]      tencentcloud-cvm:
[packer]      tencentcloud-cvm: ═══ CIS Hardening Results ═══
[packer]      tencentcloud-cvm: Mode:      apply
[packer]      tencentcloud-cvm: Profile:   L1
[packer]      tencentcloud-cvm: Total:     142
[packer]      tencentcloud-cvm: Passed:    142
[packer]      tencentcloud-cvm: Failed:    0
[packer]      tencentcloud-cvm: Score:     100%
[packer]  ==> tencentcloud-cvm: Creating custom image...
[packer]  ==> tencentcloud-cvm: Image created: img-abc123def456
[packer]  ==> tencentcloud-cvm: Terminating build instance...

✔  Build complete — image-id: img-abc123def456
```

## 命令

| 命令 | 说明 |
|---|---|
| `ohbs-image init` | 在当前目录生成 `ohbs-image.toml` |
| `ohbs-image preflight` | 校验配置、凭据和前置条件 |
| `ohbs-image validate` | 渲染模板并执行 `packer validate` |
| `ohbs-image build` | 渲染 + `packer build`（产出镜像） |
| `ohbs-image build --skip-if-unchanged` | 输入未变化时跳过重建（变更检测） |
| `ohbs-image scan [--min-score 85]` | 仅审计（不修复）+ 分数闸门 |
| `ohbs-image scan --sarif out.sarif` | 另输出 SARIF 2.1.0 失败报告 |
| `ohbs-image scan --xccdf out.xml` | 另输出 XCCDF 1.2 结果（GRC 平台接入） |
| `ohbs-image test --idempotency` | 重复执行 apply，二次有变更即失败 |
| `ohbs-image list` | 枚举可用 profile 及元数据 |
| `ohbs-image images [--latest] [-n N]` | 列出历史构建（血缘） |
| `ohbs-image pending` | 变更检测：是否需要重建（退出码 0/1） |
| `ohbs-image cleanup-images [--older-than 30]` | 按血缘年龄退役旧镜像 |
| `ohbs-image cleanup-images --apply` | 实际删除（默认仅演练） |
| `ohbs-image cleanup-images --unused-since 60` | 只删除未共享（无下游引用）的镜像 |
| `ohbs-image verify --provenance <file>` | 校验 SLSA 来源签名 |
| `ohbs-image verify --image <img-id>` | 按镜像 ID 定位来源记录 |
| `ohbs-image verify-image --image <img-id>` | 对产出镜像做干净启动验收 |
| `ohbs-image drift --host <ip> [--image <id>]` | 实例配置漂移检测（对比镜像基线） |
| `ohbs-image drift --host <ip> --save-baseline` | 保存当前主机扫描为漂移基线 |
| `ohbs-image check-source` | 源镜像刷新检测（是否需要重建） |
| `ohbs-image audit --tool oscap ...` | 独立审计：OpenSCAP（RHEL 系 SCAP 内容） |
| `ohbs-image audit --tool inspec ...` | 独立审计：Chef InSpec（dev-sec 基线） |
| `ohbs-image audit --tool kitty --parse out.csv` | 独立审计：HardeningKitty（Windows）CSV |
| `ohbs-image clean` | 删除 `.ohbs-image-build/` 工作目录 |

所有命令均支持以下参数：

| 参数 | 默认值 | 适用范围 | 说明 |
|---|---|---|---|
| `--config <path>` | `./ohbs-image.toml` | 全部 | 配置文件路径 |
| `--workdir <dir>` | `./.ohbs-image-build` | 全部 | 渲染输出目录 |
| `--quiet` | — | validate / build | 精简 packer 输出 |
| `--debug` | — | validate / build | 启用 Packer 调试日志（`PACKER_LOG=1`） |
| `-y` / `--yes` | — | build | 跳过构建确认提示 |
| `--log-file <path>` | — | build | 将完整构建日志写入文件 |
| `--skip-if-unchanged` | — | build | 源镜像/规则/基准/等级未变化时跳过 |
| `--min-score <pct>` | `85` | scan / audit / verify-image | 分数闸门（低于则退出 1） |
| `--sarif <path>` | — | scan / audit | 输出 SARIF 2.1.0 |
| `--xccdf <path>` | — | scan / audit | 输出 XCCDF 1.2（企业 GRC 接入） |
| `--host <ip>` | — | audit | 待审计目标主机（oscap/inspec） |
| `--datastream <path>` | — | audit | 目标上的 oscap SCAP 数据流（如 `/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml`） |
| `--baseline <name>` | `dev-sec/linux-baseline` | audit | inspec 基线 |
| `--parse <csv>` | — | audit --tool kitty | 待解析的 HardeningKitty 审计 CSV |
| `--older-than <days>` | `30` | cleanup-images | 退役 N 天前的构建 |
| `--keep-latest <n>` | `1` | cleanup-images | 保留最新 N 个构建 |
| `--apply` | — | cleanup-images | 实际删除（默认仅演练） |

## 配置文件

`ohbs-image.toml` 是唯一事实来源，无需手写 Packer 模板。

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
source_image_id     = "img-xxxxxxxx"       # 替换为实际 OS 镜像 ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true
# spot = true                             # 可选：构建机用竞价实例（最高省 ~90%）

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # 留空 [] 不跨地域
# share_accounts = ["uin/1234567890"]    # 可选：构建后与其它账号共享镜像
# share_org_units = ["uin/1234567890"]   # 可选：组织级共享（同一 API）

[cis]
level = 1                                 # 1 或 2
# min_score = 85                          # 重启后审计闸门（0 关闭；默认 85）
# rules_include = ["1.5.6"]               # 只运行这些规则
# rules_exclude = ["1.1.2.2.4"]           # 优先级高于 rules_include
# 单条规则参数覆写（渲染时深度合并进规则目录）：
# [cis.overrides."5.2.2"]
# ssh_max_auth_tries = 4

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Windows 构建额外需要：
# winrm_password_env = "WINRM_PASSWORD"

# 构建通知（企微群机器人 webhook）。空 webhook = 关闭。
# [notify]
# webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxx"
# on      = "failure"            # always | success | failure
# deploy_webhook = "https://ci.example.com/api/images"  # 构建成功 POST 镜像元数据（触发下游）

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
# smoke_test = true           # 快照前实例级检查
# cve_scan   = false          # 可选：快照前 trivy 漏洞闸门
# sbom       = false          # 可选：向镜像与 provenance 输出 SBOM
# verify_boot = false         # 可选：用产出镜像开探针实例做干净启动复审
# test_components = ["scripts/app-check.sh"]  # 可选：快照前执行用户自定义测试脚本
```

### 配置参考

| 节 | 字段 | 类型 | 说明 |
|---|---|---|---|
| `[build]` | `profile` | string | 12 个画像之一 |
| | `region` | string | 腾讯云地域，如 `ap-guangzhou` |
| | `zone` | string | 可用区，如 `ap-guangzhou-4` |
| | `instance_type` | string | CVM 实例规格，如 `S5.MEDIUM2` |
| | `source_image_id` | string | 目标 OS 公共镜像 ID |
| | `vpc_id` / `subnet_id` | string | 网络标识 |
| | `security_group_id` | string | 必须以 `sg-` 开头 |
| | `associate_public_ip` | bool | 为构建实例分配公网 IP |
| `[image]` | `name_prefix` | string | 产出镜像名称前缀 |
| | `copy_regions` | []string | 跨地域复制目标（空 = 跳过） |
| `[cis]` | `level` | int | 1（Level 1）或 2（Level 2） |
| `[cloud]` | `secret_id_env` | string | Secret ID 环境变量名 |
| | `secret_key_env` | string | Secret Key 环境变量名 |
| | `winrm_password_env` | string | Windows Admin 密码环境变量名（仅 Windows） |
| `[meta]` | `os_tag` | string | 产出镜像标签值 |
| | `benchmark` | string | CIS benchmark 版本标签 |
| | `ssh_port` | int | SSH 端口（默认 22；TencentOS profile 默认 36000） |
| | `ssh_timeout` | string | Packer SSH 超时（默认 "10m"） |
| | `ssh_debug_password` | string | 设置 root 密码以便 VNC 排查（默认不设置） |

## 架构

### Linux 构建流水线（SSH × ansible-local）

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ohbs-image/     │── packer build ──────────▶│ 临时 CVM          │
│             │                           │   (SSH 端口 22)  │
│ ohbs-image.toml │                           │ 1. 安装 ansible   │
│             │                           │    (dnf/apt/zypp)│
│ roles/      │── 上传至 CVM ────────────▶│ 2. CIS 执行       │
│   cis_*     │      (捆绑角色)            │    (ohbs_engine.py)│
│             │                           │ 3. 门禁：         │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer 在临时 CVM 上通过 `ansible-local` 执行三个阶段：

1. **安装** — 通过系统包管理器 + pip 安装 ansible-core。
2. **加固** — 运行捆绑的 ohbs-os 引擎（`ohbs_engine.py` + `rules.json`）。
   变量：`cis_mode: apply`、`cis_profile: L1/L2`、`cis_platform: server`。
3. **门禁** — 角色内执行：`cis_fail_on_findings: true` + `cis_min_score: 0`。
   加固后仍有残留发现项则 `ansible-playbook` 非零退出，Packer 构建失败。

#### SSH 访问安全网

CIS 规则会禁用 root 的 SSH 登录（`PermitRootLogin no` —— TencentOS 3 规则
5.1.22 / TencentOS 4 规则 5.2.10）。由于构建工具本身以 `root` 连接，
重启后会被锁在外面。ohbs-image 因此在编排层增加两道每次构建都会重新生成的
保障（不会因安装旧包而过期）：

1. **专用构建用户 `ohbs-image`** —— 由 `install-ansible.sh` 创建，具备免密
   sudo，并继承当前 SSH 用户的 `authorized_keys`；即使 root 登录被完全
   禁用也能重连。
2. **SSH guard** —— 在 firewalld / nftables / iptables 中放行实际 SSH
   端口；若 CIS 规则已设置 `PermitRootLogin no`，则临时恢复基于密钥的
   root 登录，保证 Packer 能重连。

**最终镜像交付时仍为加固态**：cleanup 阶段在快照前重新应用
`PermitRootLogin no`。管理构建出的镜像请使用 `ohbs-image` 用户（`sudo -i`
获取 root），或自行创建用户 —— 按 CIS 要求，root 密码登录默认关闭。

### Windows 构建流水线（WinRM × 控制器侧 ansible）

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ohbs-image/     │── packer build ──────────▶│ 临时 CVM          │
│             │                           │  (WinRM 5986)    │
│ ohbs-image.toml │                           │                  │
│             │                           │                  │
│ roles/      │── ansible provisioner ───▶│ CIS 执行           │
│   cis_win*  │   (控制器侧，winrm 连接)   │ (ohbs_engine.ps1)  │
│             │                           │                  │
│             │                           │ 门禁在角色内       │
│             │◀── image-id ──────────────│ CreateImage      │
└─────────────┘                           └──────────────────┘
```

Windows 构建使用 Packer 的 `ansible` provisioner（控制器侧），通过 WinRM 连接。
捆绑角色包含 `ohbs_engine.ps1`（PowerShell）。实例内无需安装任何软件 —
控制器本地需要 `ansible-core`。

### 设计要点

**捆绑角色，无 Galaxy。**
12 个 ohbs-os 引擎角色全部随包发布在 `ohbs_image/roles/` 目录下。构建时工具
将角色复制到工作目录。无网络依赖，无版本漂移。

**`ansible-local`（Linux）— 实例内自包含。**
Packer 控制器不需要能 SSH 进云内网，playbook 和角色全部在构建实例内执行。

**`ansible`（Windows）— 控制器通过 WinRM 驱动。**
Windows 镜像使用 Packer 的 `ansible` provisioner，从控制器通过 WinRM 连接。
控制器本地需安装 `ansible-core`。

**内建门禁，无外部审计。**
门禁在 Ansible 角色内部（`cis_fail_on_findings`），加固后的镜像要么通过、要么不创建。

**凭据与治理。**
AK/SK 仅通过环境变量传入（HCL `sensitive = true`）。临时实例打标并自动回收。
镜像标签记录 CIS 等级、OS 和 benchmark。

## 画像

### Linux（SSH × ansible-local）

| Profile | 操作系统 | SSH 用户 | 包管理器 | 角色 |
|---|---|---|---|---|
| `ubuntu2004` | Ubuntu 20.04 LTS | ubuntu | apt | `roles/ohbs-ubuntu2004/` |
| `ubuntu2204` | Ubuntu 22.04 LTS | ubuntu | apt | `roles/ohbs-ubuntu2204/` |
| `ubuntu2404` | Ubuntu 24.04 LTS | ubuntu | apt | `roles/ohbs-ubuntu2404/` |
| `rhel8` | RHEL 8 | root | dnf | `roles/ohbs-rhel8/` |
| `rhel9` | RHEL 9 | root | dnf | `roles/ohbs-rhel9/` |
| `rhel10` | RHEL 10 | root | dnf | `roles/ohbs-rhel10/` |
| `tencentos3` | TencentOS Server 3 | root | dnf | `roles/ohbs-tencentos3/` |
| `tencentos4` | TencentOS Server 4 | root | dnf | `roles/ohbs-tencentos4/` |

### Windows（WinRM × 控制器侧 ansible）

| Profile | 操作系统 | 用户 | 角色 |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/ohbs-win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/ohbs-win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/ohbs-win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/ohbs-win2025/` |

切换画像仅需改 `ohbs-image.toml` 中的 `[build].profile` 和 `source_image_id`。

## 测试矩阵

已验证的 CIS 加固镜像（OS × 等级全覆盖）。
所有构建均在腾讯云广州地域、`cis_allow_disruptive: false` 下完成；
以下镜像均已于 2026-08-14 在控制台复核为 `NORMAL` 状态。

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

> 分数为重启后复审结果（全量评估规则，门禁 ≥ 85）。
> kmod 类规则通过持久化 modprobe install-override 生效，构建期无需排除任何规则。
> Windows 镜像为成员服务器配置，基于腾讯云公共镜像（英文版/中文版）构建，
> 于 2026-08-14 完成构建与复审；快照前已重新锁定 WinRM（关闭 Basic/明文 HTTP,
> Administrator 密码已随机化）。
> 每个 Windows 构建仅剩的一条 fail 为「Deny access to this computer from the
> network → 包含 S-1-5-114」(2.2.2x)，属故意跳过的 disruptive 规则：应用它会
> 切断构建所依赖的 WinRM 会话。可在启动后通过 `cis_allow_disruptive: true` 启用。

## 对接 CI/CD

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows 构建：
# export WINRM_PASSWORD=xxx

ohbs-image build --log-file build.log
```

下游 CVM / 伸缩组 / Terraform 引用产出的 `image_id`。构建机固定专用 VPC + SG。

## 故障排查

| 症状 | 可能原因 | 解决 |
|---|---|---|
| `preflight` 报凭据错误 | 未 export `TENCENTCLOUD_SECRET_ID` / `_KEY` | 在 shell 中 `export TENCENTCLOUD_SECRET_ID=...` |
| `validate` 报插件下载错误 | `packer init` 失败（如构建机无网络） | 联网重新执行 `ohbs-image validate`，Packer 首次下载后会缓存插件 |
| Packer 等待 SSH 超时 | 安全组未对构建机放行 22 端口 | 添加入站规则：TCP/22，来源为构建机出口 IP —— `preflight` 现在会在能解析安全组规则和本机公网 IP 时主动提前预警此问题 |
| `ansible-playbook` 报 "python3 not found" | 构建实例 OS 未预装 Python | 确保源镜像包含 Python >= 3.6 |
| Windows 构建 WinRM 连接失败 | 未设 `WINRM_PASSWORD` 或网络不通 | export 密码 + 确保 TCP/5986 对构建 IP 放行 |
| 构建成功但仍有 CIS 发现项 | 当前 OS 的部分规则未被覆盖 | 先用 `level: 1`（Level 1 覆盖大部分常见规则） |

## 路线图

- [x] CI 流水线（GitHub Actions + OIDC，零长时 AK/SK）
- [x] 镜像治理闭环：smoke test / 血缘 / 通知 / SLSA 签名
- [x] `ohbs-image list` — 枚举可用画像及元数据
- [x] 自定义规则选择（`ohbs-image.toml` 中的 `rules_include` / `rules_exclude`）
- [x] PyPI 发布（`pip install ohbs-image`）
- [x] 自动镜像清理（按血缘年龄退役）
- [x] 独立审计工具（`ohbs-image audit` — oscap / inspec / kitty）
- [x] 基准锚定的规则 ID（引擎输出 + SARIF，可与 CIS-CAT 交叉核对）
- [x] 干净启动验收（`ohbs-image verify-image` / `[meta].verify_boot`）
- [x] 单条规则参数覆写（`[cis].overrides`）
- [x] CVE 扫描闸门 + SBOM 输出（`[meta].cve_scan` / `[meta].sbom`）
- [x] 变更检测（`ohbs-image pending` / `build --skip-if-unchanged`）
- [x] XCCDF 1.2 报告导出（`scan --xccdf`、audit `--xccdf`）
- [x] 跨账号镜像共享（`[image].share_accounts`）
- [x] provenance + 血缘锚定 SBOM（SLSA L2 风格证据）
- [x] Windows 经 HardeningKitty CSV 交叉验证（`audit --tool kitty`）
- [x] 实例配置漂移检测（`ohbs-image drift`，对比镜像基线）
- [x] 用户自定义测试组件（`[meta].test_components`）
- [x] 构建成功触发下游（`[notify].deploy_webhook`）
- [x] 竞价实例构建机（`[build].spot`，最高省 ~90%）
- [x] 安全清理（`cleanup-images --unused-since`，共享中的镜像保留）
- [x] 组织级共享（`[image].share_org_units`）
- [x] 规则集版本化（`ohbs-image list --versions`）
- [x] 源镜像刷新检测（`ohbs-image check-source`）
- [ ] SLSA L2：完全可复现构建（锁定构建环境）
- [ ] STIG 基准 profile（同一引擎，DISA 内容 — 路线图）

## 参与贡献

欢迎提交 Bug 报告和 Pull Request。开发环境搭建、lint/类型检查/测试命令、项目硬性约束（零第三方运行时依赖、不存储长期凭证）以及新增 CIS profile 的指南，请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)（英文）。

## 许可证

MIT — 详见 [LICENSE](LICENSE)。

## CIS Benchmarks 声明

本工具应用的加固规则源自 CIS Benchmark 建议。CIS Benchmarks 由
[Center for Internet Security](https://www.cisecurity.org/)（CIS）制定和维护。
本仓库捆绑的 ohbs-os 引擎角色派生自 [susunola/ohbs-os](https://github.com/susunola/ohbs-os)
项目，按其各自许可提供。

**重要提示：** 以 `apply` 模式运行 CIS 加固会修改系统配置，可能影响应用兼容性。
硬化镜像在生产环境使用前，务必在预发环境中充分测试。CIS 组织和本工具作者均不保证
所应用规则能达到完全合规 — 正式审计需使用 CIS-CAT 或等效工具独立评估。
