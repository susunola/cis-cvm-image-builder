<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b> | <a href="README.ja.md">日本語</a> | <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python&logoColor=white" alt="Python >= 3.11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/profiles-14-orange" alt="14 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
</p>

# ciscvm — CIS 加固黄金镜像构建

> 五条命令在腾讯云上构建 CIS 加固黄金镜像。无需 Galaxy，构建时零网络依赖，
> 不用手写模板 — 一切由 `ciscvm.toml` 驱动。

**做什么：** 起一台临时 CVM，应用捆绑的 [cis-os](https://github.com/susunola/cis-os)
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
| **Packer** | >= 1.9，需 `packer-plugin-tencentcloud` 插件 |
| **ansible-core** | >= 2.15（Windows 构建需在控制器本地安装） |
| **腾讯云** | 子账号，最少权限：`cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* |
| **网络** | 专用构建 VPC + 子网 + 安全组（Linux: SSH/22，Windows: WinRM/5986），来源限定构建机出口 IP |
| **源镜像** | 目标 OS 的公共镜像 ID |

\* 跨地域复制才需要 `cvm:CopyImage`。

**获取工具**

```bash
git clone https://github.com/susunola/cis-cvm-image-builder.git
cd cis-cvm-image-builder

# 直接运行（无需 pip install）
python3 ciscvm.py --version

# 可选：安装为 Python 包
pip install -e ".[dev]"
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
python3 ciscvm.py init

# 2. 编辑 ciscvm.toml，填入 VPC、子网、安全组和源镜像 ID

# 3. 构建前自检（校验配置、凭据和前置条件）
python3 ciscvm.py preflight

# 4. 干跑校验（渲染模板 + packer validate）
python3 ciscvm.py validate

# 5. 构建加固镜像
python3 ciscvm.py build

# 可选：清理渲染产物
python3 ciscvm.py clean
```

**构建输出示例（`build`）**

```
════════════════════════════════════════════════════════
  ciscvm 0.4.0 — tencentos3 (L1) → ap-guangzhou-4
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

## 命令

| 命令 | 说明 |
|---|---|
| `ciscvm.py init` | 在当前目录生成 `ciscvm.toml` |
| `ciscvm.py preflight` | 校验配置、凭据和前置条件 |
| `ciscvm.py validate` | 渲染模板并执行 `packer validate` |
| `ciscvm.py build` | 渲染 + `packer build`（产出镜像） |
| `ciscvm.py clean` | 删除 `.ciscvm-build/` 工作目录 |

所有命令均支持以下参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--config <path>` | `./ciscvm.toml` | 配置文件路径 |
| `--workdir <dir>` | `./.ciscvm-build` | 渲染输出目录 |
| `--quiet` | — | 精简输出（validate / build） |
| `-y` / `--yes` | — | 跳过构建确认提示 |

## 配置文件

`ciscvm.toml` 是唯一事实来源，无需手写 Packer 模板。

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
source_image_id     = "img-xxxxxxxx"       # 替换为实际 OS 镜像 ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # 留空 [] 不跨地域

[cis]
level = 1                                 # 1 或 2

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Windows 构建额外需要：
# winrm_password_env = "WINRM_PASSWORD"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### 配置参考

| 节 | 字段 | 类型 | 说明 |
|---|---|---|---|
| `[build]` | `profile` | string | 14 个画像之一 |
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

## 架构

### Linux 构建流水线（SSH × ansible-local）

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ciscvm.py   │── packer build ──────────▶│ 临时 CVM          │
│             │                           │   (SSH 端口 22)  │
│ ciscvm.toml │                           │ 1. 安装 ansible   │
│             │                           │    (dnf/apt/zypp)│
│ roles/      │── 上传至 CVM ────────────▶│ 2. CIS 执行       │
│   cis_*     │      (捆绑角色)            │    (cis_engine.py)│
│             │                           │ 3. 门禁：         │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer 在临时 CVM 上通过 `ansible-local` 执行三个阶段：

1. **安装** — 通过系统包管理器 + pip 安装 ansible-core。
2. **加固** — 运行捆绑的 cis-os 引擎（`cis_engine.py` + `rules.json`）。
   变量：`cis_mode: apply`、`cis_profile: L1/L2`、`cis_platform: server`。
3. **门禁** — 角色内执行：`cis_fail_on_findings: true` + `cis_min_score: 0`。
   加固后仍有残留发现项则 `ansible-playbook` 非零退出，Packer 构建失败。

### Windows 构建流水线（WinRM × 控制器侧 ansible）

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ciscvm.py   │── packer build ──────────▶│ 临时 CVM          │
│             │                           │  (WinRM 5986)    │
│ ciscvm.toml │                           │                  │
│             │                           │                  │
│ roles/      │── ansible provisioner ───▶│ CIS 执行           │
│   cis_win*  │   (控制器侧，winrm 连接)   │ (cis_engine.ps1)  │
│             │                           │                  │
│             │                           │ 门禁在角色内       │
│             │◀── image-id ──────────────│ CreateImage      │
└─────────────┘                           └──────────────────┘
```

Windows 构建使用 Packer 的 `ansible` provisioner（控制器侧），通过 WinRM 连接。
捆绑角色包含 `cis_engine.ps1`（PowerShell）。实例内无需安装任何软件 —
控制器本地需要 `ansible-core`。

### 设计要点

**捆绑角色，无 Galaxy。**
14 个 cis-os 引擎角色全部随 `ciscvm.py` 一起发布在 `roles/` 目录下。构建时工具
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

### Windows（WinRM × 控制器侧 ansible）

| Profile | 操作系统 | 用户 | 角色 |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/cis_win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/cis_win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/cis_win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/cis_win2025/` |

切换画像仅需改 `ciscvm.toml` 中的 `[build].profile` 和 `source_image_id`。

## 对接 CI/CD

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows 构建：
# export WINRM_PASSWORD=xxx

python3 ciscvm.py build
```

下游 CVM / 伸缩组 / Terraform 引用产出的 `image_id`。构建机固定专用 VPC + SG。

## 故障排查

| 症状 | 可能原因 | 解决 |
|---|---|---|
| `preflight` 报凭据错误 | 未 export `TENCENTCLOUD_SECRET_ID` / `_KEY` | 在 shell 中 `export TENCENTCLOUD_SECRET_ID=...` |
| `validate` 报 "plugin not found" | 缺少 `packer-plugin-tencentcloud` | `packer plugins install github.com/tencentcloud/tencentcloud` |
| Packer 等待 SSH 超时 | 安全组未对构建机放行 22 端口 | 添加入站规则：TCP/22，来源为构建机出口 IP |
| `ansible-playbook` 报 "python3 not found" | 构建实例 OS 未预装 Python | 确保源镜像包含 Python >= 3.6 |
| Windows 构建 WinRM 连接失败 | 未设 `WINRM_PASSWORD` 或网络不通 | export 密码 + 确保 TCP/5986 对构建 IP 放行 |
| 构建成功但仍有 CIS 发现项 | 当前 OS 的部分规则未被覆盖 | 先用 `level: 1`（Level 1 覆盖大部分常见规则） |

## 路线图

- [ ] CI 流水线（GitHub Actions）自动构建镜像
- [ ] PyPI 发布（`pip install ciscvm`）
- [ ] `ciscvm list` — 枚举可用画像及元数据
- [ ] `ciscvm report` — 获取并展示已完成构建的审计报告
- [ ] 自定义规则选择（`ciscvm.toml` 中的 `rules_include` / `rules_exclude`）

## 参与贡献

欢迎提交 Bug 报告和 Pull Request。提交前请运行测试：

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## 许可证

MIT — 详见 [LICENSE](LICENSE)。

## CIS Benchmarks 声明

本工具应用的加固规则源自 CIS Benchmark 建议。CIS Benchmarks 由
[Center for Internet Security](https://www.cisecurity.org/)（CIS）制定和维护。
本仓库捆绑的 cis-os 引擎角色派生自 [susunola/cis-os](https://github.com/susunola/cis-os)
项目，按其各自许可提供。

**重要提示：** 以 `apply` 模式运行 CIS 加固会修改系统配置，可能影响应用兼容性。
硬化镜像在生产环境使用前，务必在预发环境中充分测试。CIS 组织和本工具作者均不保证
所应用规则能达到完全合规 — 正式审计需使用 CIS-CAT 或等效工具独立评估。
