<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

# ciscvm — Packer × 腾讯云 CVM × CIS 镜像构建

在腾讯云上自动化产出 CIS 加固的黄金镜像。配置驱动的 CLI 工具：起一台临时 CVM →
应用 CIS 基准加固 → 审计门禁校验 → 捕获为自定义镜像。全部由 `ciscvm.toml` 驱动。

**Linux** 镜像通过 `ansible-local` provisioner 在实例内加固，构建期 goss 审计门禁
确保不达标不入库。三种后端：

| 后端 | 适用系统 | CIS 引擎 |
|---|---|---|
| ansible-lockdown | Ubuntu 22/24、RHEL 8/9、CentOS 8/9 | 社区 Ansible 角色 + goss 审计 |
| cis-os（捆绑） | TencentOS Server 3/4 | 捆绑 `cis_engine.py` + `rules.json`，角色内门禁 |
| ansible（远程） | Windows Server 2019/2022/2025 | 远程 Ansible over WinRM，无 build 期审计 |

> 默认：Ubuntu 22.04 LTS + CIS Level 1。完整列表见[画像一览](#画像一览)。

## 项目结构

```
cis-cvm-image/
├── ciscvm.py                 # CLI 工具（纯标准库，单文件）
├── ciscvm.toml               # 构建配置（`init` 生成）
├── README.md / README.zh-CN.md
├── LICENSE                   # MIT
├── roles/                    # 捆绑 Ansible 角色（TencentOS cis-os 引擎）
│   ├── cis_tencentos3/
│   └── cis_tencentos4/
└── .ciscvm-build/            # 渲染产物（git 忽略）
    ├── packer/
    │   ├── main.pkr.hcl
    │   ├── auto.pkrvars.hcl
    │   └── scripts/
    │       ├── install-ansible.sh
    │       └── verify-cis.sh
    └── ansible/
        ├── site.yml
        └── roles/            # 构建时从 ../roles/ 复制（cis-os 画像）
```

## 前置条件

| 条件 | 说明 |
|---|---|
| **Python** | ≥ 3.11，仅用标准库，无 pip 依赖 |
| **Packer** | ≥ 1.9，需 `packer-plugin-tencentcloud` 插件 |
| **腾讯云** | 子账号，最少权限：`cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* |
| **网络** | 专用构建 VPC + 子网 + 安全组（放行 22 入站，来源限定构建机出口 IP） |
| **源镜像** | 目标 OS 的公共镜像 ID |

\* 跨地域复制才需要 `cvm:CopyImage`。

凭据仅通过环境变量传入，不落盘：

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
```

## 快速开始

```bash
# 1. 生成配置文件
python3 ciscvm.py init

# 2. 编辑 ciscvm.toml，填入 VPC / 子网 / SG / 源镜像 ID

# 3. 构建前自检
python3 ciscvm.py preflight

# 4. 校验：渲染 + packer validate
python3 ciscvm.py validate

# 5. 构建加固镜像
python3 ciscvm.py build

# 可选：清理渲染产物
python3 ciscvm.py clean
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--config <path>` | `./ciscvm.toml` | 配置文件路径 |
| `--workdir <dir>` | `./.ciscvm-build` | 渲染输出目录 |
| `--quiet` | — | 精简输出（validate / build） |

构建成功后镜像出现在目标地域；`image.copy_regions` 非空时自动复制到其他地域。

## 配置文件

`ciscvm.toml` 是唯一事实来源：

```toml
[build]
profile             = "ubuntu22"          # 见下方画像一览
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"      # 替换为实际公共镜像 ID
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "ubuntu-2204-cis"
copy_regions = ["ap-shanghai"]            # 留空 [] 不跨地域

[cis]
level        = 1                          # 1 或 2
max_failures = 0                          # 审计失败容忍上限（仅 Linux 生效）
audit_dir    = "/opt/ubuntu22_cis"        # 需与角色审计目录一致

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
winrm_password_env = "WINRM_PASSWORD"     # 仅 Windows 需要

[meta]
os_tag    = "ubuntu-22.04"
benchmark = "CIS-v2.0.0"
```

## 画像一览

### 内置画像

| Profile | 操作系统 | 后端 | 登录用户 | 状态 |
|---|---|---|---|---|
| `ubuntu22` | Ubuntu 22.04 LTS | ansible-lockdown | ubuntu | 稳定 |
| `ubuntu24` | Ubuntu 24.04 LTS | ansible-lockdown | ubuntu | 预览 |
| `rhel8` | RHEL 8 | ansible-lockdown | root | 预览 |
| `rhel9` | RHEL 9 | ansible-lockdown | root | 预览 |
| `centos8` | CentOS 8 | ansible-lockdown（套用 RHEL 8 角色）† | root | 预览 |
| `centos9` | CentOS 9 | ansible-lockdown（套用 RHEL 9 角色）† | root | 预览 |
| `tencentos3` | TencentOS Server 3 | cis-os（捆绑角色） | root | 稳定 |
| `tencentos4` | TencentOS Server 4 | cis-os（捆绑角色） | root | 稳定 |
| `windows2019` | Windows Server 2019 | ansible（远程） | Administrator | 预览 |
| `windows2022` | Windows Server 2022 | ansible（远程） | Administrator | 预览 |
| `windows2025` | Windows Server 2025 | ansible（远程） | Administrator | 预览 |

† CentOS 套用对应 RHEL 角色，并关闭 `os_check`。

**稳定** — 已在腾讯云端到端验证。
**预览** — 角色名与变量前缀已对照上游源码核实，尚未在腾讯云端到端跑过。
验证后建议固定 `role_version`。

### 切换画像

仅改 `ciscvm.toml` 一行：

```toml
[build]
profile         = "rhel9"
source_image_id = "img-实际RHEL9镜像ID"
```

SSH 用户、后端、包管理器、审计目录等随画像自动确定，其余步骤不变。

### 新增自定义画像

在 `ciscvm.py` 的 `PROFILES` 字典中添加一项，在 `ciscvm.toml` 引用其 key。
以 RHEL 系为例：

```python
"almalinux9": {
    "ssh_username": "root",
    "role": "ansible-lockdown.rhel9_cis",
    "role_version": "",
    "audit_dir": "/opt/rhel9_cis",
    "os_tag": "almalinux-9",
    "benchmark": "CIS-v2.0.0",
    "pkg_update": "sudo dnf makecache",
    "pkg_install": "sudo dnf install -y python3-pip git",
    "clean_cmd": "sudo dnf clean all",
    "level1_var": "rhel9cis_level_1",
    "level2_var": "rhel9cis_level_2",
    "boot_pass_var": "rhel9cis_set_boot_pass",
    "os_check_var": None,
    "root_login_rule_var": "rhel9cis_rule_5_2_2",
    "preview": True,
},
```

三个必须与真实角色对齐的字段（否则加固 / 审计静默失效）：

1. **角色名** — `ansible-galaxy` 上的确切名称。不存在时改用
   `git+https://github.com/ansible-lockdown/<REPO>.git`。
2. **等级变量前缀** — `ubtu22cis_`（注意是 `ubtu` 不是 `ubuntu`），
   以角色 `defaults/main.yml` 为准。
3. **审计输出目录** — 需与角色写入 goss 结果的路径一致。

### 切换 CIS Level

`ciscvm.toml` 设 `[cis].level = 2`。Level 2 要求额外分区
（`/var`、`/var/tmp`、`/var/log`、`/var/log/audit`、`/home` 均需 `nodev`、`nosuid`、
`noexec`），需在源镜像或 `user_data` 中配置好分区再构建。

## 架构

### 构建流水线

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ciscvm.py   │── packer build ──────────▶│ 临时 CVM          │
│             │                           │                  │
│ ciscvm.toml │                           │ 1. 安装 ansible   │
│             │                           │ 2. CIS 角色（加固）│
│             │                           │ 3. 审计门禁       │
│             │                           │                  │
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer 在临时 CVM 上执行三个阶段：

1. **安装** — 在实例内安装 ansible-core 和 CIS 角色。
2. **加固** — `ansible-local` 执行 CIS 角色 remediation。云环境例外项
   （引导密码、RHEL/CentOS 的 root SSH、派生系统 OS 校验）已写入渲染后的 `site.yml`。
3. **校验** — 运行审计。失败项超过 `cis.max_failures` 则 Packer 退出 1，镜像不入库。

### 设计要点

**选择 `ansible-local` 而非 `ansible`。**
Packer 控制器不需要能 SSH 进云内网，playbook 和角色全部在实例内执行。

**云环境例外。**
引导 / GRUB 密码显式关闭防锁死。RHEL / CentOS 保留 root SSH 登录。CentOS
关闭 `os_check` 防止 RHEL 角色中止。SSH 公钥登录由 CIS 默认保留。

**构建期合规门禁。**
加固后运行 goss 审计。审计目录不存在 → 告警软跳过；路径确认后即为硬门禁，
失败项超限阻止镜像入库。

**凭据与治理。**
AK/SK 仅通过环境变量传入（HCL `sensitive = true`）。临时实例打标并自动回收。
镜像标签记录 CIS 等级、OS 和 benchmark。

## TencentOS Server（cis-os 后端）

TencentOS 3/4 使用自定义 CIS 引擎（`cis_engine.py` + `rules.json`）替代
ansible-lockdown。角色**本地捆绑**在 `roles/cis_tencentos3/` 和
`roles/cis_tencentos4/`，无需 Ansible Galaxy 安装。构建时工具将角色目录
复制到渲染工作区。

与 ansible-lockdown 后端的主要区别：

| | ansible-lockdown | cis-os（TencentOS） |
|---|---|---|
| 角色来源 | Ansible Galaxy | 本地 `roles/` 捆绑 |
| CIS 引擎 | 社区 Ansible 角色 | `cis_engine.py` + `rules.json` |
| 审计门禁 | goss（`verify-cis.sh`） | 角色内（`cis_fail_on_findings`） |
| 角色安装 | `ansible-galaxy install` | 复制到工作目录 |
| 变量 | `<role>_level_1/2` | `cis_mode: apply`、`cis_profile: L1/L2` |

门禁机制：角色设 `cis_fail_on_findings: true` 和 `cis_min_score: 0`，加固后
仍有残留发现项则 `ansible-playbook` 非零退出，Packer 构建失败。无需独立
verify 脚本。

## Windows Server（预览）

Windows 镜像无法使用 `ansible-local` / SSH，也没有 goss。对
`windows2019` / `windows2022` / `windows2025` 渲染不同流水线：

| | Linux | Windows |
|---|---|---|
| 通信 | SSH | WinRM |
| Provisioner | `ansible-local`（VM 内） | `ansible`（控制器 → 客户机） |
| 角色安装 | CVM 内部 | 控制器侧（`packer build` 前） |
| 审计门禁 | goss | 无（构建后验证） |
| 等级选择 | `<role>_level_1/2` + `--tags` | `win22cis_l1_ms` / `l2_ms` |

### 构建 Windows 镜像

```toml
[build]
profile         = "windows2022"
source_image_id = "img-实际Windows2022镜像ID"

[cloud]
winrm_password_env = "WINRM_PASSWORD"
```

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
export WINRM_PASSWORD='<符合 Windows 复杂度要求的密码>'
pip install ansible pywinrm
python3 ciscvm.py preflight && python3 ciscvm.py build
```

渲染的 playbook 设置 `win22cis_ansible_remediation: true`、
`win22cis_create_gpos: false` 及成员服务器等级变量。GPO 和域变量默认关闭。
WinRM 不会被加固禁用。

### 构建后验证

Windows 无 build 期审计门禁，在镜像产出后验证：

- 用 **Microsoft Policy Analyzer** 或 **CIS-CAT Pro** 扫描产出的镜像。
- 使用角色自带的上报功能（`win22cis_run_audit` / section 级别检查）。

## 对接 CI

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx
python3 ciscvm.py build
```

下游 CVM / 伸缩组 / Terraform 引用产出的 `image_id`。建议构建机固定专用 VPC + SG。

## 许可证

MIT
