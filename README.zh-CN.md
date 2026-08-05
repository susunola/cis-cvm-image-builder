<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

# ciscvm — CIS 加固黄金镜像构建

在腾讯云上自动化产出 CIS 加固的黄金镜像。配置驱动的 CLI 工具：起一台临时 CVM →
应用捆绑的 cis-os 引擎进行 CIS 加固 → 内建门禁校验 → 捕获为自定义镜像。全部由
`ciscvm.toml` 驱动。

支持：**14 个画像（Linux + Windows）** — Ubuntu 20/22/24、RHEL 8/9/10、
TencentOS Server 3/4、SLES 15/16、Windows Server 2016/2019/2022/2025。CIS 引擎
（`cis_engine.py` / `cis_engine.ps1` + `rules.json`）本地捆绑在 `roles/` 目录下 —
无需 Ansible Galaxy，构建时无网络依赖。门禁在 Ansible 角色内执行
（`cis_fail_on_findings: true`）：加固后仍有残留发现项则构建失败，镜像不入库。

## 项目结构

```
cis-cvm-image/
├── ciscvm.py                 # CLI 工具（纯标准库，单文件）
├── ciscvm.toml               # 构建配置（`init` 生成）
├── README.md / README.zh-CN.md
├── LICENSE                   # MIT
├── roles/                    # 捆绑 cis-os 引擎（14 个角色）
│   ├── cis_tencentos3/       #   cis_engine.py + rules.json + Ansible 角色
│   ├── cis_tencentos4/
│   ├── cis_ubuntu2004/  cis_ubuntu2204/  cis_ubuntu2404/
│   ├── cis_rhel8/       cis_rhel9/       cis_rhel10/
│   ├── cis_sles15/      cis_sles16/
│   └── cis_win2016/     cis_win2019/     cis_win2022/     cis_win2025/
└── .ciscvm-build/            # 渲染工作目录（git 忽略）
    ├── packer/
    │   ├── main.pkr.hcl
    │   ├── auto.pkrvars.hcl
    │   └── scripts/
    │       └── install-ansible.sh   # 仅 Linux
    └── ansible/
        ├── site.yml
        └── roles/            # 构建时从 ../roles/ 复制
```

## 前置条件

| 条件 | 说明 |
|---|---|
| **Python** | >= 3.11，仅用标准库，无 pip 依赖 |
| **Packer** | >= 1.9，需 `packer-plugin-tencentcloud` 插件 |
| **ansible-core** | >= 2.15（Windows 构建需在构建控制器本地安装） |
| **腾讯云** | 子账号，最少权限：`cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* |
| **网络** | 专用构建 VPC + 子网 + 安全组。Linux：放行 22 入站；Windows：放行 5986 入站。来源限定构建机出口 IP |
| **源镜像** | 目标 OS 的公共镜像 ID |

\* 跨地域复制才需要 `cvm:CopyImage`。

凭据仅通过环境变量传入：

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx

# Windows 构建额外需要：
# export WINRM_PASSWORD=xxxx
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
| `-y` / `--yes` | — | 跳过构建确认提示 |

## 配置文件

`ciscvm.toml` 是唯一事实来源：

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
| `[build]` | `profile` | string | 14 个画像之一（见上） |
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
| | `winrm_password_env` | string | Windows Administrator 密码环境变量名（仅 Windows） |
| `[meta]` | `os_tag` | string | 产出镜像标签值 |
| | `benchmark` | string | CIS benchmark 版本标签 |

## 架构

### Linux 构建流水线

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
2. **加固** — `ansible-local` 运行捆绑的 cis-os 引擎（`cis_engine.py` + `rules.json`）。
   变量：`cis_mode: apply`、`cis_profile: L1/L2`、`cis_platform: server`。
3. **门禁** — 角色内执行：`cis_fail_on_findings: true` + `cis_min_score: 0`。
   加固后仍有残留发现项则 `ansible-playbook` 非零退出，Packer 构建失败。

### Windows 构建流水线

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

## 对接 CI

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows 构建：
# export WINRM_PASSWORD=xxx

python3 ciscvm.py build
```

下游 CVM / 伸缩组 / Terraform 引用产出的 `image_id`。构建机固定专用 VPC + SG。

## 许可证

MIT
