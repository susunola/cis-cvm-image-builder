<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

# ciscvm — Packer × 腾讯云 CVM × CIS 镜像构建工具

用 Packer 起临时 CVM，通过 provisioner 跑
[ansible-lockdown](https://github.com/ansible-lockdown) 的 CIS 角色做系统加固（remediation），
最终产出符合 CIS 基准的自定义镜像（golden image）。

- **Linux**（Ubuntu / RHEL / CentOS）：通过 `ansible-local` provisioner **在实例内**执行加固，
  goss 审计做 build 期 gate。
- **Windows Server**（2019 / 2022，*preview*）：使用 **WinRM** + 远程 `ansible` provisioner
  （Ansible 在控制器侧执行，不是在 VM 里）；Windows 没有 goss 审计——见
  [Windows Server（preview）](#windows-serverpreview)。

整套流程收敛成一个**配置驱动的单命令工具**：`ciscvm.toml` 是唯一事实来源，
HCL / playbook / 脚本全部在构建时由配置渲染生成，不用手改 HCL。

> **默认目标**：Ubuntu 22.04 + CIS Level 1。换 OS / Level 见下方「换操作系统」
> （Ubuntu 24 / RHEL 8/9 / CentOS 8/9 / Windows Server 2019/2022）。

## 项目结构

```
cis-cvm-image/
├── ciscvm.py                    # 工具本体（纯标准库，单文件，python3 直接跑）
├── README.md                    # 英文版
├── README.zh-CN.md              # 本文件（中文）
└── ciscvm.toml                  # init 后生成的配置文件（单事实来源）
                                 # HCL / playbook / 脚本全部渲染进 .ciscvm-build/
```

## 前置条件

1. Python ≥ 3.11（仅用标准库，`ciscvm.py` 不依赖任何 pip 包）。
2. 构建机装 [Packer](https://developer.hashicorp.com/packer/install)（≥ 1.9）。
3. 一个**子账号** AK/SK，最小权限：`cvm:RunInstances`、`cvm:CreateImage`、
   `cvm:DescribeImages`、`cvm:CopyImage`（若用跨地域复制）、镜像共享权限（若用共享）。
   **凭据只走环境变量，绝不写进任何文件**：
   ```bash
   export TENCENTCLOUD_SECRET_ID=AKIDxxxx
   export TENCENTCLOUD_SECRET_KEY=xxxx
   ```
4. 一个**专用构建 VPC + 子网 + 安全组**（SG 放行 22 入站，来源限定你的构建机出口 IP）。
5. 你所选 OS 的官方公共镜像 ID（`source_image_id`）。控制台镜像页查看，
   或 `tccli cvm DescribeImages --Filters '[{"Name":"image-type","Values":["PUBLIC_IMAGE"]}]'`。

## 用法

```bash
# 1. 生成示例配置（写入 ciscvm.toml + .gitignore）
python3 ciscvm.py init

# 2. 编辑 ciscvm.toml：选 profile、填 VPC / 子网 / SG / 源镜像ID；凭据仍走环境变量

# 3. 构建前自检（凭据/网络/插件/参数是否就位）
python3 ciscvm.py preflight

# 4. 只校验（渲染到 .ciscvm-build/ 后跑 packer init + validate）
python3 ciscvm.py validate

# 5. 真正构建（产出镜像，自动解析并回显镜像 ID）
python3 ciscvm.py build

# 可选：删除渲染工作目录
python3 ciscvm.py clean
```

常用参数：`--config <path>`（默认 `./ciscvm.toml`）、`--workdir <dir>`（默认 `./.ciscvm-build`）、
`validate/build` 的 `--quiet`（只输出 packer 结果）。

构建成功后镜像出现在对应 region；若 `image.copy_regions` 非空会自动复制到其它地域。

## 关键设计点

### 1. CIS 怎么 apply 进去的

Packer 只负责起机器、跑 provisioner、打镜像。真正的加固是 `ansible-local` provisioner
在临时 CVM 内执行 ansible-lockdown 的 CIS 角色，逐条按 CIS 编号 remediation。
选 `ansible-local`（而非 `ansible`）是不让 Packer 控制机需要能 SSH 进云内网——
playbook 和角色都直接在实例里跑。

### 2. 云环境例外（务必保留，否则会把自己锁死）

各 OS 的**变量前缀不同**（如 Ubuntu 22 是 `ubtu22cis_`、RHEL 9 是 `rhel9cis_`——
注意 Ubuntu 是 `ubtu` 不是 `ubuntu`）。渲染出的 `ansible/site.yml` 已自动处理这些云例外：

- **引导/GRUB 密码显式关闭**（`<role>_set_grub_user_pass: false` / `<role>_set_boot_pass: false`），
  避免误配把系统锁死。
- **RHEL / CentOS** 关掉了 `rule_5_2_2`（「禁止 root 登录」那条），让加固后构建期的 shell
  provisioner 还能用 SSH 连上。
- **CentOS**（RHEL 派生、非 RHEL 本体）设 `os_check: false`，避免 RHEL 角色在 OS 检测时中止。
- `cloud-init` / IMDS 相关控制项保持角色默认（不被禁用）。

> SSH **公钥**登录默认保留，因为 CIS 本身要求 `PubkeyAuthentication yes`；工具不需要专门的
> 「保留 key」开关。

### 3. Build 期 gate（不达标就失败）

`verify-cis.sh` 在加固后跑 goss 审计，解析失败项数；超过 `cis.max_failures`（默认 0）
就 `exit 1`，让 `packer build` 失败、镜像不入库存。审计目录默认 `/opt/<role>_cis`，
如与你的角色版本不符，改 `ciscvm.toml` 的 `[cis].audit_dir` 即可。（若目录不存在，gate 会
带告警软跳过，避免路径猜错把构建卡死；确认路径后它才是硬 gate。）

### 4. 凭据 / 网络 / 治理

- AK/SK 只走环境变量，`sensitive = true`，绝不入库。
- 专用构建 VPC + SG，临时机器用完自动回收。
- 镜像名带日期与 Level，`image_tags` 记录 CIS 等级 / OS / benchmark，便于溯源。
- 跨地域用 `image.copy_regions`、跨账号用 `image_share_accounts`（需手工在控制台或
  tccli 共享，本工具产出镜像 ID 后接 Terraform / 伸缩组引用）。

## 换操作系统

工具是 **profile 驱动渲染**的：HCL / playbook / 脚本都不用手改，换 OS 只动配置或加一个字典项。

### 内置画像一览

| profile | OS | 角色 | 登录 | 状态 |
|---|---|---|---|---|---|
| `ubuntu22` | Ubuntu 22.04 | `ansible-lockdown.ubuntu22_cis` | ubuntu (ssh) | 完整支持（已验证） |
| `ubuntu24` | Ubuntu 24.04 | `ansible-lockdown.ubuntu24_cis` | ubuntu (ssh) | Preview* |
| `rhel8` | RHEL 8 | `ansible-lockdown.rhel8_cis` | root (ssh) | Preview* |
| `rhel9` | RHEL 9 | `ansible-lockdown.rhel9_cis` | root (ssh) | Preview* |
| `centos8` | CentOS 8（映射 RHEL 8 角色） | `ansible-lockdown.rhel8_cis` | root (ssh) | Preview* |
| `centos9` | CentOS 9（映射 RHEL 9 角色） | `ansible-lockdown.rhel9_cis` | root (ssh) | Preview* |
| `windows2019` | Windows Server 2019 | `Windows-2019-CIS` | Administrator (WinRM) | Preview** |
| `windows2022` | Windows Server 2022 | `Windows-2022-CIS` | Administrator (WinRM) | Preview** |
| `windows2025` | Windows Server 2025 | `Windows-2025-CIS` | Administrator (WinRM) | Preview** |

\* 角色名与变量前缀均已对照 ansible-lockdown 源码核实，但尚未在腾讯云端到端实跑。
按 preview 对待：核对你角色版本的 `[cis].audit_dir`，验证后把 `role_version` 固定。
\*\* Windows 在架构上有本质不同（WinRM + 远程 ansible，不在 VM 里跑 ansible、
无 goss 审计）。WinRM 的 provisioner 接线、成员服务器 L1/L2 变量
（`win22cis_l1_ms` / `win19cis_l1_ms`）需用真实的 Windows 构建来验证——见下方。

### 情况 A：用内置已支持的

只改 `ciscvm.toml` 一行：

```toml
[build]
profile         = "rhel9"                      # 换成内置画像名
source_image_id = "img-真实Rhel9公共镜像ID"     # 必须换成该 OS 的腾讯云公共镜像
```

SSH 用户、CIS 角色名、包管理器、审计目录等 profile 已带，自动渲染，其余命令不变。

### 情况 B：全新 OS（内置没有）

在 `ciscvm.py` 的 `PROFILES` 字典里加一项，再在 `ciscvm.toml` 用它的 key。模板
（RHEL 系示例；非 RHEL 去掉 `os_check_var` / `root_login_rule_var`；
Windows 模板参考 `PROFILES` 已有的 `windows2019` / `windows2022` / `windows2025` 项）：

```python
"almalinux9": {
    "ssh_username": "root",
    "role": "ansible-lockdown.rhel9_cis",        # Galaxy 上的确切角色名
    "role_version": "",                          # "" = 最新；固定版本以可复现
    "audit_dir": "/opt/rhel9_cis",               # 与角色审计输出目录一致
    "os_tag": "almalinux-9",
    "benchmark": "CIS-v2.0.0",
    "pkg_update": "sudo dnf makecache",
    "pkg_install": "sudo dnf install -y python3-pip git",
    "clean_cmd": "sudo dnf clean all",
    "level1_var": "rhel9cis_level_1",            # 等级变量前缀随角色而变
    "level2_var": "rhel9cis_level_2",
    "boot_pass_var": "rhel9cis_set_boot_pass",   # 显式关闭引导/GRUB 密码
    "os_check_var": None,                         # None=不设（仅 RHEL 派生系需要）
    "root_login_rule_var": "rhel9cis_rule_5_2_2",# 保留 root SSH 以便构建期连上
    "preview": True,                             # 未逐一验证就标 True，preflight 会提醒
},
```

然后 `ciscvm.toml` 里 `profile = "almalinux9"`。

### 三个必须和真实角色对齐的点（否则加固/审计会静默失效）

1. **角色名 + 版本**（`ansible-galaxy` 上的确切写法；版本不存在时可改
   `git+https://github.com/ansible-lockdown/<REPO>.git` 兜底）。
2. **等级变量前缀**（`ubtu22cis_` / `rhel9cis_` 等——**Ubuntu 是 `ubtu` 不是 `ubuntu`**；
   看角色 `defaults/main.yml`）。
3. **审计输出目录**（`audit_dir`，即 `ciscvm.toml` 的 `[cis].audit_dir`）。

### 换 CIS Level

`[cis].level = 2`。注意 **Level 2 要求额外分区**
`/var /var/tmp /var/log /var/log/audit /home`（带 `nodev/nosuid/noexec`），
公共镜像默认不满足，需先在源镜像或 user_data 里分好区再 build。

之后照旧：`preflight` → `validate` → `build`。

## Windows Server（preview）

Windows 镜像不能用 `ansible-local` / SSH，也没有 goss 审计。因此工具对 `windows2019` / `windows2022` / `windows2025`
渲染的是**不同的流水线**：

| | Linux | Windows |
|---|---|---|
| 通信方式 | SSH | **WinRM**（`communicator = "winrm"`） |
| Provisioner | `ansible-local`（VM 内执行） | `ansible`（远程，控制器 → 客户机走 WinRM） |
| 角色安装 | 临时 CVM 内（`install-ansible.sh`） | **控制器侧**，`packer build` 前自动 `ansible-galaxy role install git+…` |
| Build 期 gate | goss 审计（`verify-cis.sh`） | **无**（验证方式见下方） |
| 等级选择 | `<role>_level_1/2` + `--tags` | 成员服务器变量 `win22cis_l1_ms` / `win19cis_l1_ms` |

### 构建 Windows CIS 镜像

```toml
[build]
profile         = "windows2022"
source_image_id = "img-真实Windows2022公共镜像ID"

[cloud]
winrm_password_env = "WINRM_PASSWORD"   # Windows 管理员密码（环境变量名）
```

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
export WINRM_PASSWORD='<符合复杂度要求的 Windows Administrator 密码>'
# 控制器需要有 ansible + pywinrm：
pip install 'ansible' pywinrm
python3 ciscvm.py preflight && python3 ciscvm.py build
```

渲染出的 `ansible/site.yml` 会设 `win22cis_ansible_remediation: true` /
`win22cis_create_gpos: false`（GPO / 域相关变量保持关闭，适配独立 golden image）以及
成员服务器 Level（`win22cis_l1_ms: true`，Level 2 则是 `l2_ms`）。WinRM **不会被**加固关掉——
关掉会导致 provisioner 连不上。

### 验证（Windows 没有 goss）

因为 goss 不支持 Windows，build 期 gate **对 Windows 不生效**。在镜像产出**之后**做合规验证：

- 用 **Microsoft Policy Analyzer** 或 **CIS-CAT Pro** 扫描产出的镜像，或
- 用角色自带的上报（按你的角色版本设置 `win22cis_run_audit` / section 级别检查）。

在真实的 Windows 构建验证 WinRM 接线和 L1/L2 成员服务器变量之前，`windows2019` / `windows2022` / `windows2025`
均按 **preview** 对待，跑前请以角色 `defaults/main.yml` 为准。

## 接 CI

在 CNB / 工蜂流水线里：`export` 凭据 → `python3 ciscvm.py build`，下游 CVM / 伸缩组 /
Terraform 用产出的 `image_id` 引用。建议构建机固定专用 VPC + SG。

## 许可证

MIT
