# ciscvm — Packer × 腾讯云 CVM × CIS 镜像构建小工具

用 Packer 起临时 CVM，通过 `ansible-local` provisioner 跑
[ansible-lockdown](https://github.com/ansible-lockdown) 的 CIS 角色做系统加固（remediation），
再用 goss 审计做 build 期 gate，最终产出符合 CIS 基准的自定义镜像（golden image）。

整套流程收敛成一个**配置驱动的单命令工具**：`ciscvm.toml` 是唯一事实来源，
HCL / playbook / 脚本全部在构建时由配置渲染生成，不用手改 HCL。

> 默认目标：**Ubuntu 22.04 + CIS Level 1**。换 OS / Level 见文末「画像」。

## 目录

```
cis-cvm-image/
├── ciscvm.py                    # 工具本体（纯标准库，单文件，python3 直接跑）
├── README.md
├── packer/  ansible/  .gitignore   # 旧版手写文件，仅作参考；现在由工具渲染生成
└── ciscvm.toml                  # init 后生成的配置文件（单事实来源）
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
5. 官方 Ubuntu 22.04 公共镜像 ID（`source_image_id`）。控制台镜像页查看，
   或 `tccli cvm DescribeImages --Filters '[{"Name":"image-type","Values":["PUBLIC_IMAGE"]}]'`。

## 用法

```bash
# 1. 生成示例配置（写入 ciscvm.toml + .gitignore）
python3 ciscvm.py init

# 2. 编辑 ciscvm.toml：填 VPC / 子网 / SG / 源镜像ID；凭据仍走环境变量

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
在临时 CVM 内执行 `ansible-lockdown.ubuntu22_cis` 角色，逐条按 CIS 编号 remediation。
选 `ansible-local`（而非 `ansible`）是不让 Packer 控制机需要能 SSH 进云内网——
playbook 和角色都直接在实例里跑。

### 2. 云环境例外（务必保留，否则会把自己锁死）
`ansible/site.yml` 里已做：
- `ubuntu22cis_ssh_keys: true` —— 保留 SSH 公钥登录，不强制 password-only；
- 不启用会破坏 `cloud-init` / IMDS 的控制项（保持角色默认）；
- GRUB 引导密码默认关闭，且通过 `-e grub_user_pass=` 传空值规避角色已知 bug。

### 3. build 期 gate（不达标就失败）
`verify-cis.sh` 在加固后跑 goss 审计，解析失败项数；超过 `cis.max_failures`（默认 0）
就 `exit 1`，让 `packer build` 失败、镜像不入库存。审计目录默认 `/opt/ubuntu22_cis`，
如与你的角色版本不符，改 `ciscvm.toml` 的 `[cis].audit_dir` 即可。

### 4. 凭据 / 网络 / 治理
- AK/SK 只走环境变量，`sensitive = true`，绝不入库。
- 专用构建 VPC + SG，临时机器用完自动回收。
- 镜像名带日期与 Level，`image_tags` 记录 CIS 等级 / OS / benchmark，便于溯源。
- 跨地域用 `image.copy_regions`、跨账号用 `image_share_accounts`（需手工在控制台或
  tccli 共享，本工具产出镜像 ID 后接 Terraform / 伸缩组引用）。

## 换操作系统

工具是 **profile 驱动渲染**的：HCL / playbook / 脚本都不用手改，换 OS 只动配置或加一个字典项。

### 情况 A：用内置已支持的

`ubuntu22` 完整支持；`tencentos3` 是 preview 骨架。只改 `ciscvm.toml` 一行：

```toml
[build]
profile         = "tencentos3"                 # 换成内置画像名
source_image_id = "img-真实TencentOS公共镜像ID" # 必须换成该 OS 的腾讯云公共镜像
```

ssh 用户、CIS 角色名、包管理器、审计目录等 profile 已带，自动渲染，其余命令不变。

### 情况 B：全新 OS（内置没有）

在 `ciscvm.py` 的 `PROFILES` 字典里加一项，再在 `ciscvm.toml` 用它的 key。模板：

```python
"ubuntu24": {
    "ssh_username": "ubuntu",
    "role": "ansible-lockdown.UBUNTU24-CIS",   # 角色名+版本以 Galaxy 为准
    "role_version": "1.0.0",
    "audit_dir": "/opt/ubuntu24_cis",          # 与角色审计输出目录一致
    "os_tag": "ubuntu-24.04",
    "benchmark": "CIS-v2.0.0",
    "pkg_update": "sudo apt-get update -y",
    "pkg_install": "sudo apt-get install -y python3-pip python3-venv git",
    "level1_var": "ubuntu24cis_level_1",       # 等级变量前缀随角色而变
    "level2_var": "ubuntu24cis_level_2",
    "ssh_keys_var": "ubuntu24cis_ssh_keys",
    "preview": True,                            # 未逐一验证就标 True，preflight 会提醒
},
```

然后 `ciscvm.toml` 里 `profile = "ubuntu24"`。

### 三个必须和真实角色对齐的点（否则加固/审计会静默失效）

1. **角色名 + 版本**（`ansible-galaxy` 上的确切写法；2.0.0 不存在时可改 `git+https://github.com/ansible-lockdown/UBUNTU22-CIS.git` 兜底）。
2. **等级变量前缀**（`ubuntu22cis_` / `rhel9cis_` / `tencentos3_cis_` 等，看角色 `defaults/main.yml`）。
3. **审计输出目录**（`audit_dir`，即 `ciscvm.toml` 的 `[cis].audit_dir`）。

### 内置画像一览

| profile | OS | 角色 | ssh 用户 | 状态 |
|---|---|---|---|---|
| `ubuntu22` | Ubuntu 22.04 | `ansible-lockdown.ubuntu22_cis` | ubuntu | 完整支持 |
| `tencentos3` | TencentOS 3 | `ansible-lockdown.TencentOS3-CIS` | root | preview（角色名/变量名未逐一验证） |

### 换 CIS Level

`[cis].level = 2`。注意 **Level 2 要求额外分区** `/var /var/tmp /var/log /var/log/audit /home`
（带 `nodev/nosuid/noexec`），公共镜像默认不满足，需先在源镜像或 user_data 里分好区再 build。

之后照旧：`preflight` → `validate` → `build`。

## 接 CI

在 CNB / 工蜂流水线里：`export` 凭据 → `python3 ciscvm.py build`，下游 CVM / 伸缩组 /
Terraform 用产出的 `image_id` 引用。建议构建机固定专用 VPC + SG。
