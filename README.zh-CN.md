<p align="center">
  <a href="README.md">English</a> | <b>简体中文</b>
</p>

# ciscvm — TencentOS CIS 镜像构建

在腾讯云上自动化产出 CIS 加固的 TencentOS 黄金镜像。配置驱动的 CLI 工具：
起一台临时 CVM → 应用捆绑的 cis-os 引擎进行 CIS 加固 → 内建门禁校验 → 捕获为
自定义镜像。全部由 `ciscvm.toml` 驱动。

支持：**TencentOS Server 3 / 4**。CIS 引擎（`cis_engine.py` + `rules.json`）
本地捆绑在 `roles/` 目录下 — 无需 Ansible Galaxy，构建时无网络依赖。门禁在
Ansible 角色内执行（`cis_fail_on_findings: true`）：加固后仍有残留发现项则
构建失败，镜像不入库。

## 项目结构

```
cis-cvm-image/
├── ciscvm.py                 # CLI 工具（纯标准库，单文件）
├── ciscvm.toml               # 构建配置（`init` 生成）
├── README.md / README.zh-CN.md
├── LICENSE                   # MIT
├── roles/                    # 捆绑 cis-os 引擎
│   ├── cis_tencentos3/       #   cis_engine.py + rules.json + Ansible 角色
│   └── cis_tencentos4/
└── .ciscvm-build/            # 渲染工作目录（git 忽略）
    ├── packer/
    │   ├── main.pkr.hcl
    │   ├── auto.pkrvars.hcl
    │   └── scripts/
    │       └── install-ansible.sh
    └── ansible/
        ├── site.yml
        └── roles/            # 构建时从 ../roles/ 复制
```

## 前置条件

| 条件 | 说明 |
|---|---|
| **Python** | >= 3.11，仅用标准库，无 pip 依赖 |
| **Packer** | >= 1.9，需 `packer-plugin-tencentcloud` 插件 |
| **腾讯云** | 子账号，最少权限：`cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* |
| **网络** | 专用构建 VPC + 子网 + 安全组（放行 22 入站，来源限定构建机出口 IP） |
| **源镜像** | TencentOS Server 3 或 4 公共镜像 ID |

\* 跨地域复制才需要 `cvm:CopyImage`。

凭据仅通过环境变量传入：

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx
```

## 快速开始

```bash
# 1. 生成配置文件
python3 ciscvm.py init

# 2. 编辑 ciscvm.toml，填入 VPC / 子网 / SG / TencentOS 源镜像 ID

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
profile             = "tencentos3"         # tencentos3 | tencentos4
region              = "ap-guangzhou"
zone                = "ap-guangzhou-4"
instance_type       = "S5.MEDIUM2"
source_image_id     = "img-xxxxxxxx"       # 替换为实际 TencentOS 镜像 ID
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

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### 配置参考

| 节 | 字段 | 类型 | 说明 |
|---|---|---|---|
| `[build]` | `profile` | string | `tencentos3` 或 `tencentos4` |
| | `region` | string | 腾讯云地域，如 `ap-guangzhou` |
| | `zone` | string | 可用区，如 `ap-guangzhou-4` |
| | `instance_type` | string | CVM 实例规格，如 `S5.MEDIUM2` |
| | `source_image_id` | string | TencentOS 公共镜像 ID |
| | `vpc_id` / `subnet_id` | string | 网络标识 |
| | `security_group_id` | string | 必须以 `sg-` 开头 |
| | `associate_public_ip` | bool | 为构建实例分配公网 IP |
| `[image]` | `name_prefix` | string | 产出镜像名称前缀 |
| | `copy_regions` | []string | 跨地域复制目标（空 = 跳过） |
| `[cis]` | `level` | int | 1（Level 1）或 2（Level 2） |
| `[cloud]` | `secret_id_env` | string | Secret ID 环境变量名 |
| | `secret_key_env` | string | Secret Key 环境变量名 |
| `[meta]` | `os_tag` | string | 产出镜像标签值 |
| | `benchmark` | string | CIS benchmark 版本标签 |

## 架构

### 构建流水线

```
构建机                                     腾讯云
┌─────────────┐                           ┌──────────────────┐
│ ciscvm.py   │── packer build ──────────▶│ 临时 CVM          │
│             │                           │                  │
│ ciscvm.toml │                           │ 1. 安装 ansible   │
│             │                           │    (dnf + pip)     │
│ roles/      │── 上传至 CVM ────────────▶│ 2. CIS 执行       │
│   cis_*     │      (捆绑角色)            │    (cis_engine.py) │
│             │                           │ 3. 门禁：         │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer 在临时 CVM 上执行三个阶段：

1. **安装** — 通过 dnf + pip 安装 ansible-core。
2. **加固** — `ansible-local` 运行捆绑的 cis-os 引擎（`cis_engine.py` + `rules.json`）。
   变量：`cis_mode: apply`、`cis_profile: L1/L2`、`cis_platform: server`。
3. **门禁** — 角色内执行：`cis_fail_on_findings: true` + `cis_min_score: 0`。
   加固后仍有残留发现项则 `ansible-playbook` 非零退出，Packer 构建失败。
   无需独立的 verify 脚本。

### 设计要点

**捆绑角色，无 Galaxy。**
cis-os 引擎随 `ciscvm.py` 一起发布在 `roles/` 目录下。构建时工具将角色复制到
工作目录。无网络依赖，无版本漂移。

**选择 `ansible-local` 而非 `ansible`。**
Packer 控制器不需要能 SSH 进云内网，playbook 和角色全部在实例内执行。

**内建门禁，无外部审计。**
门禁在 Ansible 角色内部（`cis_fail_on_findings`），无独立的 goss 审计步骤。
加固后的镜像要么通过、要么不创建。

**凭据与治理。**
AK/SK 仅通过环境变量传入（HCL `sensitive = true`）。临时实例打标并自动回收。
镜像标签记录 CIS 等级、OS 和 benchmark。

## 画像

| Profile | 操作系统 | SSH 用户 | 角色 |
|---|---|---|---|
| `tencentos3` | TencentOS Server 3 | root | `roles/cis_tencentos3/` |
| `tencentos4` | TencentOS Server 4 | root | `roles/cis_tencentos4/` |

切换画像仅需改 `ciscvm.toml` 中的 `[build].profile` 和 `source_image_id`。

Level 2 要求额外分区（`/var`、`/var/tmp`、`/var/log`、`/var/log/audit`、
`/home` 均需 `nodev`、`nosuid`、`noexec`），需在源镜像或 `user_data` 中配置好
分区再构建。

## 对接 CI

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx
python3 ciscvm.py build
```

下游 CVM / 伸缩组 / Terraform 引用产出的 `image_id`。构建机固定专用 VPC + SG。

## 许可证

MIT
