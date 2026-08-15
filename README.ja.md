<p align="center">
  <a href="README.md">English</a> | <a href="README.zh-CN.md">简体中文</a> | <b>日本語</b> | <a href="README.th.md">ภาษาไทย</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.11-blue?logo=python&logoColor=white" alt="Python >= 3.11">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/profiles-12-orange" alt="12 profiles">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/cis-image/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-image/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# ciscvm — CIS ハードニング済みゴールデンイメージビルダー

> 5 つのコマンドで Tencent Cloud 上に CIS ハードニング済みゴールデンイメージを
> 構築。Galaxy 不要、ビルド時ネットワーク依存ゼロ、テンプレート手編集も不要 —
> すべて `ciscvm.toml` で駆動。

**機能：** 一時的な CVM を起動し、同梱の [cis-os](https://github.com/susunola/cis-os)
エンジンを適用して CIS ハードニングを行い、ロール内ゲートを実行し、カスタムイメー
ジとしてキャプチャします。修復後も検出項目が残っていれば、イメージが作成される前に
ビルドが失敗します。

**対象：** 再現可能で監査可能な CIS ハードニング済みベースイメージが必要な DevOps
およびセキュリティエンジニア — CI、Auto Scaling 起動テンプレート、Terraform イメー
ジ参照に利用できます。

## 目次

- [インストール](#インストール)
- [クイックスタート](#クイックスタート)
- [コマンド](#コマンド)
- [設定](#設定)
- [アーキテクチャ](#アーキテクチャ)
- [プロファイル](#プロファイル)
- [CI 連携](#ci-連携)
- [トラブルシューティング](#トラブルシューティング)
- [ロードマップ](#ロードマップ)
- [コントリビューション](#コントリビューション)
- [ライセンス](#ライセンス)
- [CIS Benchmarks に関する免責事項](#cis-benchmarks-に関する免責事項)

## インストール

**前提条件**

| 要件 | 詳細 |
|---|---|
| **Python** | >= 3.11（標準ライブラリのみ — pip 依存ゼロ） |
| **Packer** | >= 1.12 |
| **ansible-core** | >= 2.15（Windows ビルドではコントローラ側に必要） |
| **Tencent Cloud** | `cvm:RunInstances`、`cvm:CreateImage`、`cvm:DescribeImages`、`cvm:CopyImage`* を持つサブアカウント |
| **ネットワーク** | 専用 VPC + サブネット + セキュリティグループ（Linux: SSH/22、Windows: WinRM/5986）、送信元はビルドマシンの Egress IP に限定 |
| **ソースイメージ** | 対象 OS のパブリックイメージ ID |

\* クロスリージョンコピーのみ `cvm:CopyImage` が必要。

**ツールの入手**

```bash
git clone https://github.com/susunola/cis-image.git
cd cis-image

# 推奨: リポジトリからインストール（`ciscvm` コマンドを提供）
pip install .

ciscvm --version

# またはインストールせず実行（リポジトリのルートで）
python3 -m ciscvm --version

# オプション：パッケージとしてインストール
pip install -e ".[dev]"
```

**資格情報の設定**（環境変数のみ、設定ファイルには非保存）

```bash
export TENCENTCLOUD_SECRET_ID=AKIDxxxx
export TENCENTCLOUD_SECRET_KEY=xxxx

# Windows ビルドでは追加で必要：
export WINRM_PASSWORD=xxxx
```

## クイックスタート

```bash
# 1. 設定ファイルを初期化
ciscvm init

# 2. ciscvm.toml を編集し、VPC / サブネット / SG / ソースイメージ ID を設定

# 3. ビルド前チェック（設定・資格情報・前提条件を検証）
ciscvm preflight

# 4. ドライラン：レンダリング + packer validate
ciscvm validate

# 5. ハードニング済みイメージのビルド
ciscvm build

# オプション：レンダリング成果物のクリーンアップ
ciscvm clean
```

**ビルド出力例（`build`）**

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

## コマンド

| コマンド | 説明 |
|---|---|
| `ciscvm init` | カレントディレクトリに `ciscvm.toml` を生成 |
| `ciscvm preflight` | 設定・資格情報・前提条件を検証 |
| `ciscvm validate` | テンプレートをレンダリングし `packer validate` を実行 |
| `ciscvm build` | レンダリング + `packer build`（イメージを生成） |
| `ciscvm clean` | `.ciscvm-build/` 作業ディレクトリを削除 |

| フラグ | デフォルト | 説明 |
|---|---|---|
| `--config <path>` | `./ciscvm.toml` | 設定ファイル |
| `--workdir <dir>` | `./.ciscvm-build` | レンダリング出力ディレクトリ |
| `--quiet` | — | ツール出力を抑制（validate / build） |
| `-y` / `--yes` | — | ビルド確認のプロンプトをスキップ |

## 設定

`ciscvm.toml` が唯一の信頼できる情報源です — Packer テンプレートの手編集は不要。

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
source_image_id     = "img-xxxxxxxx"       # 実際の OS イメージ ID に置換
vpc_id              = "vpc-xxxxxxxx"
subnet_id           = "subnet-xxxxxxxx"
security_group_id   = "sg-xxxxxxxx"
associate_public_ip = true

[image]
name_prefix  = "tencentos3-cis"
copy_regions = ["ap-shanghai"]            # [] でクロスリージョンコピー無効

[cis]
level = 1                                 # 1 または 2

[cloud]
secret_id_env  = "TENCENTCLOUD_SECRET_ID"
secret_key_env = "TENCENTCLOUD_SECRET_KEY"
# Windows ビルドでは追加で必要：
# winrm_password_env = "WINRM_PASSWORD"

[meta]
os_tag    = "tencentos-3"
benchmark = "CIS-v1.0.0"
```

### 設定リファレンス

| セクション | フィールド | 型 | 説明 |
|---|---|---|---|
| `[build]` | `profile` | string | 12 プロファイルのいずれか |
| | `region` | string | Tencent Cloud リージョン（例：`ap-guangzhou`） |
| | `zone` | string | アベイラビリティゾーン（例：`ap-guangzhou-4`） |
| | `instance_type` | string | CVM インスタンス仕様（例：`S5.MEDIUM2`） |
| | `source_image_id` | string | OS パブリックイメージ ID |
| | `vpc_id` / `subnet_id` | string | ネットワーク識別子 |
| | `security_group_id` | string | `sg-` で始まる必要がある |
| | `associate_public_ip` | bool | ビルドインスタンスにパブリック IP を付与 |
| `[image]` | `name_prefix` | string | 出力イメージ名のプレフィックス |
| | `copy_regions` | []string | レプリカ先リージョン（空 = スキップ） |
| `[cis]` | `level` | int | 1（Level 1）または 2（Level 2） |
| `[cloud]` | `secret_id_env` | string | Tencent Cloud Secret ID の環境変数名 |
| | `secret_key_env` | string | Tencent Cloud Secret Key の環境変数名 |
| | `winrm_password_env` | string | Windows Administrator パスワードの環境変数名（Windows のみ） |
| `[meta]` | `os_tag` | string | 出力イメージのタグ値 |
| | `benchmark` | string | CIS benchmark バージョンのタグ |
| | `ssh_port` | int | SSH ポート (デフォルト 22; TencentOS: 36000) |
| | `ssh_timeout` | string | Packer SSH タイムアウト (デフォルト "10m") |
| | `ssh_debug_password` | string | VNC デバッグ用 root パスワード (デフォルト: 設定なし) |

## アーキテクチャ

### Linux ビルドパイプライン（SSH × ansible-local）

```
ビルドマシン                                Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ 一時 CVM          │
│             │                           │   (SSH 22 番)    │
│ ciscvm.toml │                           │ 1. ansible 導入   │
│             │                           │    (dnf/apt/zypp) │
│ roles/      │── CVM へアップロード ────▶│ 2. CIS 適用       │
│   cis_*     │      (同梱ロール)          │    (cis_engine.py)│
│             │                           │ 3. ゲート：       │
│             │                           │    fail_on_findings│
│             │◀── image-id ──────────────│ 4. CreateImage    │
└─────────────┘                           └──────────────────┘
```

Packer は一時 CVM 上で `ansible-local` により 3 フェーズを実行します：

1. **インストール** — OS パッケージマネージャ + pip で ansible-core を導入。
2. **ハードニング** — 同梱の cis-os エンジン（`cis_engine.py` + `rules.json`）を実行。
   変数：`cis_mode: apply`、`cis_profile: L1/L2`、`cis_platform: server`。
3. **ゲート** — ロール内：`cis_fail_on_findings: true` + `cis_min_score: 0`。
   修復後も検出が残っていれば `ansible-playbook` が非ゼロで終了し、Packer はビルドを失敗させます。

### Windows ビルドパイプライン（WinRM × コントローラ側 ansible）

```
ビルドマシン                                Tencent Cloud
┌─────────────┐                           ┌──────────────────┐
│ ciscvm/     │── packer build ──────────▶│ 一時 CVM          │
│             │                           │  (WinRM 5986)    │
│             │                           │                  │
│ roles/      │── ansible プロビジョナー ─▶│ CIS 適用          │
│   cis_win*  │   (コントローラ側、       │ (cis_engine.ps1)  │
│             │    winrm 接続)            │                  │
│             │                           │ ロール内ゲート    │
│             │◀── image-id ──────────────│ CreateImage       │
└─────────────┘                           └──────────────────┘
```

Windows ビルドは Packer の `ansible` プロビジョナー（コントローラ側）を WinRM 経由
で使用します。同梱ロールには `cis_engine.ps1`（PowerShell）が含まれます。インスタ
ンス側には何もインストール不要 — コントローラ側に `ansible-core` が必要です。

### 設計上の判断

**ロールは同梱、Galaxy なし。**
12 種すべての cis-os エンジンロールをパッケージ内の `ciscvm/roles/` に同梱。ビルド
時にツールが選択されたロールを作業ディレクトリへコピー。ネットワーク依存なし、
バージョン漂流なし。

**`ansible-local`（Linux）— インスタンス内で自己完結。**
Packer コントローラはクラウド VPC へ SSH できる必要がありません。Playbook と
ロールはビルドインスタンス内で実行されます。

**`ansible`（Windows）— コントローラから WinRM 駆動。**
Windows イメージは Packer の `ansible` プロビジョナーをコントローラから使用し、
WinRM で接続します。コントローラ側に `ansible-core` のインストールが必要。

**ビルド時ゲート、外部監査なし。**
ゲートは Ansible ロール内（`cis_fail_on_findings`）。ハードニング済みイメージは
合格するか、作成されないかのいずれかです。

**資格情報とガバナンス。**
AK/SK は環境変数のみ（HCL の `sensitive = true`）。一時インスタンスはタグ付けされ
自動回収されます。イメージタグに CIS レベル、OS、benchmark を記録。

## プロファイル

### Linux（SSH × ansible-local）

| プロファイル | OS | SSH ユーザー | パッケージマネージャ | ロール |
|---|---|---|---|---|
| `ubuntu2004` | Ubuntu 20.04 LTS | ubuntu | apt | `roles/cis_ubuntu2004/` |
| `ubuntu2204` | Ubuntu 22.04 LTS | ubuntu | apt | `roles/cis_ubuntu2204/` |
| `ubuntu2404` | Ubuntu 24.04 LTS | ubuntu | apt | `roles/cis_ubuntu2404/` |
| `rhel8` | RHEL 8 | root | dnf | `roles/cis_rhel8/` |
| `rhel9` | RHEL 9 | root | dnf | `roles/cis_rhel9/` |
| `rhel10` | RHEL 10 | root | dnf | `roles/cis_rhel10/` |
| `tencentos3` | TencentOS Server 3 | root | dnf | `roles/cis_tencentos3/` |
| `tencentos4` | TencentOS Server 4 | root | dnf | `roles/cis_tencentos4/` |

### Windows（WinRM × コントローラ側 ansible）

| プロファイル | OS | ユーザー | ロール |
|---|---|---|---|
| `win2016` | Windows Server 2016 | Administrator | `roles/cis_win2016/` |
| `win2019` | Windows Server 2019 | Administrator | `roles/cis_win2019/` |
| `win2022` | Windows Server 2022 | Administrator | `roles/cis_win2022/` |
| `win2025` | Windows Server 2025 | Administrator | `roles/cis_win2025/` |

プロファイルを切り替えるには、`ciscvm.toml` の `[build].profile` と `source_image_id`
を変更してください。

## テストマトリクス

検証済み CIS  hardened イメージの OS × レベル一覧。
すべて Tencent Cloud 広州リージョンで `cis_allow_disruptive: false` によりビルドされ、
以下のイメージは 2026-08-14 にコンソールで `NORMAL` であることを再確認済みです。

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

> スコアは再起動後の再監査結果です（全評価ルール対象、ゲート ≥ 85）。
> kmod 系ルールは永続的な modprobe install-override で適用されるため、
> ビルド時にルールを除外する必要はありません。
> Windows イメージは Tencent Cloud 公開イメージ(英語版/中国語版)からの
> メンバーサーバー構成で、2026-08-14 にビルド・再監査済み。スナップショット前に
> WinRM は再ロック済み(Basic/平文 HTTP 無効、Administrator パスワードはランダム化)。
> 各 Windows ビルドで残る唯一の fail は「Deny access to this computer from the
> network → S-1-5-114 を含む」(2.2.2x) で、disruptive として意図的にスキップして
> います(適用するとビルドが利用する WinRM セッションが切断されるため)。
> 起動後に `cis_allow_disruptive: true` で有効化できます。

## CI 連携

```bash
export TENCENTCLOUD_SECRET_ID=xxx
export TENCENTCLOUD_SECRET_KEY=xxx

# Windows ビルド：
# export WINRM_PASSWORD=xxx

ciscvm build
```

下流の CVM / Auto Scaling / Terraform は出力された `image_id` を参照してください。
ビルドマシンは専用の VPC と SG にピン留めします。

## トラブルシューティング

| 症状 | 原因 | 解決策 |
|---|---|---|
| `preflight` で資格情報エラー | `TENCENTCLOUD_SECRET_ID` / `_KEY` 未設定 | シェルで `export TENCENTCLOUD_SECRET_ID=...` を実行 |
| `validate` でプラグインダウンロードエラー | `packer init` 失敗（オフラインビルドマシンなど） | インターネット接続ありで `ciscvm validate` を再実行 — Packer は初回ダウンロード後にプラグインをキャッシュします |
| Packer が SSH 待機中にタイムアウト | セキュリティグループがポート 22 を許可していない | インバウンドルールを追加：TCP/22、送信元はビルドマシンの Egress IP |
| `ansible-playbook` で "python3 not found" | ビルドインスタンスの OS に Python 未導入 | ソースイメージに Python >= 3.6 が含まれていることを確認 |
| Windows ビルドで WinRM 接続エラー | `WINRM_PASSWORD` 未設定またはネットワーク不通 | パスワードを export + TCP/5986 がビルド IP から接続可能か確認 |
| ビルド成功後も CIS 検出が残っている | 当該 OS の一部ルールが未対応 | まず `level: 1`（Level 1 は主要な検出項目をカバー）で再実行 |

## ロードマップ

- [ ] CI パイプライン（GitHub Actions）による自動イメージビルド
- [ ] PyPI パッケージ（`pip install ciscvm`）
- [ ] `ciscvm list` — 利用可能なプロファイルとメタデータの一覧表示
- [ ] `ciscvm report` — 完了したビルドの監査レポートを取得・表示
- [ ] カスタムルール選択（`ciscvm.toml` の `rules_include` / `rules_exclude`）

## コントリビューション

バグ報告とプルリクエストを歓迎します。提出前にテストを実行してください：

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## ライセンス

MIT — [LICENSE](LICENSE) を参照。

## CIS Benchmarks に関する免責事項

本ツールは CIS Benchmark 推奨事項に基づくハードニングルールを適用します。
CIS Benchmarks は [Center for Internet Security](https://www.cisecurity.org/)（CIS）
によって策定・保守されています。本リポジトリに同梱されている cis-os エンジンロール
は [susunola/cis-os](https://github.com/susunola/cis-os) プロジェクトから派生した
ものであり、それぞれのライセンスに基づいて提供されています。

**重要：** `apply` モードでの CIS ハードニングはシステム設定を変更し、アプリケー
ション互換性に影響を与える可能性があります。本番環境で使用する前に、必ずステージ
ング環境でハードニング済みイメージをテストしてください。CIS 組織および本ツールの
作者は、適用されたルールが完全なコンプライアンスを達成することを保証しません —
正式な監査には CIS-CAT または同等のツールによる独立した評価が必要です。
