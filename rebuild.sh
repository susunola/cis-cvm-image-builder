#!/usr/bin/env bash
# 一键: 彻底清理 → 重新 clone → 装最新 ciscvm → 校验版本一致 → 带日志 build
set -euo pipefail

REPO=/opt/cis-cvm-image-builder
CONFIG=/opt/ciscvm.toml
ENV_FILE=/opt/env
LOG=/opt/run.log

echo "[1/6] 加载 AK/SK ($ENV_FILE)"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "[2/6] 彻底清理旧文件"
rm -rf "$REPO"
pip uninstall -y ciscvm >/dev/null 2>&1 || true
pip cache purge >/dev/null 2>&1 || true
rm -rf ./.ciscvm-build

echo "[3/6] 重新拉取代码 (main 分支最新)"
git clone https://github.com/susunola/cis-cvm-image-builder.git "$REPO"
cd "$REPO"
echo "     commit: $(git rev-parse --short HEAD)"

echo "[4/6] 全新安装 ciscvm"
pip install --no-cache-dir --force-reinstall --root-user-action=ignore .

echo "[5/6] 校验代码与二进制版本一致"
# 版本号单一来源: ciscvm/__init__.py 的 VERSION（pyproject 动态读取它）
CODE_VERSION=$(grep -m1 '^VERSION = ' ciscvm/__init__.py | sed 's/^VERSION = "//;s/"$//')
BIN_VERSION=$(ciscvm --version | awk '{print $2}')
echo "     代码版本: $CODE_VERSION | 二进制版本: $BIN_VERSION"
if [ "$CODE_VERSION" != "$BIN_VERSION" ]; then
    echo "ERROR: 版本不一致，二进制不是从当前代码构建的！" >&2
    exit 1
fi

echo "[6/6] 构建 (日志: $LOG, debug 开启)"
ciscvm build --config "$CONFIG" --yes --debug --log-file "$LOG"
