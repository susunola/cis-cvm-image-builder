#!/usr/bin/env bash
# 一键: 清理 /opt/cis-cvm-image-builder → 重新 clone → 装最新 ciscvm → 带日志 build
set -euo pipefail

REPO=/opt/cis-cvm-image-builder
CONFIG=/opt/ciscvm.toml
ENV_FILE=/opt/env
LOG=/opt/run.log

echo "[1/5] 加载 AK/SK ($ENV_FILE)"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "[2/5] 清理旧代码目录: $REPO"
rm -rf "$REPO"

echo "[3/5] 重新拉取代码"
git clone https://github.com/susunola/cis-cvm-image-builder.git "$REPO"
cd "$REPO"

echo "[4/5] 全新安装 ciscvm"
pip uninstall -y ciscvm >/dev/null 2>&1 || true
pip install --no-cache-dir --force-reinstall .

echo "[5/5] 构建 (日志: $LOG)"
ciscvm build --config "$CONFIG" --yes --log-file "$LOG"
