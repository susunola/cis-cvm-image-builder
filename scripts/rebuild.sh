#!/usr/bin/env bash
# 一键: 彻底清理 → 重新 clone → 装最新 ciscvm → 带日志 build
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

echo "[2/5] 彻底清理旧文件"
# 旧代码目录（含 .venv / __pycache__ / *.egg-info / .ciscvm-build 渲染残留）
rm -rf "$REPO"
# 卸载旧 ciscvm
pip uninstall -y ciscvm >/dev/null 2>&1 || true
# 清 pip 缓存，避免重装命中旧 wheel
pip cache purge >/dev/null 2>&1 || true
# 保险：当前目录下可能残留的渲染目录
rm -rf ./.ciscvm-build

echo "[3/5] 重新拉取代码"
git clone https://github.com/susunola/cis-cvm-image-builder.git "$REPO"
cd "$REPO"

echo "[4/5] 全新安装 ciscvm"
pip install --no-cache-dir --force-reinstall .

echo "[5/5] 构建 (日志: $LOG)"
ciscvm build --config "$CONFIG" --yes --log-file "$LOG"
