#!/usr/bin/env bash
# 一键: 彻底清理 → 重新 clone → 装最新 ciscvm → 校验版本一致 → 带日志 build
# --upload  构建后将 run.log 推送到 git（省去 scp 手动传日志）
set -euo pipefail

REPO=/opt/cis-cvm-image-builder
CONFIG=/opt/ciscvm.toml
ENV_FILE=/opt/env
LOG=/opt/run.log
GITHUB_TOKEN=${GITHUB_TOKEN:-}
GIT_REMOTE=https://${GITHUB_TOKEN}@github.com/susunola/cis-cvm-image-builder.git

# ── 参数解析 ──
UPLOAD=false
for arg in "$@"; do
    case "$arg" in
        --upload) UPLOAD=true ;;
        *) echo "未知参数: $arg"; exit 1 ;;
    esac
done

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
pip install --no-cache-dir --force-reinstall .

echo "[5/6] 校验代码与二进制版本一致"
CODE_VERSION=$(grep -m1 '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')
BIN_VERSION=$(ciscvm --version | awk '{print $2}')
echo "     代码版本: $CODE_VERSION | 二进制版本: $BIN_VERSION"
if [ "$CODE_VERSION" != "$BIN_VERSION" ]; then
    echo "ERROR: 版本不一致，二进制不是从当前代码构建的！" >&2
    exit 1
fi

echo "[6/6] 构建 (日志: $LOG, debug 开启)"
BUILD_RC=0
ciscvm build --config "$CONFIG" --yes --debug --log-file "$LOG" || BUILD_RC=$?

# ── 上传日志到 git（run.log 每次覆写，必定产生新 commit）──
if $UPLOAD; then
    echo "[7/7] 上传日志"
    mkdir -p "$REPO/logs"
    cp "$LOG" "$REPO/logs/run.log"
    cd "$REPO"
    git add logs/run.log
    git -c user.name="rebuild-bot" \
        -c user.email="bot@cis-cvm" \
        commit -m "ci: run.log ($(date '+%Y-%m-%d %H:%M:%S'))"
    git push "$GIT_REMOTE"
    echo "     已推送: $(git rev-parse --short HEAD)"
fi

exit $BUILD_RC
