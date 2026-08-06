#!/usr/bin/env bash
# ============================================================================
# ciscvm — 清理 + 升级 + 构建 一键脚本
#
# 用法:
#   bash /opt/rebuild.sh            # 清理旧版 → 重装最新 → 跑构建
#   bash /opt/rebuild.sh --skip-upgrade   # 只清理并重跑构建（不重装）
#   bash /opt/rebuild.sh --dry-run        # 只打印将执行的命令，不执行
#
# 环境约定（与你的部署一致）:
#   - 工作目录:      /opt
#   - 配置文件:      /opt/ciscvm.toml
#   - AK/SK 环境变量: /opt/env （格式: export TENCENTCLOUD_SECRET_ID=xxx
#                                 export TENCENTCLOUD_SECRET_KEY=xxx）
#   - 构建日志:      /opt/run.log
# ============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 可调参数
# ---------------------------------------------------------------------------
WORK_DIR="${WORK_DIR:-/opt}"
CONFIG_FILE="${CONFIG_FILE:-${WORK_DIR}/ciscvm.toml}"
ENV_FILE="${ENV_FILE:-${WORK_DIR}/env}"
LOG_FILE="${LOG_FILE:-${WORK_DIR}/run.log}"
REPO_URL="https://github.com/susunola/cis-cvm-image-builder.git"
MIN_VERSION="0.9.2"          # 低于此版本视为旧版，重装后必须 >= 该版本
SKIP_UPGRADE=0
DRY_RUN=0

# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[rebuild]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[rebuild]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[rebuild]\033[0m %s\n' "$*" >&2; exit 1; }

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '\033[1;36m[rebuild][dry]\033[0m %s\n' "$*"
        return 0
    fi
    "$@"
}

# 版本比较: a >= b ? （处理 0.9.2 / 1.0.0 这类纯数字点分版本）
ver_ge() {
    local a b ia ib
    IFS=. read -r -a ia <<< "$1"
    IFS=. read -r -a ib <<< "$2"
    for i in 0 1 2; do
        a="${ia[$i]:-0}"; b="${ib[$i]:-0}"
        if (( a > b )); then return 0; fi
        if (( a < b )); then return 1; fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# 0. 解析参数
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --skip-upgrade) SKIP_UPGRADE=1 ;;
        --dry-run)      DRY_RUN=1 ;;
        *) die "未知参数: ${arg}（支持 --skip-upgrade / --dry-run）" ;;
    esac
done

# ---------------------------------------------------------------------------
# 1. 进入工作目录
# ---------------------------------------------------------------------------
cd "$WORK_DIR" || die "无法进入工作目录 $WORK_DIR"

# ---------------------------------------------------------------------------
# 2. 加载 AK/SK（幂等，支持 export 或裸 KEY=VALUE 两种写法）
# ---------------------------------------------------------------------------
if [ -f "$ENV_FILE" ]; then
    set -a                              # 自动导出后续赋值
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
    log "已加载 AK/SK: $ENV_FILE"
else
    die "找不到 AK/SK 文件: ${ENV_FILE}（请创建并写入 export TENCENTCLOUD_SECRET_ID=... / TENCENTCLOUD_SECRET_KEY=...）"
fi

if [ -z "${TENCENTCLOUD_SECRET_ID:-}" ] || [ -z "${TENCENTCLOUD_SECRET_KEY:-}" ]; then
    die "AK/SK 未设置完整（$ENV_FILE 中缺少 TENCENTCLOUD_SECRET_ID 或 TENCENTCLOUD_SECRET_KEY）"
fi

# ---------------------------------------------------------------------------
# 3. 清理：卸载旧包 + 删除渲染工作目录
# ---------------------------------------------------------------------------
log "==> 清理旧版本 =="
run pip uninstall -y ciscvm 2>/dev/null || true
if [ -d "${WORK_DIR}/.ciscvm-build" ]; then
    log "删除渲染目录: ${WORK_DIR}/.ciscvm-build"
    run rm -rf "${WORK_DIR}/.ciscvm-build"
fi
# 清掉 pip 对 git 源的缓存，避免重装时命中旧 wheel
run pip cache purge 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. 升级：从 GitHub main 分支强制重装
# ---------------------------------------------------------------------------
if [ "$SKIP_UPGRADE" -eq 1 ]; then
    log "==> 跳过升级（--skip-upgrade）=="
else
    log "==> 从 $REPO_URL@main 重装最新版 =="
    run pip install --no-cache-dir --force-reinstall \
        "git+${REPO_URL}@main"
fi

# ---------------------------------------------------------------------------
# 5. 版本校验：必须 >= MIN_VERSION，防止又跑旧代码
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    log "当前版本: (dry-run 跳过版本校验)"
elif command -v ciscvm >/dev/null 2>&1; then
    INSTALLED_VERSION="$(ciscvm --version | awk '{print $2}')"
    log "当前版本: ${INSTALLED_VERSION}（要求 >= ${MIN_VERSION}）"
    if ! ver_ge "$INSTALLED_VERSION" "$MIN_VERSION"; then
        die "版本过低: $INSTALLED_VERSION < ${MIN_VERSION}。请检查 pip 源/网络后重试。"
    fi
else
    die "ciscvm 不在 PATH。请检查 pip 安装是否成功。"
fi

# ---------------------------------------------------------------------------
# 6. 构建
# ---------------------------------------------------------------------------
log "==> 开始构建（配置: ${CONFIG_FILE}，日志: ${LOG_FILE}）=="
if [ ! -f "$CONFIG_FILE" ]; then
    die "找不到配置文件: $CONFIG_FILE"
fi

# 预检通过后再正式构建；-y 跳过交互确认，--log-file 输出到 run.log
run ciscvm preflight --config "$CONFIG_FILE"
run ciscvm build --config "$CONFIG_FILE" --yes --log-file "$LOG_FILE"

log "==> 构建完成，日志: $LOG_FILE =="
log "（如需再次运行: bash ${0}）"
