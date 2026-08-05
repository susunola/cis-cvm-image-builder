#!/usr/bin/env bash
# build 期 CIS 审计 gate：加固后跑 goss 审计，失败项超限则 exit 1 让 packer build 失败
# 可调环境变量：
#   CIS_AUDIT_DIR     角色审计输出目录（默认 /opt/ubuntu22_cis，按角色版本调整）
#   CIS_MAX_FAILURES  允许的失败项数（默认 0）
set -uo pipefail

AUDIT_DIR="${CIS_AUDIT_DIR:-/opt/ubuntu22_cis}"
MAX_FAILURES="${CIS_MAX_FAILURES:-0}"

if [ ! -d "$AUDIT_DIR" ]; then
  echo "WARN: 审计目录 $AUDIT_DIR 不存在，跳过硬 gate。" >&2
  echo "      请按你使用的角色版本设置 CIS_AUDIT_DIR（参考角色 README 的 audit 输出位置）。" >&2
  exit 0
fi

LOG="$(mktemp)"
if [ -x "$AUDIT_DIR/run_audit.sh" ]; then
  echo "==> 运行角色自带审计 run_audit.sh"
  bash "$AUDIT_DIR/run_audit.sh" | tee "$LOG" || true
elif command -v goss >/dev/null 2>&1 && [ -f "$AUDIT_DIR/goss.yaml" ]; then
  echo "==> 直接运行 goss"
  goss -g "$AUDIT_DIR/goss.yaml" render --format json >/dev/null 2>&1 || true
  goss -g "$AUDIT_DIR/goss.yaml" validate | tee "$LOG" || true
else
  echo "WARN: 在 $AUDIT_DIR 未找到 run_audit.sh 或 goss，跳过硬 gate。" >&2
  exit 0
fi

# 解析失败项数（兼容 goss 多种摘要格式）
if grep -qiE 'Failed[[:space:]]*:[[:space:]]*[0-9]+' "$LOG"; then
  failures=$(grep -oiE 'Failed[[:space:]]*:[[:space:]]*([0-9]+)' "$LOG" | grep -oE '[0-9]+' | head -1)
elif grep -qiE '[0-9]+[[:space:]]*fail' "$LOG"; then
  failures=$(grep -oiE '([0-9]+)[[:space:]]*fail' "$LOG" | grep -oE '[0-9]+' | head -1)
else
  failures=$(grep -ciE '\bFAIL\b' "$LOG")
fi
failures="${failures:-0}"

echo "------------------------------------------------------------"
echo "CIS 审计失败项: $failures  (容忍上限: $MAX_FAILURES)"
echo "------------------------------------------------------------"

if [ "$failures" -gt "$MAX_FAILURES" ]; then
  echo "ERROR: CIS 审计失败项 ($failures) 超过容忍上限 ($MAX_FAILURES)，构建失败。" >&2
  exit 1
fi

echo "OK: CIS 审计在容忍范围内，构建继续。"
exit 0
