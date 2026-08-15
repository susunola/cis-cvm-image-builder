#!/usr/bin/env bash
# One-shot: full clean -> fresh clone -> install latest cis-image -> verify
# version consistency -> build with logging.
set -euo pipefail

REPO=/opt/cis-image
CONFIG="$REPO/cis-image.toml"
ENV_FILE=/opt/env
LOG=/opt/run.log

echo "[1/6] Loading AK/SK ($ENV_FILE)"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "[2/6] Purging old files"
# Preserve the local build config across the repo wipe — it lives INSIDE
# the checkout ($REPO/cis-image.toml) so it is clearly project-scoped.
[ -f "$CONFIG" ] && cp "$CONFIG" /tmp/cis-image.toml.save
rm -rf "$REPO"
pip uninstall -y cis-image >/dev/null 2>&1 || true
pip cache purge >/dev/null 2>&1 || true
rm -rf ./.cis-image-build

echo "[3/6] Cloning latest code (main branch)"
git clone https://github.com/susunola/cis-image.git "$REPO"
cd "$REPO"
echo "     commit: $(git rev-parse --short HEAD)"
if [ -f /tmp/cis-image.toml.save ]; then
    cp /tmp/cis-image.toml.save "$CONFIG"
    rm -f /tmp/cis-image.toml.save
    echo "     restored $CONFIG"
fi

echo "[4/6] Fresh-installing cis-image"
pip install --no-cache-dir --force-reinstall --root-user-action=ignore .

echo "[5/6] Verifying code/binary version match"
# Single source of truth for the version: cis_image/__init__.py VERSION
# (pyproject reads it dynamically).
CODE_VERSION=$(grep -m1 '^VERSION = ' cis_image/__init__.py | sed 's/^VERSION = "//;s/"$//')
BIN_VERSION=$(cis-image --version | awk '{print $2}')
echo "     code version: $CODE_VERSION | binary version: $BIN_VERSION"
if [ "$CODE_VERSION" != "$BIN_VERSION" ]; then
    echo "ERROR: version mismatch — the binary was not built from the current code!" >&2
    exit 1
fi

echo "[6/6] Building (log: $LOG, debug on)"
cis-image build --config "$CONFIG" --yes --debug --log-file "$LOG"
