# Multi-stage image for running scripts/check_readme.py (the CI
# README-freshness guard) in a clean, reproducible Python environment.
#
# Why: contributors can validate that README.md stays in sync with the CLI
# (subcommands + OS profiles) without relying on their local Python state.
# The image installs ohbs-image from a freshly built wheel, so the check runs
# against the real package surface.
#
# Usage:
#   docker build -t ohbs-image:check-readme .
#   # build succeeds only if README.md documents every subcommand + profile
#   # re-run against a modified checkout:
#   docker run --rm -v "$(pwd):/app" ohbs-image:check-readme

# --- stage 1: build the wheel -----------------------------------------------
FROM python:3.11-slim AS build
WORKDIR /src
COPY pyproject.toml MANIFEST.in README.md ./
COPY ohbs_image ./ohbs_image
RUN pip install --no-cache-dir build \
 && python -m build --wheel

# --- stage 2: runtime with the installed package + check script --------------
FROM python:3.11-slim
WORKDIR /app
COPY --from=build /src/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# The source files the check reads at runtime. Keep the scripts/ layout so
# check_readme.py resolves its default README path (repo root) correctly.
COPY README.md /app/README.md
COPY scripts/check_readme.py /app/scripts/check_readme.py

ENTRYPOINT ["python", "scripts/check_readme.py"]
