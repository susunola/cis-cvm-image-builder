#!/usr/bin/env bash
# Check upstream packer-plugin-tencentcloud for a fix to issue #166
# ("instance not exist" intermittent failure). Exits 0 and prints a summary.
# Usage: bash scripts/check_tencentcloud_plugin.sh
set -euo pipefail

# Optional local env (defines GITHUB_TOKEN for a higher API rate limit).
# Not required — without a token the anonymous rate limit still allows the
# two lookups below, so the script must work on any machine / CI runner.
# shellcheck disable=SC1090
if [ -f ~/wbenv ]; then
  source ~/wbenv
fi

REPO="hashicorp/packer-plugin-tencentcloud"
ISSUE=166

AUTH=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  AUTH=(-H "Authorization: Bearer $GITHUB_TOKEN")
fi

echo "=== Issue #$ISSUE status ==="
curl -s ${AUTH[@]+"${AUTH[@]}"} \
  "https://api.github.com/repos/$REPO/issues/$ISSUE" |
  python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  state: {d.get('state')}\")
print(f\"  comments: {d.get('comments')}\")
print(f\"  updated: {d.get('updated_at')}\")
print(f\"  title: {d.get('title')}\")
"

echo "=== Latest releases (look for v1.2.x+ > v1.2.0) ==="
curl -s ${AUTH[@]+"${AUTH[@]}"} \
  "https://api.github.com/repos/$REPO/releases?per_page=5" |
  python3 -c "
import json,sys,re
rels=json.load(sys.stdin)
latest=None
for r in rels:
    tag=r.get('tag_name','')
    print(f\"  {tag}  published={r.get('published_at')}\")
    m=re.match(r'v?(\d+)\.(\d+)\.(\d+)', tag)
    if m:
        v=tuple(int(x) for x in m.groups())
        if latest is None or v>latest[0]:
            latest=(v, tag)
if latest and latest[0] > (1,2,0):
    print(f\"  >>> NEW VERSION: {latest[1]} (fix may be available)\")
else:
    print(f\"  >>> No release newer than v1.2.0 yet.\")
"
