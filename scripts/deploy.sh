#!/bin/sh
# Deploy basin-flowviz.
#
# 1. The local catalogue overlay must exist for the esbuild bundle
#    (render.ts imports it); copy the committed neutral example when the
#    real local overlay is missing so a clean checkout still builds.
# 2. Cache-busting (run-4 lesson): every deploy stamps the git short
#    SHA over the ?v=__BUILD__ placeholders in index.html, so browsers
#    can never serve a stale app.js against a fresh page. The stamped
#    copy is restored from a backup even if the deploy fails (trap), so
#    uncommitted local edits are never lost.
set -e
cd "$(dirname "$0")/.."
if [ ! -f src/catalog/catalog.local.json ]; then
  cp src/catalog/catalog.local.example.json src/catalog/catalog.local.json
  echo "note: src/catalog/catalog.local.json was missing; deployed with the neutral example overlay"
fi
VER="$(git rev-parse --short HEAD 2>/dev/null || date +%s)"
cp public/index.html public/index.html.deploy-bak
restore() { mv -f public/index.html.deploy-bak public/index.html; }
trap restore EXIT INT TERM
sed -i '' -e "s/__BUILD__/${VER}/g" public/index.html
if grep -q "__BUILD__" public/index.html; then
  echo "error: unexpanded __BUILD__ placeholder remains in index.html"
  exit 1
fi
npx wrangler deploy "$@"
