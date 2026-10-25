#!/bin/sh
# Deploy basin-flowviz. The local catalogue overlay must exist for the
# esbuild bundle (render.ts imports it); copy the committed neutral
# example when the real local overlay is missing so a clean checkout
# still builds. The real overlay is gitignored and never committed.
set -e
cd "$(dirname "$0")/.."
if [ ! -f src/catalog/catalog.local.json ]; then
  cp src/catalog/catalog.local.example.json src/catalog/catalog.local.json
  echo "note: src/catalog/catalog.local.json was missing; deployed with the neutral example overlay"
fi
exec npx wrangler deploy "$@"
