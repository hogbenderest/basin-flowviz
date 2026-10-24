#!/usr/bin/env bash
# Basin live data flow demo: one-shot setup for the Basin resources.
# Everything before the sinks is already done (bucket, catalog, streams,
# Worker deploy). This script creates the sinks and pipelines once the two
# tokens exist in .dev.vars.
#
# Usage:  bash scripts/setup-basin.sh
#
# Requires: wrangler logged in (wrangler login), CLOUDFLARE_API_TOKEN env var
# unset or carrying Workers Pipelines + Workers Scripts edit permissions.
# Reads BASIN_SQL_TOKEN from .dev.vars for the Iceberg sink catalog tokens.

set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .dev.vars ]; then
  echo "Missing .dev.vars with BASIN_SQL_TOKEN=... (see .env.example)" >&2
  exit 1
fi
# NOTE: not `source <(grep ...)`: macOS's stock bash 3.2 races the process
# substitution (source can read EOF before grep writes, yielding empty vars).
# Command substitution below is synchronous; same pattern as DEPLOY.md.
BASIN_SQL_TOKEN=$(grep '^BASIN_SQL_TOKEN=' .dev.vars | cut -d= -f2-)
BASIN_INGEST_TOKEN=$(grep '^BASIN_INGEST_TOKEN=' .dev.vars | cut -d= -f2-)
if [ -z "${BASIN_SQL_TOKEN:-}" ]; then
  echo "BASIN_SQL_TOKEN empty in .dev.vars" >&2
  exit 1
fi
CT="$BASIN_SQL_TOKEN"

WRAP() { if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then env -u CLOUDFLARE_API_TOKEN "$@"; else "$@"; fi; }
W() { WRAP npx wrangler@4.145.0 basin pipelines "$@"; }

# --- Bluesky sinks (5) -------------------------------------------------------
for t in post like repost follow block; do
  W sinks create "bsky_${t}_sink" --type r2-data-catalog --bucket basin-demo \
    --namespace bsky --table "bsky_${t}" --catalog-token "$CT" --roll-interval 60
done

# --- Home Assistant sinks (2) ------------------------------------------------
W sinks create ha_state_changes_sink --type r2-data-catalog --bucket basin-demo \
  --namespace ha --table ha_state_changes --catalog-token "$CT" --roll-interval 60
W sinks create ha_sensor_readings_sink --type r2-data-catalog --bucket basin-demo \
  --namespace ha --table ha_sensor_readings --catalog-token "$CT" --roll-interval 60

# --- Homelab sinks (5) --------------------------------------------------------
for t in syslog host_metrics unifi_devices unifi_clients dns_queries; do
  W sinks create "homelab_${t}_sink" --type r2-data-catalog --bucket basin-demo \
    --namespace homelab --table "$t" --catalog-token "$CT" --roll-interval 60
done

# --- Pipelines (one SQL file each) --------------------------------------------
W create bsky_pipeline   --sql-file sql/bsky-fanout.sql
W create ha_pipeline     --sql-file sql/ha-pipeline.sql
W create homelab_pipeline --sql-file sql/homelab-pipeline.sql

# --- Worker secret for the SQL console ----------------------------------------
printf '%s' "$CT" | WRAP npx wrangler@4.145.0 secret put BASIN_SQL_TOKEN

echo
echo "Done. Verification (expect first rows 3-7 minutes after data flows):"
echo "  export WRANGLER_BASIN_SQL_AUTH_TOKEN=\$BASIN_SQL_TOKEN"
echo "  npx wrangler basin sql query 48f5cc18f1a716e781d39f1d6777ddc9_basin-demo \"SHOW DATABASES\""
echo "Then toggle Bluesky on in the UI and watch bsky.bsky_like grow."
