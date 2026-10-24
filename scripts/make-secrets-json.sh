#!/usr/bin/env bash
# Generate Vector's secrets.json from the legacy vector.env file.
#
# Vector 0.57+ disabled ${VAR} environment interpolation in config files
# (security change; see vector.dev/docs/reference/configuration/secrets).
# The vector-central.toml config therefore reads every secret via
# SECRET[basin.<key>] references from a JSON file backend. This script
# converts the old KEY=value env file into that JSON file with safe
# encoding (python json handles any special characters in passwords).
#
# Usage:
#   bash scripts/make-secrets-json.sh [/path/to/vector.env] [/path/to/secrets.json]
#
# Defaults match the server111 install: ~/basin-flowviz-vector/vector.env
# -> ~/basin-flowviz-vector/secrets.json (mode 600).
#
# Keys skipped by design: vector_data_dir (data_dir is hardcoded in the
# config) and mqtt_broker_url (the broker host is hardcoded; unused).

set -euo pipefail

SRC="${1:-$HOME/basin-flowviz-vector/vector.env}"
DST="${2:-$HOME/basin-flowviz-vector/secrets.json}"

if [ ! -f "$SRC" ]; then
  echo "No env file at $SRC (expected KEY=value lines)" >&2
  exit 1
fi

python3 - "$SRC" "$DST" <<'PYEOF'
import json, sys, os

src, dst = sys.argv[1], sys.argv[2]
skip = {"vector_data_dir", "mqtt_broker_url"}
secrets = {}
with open(src) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        if key in skip:
            continue
        if value:
            secrets[key] = value

with open(dst, "w") as f:
    json.dump(secrets, f, indent=2)
os.chmod(dst, 0o600)
print(f"wrote {len(secrets)} secrets to {dst}")
PYEOF
