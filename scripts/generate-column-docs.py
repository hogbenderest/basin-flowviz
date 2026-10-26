#!/usr/bin/env python3
"""Compile the basin-flowviz semantic catalogue into queryable warehouse
documentation (meta.column_docs + meta.platform_facts).

Reads src/catalog/catalog.v1.json (the single source of truth for table
semantics, extraction patterns, cross-references and platform facts)
and POSTs the compiled rows to the Basin ingest API for the
meta_docs_stream, which lands them in meta.column_docs and
meta.platform_facts tables.

The refresh model is append-only with a generation_id timestamp (Basin
Pipelines cannot DELETE; the stream is INSERT-only). External engines
query the latest generation:

    SELECT * FROM meta.column_docs
    WHERE generation_id = (SELECT MAX(generation_id) FROM meta.column_docs)

Usage:
  python3 scripts/generate-column-docs.py

Prerequisites: the meta_docs_stream, both sinks and the pipeline must
exist (scripts/setup-basin.sh creates them on first run). Reads
BASIN_INGEST_TOKEN from .dev.vars. Never prints the token.
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The ingest endpoint for the meta_docs_stream (from wrangler.jsonc /
# setup-basin.sh; the stream URI is printed by `wrangler pipelines stream
# create` and stored in the deployment notes). The URI below is the
# meta_docs_stream created by setup-basin.sh.
INGEST = os.environ.get(
    "META_DOCS_INGEST",
    "https://aa7289e8c2694ec391aca954d91b3b75.ingest.cloudflare.com",
)


def load_catalog():
    with open(os.path.join(REPO, "src", "catalog", "catalog.v1.json")) as f:
        return json.load(f)


def load_ingest_uri():
    """Read the actual stream URI from the setup notes or env."""
    uri = os.environ.get("META_DOCS_INGEST")
    if uri:
        return uri
    # The setup script writes the stream URI to a known location
    notes = os.path.join(REPO, ".meta-stream-uri")
    if os.path.exists(notes):
        return open(notes).read().strip()
    print("ERROR: set META_DOCS_INGEST env var or create .meta-stream-uri")
    print("       (run scripts/setup-basin.sh to create the stream first)")
    sys.exit(1)


def load_token():
    for line in open(os.path.join(REPO, ".dev.vars")):
        if line.startswith("BASIN_INGEST_TOKEN="):
            return line.strip().split("=", 1)[1].strip().strip('"')
    print("ERROR: BASIN_INGEST_TOKEN not found in .dev.vars")
    sys.exit(1)


def post_batch(token, uri, rows):
    """POST a batch of rows to the ingest API (arrays are accepted)."""
    if not rows:
        return 0
    req = urllib.request.Request(
        uri,
        data=json.dumps(rows).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "basin-flowviz-docs/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        r.read()
    return len(rows)


def compile_column_docs(catalog):
    """Transform the catalogue into meta.column_docs rows."""
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    extraction = catalog.get("extractionPatterns", {})
    cross_refs = extraction.get("cross_references", {})
    rows = []

    for t in catalog.get("tables", []):
        tid = t["id"]
        ex = extraction.get(tid, {})

        # Table-level row
        caveats = t.get("caveats", [])
        synonyms = t.get("synonyms", [])
        notes = []
        if t.get("statusNote"):
            notes.append(t["statusNote"])
        if ex.get("note"):
            notes.append(ex["note"])

        # Cross-references that mention this table
        my_cross = []
        for label, desc in cross_refs.items():
            if tid.split(".")[-1].replace("_", "") in desc.lower().replace("_", "").replace(" ", ""):
                my_cross.append(f"{label}: {desc}")
            elif tid in desc:
                my_cross.append(f"{label}: {desc}")

        rows.append({
            "event_id": f"doc-table-{tid}-{gen}",
            "event_type": "meta_column_docs",
            "id": tid,
            "kind": "table",
            "parent_id": None,
            "name": tid,
            "description": f"{t.get('label', tid)}: {t.get('grain', '')}",
            "extraction_default": None,
            "extraction_fallback": None,
            "unit": None,
            "time_column": t.get("queryTimeColumn"),
            "time_basis": t.get("queryTimeBasis"),
            "privacy": t.get("privacyClass"),
            "caveats": json.dumps(caveats + notes),
            "cross_refs": json.dumps(my_cross),
            "synonyms": json.dumps(synonyms),
            "generation_id": gen,
            "ts": gen,
        })

        # Column-level rows
        for col in t.get("columns", []):
            colname = col["name"]
            col_ex = ex.get(colname, {})
            col_note = col.get("note", "")
            desc = col_ex.get("reason") or col_note or f"column {colname}"
            extraction_default = col_ex.get("default")
            extraction_fallback = col_ex.get("fallback")
            guard = col_ex.get("guard")
            if guard:
                extraction_default = f"GUARD: {guard} THEN {extraction_default}" if extraction_default else None

            col_cross = []
            if tid in cross_refs.get("wifi_signal", ""):
                col_cross.append(f"wifi signal: {cross_refs['wifi_signal']}")
            if tid in cross_refs.get("sensor_vs_state", ""):
                col_cross.append(f"sensor vs state: {cross_refs['sensor_vs_state']}")

            rows.append({
                "event_id": f"doc-col-{tid}-{colname}-{gen}",
                "event_type": "meta_column_docs",
                "id": f"{tid}.{colname}",
                "kind": "column",
                "parent_id": tid,
                "name": colname,
                "description": desc,
                "extraction_default": extraction_default,
                "extraction_fallback": extraction_fallback,
                "unit": col_ex.get("unit"),
                "time_column": None,
                "time_basis": None,
                "privacy": t.get("privacyClass"),
                "caveats": json.dumps([col_note] if col_note else []),
                "cross_refs": json.dumps(col_cross),
                "synonyms": json.dumps(col.get("jsonPaths", [])),
                "generation_id": gen,
                "ts": gen,
            })

    return rows, gen


def compile_platform_facts(catalog):
    """Transform the catalogue's extractionPatterns.platform_facts into
    meta.platform_facts rows."""
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    facts = catalog.get("extractionPatterns", {}).get("platform_facts", {})
    rows = []
    for i, (key, value) in enumerate(facts.items()):
        rows.append({
            "event_id": f"fact-{key}-{gen}",
            "event_type": "meta_platform_facts",
            "id": key,
            "scope": "basin_sql",
            "fact": key,
            "value": value,
            "verified_at": gen,
            "caveats": None,
            "generation_id": gen,
            "ts": gen,
        })
    return rows, gen


def main():
    catalog = load_catalog()
    uri = load_ingest_uri()
    token = load_token()

    print("compiling column docs...")
    doc_rows, gen1 = compile_column_docs(catalog)
    print(f"  {len(doc_rows)} column_docs rows (generation {gen1})")

    print("compiling platform facts...")
    fact_rows, gen2 = compile_platform_facts(catalog)
    print(f"  {len(fact_rows)} platform_facts rows (generation {gen2})")

    print(f"posting {len(doc_rows) + len(fact_rows)} rows in batches...")
    sent = 0
    all_rows = doc_rows + fact_rows
    for i in range(0, len(all_rows), 50):
        batch = all_rows[i:i + 50]
        try:
            sent += post_batch(token, uri, batch)
            print(f"  batch {i // 50 + 1}: {sent}/{len(all_rows)} rows posted")
        except Exception as e:
            print(f"  ERROR on batch starting at row {i}: {e}")
            sys.exit(1)

    print(f"done: {sent} rows posted. Query with:")
    print(f'  SELECT * FROM meta.column_docs')
    print(f"  WHERE generation_id = '{gen1}'")
    print(f"  SELECT * FROM meta.platform_facts")
    print(f"  WHERE generation_id = '{gen2}'")


if __name__ == "__main__":
    main()
