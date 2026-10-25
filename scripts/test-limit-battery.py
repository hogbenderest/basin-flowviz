#!/usr/bin/env python3
"""LIMIT battery (standing rule 2, run-2 audit): the sanitizeSql LIMIT
parser must reject the engine-grammar forms the old regex did not model
(MySQL comma form, scientific notation, LIMIT ALL, subquery smuggling,
offset caps, write keywords, stray semicolons, comment-hidden limits),
and /api/sql must still accept and run valid shapes.

Usage: python3 scripts/test-limit-battery.py [base_url]
Default base: http://127.0.0.1:8787 (wrangler dev).

Guard rejections must return HTTP 400. Valid queries execute against the
real Basin endpoint the dev/remote Worker is configured with (each costs
at most one 10 MB-minimum query, so the battery is deliberately small).
"""
import json
import sys
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")

REJECT = [
    ("comma form: count smuggled past the first number",
     "SELECT domain FROM homelab.dns_queries LIMIT 1, 9999999"),
    ("scientific notation count",
     "SELECT 1 AS x FROM bsky.bsky_post LIMIT 1e4"),
    ("LIMIT ALL",
     "SELECT 1 AS x FROM bsky.bsky_post LIMIT ALL"),
    ("over-cap LIMIT in the outer query",
     "SELECT * FROM (SELECT domain FROM homelab.dns_queries WHERE __ingest_ts >= now() - INTERVAL '1 day') AS s LIMIT 99999999"),
    ("over-cap OFFSET",
     "SELECT domain FROM homelab.dns_queries LIMIT 10 OFFSET 99999999"),
    ("write keyword",
     "DELETE FROM homelab.dns_queries"),
    ("stray semicolon (multi-statement)",
     "SELECT 1 AS x FROM bsky.bsky_post; SELECT 2 AS y FROM bsky.bsky_post"),
    ("comment-hidden over-cap LIMIT (comment stripped before analysis)",
     "SELECT 1 AS x FROM bsky.bsky_post LIMIT /* keep */ 99999999"),
]

# Rejected by the engine backstop rather than the guard: must still fail,
# either as a guard 400 or a Basin error envelope with success:false.
ENGINE_REJECT = [
    ("bare SELECT of literals (engine rule: must reference a table)",
     "SELECT 1 AS x"),
]

ACCEPT = [
    ("valid bounded query runs (era-safe JSON extraction)",
     "SELECT COALESCE(json_get_str(fields, 'domain'), json_get_str(json_get_str(fields), 'domain')) AS domain FROM homelab.dns_queries WHERE __ingest_ts >= now() - INTERVAL '1 hour' LIMIT 1"),
    ("no LIMIT is accepted (guard appends its cap)",
     "SELECT event_id FROM homelab.dns_queries WHERE __ingest_ts >= now() - INTERVAL '1 hour'"),
]


def post_sql(query: str):
    req = urllib.request.Request(
        f"{BASE}/api/sql",
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


def main() -> int:
    passed = failed = 0
    for desc, q in REJECT:
        status, body = post_sql(q)
        ok = status == 400 and body.get("success") is False
        if ok:
            passed += 1
            print(f"PASS [400] {desc}")
        else:
            failed += 1
            print(f"FAIL want 400/success:false, got {status}: {desc}")
            print(f"     body: {json.dumps(body)[:200]}")
    for desc, q in ENGINE_REJECT:
        status, body = post_sql(q)
        ok = body.get("success") is False
        if ok:
            passed += 1
            print(f"PASS [{status}/engine] {desc}")
        else:
            failed += 1
            print(f"FAIL want success:false, got {status}: {desc}")
            print(f"     body: {json.dumps(body)[:200]}")
    for desc, q in ACCEPT:
        status, body = post_sql(q)
        ok = status == 200 and body.get("success") is True
        if ok:
            passed += 1
            print(f"PASS [200] {desc}")
        else:
            failed += 1
            print(f"FAIL want 200/success:true, got {status}: {desc}")
            print(f"     body: {json.dumps(body)[:200]}")

    # W4 drill-through route (run-3 amendment 6): malformed ids rejected,
    # well-formed unknown ids honestly found:false, unknown kind rejected.
    def get_event(path):
        req = urllib.request.Request(f"{BASE}{path}")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except Exception:
                return e.code, {}

    event_cases = [
        ("event route: too-short id -> 400", "/api/event/" + "x" * 11, 400, None),
        ("event route: invalid characters -> 400", "/api/event/" + "bad%20id%20here!", 400, None),
        ("event route: unknown kind -> 400",
         "/api/event/0123456789ab-cdef-0123?kind=weird%20kind", 400, None),
        ("event route: valid-shape unknown id -> 200 found:false",
         "/api/event/0123456789ab-cdef-unknown?kind=syslog", 200, False),
    ]
    for desc, path, want, found in event_cases:
        status, body = get_event(path)
        ok = status == want and (found is None or body.get("found") is found)
        if ok:
            passed += 1
            print(f"PASS [{want}] {desc}")
        else:
            failed += 1
            print(f"FAIL want {want}, got {status} {json.dumps(body)[:120]}: {desc}")
    print(f"\nlimit battery: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
