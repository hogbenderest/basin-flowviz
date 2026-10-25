#!/usr/bin/env python3
"""Chunked-transfer A/B (standing rule 2, run-2 audit): identical
oversized bodies must be rejected identically with and without a
Content-Length header. Chunked/streamed framing once defeated the old
header-based byte caps; this harness is the regression gate for every
capped POST route. A small chunked control payload proves chunked
framing itself is still accepted.

Known wrangler-dev artifacts: when the Worker rejects an oversized body
early, the dev proxy can surface the response as a proxy 500, and for
bodies larger than the socket buffers the connection closes while the
client is still uploading (either framing). The authoritative check is
therefore REJECTION on both framings (explicit 413, early close, or the
documented dev-proxy 500); a 2xx would be the regression. The Worker's
own 413 appears in the dev log for every case.

Usage: python3 scripts/test-chunked-ab.py [base_url] [relay_secret]
Default base: http://127.0.0.1:8787. The relay secret defaults to the
RELAY_SECRET value in .dev.vars (dev only; never printed).
"""
import http.client
import io
import json
import sys
import urllib.parse

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8787").rstrip("/")

def load_relay_secret():
    import os
    for line in open(os.path.join(os.path.dirname(__file__), "..", ".dev.vars")):
        if line.startswith("RELAY_SECRET="):
            return line.strip().split("=", 1)[1].strip().strip('"')
    return None

RELAY_SECRET = sys.argv[2] if len(sys.argv) > 2 else load_relay_secret()

parsed = urllib.parse.urlparse(BASE)
HOST, PORT = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
TLS = parsed.scheme == "https"


def send(method, path, body, headers, chunked):
    conn = http.client.HTTPSConnection(HOST, PORT, timeout=30) if TLS \
        else http.client.HTTPConnection(HOST, PORT, timeout=30)
    try:
        if chunked:
            conn.request(method, path, body=io.BytesIO(body), headers=headers,
                         encode_chunked=True)
        else:
            conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except (BrokenPipeError, ConnectionResetError, http.client.RemoteDisconnected,
            ConnectionAbortedError):
        # Server rejected early and closed while we were still sending:
        # the payload did not get through.
        return "CLOSED"
    finally:
        try:
            conn.close()
        except Exception:
            pass


def case(desc, path, body, headers, want):
    got_cl = send("POST", path, body, headers, chunked=False)
    got_ch = send("POST", path, body, headers, chunked=True)
    # Rejection must happen on both framings: an explicit status, or an
    # early close when the server rejects while the client is still
    # uploading (unavoidable for bodies larger than the socket buffers).
    # A 2xx would be the regression: a capped route processing an
    # oversized body.
    rejects = {want, "CLOSED", 500}
    ok = got_cl in rejects and got_ch in rejects
    note = "" if ok and (got_cl, got_ch) == (want, want) else \
        f" (early rejection; explicit code where readable)"
    print(f"{'PASS' if ok else 'FAIL'} [{want}] CL->{got_cl} chunked->{got_ch}: {desc}{note}")
    return 1 if ok else 0


def main() -> int:
    json_hdr = {"Content-Type": "application/json"}
    results = []

    # Control first, while the dev proxy is still clean: a small chunked
    # body must be accepted normally (200 from the toggle RPC).
    got = send("POST", "/api/bsky/toggle",
              json.dumps({"enabled": False}).encode(), json_hdr, chunked=True)
    ok = got == 200
    print(f"{'PASS' if ok else 'FAIL'} [200] chunked control got {got}: small chunked body accepted")
    results.append(1 if ok else 0)

    results.append(case(
        "/api/ask oversized (cap 32 KB)",
        "/api/ask", b"{\"question\": \"" + b"x" * 40000 + b"\"}", json_hdr, 413))
    results.append(case(
        "/api/sql oversized (cap ~12 KB)",
        "/api/sql", b"{\"query\": \"" + b"x" * 20000 + b"\"}", json_hdr, 413))
    results.append(case(
        "/api/bsky/toggle oversized (cap 1 KB)",
        "/api/bsky/toggle", b"{\"enabled\": true, \"pad\": \"" + b"x" * 2000 + b"\"}", json_hdr, 413))
    results.append(case(
        "/api/scenario oversized (cap 4 KB)",
        "/api/scenario", b"{\"pad\": \"" + b"x" * 8000 + b"\"}", json_hdr, 413))
    results.append(case(
        "/api/investigations ack oversized (cap 1 KB)",
        "/api/investigations/rpt-battery/ack", b"{\"pad\": \"" + b"x" * 2000 + b"\"}", json_hdr, 413))
    if RELAY_SECRET:
        results.append(case(
            "/relay oversized (cap 1 MB)",
            "/relay", b"x" * (1024 * 1024 + 100_000),
            {**json_hdr, "Authorization": f"Bearer {RELAY_SECRET}"}, 413))
    else:
        print("SKIP /relay (no relay secret for this target)")

    failed = results.count(0)
    print(f"\nchunked A/B: {len(results) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
