#!/usr/bin/env python3
"""UniFi wifi radio-metrics poller for basin-flowviz (plan W1).

Stateless single-shot: poll the UniFi console's classic site API, emit
one host_metrics row per wireless client and one per AP radio to the
Basin homelab stream, exit. Cron is the supervisor (per-minute, flock +
timeout in the crontab line): a crashed run is simply absent and the
next minute is a clean process.

Stdlib only. Secrets come from the same secrets.json Vector reads
(flat keys, mode 600). Never print secret values.

Self-observability: any failure emits a rate-limited wifi_poll_error
row into the same stream (one per stage per 15 minutes) and the log
self-caps at 500 lines. A state file guards the zero-clients anomaly:
zero wireless clients after dozens were known is a failed poll, not
truth.

Fields are direct JSON objects (single-encoded), matching the current
dns_queries convention; the app's era-safe COALESCE extraction handles
both encodings.

Verify on server111:
  python3 ~/basin-wifi-poller/wifi-poller.py && tail ~/basin-wifi-poller/poller.log

Rollback: comment out the crontab line.
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

CONSOLE = "https://192.168.86.111:11443"
API_BASE = CONSOLE + "/proxy/network/api/s/default"
SECRETS = os.environ.get(
    "WIFI_POLLER_SECRETS", os.path.expanduser("~/basin-flowviz-vector/secrets.json")
)
STATE = os.path.expanduser("~/basin-wifi-poller/state.json")
LOG = os.path.expanduser("~/basin-wifi-poller/poller.log")

# The homelab stream (same one Vector's homelab_basin sink writes to).
INGEST = "https://578aef7b6d5b4ad6980dcdc79456da4a.ingest.cloudflare.com"

UNAUTH_CTX = ssl.create_default_context()
UNAUTH_CTX.check_hostname = False
UNAUTH_CTX.verify_mode = ssl.CERT_NONE

ERROR_ROW_PERIOD = 15 * 60  # one error row per stage per 15 minutes
ZERO_CLIENT_FLOOR = 20  # below this with zero clients = failed poll
UA = "basin-flowviz-wifi-poller/1.0 (server111)"


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(line):
    try:
        with open(LOG, "a") as f:
            f.write(f"{now_iso()} {line}\n")
    except OSError:
        pass


def cap_log():
    try:
        with open(LOG) as f:
            lines = f.readlines()
        if len(lines) > 500:
            with open(LOG, "w") as f:
                f.writelines(lines[-500:])
    except OSError:
        pass


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"clients_seen": 0, "errors": {}}


def save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(st, f)
    except OSError:
        pass


def fetch_json(url, headers, timeout=20):
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, **headers}
    )
    with urllib.request.urlopen(req, timeout=timeout, context=UNAUTH_CTX) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def post_row(token, row, timeout=20):
    req = urllib.request.Request(
        INGEST,
        data=json.dumps(row).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": UA,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read()


def num(v):
    try:
        if v is None:
            return None
        f = float(v)
        return f if f == f else None  # NaN guard
    except (TypeError, ValueError):
        return None


def maybe_error_row(st, token, stage, detail):
    """Rate-limited self-reporting into the same stream."""
    last = st["errors"].get(stage, 0)
    if time.time() - last < ERROR_ROW_PERIOD:
        return
    st["errors"][stage] = time.time()
    row = {
        "event_id": str(uuid.uuid4()),
        "event_type": "host_metrics",
        "host": "wifi-poller",
        "ts": now_iso(),
        "message": None,
        "fields": {
            "name": "wifi_poll_error",
            "value": 1,
            "tags": {"stage": stage, "detail": str(detail)[:200]},
        },
    }
    try:
        post_row(token, row)
    except Exception:
        pass


def fail(st, token, stage, detail):
    log(f"FAIL stage={stage} detail={str(detail)[:200]}")
    maybe_error_row(st, token, stage, detail)
    save_state(st)
    sys.exit(1)


def main():
    cap_log()
    st = load_state()
    try:
        with open(SECRETS) as f:
            secrets = json.load(f)
        # Flat keys are the server111 convention (make-secrets-json.sh);
        # accept the basin.*-prefixed form too for other deployments.
        api_key = secrets.get("unifi_api_key") or secrets.get("basin.unifi_api_key")
        token = secrets.get("basin_ingest_token") or secrets.get("basin.basin_ingest_token")
        if not api_key or not token:
            raise KeyError("unifi_api_key / basin_ingest_token")
    except (OSError, KeyError, ValueError) as e:
        log(f"FAIL stage=secrets detail={str(e)[:200]}")
        sys.exit(1)

    headers = {"X-API-KEY": api_key, "Accept": "application/json"}

    data = None
    last_err = None
    for attempt in (1, 2):
        try:
            sta = fetch_json(f"{API_BASE}/stat/sta", headers)
            dev = fetch_json(f"{API_BASE}/stat/device", headers)
            for page in (sta, dev):
                if not isinstance(page, dict):
                    raise ValueError("response is not an object")
                rc = (page.get("meta") or {}).get("rc")
                if rc != "ok":
                    raise ValueError(f"meta.rc={rc!r}")
                if not isinstance(page.get("data"), list):
                    raise ValueError("data is not an array")
            data = (sta["data"], dev["data"])
            break
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as e:
            last_err = e
            if attempt == 1:
                time.sleep(2)
    if data is None:
        fail(st, token, "fetch", last_err)

    clients_all, devices = data
    # Wireless only: is_wired false / ap_mac present. `signal` is dBm;
    # `rssi` is a relative index and must not be used.
    clients = [
        c
        for c in clients_all
        if isinstance(c, dict)
        and (c.get("is_wired") is False or c.get("ap_mac"))
        and not c.get("is_wired")
    ]
    if not clients:
        if st.get("clients_seen", 0) > ZERO_CLIENT_FLOOR:
            fail(st, token, "validate", "zero wireless clients after many known; treating as failed poll")
    st["clients_seen"] = len(clients)

    rows = []
    bad = 0
    for c in clients:
        try:
            signal = num(c.get("signal"))
            if signal is None:
                bad += 1
                continue
            host = str(c.get("hostname") or c.get("name") or c.get("mac") or "unknown")
            tags = {}
            for k, v in (
                ("ap", c.get("last_uplink_name")),
                ("channel", c.get("channel")),
                ("radio", c.get("radio")),
                ("noise", num(c.get("noise"))),
                ("tx_rate_kbps", num(c.get("tx_rate"))),
                ("rx_rate_kbps", num(c.get("rx_rate"))),
                ("tx_retries", num(c.get("tx_retries"))),
                ("satisfaction", num(c.get("satisfaction"))),
            ):
                if v is not None:
                    tags[k] = v
            rows.append(
                {
                    "event_id": str(uuid.uuid4()),
                    "event_type": "host_metrics",
                    "host": host,
                    "ts": now_iso(),
                    "message": None,
                    "fields": {"name": "wifi_client", "value": signal, "tags": tags},
                }
            )
        except Exception:
            bad += 1

    for d in devices:
        if not isinstance(d, dict):
            bad += 1
            continue
        ap = str(d.get("name") or d.get("mac") or "unknown")
        for rt in d.get("radio_table_stats") or []:
            try:
                cu = num(rt.get("cu_total"))
                if cu is None:
                    bad += 1
                    continue
                tags = {}
                for k, v in (
                    ("ap", ap),
                    ("radio", rt.get("radio") or rt.get("radio_name")),
                    ("channel", rt.get("channel")),
                    ("num_sta", num(rt.get("num_sta"))),
                    ("tx_retries_pct", num(rt.get("tx_retries_pct"))),
                    ("satisfaction", num(rt.get("satisfaction"))),
                    ("state", rt.get("state")),
                ):
                    if v is not None:
                        tags[k] = v
                rows.append(
                    {
                        "event_id": str(uuid.uuid4()),
                        "event_type": "host_metrics",
                        "host": ap,
                        "ts": now_iso(),
                        "message": None,
                        "fields": {"name": "wifi_ap_radio", "value": cu, "tags": tags},
                    }
                )
            except Exception:
                bad += 1

    total_candidates = max(len(clients) + len(devices) * 2, 1)
    if bad / total_candidates > 0.2:
        fail(st, token, "validate", f"{bad} of ~{total_candidates} rows malformed")

    sent = 0
    for row in rows:
        try:
            post_row(token, row)
            sent += 1
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            log(f"ingest error on one row: {str(e)[:120]}")
            maybe_error_row(st, token, "ingest", e)
            save_state(st)
            sys.exit(1)

    save_state(st)
    log(f"ok clients={len(clients)} aps={len(devices)} rows_sent={sent} bad={bad}")


if __name__ == "__main__":
    main()
