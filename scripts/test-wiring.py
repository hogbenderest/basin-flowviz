#!/usr/bin/env python3
"""Wiring lint (run-4 lesson: the tab buttons shipped with no click
listeners, and no other gate could see that - typecheck, node --check and
the SQL battery are all blind to missing DOM wiring).

Checks, in order:
1. Every $("id") / getElementById("id") reference in app.js/ask.js matches
   an id present in index.html (catches JS wired to deleted elements).
2. Every interactive element in index.html (button/input/textarea/nav
   carrying an id) is referenced somewhere in the JS (catches elements
   that were given markup but never wired).
3. Explicit assertions for the known wirings that shipped broken once.

Exit 1 on any failure. Run before every deploy that touches the frontend.
"""
import re
import sys
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent
html = (root / "public/index.html").read_text()
js = (root / "public/app.js").read_text() + "\n" + (root / "public/ask.js").read_text()

html_ids = set(re.findall(r'id="([^"]+)"', html))
js_ids = set(re.findall(r'\$\("([^"]+)"\)', js)) | set(
    re.findall(r'getElementById\("([^"]+)"\)', js)
)
# selector-based references: querySelector("#ticker .ticker-title") etc.
for m in re.findall(r'querySelector(?:All)?\("#([a-z0-9-]+)', js):
    js_ids.add(m)

# Interactive elements: anything the user can click/type into must be wired.
interactive_html = set(re.findall(
    r'<(?:button|input|textarea|nav|label)\b[^>]*\bid="([^"]+)"', html))
interactive_html |= set(re.findall(r'\bid="([^"]+)"[^>]*><input', html))

fails = []

for i in sorted(js_ids - html_ids):
    fails.append(f"JS references missing element id: {i}")

for i in sorted(interactive_html - js_ids):
    fails.append(f"interactive element never referenced in JS: {i}")

# Known wirings that shipped broken once - assert explicitly.
known = [
    ("tab buttons have click listeners",
     bool(re.search(r"for\s*\(const btn of tabBtns\).*addEventListener|tabBtns\.forEach", js))),
    ("sql-run wired", '$("sql-run")' in js),
    ("ask-submit wired", '$("ask-submit")' in js),
    ("ticker handle wired", "tickerHandle.addEventListener" in js),
    ("event modal close wired", '$("event-modal-close").addEventListener' in js),
    ("bsky toggle wired", '$("bsky-toggle")' in js),
]
for desc, ok in known:
    if not ok:
        fails.append(f"known wiring missing: {desc}")

# Display-only ids (no wiring expected) - listed so the lint stays honest.
DISPLAY_ONLY = {
    "stat-rate", "stat-rows", "stat-fresh", "stat-cost", "stat-byterow",
    "stat-fresh-box", "stat-cost-box", "stat-byterow-box", "ask-note",
    "ask-session", "ask-chips", "sql-chips", "ask-body", "sql-result",
    "ask-input", "sql-input", "event-modal-title", "event-modal-body",
    "inbox-list", "inbox-report", "ticker-list", "ticker-handle",
    "edges", "columns", "topbar", "tabs", "ask-mode", "flow",
    "event-modal", "ask-rail", "ask-workspace", "tab-flow",
    "tab-investigations", "tab-ask", "inbox-badge", "bsky-state",
}
orphans = (html_ids - js_ids) - DISPLAY_ONLY
for i in sorted(orphans):
    fails.append(f"html id never referenced in JS (add to DISPLAY_ONLY if intentional): {i}")

if fails:
    for f in fails:
        print(f"FAIL {f}")
    print(f"\nwiring lint: {len(fails)} failure(s)")
    sys.exit(1)
print(f"wiring lint: OK ({len(html_ids)} html ids, {len(js_ids)} js refs, {len(known)} known wirings)")
