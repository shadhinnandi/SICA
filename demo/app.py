"""
SICA Web Dashboard — Flask backend.

This file is a thin presentation layer over the existing SICA engine in run.py.
It never reimplements the detection algorithm; every call goes back to run.py.
"""

import csv
import io
import json
import os
import sys

from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# Make sure run.py (one directory up) is importable.
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Import the existing SICA engine — safe because run.py has __main__ guard.
import run as sica

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _read_csv(filename):
    """Return list-of-dicts from a CSV file inside results/."""
    path = os.path.join(ROOT, "results", filename)
    if not os.path.exists(path):
        return None
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/config")
def api_config():
    """Return the actual SICA constants from run.py."""
    return jsonify({
        "W_AGENT":      sica.W_AGENT,
        "W_NETWORK":    sica.W_NETWORK,
        "W_FORK":       sica.W_FORK,
        "THRESHOLD":    sica.THRESHOLD,
        "VERSION_ONLY": sica.VERSION_ONLY,
        "SAME_16":      sica.SAME_16,
        "SAME_24":      sica.SAME_24,
        "agents":       list(sica.AGENTS.keys()),
    })


@app.route("/api/datasets", methods=["POST"])
def api_datasets():
    """Run the existing dataset analysis and return results."""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        sica.run_datasets()
    finally:
        sys.stdout = old_stdout

    rows = _read_csv("dataset_results.csv")
    if rows is None:
        return jsonify({"error": "results/dataset_results.csv not found"}), 500

    # Build per-dataset summary
    summary = {}
    for row in rows:
        ds = row["dataset"]
        if ds not in summary:
            summary[ds] = {
                "sessions": 0, "normal": 0, "hijacked": 0,
                "alerts": 0, "caught": 0,
            }
        s = summary[ds]
        s["sessions"] += 1
        attacked = row["simulated_hijack"] == "yes"
        alerted  = row["result"] == "ALERT"
        if attacked:
            s["hijacked"] += 1
            if alerted:
                s["caught"] += 1
        else:
            s["normal"] += 1
        if alerted:
            s["alerts"] += 1

    return jsonify({"summary": summary, "rows": rows})


@app.route("/api/tests", methods=["POST"])
def api_tests():
    """Run the existing test suite and return results."""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        sica.run_tests()
    finally:
        sys.stdout = old_stdout

    rows = _read_csv("test_results.csv")
    if rows is None:
        return jsonify({"error": "results/test_results.csv not found"}), 500

    total  = len(rows)
    passed = sum(1 for r in rows if r["status"] == "PASS")
    return jsonify({"total": total, "passed": passed, "failed": total - passed, "rows": rows})


@app.route("/api/session", methods=["POST"])
def api_session():
    """
    Evaluate one new request against the existing session history.

    Accepts JSON body in two modes:

    Mode A — five explicit client-binding fields (preferred):
      {
        "history": [
            {"ip": "...", "browser": "...", "browser_version": "...",
             "os_name": "...", "device": "..."},
            ...
        ],
        "ip":              "...",
        "browser":         "...",
        "browser_version": "...",
        "os_name":         "...",
        "device":          "..."
      }

    Mode B — legacy ip + ua shortcut (backward compatible):
      {
        "history": [{"ip": "...", "ua": "..."}, ...],
        "ip": "...",
        "ua": "..."
      }

    Returns the SICA result for the latest request including both the
    per-request risk and the persistent session alert state.
    """
    data    = request.get_json(force=True)
    history = data.get("history", [])

    # -----------------------------------------------------------------------
    # Build client tuple for the NEW request
    # -----------------------------------------------------------------------
    if "browser" in data and data["browser"]:
        # Mode A: five explicit fields provided by the web UI
        ip             = data.get("ip", "").strip()
        browser        = data.get("browser", "").strip()
        browser_version = data.get("browser_version", "").strip()
        os_name        = data.get("os_name", "").strip()
        device         = data.get("device", "").strip()
        new_client = (ip, browser, browser_version, os_name, device)
        # For the response we also know ua = None (not used in this mode)
        ua = None
    else:
        # Mode B: legacy ip + ua shortcut
        ip = data.get("ip", "").strip()
        ua = sica.AGENTS.get(data.get("ua", "").lower(), data.get("ua", ""))
        browser, browser_version, os_name, device = sica.parse_agent(ua)
        new_client = (ip, browser, browser_version, os_name, device)

    # -----------------------------------------------------------------------
    # Rebuild client tuples for history entries
    # (supports both the new five-field format and the old {ip, ua} format)
    # -----------------------------------------------------------------------
    def _history_to_client(h):
        if "browser" in h and h["browser"]:
            return (
                h["ip"],
                h["browser"],
                h.get("browser_version", ""),
                h.get("os_name", ""),
                h.get("device", ""),
            )
        # legacy ua path
        req_ua = sica.AGENTS.get(h.get("ua", "").lower(), h.get("ua", ""))
        b, v, o, d = sica.parse_agent(req_ua)
        return (h["ip"], b, v, o, d)

    all_clients = [_history_to_client(h) for h in history] + [new_client]

    steps   = sica.check_session(all_clients)
    latest  = steps[-1]

    # The session is alerted if ANY prior or current request crossed the threshold.
    session_alerted = latest.get("session_alerted", False)
    alert_reason    = latest.get("alert_reason")
    alert_request   = latest.get("alert_request")

    # Decision: ALERT if current risk >= threshold OR session already alerted.
    decision = sica.decide(latest["risk"], session_alerted)

    # Human-readable labels matching run.py's describe() function
    net_labels = {
        1.0:              "Changed (different network)",
        sica.SAME_16:    f"Changed (different /24, same /16)",
        sica.SAME_24:    f"Changed (new IP, same /24)",
        0.0:              "Same",
    }
    agent_labels = {
        1.0:              "Changed (browser/OS/device)",
        sica.VERSION_ONLY: "Changed (version only)",
        0.0:              "Same",
    }

    # Session status label for the UI
    if session_alerted:
        if latest["risk"] >= sica.THRESHOLD:
            session_status = "ALERTED (current request above threshold)"
        else:
            session_status = f"ALERTED (flagged at request {alert_request}; current risk below threshold)"
    else:
        session_status = "CLEAN"

    return jsonify({
        # Request binding fields
        "ip":              new_client[0],
        "browser":         new_client[1],
        "version":         new_client[2],
        "os":              new_client[3],
        "device":          new_client[4],
        # Per-request scores
        "agent":           latest["agent"],
        "network":         latest["network"],
        "fork":            latest["fork"],
        "risk":            latest["risk"],
        # Session-level alert state
        "session_alerted": session_alerted,
        "session_status":  session_status,
        "alert_reason":    alert_reason,
        "alert_request":   alert_request,
        # Decision (combines per-request risk + session state)
        "decision":        decision,
        # Labels
        "net_label":       net_labels.get(latest["network"], str(latest["network"])),
        "agent_label":     agent_labels.get(latest["agent"],  str(latest["agent"])),
        "fork_label":      "Yes (binding fork)" if latest["fork"] else "No",
        "threshold":       sica.THRESHOLD,
    })


if __name__ == "__main__":
    print("SICA Web Dashboard")
    print(f"  Engine loaded from : {ROOT}/run.py")
    print(f"  Threshold          : {sica.THRESHOLD}")
    # Port 5000 is taken by the macOS AirPlay Receiver, so default to 8050.
    port = int(os.environ.get("SICA_PORT", "8050"))
    print(f"  Starting           : http://127.0.0.1:{port}")
    app.run(debug=False, host="127.0.0.1", port=port)
