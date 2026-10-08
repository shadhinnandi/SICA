import csv
import os
import re
import sys

W_AGENT = 0.3718     # user-agent changed
W_NETWORK = 0.3301   # network changed
W_FORK = 0.2981      # an earlier client came back (binding fork)
THRESHOLD = 0.6282

# smaller changes get a partial score
VERSION_ONLY = 0.35  # same browser, only the version number changed
SAME_16 = 0.45       # new /24 subnet inside the same /16 network
SAME_24 = 0.15       # new address inside the same /24 subnet
RECENT = 4           # how many different clients a session remembers

HERE = os.path.dirname(os.path.abspath(__file__))
DATASETS = {"W1": "data/W1_sample.csv", "W2": "data/W2_sample.csv"}
TEST_FILE = "data/test_cases.csv"
RESULTS = "results"

BROWSERS = [
    ("Edge", ["edg/", "edge/"], []),
    ("Opera", ["opr/", "opera"], []),
    ("Chrome", ["chrome/", "crios/"], ["edg/", "opr/"]),
    ("Firefox", ["firefox/", "fxios/"], []),
    ("Safari", ["safari/"], ["chrome/", "crios/", "edg/", "opr/"]),
    ("IE", ["msie", "trident/"], []),
    ("APT", ["apt-http"], []),
    ("Wget", ["wget/"], []),
    ("Curl", ["curl/"], []),
    ("FeedReader", ["feedparser", "feedburner", "feedly", "rss"], []),
    ("Bot", ["bot", "spider", "crawler", "slurp", "bingpreview"], []),
    ("Library", ["python-", "java/", "libwww", "go-http", "okhttp", "urllib"], []),
]
SYSTEMS = [
    ("iOS", ["iphone", "ipad", "ipod", "cpu os"]),
    ("Android", ["android"]),
    ("Windows", ["windows"]),
    ("macOS", ["macintosh", "mac os x"]),
    ("ChromeOS", ["cros"]),
    ("Ubuntu", ["ubuntu"]),
    ("Debian", ["debian"]),
    ("Linux", ["linux", "x11"]),
]
VERSION_AT = {
    "Chrome": ["chrome/", "crios/"], "Firefox": ["firefox/", "fxios/"],
    "Safari": ["version/", "safari/"], "Edge": ["edg/", "edge/"],
    "Opera": ["opr/", "opera/"], "IE": ["msie ", "rv:"],
    "APT": ["(", "apt-http/"], "Wget": ["wget/"], "Curl": ["curl/"],
}

# shortcuts for the manual test so long User-Agent strings don't have to be typed
AGENTS = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "chrome121": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "curl": "curl/8.4.0",
}


def parse_agent(ua):
    """User-Agent string -> (browser, major version, OS, device)."""
    if ua.strip().lower() in ("", "-", "nan", "unknown"):
        return "unknown", "", "unknown", "unknown"
    low = ua.lower()

    browser = "Other"
    for name, tokens, not_tokens in BROWSERS:
        if any(t in low for t in tokens) and not any(t in low for t in not_tokens):
            browser = name
            break

    system = "Other"
    for name, tokens in SYSTEMS:
        if any(t in low for t in tokens):
            system = name
            break

    if system in ("iOS", "Android"):
        device = "Mobile" if "mobile" in low or "iphone" in low else "Tablet"
    elif system == "Other":
        device = "Other"
    else:
        device = "Desktop"

    version = ""
    for key in VERSION_AT.get(browser, []):
        i = low.find(key)
        if i >= 0:
            m = re.search(r"\d+", ua[i + len(key): i + len(key) + 12])
            if m:
                version = m.group()
                break

    return browser, version, system, device


def subnets(ip):
    """Return the /16 and /24 part of an address, e.g. 203.0 and 203.0.113."""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:2]), ":".join(parts[:3])
    parts = ip.split(".")
    if len(parts) != 4:
        return ip, ip
    return ".".join(parts[:2]), ".".join(parts[:3])


def agent_score(client, ref):
    # client = (ip, browser, version, os, device)
    if (client[1], client[3], client[4]) != (ref[1], ref[3], ref[4]):
        return 1.0
    if client[2] != ref[2]:
        return VERSION_ONLY
    return 0.0


def network_score(client, ref):
    net16, net24 = subnets(client[0])
    ref16, ref24 = subnets(ref[0])
    if net16 != ref16:
        return 1.0
    if net24 != ref24:
        return SAME_16
    if client[0] != ref[0]:
        return SAME_24
    return 0.0


def client_of(row):
    """One dataset row -> client (ip, browser, version, os, device)."""
    return (row["ip_address"], row["browser"], row["browser_version"],
            row["operating_system"], row["device_type"])


def check_session(clients):
    """Score every request of one session. clients = [(ip, browser, version, os, device), ...]

    Each step dict now includes:
      agent, network, fork, risk  — per-request scores (unchanged)
      session_alerted             — True once any request has crossed THRESHOLD
      alert_reason                — human-readable reason for the persistent alert
      alert_request               — 1-based index of the request that first triggered ALERT
    """
    steps = []
    ref = last = None
    recent = []

    # Persistent session-level alert state — sticky once set.
    session_alerted = False
    alert_reason = None
    alert_request = None

    for client in clients:
        if ref is None:
            ref = last = client
            recent = [client]
            steps.append({
                "agent": 0.0, "network": 0.0, "fork": 0.0, "risk": 0.0,
                "session_alerted": False, "alert_reason": None, "alert_request": None,
            })
            continue

        changed = client != last
        fork = changed and client in recent

        agent = agent_score(client, ref)
        net = network_score(client, ref)
        risk = W_AGENT * agent + W_NETWORK * net + W_FORK * (1.0 if fork else 0.0)
        risk = round(risk, 4)

        # --- Persistent session alert state ----------------------------
        # The individual request risk is calculated normally.  Only AFTER
        # that do we check whether this (or a previous) request crossed
        # the threshold and mark the session as permanently alerted.
        newly_alerted = not session_alerted and risk >= THRESHOLD
        if newly_alerted:
            session_alerted = True
            alert_request = len(steps) + 1   # 1-based
            if fork:
                alert_reason = "Binding fork detected (an earlier client re-appeared after a different one used this session)"
            else:
                alert_reason = "Client-binding change exceeded the risk threshold"
        # ---------------------------------------------------------------

        steps.append({
            "agent": agent, "network": net,
            "fork": 1.0 if fork else 0.0,
            "risk": risk,
            "session_alerted": session_alerted,
            "alert_reason": alert_reason,
            "alert_request": alert_request,
        })

        if changed:
            if client not in recent:
                recent.append(client)
                if len(recent) > RECENT:
                    recent.pop(0)
            last = client
            # A one-way move (e.g. Wi-Fi -> mobile data) is charged once and the
            # session now belongs to the new client. When an old client comes
            # back we can't tell who the owner is, so the reference stays.
            # Once the session is alerted the reference is frozen: the client
            # that caused the alert must not become the trusted client, or its
            # next requests would be compared with itself and look normal.
            if newly_alerted and fork:
                ref = client    # the earlier client that came back
            elif not fork and not session_alerted:
                ref = client

    return steps


def decide(risk, session_alerted=False):
    """Return ALERT if the individual risk crosses the threshold OR if the
    session has already been flagged as compromised (persistent alert state)."""
    return "ALERT" if (risk >= THRESHOLD or session_alerted) else "ALLOW"


def load_sessions(path, key):
    sessions = {}
    with open(os.path.join(HERE, path), newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            sessions.setdefault(row[key], []).append(row)
    return sessions


def save_csv(name, header, rows):
    os.makedirs(os.path.join(HERE, RESULTS), exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(os.path.join(HERE, path), "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)
    return path


def run_datasets():
    out = []
    for name, path in DATASETS.items():
        sessions = load_sessions(path, "session_id")
        alerts = caught = attacks = false_alarms = 0

        for sid, reqs in sessions.items():
            steps = check_session([client_of(r) for r in reqs])
            peak = max(s["risk"] for s in steps)
            result = decide(peak)
            attacked = any(r["attack"] == "1" for r in reqs)

            alerts += result == "ALERT"
            attacks += attacked
            caught += attacked and result == "ALERT"
            false_alarms += not attacked and result == "ALERT"
            out.append([name, sid, len(reqs), "yes" if attacked else "no", f"{peak:.4f}", result])

        normal = len(sessions) - attacks
        print(f"\nDataset: {name}  ({path})")
        print(f"  Sessions checked : {len(sessions)}  ({normal} normal, {attacks} with a simulated hijack)")
        print(f"  Alerts           : {alerts}")
        print(f"  Hijacks detected : {caught}/{attacks}")
        print(f"  False alarms     : {false_alarms}/{normal}")

    saved = save_csv("dataset_results.csv",
                     ["dataset", "session_id", "requests", "simulated_hijack", "peak_risk", "result"], out)
    print(f"\nPer-session results saved to {saved}")


def run_tests():
    cases = load_sessions(TEST_FILE, "test_id")
    out = []
    passed = 0

    for test_id, reqs in cases.items():
        steps = check_session([client_of(r) for r in reqs])
        peak = max(s["risk"] for s in steps)
        got = decide(peak)
        expected = reqs[0]["expected"]
        ok = got == expected
        passed += ok

        print(f"\nTest {test_id}: {reqs[0]['name']}")
        print(f"  Expected: {expected}")
        print(f"  Got:      {got}  (risk {peak:.4f})")
        print("  PASS" if ok else "  FAIL")
        out.append([test_id, reqs[0]["name"], expected, got, f"{peak:.4f}", "PASS" if ok else "FAIL"])

    print(f"\nPassed: {passed}/{len(cases)}")
    saved = save_csv("test_results.csv", ["test_id", "name", "expected", "got", "risk", "status"], out)
    print(f"Results saved to {saved}")
    return passed == len(cases)


def describe(step):
    net = {1.0: "Yes (different network)", SAME_16: "Yes (different subnet, same network)",
           SAME_24: "Yes (new IP, same subnet)", 0.0: "No"}
    agent = {1.0: "Yes (different browser/OS/device)", VERSION_ONLY: "Yes (browser version only)",
             0.0: "No"}
    alerted = step.get("session_alerted", False)
    reason  = step.get("alert_reason")
    alert_req = step.get("alert_request")

    print(f"  Network change    : {net.get(step['network'], str(step['network']))}")
    print(f"  User-agent change : {agent.get(step['agent'], str(step['agent']))}")
    print(f"  Old client back   : {'Yes (binding fork)' if step['fork'] else 'No'}")
    print(f"  Current risk      : {step['risk']:.4f}   (threshold: {THRESHOLD})")
    if alerted:
        indicator = " [current request above threshold]" if step['risk'] >= THRESHOLD else " [below threshold, but session is alerted]"
        print(f"  Session status    : ALERTED (first flagged at request {alert_req}){indicator}")
        if reason:
            print(f"  Alert reason      : {reason}")
        print(f"  Decision          : ALERT")
    else:
        print(f"  Session status    : CLEAN")
        print(f"  Decision          : ALLOW")


def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return "done"


# Valid OS and device choices for the manual CLI.
_VALID_OS  = ["Windows", "macOS", "Linux", "Ubuntu", "Debian", "ChromeOS",
               "Android", "iOS", "Other"]
_VALID_DEV = ["Desktop", "Mobile", "Tablet", "Other"]


def _ask_choice(prompt, choices, prev=None):
    """Ask the user to pick from a list; blank reuses prev."""
    listing = ", ".join(choices)
    while True:
        val = ask(f"  {prompt} [{listing}]: ")
        if val.lower() in ("done", "q"):
            return None        # signal caller to break
        if val == "" and prev is not None:
            return prev
        # Case-insensitive match
        match = next((c for c in choices if c.lower() == val.lower()), None)
        if match:
            return match
        print(f"  Invalid value. Choose from: {listing}")


def manual_test():
    """Interactive CLI: collect five client-binding fields per request.

    Client tuple used internally: (ip, browser, browser_version, os, device)
    This matches the tuple produced by parse_agent() and expected by
    check_session() / agent_score() / network_score().
    """
    print("\nManual test: enter the requests of one session in order.")
    print("Enter each field separately (IP / Browser / Version / OS / Device).")
    print("Press Enter to reuse the previous value, type 'done' or 'q' to finish.\n")

    sid = ask("Session ID: ") or "demo"

    # Each entry is already a 5-tuple: (ip, browser, version, os, device)
    clients = []
    prev = None   # previous 5-tuple for reuse-on-blank

    while True:
        n = len(clients) + 1
        print(f"\nRequest {n}")

        # --- IP ---
        ip = ask("  IP address: ")
        if ip.lower() in ("done", "q"):
            break
        if not ip:
            if prev is None:
                print("  Please enter an IP address.")
                continue
            ip = prev[0]

        # --- Browser ---
        browser_names = [b[0] for b in BROWSERS]
        browser = _ask_choice("Browser", browser_names, prev[1] if prev else None)
        if browser is None:
            break

        # --- Browser version ---
        ver_raw = ask(f"  Browser version (major number, e.g. 121): ")
        if ver_raw.lower() in ("done", "q"):
            break
        if ver_raw == "" and prev is not None:
            ver = prev[2]
        else:
            ver = ver_raw.strip()

        # --- OS ---
        os_name = _ask_choice("Operating system", _VALID_OS, prev[3] if prev else None)
        if os_name is None:
            break

        # --- Device ---
        device = _ask_choice("Device", _VALID_DEV, prev[4] if prev else None)
        if device is None:
            break

        client = (ip, browser, ver, os_name, device)
        clients.append(client)
        prev = client

        # Print parsed client info
        print(f"  Client → IP: {ip}  Browser: {browser} {ver}  OS: {os_name}  Device: {device}")

        if n == 1:
            print("  First request: client recorded for this session (risk 0.0000)")
            print("  Session status: CLEAN")
            print("  Decision: ALLOW")
        else:
            steps = check_session(clients)
            describe(steps[-1])

    if len(clients) > 1:
        steps = check_session(clients)
        peak  = max(s["risk"] for s in steps)
        final_alerted = steps[-1].get("session_alerted", False)
        final_decision = decide(peak, final_alerted)
        print(f"\nSession {sid}: {len(clients)} requests")
        print(f"  Highest individual risk : {peak:.4f}")
        print(f"  Session status          : {'ALERTED' if final_alerted else 'CLEAN'}")
        print(f"  Final decision          : {final_decision}")


def show_settings():
    print(f"""
risk = {W_AGENT} x user_agent_change
     + {W_NETWORK} x network_change
     + {W_FORK} x old_client_back

user_agent_change : 1 = browser/OS/device changed, {VERSION_ONLY} = only the version, 0 = same
network_change    : 1 = different /16 network, {SAME_16} = different /24 subnet,
                    {SAME_24} = different IP in the same /24, 0 = same IP
old_client_back   : 1 = a client seen earlier in this session appears again
                    after a different one (binding fork), else 0

A session gets ALERT when any request reaches risk >= {THRESHOLD}, otherwise ALLOW.""")


def menu():
    while True:
        print("\n==== SICA: Session Integrity and Continuity Analysis ====")
        print("1. Run datasets (W1, W2 samples)")
        print("2. Run test cases")
        print("3. Manual test")
        print("4. Show risk formula")
        print("5. Exit")
        choice = ask("Choose: ")
        if choice == "1":
            run_datasets()
        elif choice == "2":
            run_tests()
        elif choice == "3":
            manual_test()
        elif choice == "4":
            show_settings()
        elif choice in ("5", "done", "q"):
            break


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        if arg == "--data":
            run_datasets()
        elif arg == "--test":
            sys.exit(0 if run_tests() else 1)
        elif arg == "--manual":
            manual_test()
        else:
            menu()
    except KeyboardInterrupt:
        print()
