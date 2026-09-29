"""SICA: Session Integrity and Continuity Analysis

Detects possible HTTP session hijacking from server access logs.
A session should keep the same client (network + User-Agent). When the client
changes in the middle of a session the risk goes up, and when the risk reaches
the threshold the session is flagged with an ALERT.

    python run.py            menu
    python run.py --data     check the W1 and W2 samples
    python run.py --test     run the test cases
    python run.py --manual   type in a session by hand
"""
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
    """Score every request of one session. clients = [(ip, browser, version, os, device), ...]"""
    steps = []
    ref = last = None
    recent = []

    for client in clients:
        if ref is None:
            ref = last = client
            recent = [client]
            steps.append({"agent": 0.0, "network": 0.0, "fork": 0.0, "risk": 0.0})
            continue

        changed = client != last
        fork = changed and client in recent

        agent = agent_score(client, ref)
        net = network_score(client, ref)
        risk = W_AGENT * agent + W_NETWORK * net + W_FORK * (1.0 if fork else 0.0)
        steps.append({"agent": agent, "network": net, "fork": 1.0 if fork else 0.0,
                      "risk": round(risk, 4)})

        if changed:
            if client not in recent:
                recent.append(client)
                if len(recent) > RECENT:
                    recent.pop(0)
            last = client
            # A one-way move (e.g. Wi-Fi -> mobile data) is charged once and the
            # session now belongs to the new client. When an old client comes
            # back we can't tell who the owner is, so the reference stays.
            if not fork:
                ref = client

    return steps


def decide(risk):
    return "ALERT" if risk >= THRESHOLD else "ALLOW"


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
    print(f"  Network change    : {net[step['network']]}")
    print(f"  User-agent change : {agent[step['agent']]}")
    print(f"  Old client back   : {'Yes (binding fork)' if step['fork'] else 'No'}")
    print(f"  Risk: {step['risk']:.4f}   Threshold: {THRESHOLD}   ->  {decide(step['risk'])}")


def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        return "done"


def manual_test():
    print("\nManual test: enter the requests of one session in order.")
    print("User-Agent shortcuts: " + ", ".join(AGENTS))
    print("Press Enter to reuse the previous value, type 'done' to finish.\n")

    sid = ask("Session ID: ") or "demo"
    requests = []
    while True:
        n = len(requests) + 1
        print(f"\nRequest {n}")
        ip = ask("  IP: ")
        if ip.lower() in ("done", "q"):
            break
        if not ip:
            if not requests:
                print("  Please enter an IP address.")
                continue
            ip = requests[-1][0]
        ua = ask("  User-Agent: ")
        if ua.lower() in ("done", "q"):
            break
        if not ua:
            ua = requests[-1][1] if requests else "-"
        ua = AGENTS.get(ua.lower(), ua)
        requests.append((ip, ua))
        clients = [(i,) + parse_agent(u) for i, u in requests]

        if n == 1:
            print("  First request: client recorded for this session (risk 0)")
        else:
            describe(check_session(clients)[-1])

    if len(requests) > 1:
        peak = max(s["risk"] for s in check_session(clients))
        print(f"\nSession {sid}: {len(requests)} requests, highest risk {peak:.4f}  ->  {decide(peak)}")


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
