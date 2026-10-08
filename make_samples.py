
import csv
import os
import re
from datetime import datetime

from run import parse_agent

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = {"W1": "data/W1/apache_sample_1.log", "W2": "data/W2/nginx_real.log"}
N_SESSIONS = 100
MIN_REQUESTS = 7
IDLE_GAP = 30 * 60
ATTACKS = ["concurrent", "concurrent_copied_ua", "takeover", "takeover_copied_ua"]

LOG_LINE = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" \d{3} \S+(?: "(.*?)" "(.*?)")?')


def read_log(path):
    rows = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LOG_LINE.match(line)
            if not m:
                continue
            ip, time, request, _, agent = m.groups()
            parts = request.split()
            rows.append({
                "time": datetime.strptime(time.split()[0], "%d/%b/%Y:%H:%M:%S"),
                "ip": ip,
                "user_agent": agent or "-",
                "path": parts[1] if len(parts) > 1 else request,
                "attack": 0,
            })
    rows.sort(key=lambda r: r["time"])
    return rows


def make_sessions(rows):
    # The logs have no session cookie, so one client (IP + User-Agent)
    # with no pause longer than 30 minutes counts as one session.
    clients = {}
    for r in rows:
        clients.setdefault((r["ip"], r["user_agent"]), []).append(r)

    sessions = []
    for reqs in clients.values():
        current = [reqs[0]]
        for r in reqs[1:]:
            if (r["time"] - current[-1]["time"]).total_seconds() > IDLE_GAP:
                sessions.append(current)
                current = []
            current.append(r)
        sessions.append(current)

    sessions = [s for s in sessions if len(s) >= MIN_REQUESTS]
    sessions.sort(key=lambda s: s[0]["time"])
    return sessions[:N_SESSIONS]


def network(ip):
    return ".".join(ip.split(".")[:2])


def add_attack(victim, attacker, kind):
    cut = len(victim) // 2
    ip = attacker[0]["ip"]
    agent = victim[0]["user_agent"] if kind.endswith("copied_ua") else attacker[0]["user_agent"]
    stolen = [dict(r, ip=ip, user_agent=agent, attack=1) for r in victim[cut:]]

    if kind.startswith("concurrent"):
        # attacker sends two requests while the victim keeps browsing
        return victim[:cut] + stolen[:2] + victim[cut:]
    # takeover: the victim stops and the attacker continues the session
    return victim[:cut] + stolen


def main():
    for name, source in SOURCES.items():
        sessions = make_sessions(read_log(os.path.join(HERE, source)))
        out = os.path.join(HERE, "data", f"{name}_sample.csv")

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, lineterminator="\n")
            writer.writerow(["session_id", "request_no", "timestamp", "ip_address", "browser",
                             "browser_version", "operating_system", "device_type", "attack"])
            n_attacks = 0
            for i, session in enumerate(sessions):
                if i % 5 == 4:
                    # first later session from a different network plays the attacker
                    j = (i + 1) % len(sessions)
                    while network(sessions[j][0]["ip"]) == network(session[0]["ip"]):
                        j = (j + 1) % len(sessions)
                    session = add_attack(session, sessions[j], ATTACKS[n_attacks % 4])
                    n_attacks += 1
                for n, r in enumerate(session, 1):
                    browser, version, system, device = parse_agent(r["user_agent"])
                    writer.writerow([f"{name}-{i + 1:03d}", n, r["time"], r["ip"], browser,
                                     version or "-", system, device, r["attack"]])

        print(f"data/{name}_sample.csv: {len(sessions)} sessions, {n_attacks} with a simulated hijack")


if __name__ == "__main__":
    main()
