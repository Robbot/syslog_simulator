#!/usr/bin/env python3
"""
syslog_simulator.py
Simulate a Linux device producing real-time syslog messages with a fixed hostname.
- Outputs RFC3164-like syslog lines to stdout and/or sends to a syslog server via UDP/TCP.
- Content is randomized but plausible (sshd, sudo, cron, systemd, kernel, nginx, etc.)

Examples:
  # 1) Print to stdout (pipe to whatever)
  python3 syslog_simulator.py --hostname web-01 --stdout

  # 2) Send UDP to a syslog receiver (e.g., rsyslog on 192.168.1.10:514)
  python3 syslog_simulator.py --hostname db-01 --udp 192.168.1.10:514

  # 3) Send TCP + also stdout, 5-12 msgs/sec
  python3 syslog_simulator.py --hostname app-01 --tcp 127.0.0.1:514 --rate 5:12 --stdout
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import random
import socket
import sys
import time
from dataclasses import dataclass
from typing import Optional, Tuple


# ----------------------------
# Syslog basics (RFC3164-ish)
# ----------------------------
FACILITIES = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}
SEVERITIES = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}


def rfc3164_ts(now: Optional[dt.datetime] = None) -> str:
    # RFC3164 timestamp: "Mmm dd hh:mm:ss" (no year, no timezone)
    # Example: "Jan 16 12:34:56"
    if now is None:
        now = dt.datetime.now()
    return now.strftime("%b %e %H:%M:%S")


def pri(facility: str, severity: str) -> int:
    return FACILITIES[facility] * 8 + SEVERITIES[severity]


@dataclass
class Destination:
    mode: str  # "udp"|"tcp"|"none"
    host: str = ""
    port: int = 0


# ----------------------------
# Random but plausible content
# ----------------------------
USERS = ["root", "ubuntu", "ec2-user", "admin", "robcio", "svc-backup", "nginx", "postgres"]
SERVICES = ["sshd", "sudo", "cron", "systemd", "kernel", "nginx", "dbus-daemon", "NetworkManager", "dockerd"]
IFACES = ["eth0", "ens18", "enp3s0", "wlan0"]
DISKS = ["sda", "sdb", "nvme0n1"]
UNITS = ["sshd.service", "nginx.service", "docker.service", "cron.service", "rsyslog.service"]
COUNTRIES = ["IE", "PL", "DE", "US", "FR", "NL", "SE"]
SSH_METHODS = ["publickey", "password", "keyboard-interactive/pam"]
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
HTTP_CODES = [200, 201, 204, 301, 302, 400, 401, 403, 404, 429, 500, 502, 503]
PATHS = ["/", "/login", "/api/v1/health", "/api/v1/users", "/static/app.js", "/admin", "/robots.txt"]
UA = [
    "curl/8.4.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/121.0",
    "Prometheus/2.48.0",
]


def rand_ip() -> str:
    # avoid 0/255, keep it plausible
    return f"{random.randint(10, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def rand_pid() -> int:
    return random.randint(100, 65000)


def choose_weighted(items):
    # items: list of (weight, value)
    total = sum(w for w, _ in items)
    r = random.uniform(0, total)
    upto = 0.0
    for w, v in items:
        if upto + w >= r:
            return v
        upto += w
    return items[-1][1]


def msg_sshd() -> Tuple[str, str, str, str]:
    # facility, severity, tag, content
    pid = rand_pid()
    src_ip = rand_ip()
    user = random.choice(USERS)
    method = random.choice(SSH_METHODS)
    port = random.randint(1024, 65535)
    outcome = choose_weighted([
        (70, "Accepted"),
        (25, "Failed"),
        (5, "Invalid user"),
    ])

    if outcome == "Accepted":
        sev = choose_weighted([(85, "info"), (15, "notice")])
        content = f"{outcome} {method} for {user} from {src_ip} port {port} ssh2"
    elif outcome == "Failed":
        sev = choose_weighted([(70, "warning"), (30, "notice")])
        content = f"{outcome} {method} for {user} from {src_ip} port {port} ssh2"
    else:
        sev = "warning"
        content = f"{outcome} {user} from {src_ip} port {port}"

    return ("authpriv", sev, f"sshd[{pid}]", content)


def msg_sudo() -> Tuple[str, str, str, str]:
    pid = rand_pid()
    actor = random.choice([u for u in USERS if u != "root"])
    target = "root"
    tty = random.choice(["pts/0", "pts/1", "pts/2", "tty1"])
    pwd = random.choice(["/home/" + actor, "/var/www", "/etc", "/opt/app"])
    cmd = random.choice([
        "/usr/bin/systemctl restart nginx",
        "/usr/bin/journalctl -u sshd --since today",
        "/usr/bin/apt-get update",
        "/usr/bin/docker ps",
        "/usr/sbin/useradd tempuser",
    ])
    sev = choose_weighted([(80, "notice"), (20, "info")])
    content = f"{actor} : TTY={tty} ; PWD={pwd} ; USER={target} ; COMMAND={cmd}"
    return ("authpriv", sev, f"sudo[{pid}]", content)


def msg_cron() -> Tuple[str, str, str, str]:
    pid = rand_pid()
    user = random.choice(USERS)
    job = random.choice([
        "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
        f"({user}) CMD (/usr/bin/python3 /opt/app/maintenance.py)",
        f"({user}) CMD (/usr/bin/find /tmp -type f -mtime +7 -delete)",
    ])
    sev = "info"
    return ("cron", sev, f"CRON[{pid}]", job)


def msg_systemd() -> Tuple[str, str, str, str]:
    unit = random.choice(UNITS)
    action = choose_weighted([
        (45, "Started"),
        (35, "Stopped"),
        (20, "Reloaded"),
    ])
    sev = choose_weighted([(70, "info"), (20, "notice"), (10, "warning")])
    content = f"{action} {unit}."
    return ("daemon", sev, "systemd[1]", content)


def msg_kernel() -> Tuple[str, str, str, str]:
    # kernel messages often use facility kern
    iface = random.choice(IFACES)
    disk = random.choice(DISKS)
    kind = choose_weighted([
        (35, "link"),
        (30, "disk"),
        (20, "oom"),
        (15, "net"),
    ])

    if kind == "link":
        state = choose_weighted([(70, "up"), (30, "down")])
        sev = "notice" if state == "up" else "warning"
        content = f"{iface}: Link is {state} at {random.choice([100, 1000, 2500])}Mbps, full duplex"
    elif kind == "disk":
        sev = choose_weighted([(60, "info"), (30, "notice"), (10, "warning")])
        content = f"sd {disk}: {random.randint(1, 10)}.{random.randint(0, 9)}: {random.choice(['Attached SCSI disk', 'Write Protect is off', 'Synchronizing SCSI cache'])}"
    elif kind == "oom":
        sev = "err"
        pid = rand_pid()
        proc = random.choice(["java", "python3", "node", "postgres"])
        content = f"Out of memory: Killed process {pid} ({proc}) total-vm:{random.randint(500000, 8000000)}kB, anon-rss:{random.randint(10000, 2000000)}kB"
    else:
        sev = choose_weighted([(60, "info"), (30, "notice"), (10, "warning")])
        content = f"IPv4: martian source {rand_ip()} from {rand_ip()}, on dev {iface}"
    return ("kern", sev, "kernel", content)


def msg_nginx() -> Tuple[str, str, str, str]:
    pid = rand_pid()
    src_ip = rand_ip()
    method = random.choice(HTTP_METHODS)
    path = random.choice(PATHS)
    code = random.choice(HTTP_CODES)
    size = random.randint(64, 50000)
    ua = random.choice(UA)
    host = random.choice(["example.com", "intranet.local", "api.service.local"])
    rt = round(random.uniform(0.001, 2.5), 3)
    sev = "info" if code < 400 else ("warning" if code < 500 else "err")
    content = f'{src_ip} - - "{method} {path} HTTP/1.1" {code} {size} "-" "{ua}" host="{host}" rt={rt}'
    return ("local0", sev, f"nginx[{pid}]", content)


def msg_networkmanager() -> Tuple[str, str, str, str]:
    pid = rand_pid()
    iface = random.choice(IFACES)
    sev = choose_weighted([(80, "info"), (20, "notice")])
    content = choose_weighted([
        (50, f"<info>  [device:{iface}] state change: disconnected -> connecting"),
        (40, f"<info>  [device:{iface}] state change: connecting -> connected"),
        (10, f"<warn>  [device:{iface}] DHCP timeout, retrying"),
    ])
    return ("daemon", sev, f"NetworkManager[{pid}]", content)


GENERATORS = [
    (22, msg_sshd),
    (18, msg_sudo),
    (12, msg_cron),
    (12, msg_systemd),
    (14, msg_kernel),
    (14, msg_nginx),
    (8, msg_networkmanager),
]


def make_message(hostname: str) -> str:
    facility, severity, tag, content = choose_weighted(GENERATORS)()
    p = pri(facility, severity)
    ts = rfc3164_ts()
    # RFC3164: "<PRI>timestamp hostname tag: message"
    return f"<{p}>{ts} {hostname} {tag}: {content}"


# ----------------------------
# Sending / output
# ----------------------------
class SyslogSender:
    def __init__(self, dest: Destination):
        self.dest = dest
        self.sock: Optional[socket.socket] = None

    def open(self):
        if self.dest.mode == "none":
            return
        if self.dest.mode == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.dest.mode == "tcp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.dest.host, self.dest.port))
        else:
            raise ValueError(f"Unsupported mode: {self.dest.mode}")

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def send(self, line: str):
        if self.dest.mode == "none":
            return
        if not self.sock:
            raise RuntimeError("Socket not open")
        data = (line + "\n").encode("utf-8", errors="replace")
        if self.dest.mode == "udp":
            self.sock.sendto(data, (self.dest.host, self.dest.port))
        else:  # tcp
            self.sock.sendall(data)


def parse_hostport(s: str) -> Tuple[str, int]:
    if ":" not in s:
        raise ValueError("Expected HOST:PORT")
    host, port_s = s.rsplit(":", 1)
    port = int(port_s)
    if not (1 <= port <= 65535):
        raise ValueError("PORT out of range")
    return host, port


def parse_rate(s: str) -> Tuple[float, float]:
    # msgs per second range "min:max"
    if ":" in s:
        a, b = s.split(":", 1)
        lo = float(a)
        hi = float(b)
    else:
        lo = hi = float(s)
    if lo <= 0 or hi <= 0 or hi < lo:
        raise ValueError("Invalid rate; expected N or MIN:MAX, both > 0")
    return lo, hi


def main():
    ap = argparse.ArgumentParser(description="Real-time syslog device simulator (fixed hostname, randomized content).")
    ap.add_argument("--hostname", required=True, help="Fixed hostname to embed in syslog lines (e.g., web-01)")
    ap.add_argument("--stdout", action="store_true", help="Print syslog lines to stdout")
    ap.add_argument("--udp", help="Send to syslog receiver via UDP as HOST:PORT (e.g., 192.168.1.10:514)")
    ap.add_argument("--tcp", help="Send to syslog receiver via TCP as HOST:PORT (e.g., 127.0.0.1:514)")
    ap.add_argument("--rate", default="1:4", help="Messages/sec, N or MIN:MAX (default 1:4)")
    ap.add_argument("--jitter", default="0.25", help="Extra random delay seconds added per message (default 0.25)")
    ap.add_argument("--seed", type=int, default=None, help="Random seed (for repeatability)")
    ap.add_argument("--count", type=int, default=0, help="If >0, send this many messages then exit (default 0=infinite)")
    args = ap.parse_args()

    if not args.stdout and not args.udp and not args.tcp:
        ap.error("Choose at least one output: --stdout and/or --udp HOST:PORT and/or --tcp HOST:PORT")

    if args.udp and args.tcp:
        ap.error("Choose only one network mode: --udp or --tcp (you can still also use --stdout)")

    if args.seed is not None:
        random.seed(args.seed)
    else:
        # make it different per run
        random.seed(int.from_bytes(os.urandom(8), "big"))

    lo, hi = parse_rate(args.rate)
    jitter = float(args.jitter)
    jitter = max(0.0, jitter)

    dest = Destination(mode="none")
    if args.udp:
        host, port = parse_hostport(args.udp)
        dest = Destination(mode="udp", host=host, port=port)
    elif args.tcp:
        host, port = parse_hostport(args.tcp)
        dest = Destination(mode="tcp", host=host, port=port)

    sender = SyslogSender(dest)
    try:
        sender.open()
    except Exception as e:
        print(f"ERROR: failed to open {dest.mode} destination {dest.host}:{dest.port} -> {e}", file=sys.stderr)
        sys.exit(2)

    sent = 0
    try:
        while True:
            line = make_message(args.hostname)

            if args.stdout:
                print(line, flush=True)

            if dest.mode != "none":
                try:
                    sender.send(line)
                except Exception as e:
                    print(f"ERROR: send failed ({dest.mode} {dest.host}:{dest.port}): {e}", file=sys.stderr)
                    # For TCP, a receiver restart will break the connection. Exit so your supervisor can restart.
                    sys.exit(3)

            sent += 1
            if args.count > 0 and sent >= args.count:
                break

            # Sleep so it feels "real-time": inverse of msgs/sec, with some randomness.
            rate = random.uniform(lo, hi)
            base_delay = 1.0 / rate
            time.sleep(base_delay + random.uniform(0.0, jitter))
    finally:
        sender.close()


if __name__ == "__main__":
    main()

