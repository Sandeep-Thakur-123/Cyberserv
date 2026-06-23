"""
parser.py - Regex-Based SSH Log Parser
Supports both log formats:
  - Classic syslog:  "Jun 22 14:32:01 host sshd[PID]: message"
  - Ubuntu 26.04+:   "2026-06-23T12:36:10.989922+00:00 host sshd-session[PID]: message"
"""

import re
from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedLogEntry:
    timestamp:    Optional[datetime]
    ip_address:   Optional[str]
    target_user:  Optional[str]
    event_status: str
    port:         Optional[str]
    raw_log:      str
    is_parsed:    bool = True


# ── Timestamp Patterns ─────────────────────────────────────────────

# Format 1 - Classic syslog:  Jun 22 14:32:01
_RE_TS_SYSLOG = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# Format 2 - ISO 8601 (Ubuntu 26.04):  2026-06-23T12:36:10.989922+00:00
_RE_TS_ISO = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<time>\d{2}:\d{2}:\d{2})"
)

# ── SSH Line Pattern ───────────────────────────────────────────────
# Matches both sshd[PID] and sshd-session[PID]
_RE_SSHD_LINE = re.compile(
    r"^\S+\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<message>.+)$"
)

# ── IP Address ─────────────────────────────────────────────────────
_RE_IP = re.compile(
    r"(?:from\s+|rhost=)(?P<ip>"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
    r")"
)

# ── Username ───────────────────────────────────────────────────────
_RE_USER = re.compile(
    r"for\s+(?:invalid\s+user\s+)?(?P<user>\S+)"
)

# ── Port ───────────────────────────────────────────────────────────
_RE_PORT = re.compile(r"port\s+(?P<port>\d+)")

# ── Event Classification (ordered most specific first) ─────────────
_EVENT_PATTERNS = [
    (re.compile(r"Failed\s+password",                  re.I), "Failed password"),
    (re.compile(r"Failed\s+publickey",                 re.I), "Failed publickey"),
    (re.compile(r"Accepted\s+password",                re.I), "Accepted password"),
    (re.compile(r"Accepted\s+publickey",               re.I), "Accepted publickey"),
    (re.compile(r"Invalid\s+user",                     re.I), "Invalid user"),
    (re.compile(r"Did\s+not\s+receive\s+identification",re.I),"No identification"),
    (re.compile(r"Bad\s+protocol\s+version",           re.I), "Bad protocol version"),
    (re.compile(r"Connection\s+reset\s+by\s+invalid",  re.I), "Invalid user"),
    (re.compile(r"Connection\s+closed",                re.I), "Connection closed"),
    (re.compile(r"Disconnected\s+from",                re.I), "Disconnected"),
    (re.compile(r"session\s+opened",                   re.I), "Session opened"),
    (re.compile(r"session\s+closed",                   re.I), "Session closed"),
    (re.compile(r"maximum\s+authentication\s+attempts", re.I),"Max auth attempts exceeded"),
    (re.compile(r"Received\s+disconnect",              re.I), "Received disconnect"),
    (re.compile(r"Timeout\s+before\s+authentication",  re.I), "Auth timeout"),
    (re.compile(r"pam_unix",                           re.I), "PAM event"),
    (re.compile(r"sudo:",                              re.I), "sudo event"),
]

_UNKNOWN_STATUS = "Unknown SSH event"


def _parse_timestamp(line: str) -> Optional[datetime]:
    """
    Tries ISO 8601 format first (Ubuntu 26.04+),
    then falls back to classic syslog format.
    """
    # Try ISO 8601 first: 2026-06-23T12:36:10.989922+00:00
    m = _RE_TS_ISO.match(line)
    if m:
        try:
            return datetime(
                int(m.group("year")),
                int(m.group("month")),
                int(m.group("day")),
                *[int(x) for x in m.group("time").split(":")]
            )
        except ValueError:
            pass

    # Fallback: classic syslog Jun 22 14:32:01
    m = _RE_TS_SYSLOG.match(line)
    if m:
        try:
            year = datetime.now().year
            ts = f"{m.group('month')} {m.group('day')} {m.group('time')} {year}"
            return datetime.strptime(ts, "%b %d %H:%M:%S %Y")
        except ValueError:
            pass

    return None


def _classify_event(message: str) -> str:
    for pattern, label in _EVENT_PATTERNS:
        if pattern.search(message):
            return label
    return _UNKNOWN_STATUS


def parse_log_line(raw_line: str) -> Optional[ParsedLogEntry]:
    """
    Parses a single auth.log line into a ParsedLogEntry.
    Returns None for blank or completely unparseable lines.
    """
    line = raw_line.strip()
    if not line:
        return None

    timestamp = _parse_timestamp(line)
    if timestamp is None:
        return None

    # Extract SSH message body (works for both sshd and sshd-session)
    sshd_match = _RE_SSHD_LINE.match(line)
    message = sshd_match.group("message") if sshd_match else line

    event_status = _classify_event(message)

    ip_match   = _RE_IP.search(message)
    ip_address = ip_match.group("ip") if ip_match else None

    # Also try to grab IP from "Connection reset by invalid user X IP port Y"
    if not ip_address:
        m = re.search(r"invalid user \S+ (\d{1,3}(?:\.\d{1,3}){3})", message, re.I)
        if m:
            ip_address = m.group(1)

    user_match  = _RE_USER.search(message)
    target_user = user_match.group("user") if user_match else None

    if target_user and (
        len(target_user) > 32
        or not re.match(r"^[a-zA-Z0-9_.\-@]+$", target_user)
    ):
        target_user = None

    port_match = _RE_PORT.search(message)
    port       = port_match.group("port") if port_match else None

    return ParsedLogEntry(
        timestamp=timestamp,
        ip_address=ip_address,
        target_user=target_user,
        event_status=event_status,
        port=port,
        raw_log=line,
        is_parsed=True,
    )


def is_failure_event(entry: ParsedLogEntry) -> bool:
    """Returns True for events that count toward anomaly threshold."""
    return entry.event_status in {
        "Failed password",
        "Failed publickey",
        "Invalid user",
        "No identification",
        "Bad protocol version",
        "Max auth attempts exceeded",
        "Auth timeout",
    }


# ── Self-test ──────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # Ubuntu 26.04 ISO format with sshd-session
        '2026-06-23T12:36:10.989922+00:00 ip-172-31-45-128 sshd-session[13937]: Invalid user wronguser from 49.156.88.143 port 59501',
        '2026-06-23T12:36:11.030023+00:00 ip-172-31-45-128 sshd-session[13937]: Connection reset by invalid user wronguser 49.156.88.143 port 59501 [preauth]',
        '2026-06-23T12:47:11.695767+00:00 ip-172-31-45-128 sshd-session[13979]: Accepted publickey for ubuntu from 13.233.177.5 port 59120 ssh2',
        # Classic syslog format
        'Jun 22 14:32:01 server sshd[9421]: Failed password for root from 203.0.113.42 port 51234 ssh2',
        'Jun 22 14:32:05 server sshd[9422]: Invalid user admin from 203.0.113.42 port 51235',
    ]

    print("=" * 65)
    print("  Parser Self-Test — Ubuntu 26.04 + Classic formats")
    print("=" * 65)
    for raw in tests:
        result = parse_log_line(raw)
        if result:
            status = "FAILURE" if is_failure_event(result) else "normal"
            print(f"  OK  [{result.event_status}] ({status})")
            print(f"      IP={result.ip_address}  User={result.target_user}")
        else:
            print(f"  SKIP: {raw[:60]}")
        print()