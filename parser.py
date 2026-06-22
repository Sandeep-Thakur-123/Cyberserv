"""
============================================================
 parser.py — Regex-Based SSH Log Parser
============================================================
 Parses raw Linux SSH log lines (from /var/log/auth.log or
 mock_auth.log) and extracts structured fields.

 Supported event types:
   - "Failed password"   → brute-force / bad credentials
   - "Accepted password" → successful authentication
   - "Accepted publickey"→ key-based login success
   - "Invalid user"      → probe with non-existent username
   - "Connection closed" → session end event
   - "Disconnected"      → client disconnected
   - "PAM"               → authentication subsystem events
============================================================
"""

import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ── Parsed Log Result Dataclass ────────────────────────────

@dataclass
class ParsedLogEntry:
    """
    Represents a fully parsed SSH log line.

    Attributes:
        timestamp:    The parsed datetime object of the event.
        ip_address:   Source IP address (IPv4 or IPv6), or None.
        target_user:  The SSH username attempted, or None.
        event_status: High-level event classification string.
        port:         The source port, or None.
        raw_log:      The original unmodified log line.
        is_parsed:    True if at least the timestamp was matched.
    """
    timestamp:    Optional[datetime]
    ip_address:   Optional[str]
    target_user:  Optional[str]
    event_status: str
    port:         Optional[str]
    raw_log:      str
    is_parsed:    bool = True


# ══════════════════════════════════════════════════════════════
#  Compiled Regular Expressions
# ══════════════════════════════════════════════════════════════

# Standard syslog timestamp prefix: "Jun 15 08:45:01"
# Matches both single-digit and double-digit days (space-padded)
_RE_TIMESTAMP = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)

# SSH daemon log line structure:
#   "Jun 15 08:45:01 hostname sshd[PID]: MESSAGE"
_RE_SSHD_LINE = re.compile(
    r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)

# IPv4 and IPv6 address capture
_RE_IP = re.compile(
    r"(?:from\s+|rhost=)(?P<ip>"
    r"(?:\d{1,3}\.){3}\d{1,3}"           # IPv4
    r"|(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6
    r")"
)

# Username capture — handles both "for USER" and "for invalid user USER"
_RE_USER = re.compile(
    r"for\s+(?:invalid\s+user\s+)?(?P<user>\S+)"
)

# Source port capture
_RE_PORT = re.compile(r"port\s+(?P<port>\d+)")

# ── Event Classification Patterns (ordered: most specific first) ──
_EVENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Auth failures
    (re.compile(r"Failed\s+password",          re.IGNORECASE), "Failed password"),
    (re.compile(r"Failed\s+publickey",          re.IGNORECASE), "Failed publickey"),
    # Auth successes
    (re.compile(r"Accepted\s+password",         re.IGNORECASE), "Accepted password"),
    (re.compile(r"Accepted\s+publickey",        re.IGNORECASE), "Accepted publickey"),
    # Probe / invalid
    (re.compile(r"Invalid\s+user",              re.IGNORECASE), "Invalid user"),
    (re.compile(r"Did\s+not\s+receive\s+identification", re.IGNORECASE), "No identification"),
    (re.compile(r"Bad\s+protocol\s+version",    re.IGNORECASE), "Bad protocol version"),
    # Session lifecycle
    (re.compile(r"Connection\s+closed",         re.IGNORECASE), "Connection closed"),
    (re.compile(r"Disconnected\s+from",         re.IGNORECASE), "Disconnected"),
    (re.compile(r"session\s+opened",            re.IGNORECASE), "Session opened"),
    (re.compile(r"session\s+closed",            re.IGNORECASE), "Session closed"),
    # Rate limiting / blocking
    (re.compile(r"maximum\s+authentication\s+attempts\s+exceeded", re.IGNORECASE), "Max auth attempts exceeded"),
    (re.compile(r"Received\s+disconnect",       re.IGNORECASE), "Received disconnect"),
    # PAM subsystem
    (re.compile(r"pam_unix",                    re.IGNORECASE), "PAM event"),
    # CRON / sudo / su events (non-SSH but present in auth.log)
    (re.compile(r"sudo:",                       re.IGNORECASE), "sudo event"),
    (re.compile(r"su:",                         re.IGNORECASE), "su event"),
    (re.compile(r"CRON",                        re.IGNORECASE), "CRON event"),
]

# Fallback classification for unrecognized sshd lines
_UNKNOWN_STATUS = "Unknown SSH event"


# ══════════════════════════════════════════════════════════════
#  Timestamp Parser
# ══════════════════════════════════════════════════════════════

def _parse_timestamp(line: str) -> Optional[datetime]:
    """
    Extracts and returns a datetime from the syslog timestamp prefix.
    Uses the current year since syslog format omits the year.

    Args:
        line: The raw log line string.

    Returns:
        A datetime object, or None if no timestamp was matched.
    """
    m = _RE_TIMESTAMP.match(line)
    if not m:
        return None

    current_year = datetime.now().year
    time_str = f"{m.group('month')} {m.group('day')} {m.group('time')} {current_year}"
    try:
        return datetime.strptime(time_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


# ══════════════════════════════════════════════════════════════
#  Event Classifier
# ══════════════════════════════════════════════════════════════

def _classify_event(message: str) -> str:
    """
    Matches the SSH message text against ordered event patterns
    and returns the first matching classification string.

    Args:
        message: The body of the sshd log message.

    Returns:
        A human-readable event status string.
    """
    for pattern, label in _EVENT_PATTERNS:
        if pattern.search(message):
            return label
    return _UNKNOWN_STATUS


# ══════════════════════════════════════════════════════════════
#  Main Parser
# ══════════════════════════════════════════════════════════════

def parse_log_line(raw_line: str) -> Optional[ParsedLogEntry]:
    """
    Parses a single raw auth.log line into a structured ParsedLogEntry.

    Args:
        raw_line: A single line of text from the log file.

    Returns:
        A ParsedLogEntry if the line contains a parseable timestamp,
        or None if the line is blank or completely unparseable.
    """
    line = raw_line.strip()
    if not line:
        return None

    # ── Timestamp (required field) ─────────────────────────
    timestamp = _parse_timestamp(line)
    if timestamp is None:
        return None   # Skip non-log garbage lines

    # ── Extract SSH message body ───────────────────────────
    sshd_match = _RE_SSHD_LINE.match(line)
    message = sshd_match.group("message") if sshd_match else line

    # ── Event Classification ───────────────────────────────
    event_status = _classify_event(message)

    # ── IP Address ─────────────────────────────────────────
    ip_match  = _RE_IP.search(message)
    ip_address = ip_match.group("ip") if ip_match else None

    # ── Username ───────────────────────────────────────────
    user_match   = _RE_USER.search(message)
    target_user  = user_match.group("user") if user_match else None

    # Sanitize: reject false positives like "authenticating" / "auth"
    if target_user and (len(target_user) > 32 or not re.match(r"^[a-zA-Z0-9_.\-@]+$", target_user)):
        target_user = None

    # ── Port ───────────────────────────────────────────────
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
    """
    Returns True if the log entry represents a failed or suspicious
    authentication attempt that should count toward the anomaly threshold.

    Args:
        entry: A ParsedLogEntry object.

    Returns:
        True for failure-class events, False for benign events.
    """
    failure_statuses = {
        "Failed password",
        "Failed publickey",
        "Invalid user",
        "No identification",
        "Bad protocol version",
        "Max auth attempts exceeded",
    }
    return entry.event_status in failure_statuses


# ── Manual test entry point ────────────────────────────────
if __name__ == "__main__":
    test_lines = [
        "Jun 22 14:32:01 server sshd[9421]: Failed password for root from 203.0.113.42 port 51234 ssh2",
        "Jun 22 14:32:05 server sshd[9422]: Invalid user admin from 203.0.113.42 port 51235",
        "Jun 22 14:33:00 server sshd[9450]: Accepted password for deploy from 10.0.0.5 port 22 ssh2",
        "Jun 22 14:33:01 server sshd[9451]: session opened for user deploy by (uid=0)",
        "Jun 22 14:33:10 server sshd[9460]: Failed password for invalid user oracle from 198.51.100.7 port 44100 ssh2",
        "Jun 22 14:34:00 server sshd[9470]: Disconnected from 203.0.113.42 port 51234 [preauth]",
        "",                   # blank line — should return None
        "Not a log line",     # garbage — should return None
    ]

    print("=" * 60)
    print("  Parser Self-Test")
    print("=" * 60)
    for raw in test_lines:
        result = parse_log_line(raw)
        if result:
            print(f"  ✓ [{result.event_status}]")
            print(f"    IP={result.ip_address}  User={result.target_user}  Port={result.port}")
            print(f"    Time={result.timestamp}")
        else:
            print(f"  ✗ Skipped: {repr(raw[:50])}")
        print()
