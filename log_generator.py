"""
============================================================
 log_generator.py — Mock SSH Auth Log Generator
============================================================
 Simulates a live Linux /var/log/auth.log by continuously
 appending realistic SSH log entries to `mock_auth.log`.

 Features:
   - Randomized IP addresses and usernames
   - Realistic syslog timestamp format
   - Mix of successful and failed authentication events
   - Periodic "burst" mode: 5-10 rapid failures from ONE IP
     to trigger the anomaly detector in monitor.py
   - Configurable write interval and burst probability
   - Graceful Ctrl+C shutdown

 Usage:
   python log_generator.py [--burst-prob 0.15] [--interval 1.5]
============================================================
"""

import argparse
import random
import sys
import time
from datetime import datetime
from pathlib import Path

from colorama import Fore, Style, init

init(autoreset=True)

# ── Output Log File ────────────────────────────────────────
OUTPUT_FILE = Path("mock_auth.log")

# ── Realistic SSH Usernames to Probe ──────────────────────
COMMON_USERNAMES = [
    "root", "admin", "ubuntu", "deploy", "oracle", "postgres",
    "test", "user", "guest", "ftp", "support", "nagios",
    "jenkins", "git", "www-data", "pi", "vagrant", "ansible",
]

# ── Legitimate Users (for successful logins) ──────────────
LEGIT_USERS = ["deploy", "ubuntu", "devops", "sre_user", "monitor"]

# ── Hostname to embed in log lines ────────────────────────
HOSTNAMES = ["webserver01", "db-prod-02", "api-gateway", "bastion-host"]

# ── SSH Event Templates ───────────────────────────────────
# Placeholders: {ts}, {host}, {pid}, {user}, {ip}, {port}
EVENT_TEMPLATES: list[tuple[float, str]] = [
    # (relative_weight, template_string)
    (0.40, "{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"),
    (0.15, "{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"),
    (0.15, "{ts} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}"),
    (0.12, "{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"),
    (0.05, "{ts} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:abc123xyz"),
    (0.04, "{ts} {host} sshd[{pid}]: session opened for user {user} by (uid=0)"),
    (0.03, "{ts} {host} sshd[{pid}]: session closed for user {user}"),
    (0.03, "{ts} {host} sshd[{pid}]: Connection closed by {ip} port {port} [preauth]"),
    (0.02, "{ts} {host} sshd[{pid}]: Disconnected from {ip} port {port} [preauth]"),
    (0.01, "{ts} {host} sshd[{pid}]: Did not receive identification string from {ip} port {port}"),
]

# Separate weights and templates for random.choices()
_WEIGHTS    = [w for w, _ in EVENT_TEMPLATES]
_TEMPLATES  = [t for _, t in EVENT_TEMPLATES]


# ══════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════

def _random_ip() -> str:
    """Generates a random-looking public IPv4 address."""
    # Use RFC 5737 documentation ranges to avoid real IPs
    ranges = [
        (203, 0,   113, None),
        (198, 51,  100, None),
        (192, 0,   2,   None),
        (198, 18,  None, None),
        (10,  None, None, None),
    ]
    prefix = random.choice(ranges)
    octets = []
    for octet in prefix:
        octets.append(str(octet) if octet is not None else str(random.randint(1, 254)))
    # Fill remaining octets
    while len(octets) < 4:
        octets.append(str(random.randint(1, 254)))
    return ".".join(octets[:4])


def _random_port() -> int:
    """Returns a random ephemeral port number."""
    return random.randint(32768, 65535)


def _now_syslog() -> str:
    """Returns the current time formatted as syslog prefix: 'Jun 22 14:05:01'"""
    return datetime.now().strftime("%b %e %H:%M:%S").replace("  ", " ")


def _make_log_line(template: str, ip: str, user: str) -> str:
    """Renders a log template with realistic randomized values."""
    return template.format(
        ts=_now_syslog(),
        host=random.choice(HOSTNAMES),
        pid=random.randint(1000, 65535),
        user=user,
        ip=ip,
        port=_random_port(),
    )


def _write_line(line: str, fh) -> None:
    """Appends a line to the log file and flushes immediately."""
    fh.write(line + "\n")
    fh.flush()


# ══════════════════════════════════════════════════════════════
#  Burst Attack Simulator
# ══════════════════════════════════════════════════════════════

def _generate_burst(fh, burst_ip: str | None = None, burst_size: int | None = None) -> None:
    """
    Simulates a rapid brute-force burst from a single attacker IP.
    Writes 5–10 'Failed password' or 'Invalid user' lines in quick
    succession to trigger the anomaly threshold in monitor.py.

    Args:
        fh:         Open file handle for the log file.
        burst_ip:   The attacker IP (random if None).
        burst_size: Number of attempts (random 5-10 if None).
    """
    attacker_ip = burst_ip or _random_ip()
    count       = burst_size or random.randint(5, 10)
    user        = random.choice(COMMON_USERNAMES)

    print(
        f"\n{Fore.RED}[BURST] Simulating brute-force: {count} attempts "
        f"from {attacker_ip} targeting '{user}'{Style.RESET_ALL}"
    )

    burst_templates = [
        "{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
        "{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2",
        "{ts} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}",
    ]

    for i in range(count):
        tmpl = random.choice(burst_templates)
        line = _make_log_line(tmpl, attacker_ip, user)
        _write_line(line, fh)
        print(f"  {Fore.YELLOW}[BURST {i+1}/{count}] {line}{Style.RESET_ALL}")
        time.sleep(random.uniform(0.1, 0.4))   # Rapid-fire with tiny delay

    # After the burst, simulate the attacker closing the connection
    close_line = (
        f"{_now_syslog()} {random.choice(HOSTNAMES)} "
        f"sshd[{random.randint(1000,65535)}]: "
        f"Disconnected from {attacker_ip} port {_random_port()} [preauth]"
    )
    _write_line(close_line, fh)
    print(f"{Fore.RED}[BURST] Burst complete from {attacker_ip}.{Style.RESET_ALL}\n")


# ══════════════════════════════════════════════════════════════
#  Main Generator Loop
# ══════════════════════════════════════════════════════════════

def run_generator(interval: float = 1.5, burst_prob: float = 0.12) -> None:
    """
    Continuously appends log lines to mock_auth.log.

    Args:
        interval:   Base sleep interval between normal log writes (seconds).
        burst_prob: Probability [0.0–1.0] of triggering a burst each cycle.
    """
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║   Mock SSH Log Generator — AI Log Monitor        ║")
    print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Output file   : {OUTPUT_FILE.resolve()}")
    print(f"  Write interval : {interval}s")
    print(f"  Burst prob     : {burst_prob*100:.0f}% per cycle")
    print(f"  Press Ctrl+C to stop.\n{Style.RESET_ALL}")

    line_count = 0

    with OUTPUT_FILE.open("a", encoding="utf-8") as fh:
        # Write a session start marker
        fh.write(
            f"-- Log generator started at {datetime.now().isoformat()} --\n"
        )
        fh.flush()

        try:
            while True:
                # ── Burst attack? ──────────────────────────
                if random.random() < burst_prob:
                    _generate_burst(fh)
                    line_count += random.randint(5, 10)

                # ── Normal random event ────────────────────
                else:
                    template = random.choices(_TEMPLATES, weights=_WEIGHTS, k=1)[0]
                    # Use legit user for accepted events, attacker user otherwise
                    if "Accepted" in template or "session" in template:
                        user = random.choice(LEGIT_USERS)
                        ip   = f"10.0.0.{random.randint(1, 20)}"    # Internal IP
                    else:
                        user = random.choice(COMMON_USERNAMES)
                        ip   = _random_ip()

                    line = _make_log_line(template, ip, user)
                    _write_line(line, fh)
                    line_count += 1

                    # Determine color for display
                    if "Accepted" in line:
                        color = Fore.GREEN
                    elif "Failed" in line or "Invalid" in line:
                        color = Fore.RED
                    else:
                        color = Fore.WHITE

                    print(f"{color}[{line_count:>5}] {line}{Style.RESET_ALL}")

                time.sleep(interval + random.uniform(-0.3, 0.3))

        except KeyboardInterrupt:
            fh.write(
                f"\n-- Log generator stopped at {datetime.now().isoformat()} "
                f"({line_count} lines written) --\n"
            )
            print(
                f"\n{Fore.YELLOW}[GEN] Stopped. "
                f"Total lines written: {line_count}{Style.RESET_ALL}"
            )


# ── CLI Entry Point ────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mock SSH auth log generator for AI Log Monitor testing."
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.5,
        help="Seconds between normal log writes (default: 1.5)",
    )
    parser.add_argument(
        "--burst-prob",
        type=float,
        default=0.12,
        help="Burst probability per cycle 0.0–1.0 (default: 0.12 = 12%%)",
    )
    parser.add_argument(
        "--burst-now",
        action="store_true",
        help="Write a single burst immediately and exit (for quick testing)",
    )
    args = parser.parse_args()

    if args.burst_now:
        print(f"{Fore.YELLOW}[GEN] Writing a single burst to {OUTPUT_FILE}...{Style.RESET_ALL}")
        with OUTPUT_FILE.open("a", encoding="utf-8") as fh:
            _generate_burst(fh)
        print(f"{Fore.GREEN}[GEN] Done.{Style.RESET_ALL}")
        sys.exit(0)

    run_generator(interval=args.interval, burst_prob=args.burst_prob)
