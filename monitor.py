"""
monitor.py - Main Event Loop and Orchestrator
FULLY AUTONOMOUS: AI decides, Engine acts, zero human intervention needed.

Flow:
  LogTailer -> Parser -> MySQL -> AnomalyDetector
  -> Gemini AI -> ActionEngine (block/email/slack/kill-session)

Action Matrix:
  CRITICAL -> UFW block + fail2ban + iptables + kill sessions + email + slack
  HIGH     -> UFW block + fail2ban + email + slack
  MEDIUM   -> rate-limit + email + slack
  LOW      -> log to DB only (silent)
"""

import os
import sys
import time
import signal
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from colorama import Fore, Back, Style, init

from database      import (initialize_database, insert_log_entry,
                            update_ai_summary, fetch_recent_logs_by_ip,
                            fetch_log_stats)
from parser        import parse_log_line, is_failure_event
from ai_analyzer   import AIAnalyzer, ThreatReport
from action_engine import execute_response, print_startup_info

load_dotenv()
init(autoreset=True)

# ── Configuration ──────────────────────────────────────────────
LOG_FILE_PATH     = Path(os.getenv("LOG_FILE_PATH", "mock_auth.log"))
ANOMALY_THRESHOLD = int(os.getenv("ANOMALY_THRESHOLD", "5"))
POLL_INTERVAL     = float(os.getenv("MONITOR_POLL_INTERVAL", "2"))
AI_CONTEXT_LIMIT  = int(os.getenv("AI_CONTEXT_LOG_LIMIT", "20"))
FAILURE_WINDOW_SEC = 300
AI_COOLDOWN_SEC    = 300

BANNER = (
    Fore.CYAN +
    "+============================================================+\n"
    "|    AI-Enhanced System Log Monitor  v2.0  AUTONOMOUS        |\n"
    "|    Powered by Google Gemini 2.5 Flash                      |\n"
    "+============================================================+\n"
    "|  Mode   : 100% Autonomous (zero human intervention)        |\n"
    "|  AI     : gemini-2.5-flash                                 |\n"
    "|  DB     : MySQL (auto-provisioned)                         |\n"
    "+============================================================+"
    + Style.RESET_ALL
)


def _ts():
    return f"{Fore.WHITE}{datetime.now().strftime('%H:%M:%S')}{Style.RESET_ALL}"

def _log(tag, message, color=Fore.WHITE):
    print(f"{_ts()} {color}[{tag}]{Style.RESET_ALL} {message}")

def _sep(char="-", width=70, color=Fore.CYAN):
    print(f"{color}{char * width}{Style.RESET_ALL}")


# ── Log Tailer ─────────────────────────────────────────────────

class LogTailer:
    """Efficiently tails a log file by tracking byte offset."""

    def __init__(self, filepath):
        self.filepath = filepath
        self._offset  = 0
        self._ensure_exists()
        self._offset = filepath.stat().st_size
        _log("TAIL", f"Watching : {filepath.resolve()}", Fore.CYAN)
        _log("TAIL", f"Skipped  : {self._offset} existing bytes (live mode)", Fore.CYAN)

    def _ensure_exists(self):
        if not self.filepath.exists():
            self.filepath.touch()

    def read_new_lines(self):
        try:
            current_size = self.filepath.stat().st_size
        except FileNotFoundError:
            self._ensure_exists()
            return []

        if current_size < self._offset:
            _log("TAIL", "Log rotation detected - resetting offset.", Fore.YELLOW)
            self._offset = 0

        if current_size == self._offset:
            return []

        with self.filepath.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._offset)
            content = fh.read()
            self._offset = fh.tell()

        return [l for l in content.splitlines() if l.strip()]


# ── Anomaly Detector ───────────────────────────────────────────

class AnomalyDetector:
    """Thread-safe sliding-window failure counter per IP."""

    def __init__(self, threshold, window_sec, cooldown_sec):
        self.threshold = threshold
        self.window    = timedelta(seconds=window_sec)
        self.cooldown  = timedelta(seconds=cooldown_sec)
        self._lock     = threading.RLock()
        self._failures = defaultdict(list)
        self._alerted  = {}

    def record_failure(self, ip):
        with self._lock:
            now    = datetime.now()
            cutoff = now - self.window
            self._failures[ip].append(now)
            self._failures[ip] = [t for t in self._failures[ip] if t > cutoff]
            count = len(self._failures[ip])

            if count < self.threshold:
                return False

            last = self._alerted.get(ip)
            if last and (now - last) < self.cooldown:
                return False

            self._alerted[ip] = now
            return True

    def get_count(self, ip):
        with self._lock:
            now    = datetime.now()
            cutoff = now - self.window
            return sum(1 for t in self._failures.get(ip, []) if t > cutoff)


# ── Session Statistics ─────────────────────────────────────────

class SessionStats:
    """In-memory session statistics tracker."""

    def __init__(self):
        self._lock            = threading.Lock()
        self.lines_processed  = 0
        self.lines_parsed     = 0
        self.lines_inserted   = 0
        self.failures_logged  = 0
        self.successes_logged = 0
        self.ai_analyses      = 0
        self.alerts_triggered = 0
        self.auto_blocks      = 0
        self.emails_sent      = 0
        self.slack_sent       = 0
        self.start_time       = datetime.now()

    def inc(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, getattr(self, k) + v)

    def uptime(self):
        d = datetime.now() - self.start_time
        h, r = divmod(int(d.total_seconds()), 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}h {m:02d}m {s:02d}s"

    def display(self):
        _sep("=")
        print(f"{Fore.CYAN}  SESSION STATS  |  Uptime: {self.uptime()}{Style.RESET_ALL}")
        _sep()
        rows = [
            ("Lines processed",    self.lines_processed,  Fore.WHITE),
            ("Lines parsed",       self.lines_parsed,     Fore.WHITE),
            ("Inserted to DB",     self.lines_inserted,   Fore.WHITE),
            ("Failed auth events", self.failures_logged,  Fore.RED),
            ("Successful logins",  self.successes_logged, Fore.GREEN),
            ("Alerts triggered",   self.alerts_triggered, Fore.YELLOW),
            ("AI analyses run",    self.ai_analyses,      Fore.CYAN),
            ("IPs auto-blocked",   self.auto_blocks,      Fore.RED),
            ("Emails sent",        self.emails_sent,      Fore.CYAN),
            ("Slack alerts sent",  self.slack_sent,       Fore.CYAN),
        ]
        for label, value, color in rows:
            print(f"  {color}{label:<25}: {value}{Style.RESET_ALL}")
        _sep("=")


# ── AI + Action Worker (background thread) ─────────────────────

def _ai_and_action_worker(analyzer, ip_address, failure_count, threshold,
                           last_row_id, stats):
    """
    Runs in a daemon thread so the main loop is never blocked.
    Full autonomous pipeline:
      1. Fetch recent DB logs for context
      2. Call Gemini AI -> ThreatReport
      3. Save AI summary to MySQL
      4. Print report to terminal
      5. ACTION ENGINE -> auto block / email / slack / kill sessions
      6. Update session statistics
    """

    # Step 1 & 2: AI analysis
    _log("AI", f"Analysing {ip_address}...", Fore.MAGENTA)
    stats.inc(ai_analyses=1)
    recent_logs = fetch_recent_logs_by_ip(ip_address, limit=AI_CONTEXT_LIMIT)
    report = analyzer.analyze_threat(
        ip_address=ip_address,
        recent_logs=recent_logs,
        failure_count=failure_count,
        threshold=threshold,
    )

    # Step 3: Save to DB
    if update_ai_summary(last_row_id, report.to_db_string()):
        _log("AI", f"Summary saved to DB row {last_row_id}.", Fore.GREEN)
    else:
        _log("AI", f"Could not save to DB row {last_row_id}.", Fore.RED)

    # Step 4: Print threat report
    sep_color = Fore.RED if report.threat_level in ("CRITICAL", "HIGH") else Fore.YELLOW
    _sep("=", color=sep_color)
    lvl_color = {
        "CRITICAL": Back.RED + Fore.WHITE,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.WHITE,
    }.get(report.threat_level, Fore.WHITE)

    print(f"\n  {lvl_color}[THREAT] {report.threat_level} | {report.attack_type}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}IP          :{Style.RESET_ALL} {ip_address}")
    print(f"  {Fore.CYAN}Failures    :{Style.RESET_ALL} {failure_count} in last 5 minutes")
    print(f"  {Fore.CYAN}Summary     :{Style.RESET_ALL} {report.summary}")

    if report.evidence:
        print(f"\n  {Fore.YELLOW}Evidence:{Style.RESET_ALL}")
        for e in report.evidence[:4]:
            print(f"    * {e}")

    if report.recommendations:
        print(f"\n  {Fore.GREEN}AI Recommendations:{Style.RESET_ALL}")
        for i, r in enumerate(report.recommendations[:5], 1):
            print(f"    {i}. {r}")
    _sep("=", color=sep_color)

    # Step 5: AUTONOMOUS ACTION ENGINE
    _sep("-", color=Fore.MAGENTA)
    _log("ENGINE", "Autonomous Action Engine firing now...", Fore.MAGENTA)
    _sep("-", color=Fore.MAGENTA)

    action_result = execute_response(report)

    # Step 6: Update stats
    if action_result.blocked:
        stats.inc(auto_blocks=1)
    if action_result.email_sent:
        stats.inc(emails_sent=1)
    if action_result.slack_sent:
        stats.inc(slack_sent=1)


# ── Main Monitor ───────────────────────────────────────────────

class LogMonitor:
    """Main orchestrator — fully autonomous once started."""

    def __init__(self):
        self.stats    = SessionStats()
        self.detector = AnomalyDetector(
            threshold=ANOMALY_THRESHOLD,
            window_sec=FAILURE_WINDOW_SEC,
            cooldown_sec=AI_COOLDOWN_SEC,
        )
        self.tailer   = LogTailer(LOG_FILE_PATH)
        self.analyzer = AIAnalyzer()
        self._running = True
        signal.signal(signal.SIGINT, self._shutdown_handler)

    def _shutdown_handler(self, signum, frame):
        print(f"\n\n{Fore.YELLOW}[MONITOR] Ctrl+C received. Shutting down...{Style.RESET_ALL}")
        self._running = False

    def _process_line(self, raw_line):
        self.stats.inc(lines_processed=1)
        entry = parse_log_line(raw_line)
        if entry is None:
            return

        self.stats.inc(lines_parsed=1)

        if "Failed" in entry.event_status or "Invalid" in entry.event_status:
            sc = Fore.RED
        elif "Accepted" in entry.event_status:
            sc = Fore.GREEN
        elif "session" in entry.event_status.lower():
            sc = Fore.CYAN
        else:
            sc = Fore.WHITE

        print(
            f"{_ts()} {sc}[{entry.event_status:<28}]{Style.RESET_ALL}"
            f" IP={entry.ip_address or 'N/A':<16}"
            f" User={entry.target_user or 'N/A'}"
        )

        row_id = insert_log_entry(
            log_timestamp=entry.timestamp or datetime.now(),
            ip_address=entry.ip_address,
            target_user=entry.target_user,
            event_status=entry.event_status,
            raw_log=entry.raw_log,
        )
        if row_id:
            self.stats.inc(lines_inserted=1)

        if is_failure_event(entry):
            self.stats.inc(failures_logged=1)
        elif "Accepted" in entry.event_status:
            self.stats.inc(successes_logged=1)

        # Anomaly detection -> autonomous response
        if is_failure_event(entry) and entry.ip_address:
            if self.detector.record_failure(entry.ip_address):
                count = self.detector.get_count(entry.ip_address)
                self.stats.inc(alerts_triggered=1)
                _sep("-", color=Fore.YELLOW)
                _log("ALERT",
                     f"{count} failures from {entry.ip_address} "
                     f"(threshold={ANOMALY_THRESHOLD}) -- autonomous response launching!",
                     Fore.YELLOW)
                _sep("-", color=Fore.YELLOW)

                thread = threading.Thread(
                    target=_ai_and_action_worker,
                    args=(self.analyzer, entry.ip_address, count,
                          ANOMALY_THRESHOLD, row_id or 0, self.stats),
                    daemon=True,
                    name=f"AI-{entry.ip_address}",
                )
                thread.start()

    def run(self):
        print(BANNER)
        _sep("=")
        print(f"  {Fore.WHITE}Monitor Configuration:{Style.RESET_ALL}")
        print(f"    Log file        : {LOG_FILE_PATH.resolve()}")
        print(f"    Poll interval   : {POLL_INTERVAL}s")
        print(f"    Alert threshold : {ANOMALY_THRESHOLD} failures / {FAILURE_WINDOW_SEC}s window")
        print(f"    AI cooldown     : {AI_COOLDOWN_SEC}s per IP")
        print(f"    AI context rows : {AI_CONTEXT_LIMIT}")
        print_startup_info()
        _sep("=")

        db_stats = fetch_log_stats()
        if db_stats and db_stats.get("total"):
            print(f"\n  {Fore.CYAN}Historical DB Stats:{Style.RESET_ALL}")
            print(f"    Total rows      : {db_stats.get('total', 0)}")
            print(f"    Failed auths    : {db_stats.get('failed', 0)}")
            print(f"    Accepted logins : {db_stats.get('accepted', 0)}")
            print(f"    AI-analyzed     : {db_stats.get('ai_analyzed', 0)}")
            print()

        _log("MONITOR", "Live monitoring started. Press Ctrl+C to stop.", Fore.GREEN)
        _sep()

        try:
            while self._running:
                for line in self.tailer.read_new_lines():
                    if not self._running:
                        break
                    self._process_line(line)
                time.sleep(POLL_INTERVAL)
        except Exception as exc:
            _log("ERROR", f"Main loop error: {exc}", Fore.RED)
            raise
        finally:
            _log("MONITOR", "Shutting down...", Fore.YELLOW)
            active = [t for t in threading.enumerate() if t.name.startswith("AI-")]
            if active:
                _log("MONITOR", f"Waiting for {len(active)} AI thread(s)...", Fore.YELLOW)
                for t in active:
                    t.join(timeout=30)
            self.stats.display()
            _log("MONITOR", "Stopped. Goodbye.", Fore.CYAN)


# ── Entry Point ────────────────────────────────────────────────

def main():
    _log("INIT", "Initializing database schema...", Fore.CYAN)
    initialize_database()
    LogMonitor().run()


if __name__ == "__main__":
    main()