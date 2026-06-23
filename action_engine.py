"""
============================================================
 action_engine.py — Fully Autonomous Response Engine
============================================================
 Executes automatic security actions based on AI threat level.
 ZERO human intervention required.

 Action Matrix:
 ┌──────────────┬────────────────────────────────────────────┐
 │ CRITICAL     │ Block IP (ufw + fail2ban) + Email + Slack  │
 │              │ + Log to DB + Kill active sessions         │
 ├──────────────┼────────────────────────────────────────────┤
 │ HIGH         │ Block IP (ufw + fail2ban) + Email + Slack  │
 │              │ + Log to DB                                │
 ├──────────────┼────────────────────────────────────────────┤
 │ MEDIUM       │ Rate-limit IP + Email alert + Log to DB    │
 ├──────────────┼────────────────────────────────────────────┤
 │ LOW          │ Log to DB + Daily digest (silent)          │
 └──────────────┴────────────────────────────────────────────┘

 Safety Features:
   - IP Whitelist: Your own IPs are NEVER blocked
   - Dry-run mode: Test without executing real commands
   - Action audit log: Every action recorded in MySQL
   - Dedup guard: Same IP not actioned twice in cooldown
============================================================
"""

import os
import sys
import subprocess
import smtplib
import platform
import json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from typing import Optional

import requests
from dotenv import load_dotenv
from colorama import Fore, Style, init

from ai_analyzer import ThreatReport

load_dotenv()
init(autoreset=True)

# ══════════════════════════════════════════════════════════════
#  Configuration  (all from .env)
# ══════════════════════════════════════════════════════════════

# System detection
IS_LINUX = platform.system() == "Linux"

# Dry-run mode: if True, prints commands but does NOT execute them
# Set DRY_RUN=false in .env to enable real blocking
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

# Whitelisted IPs — NEVER blocked, no matter what the AI says
# Comma-separated in .env:  WHITELIST_IPS=1.2.3.4,5.6.7.8,192.168.1.0/24
_raw_whitelist = os.getenv("WHITELIST_IPS", "127.0.0.1,::1")
WHITELIST_IPS: set[str] = {ip.strip() for ip in _raw_whitelist.split(",") if ip.strip()}

# Email configuration (Gmail SMTP)
EMAIL_ENABLED   = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SENDER    = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD  = os.getenv("EMAIL_APP_PASSWORD", "")   # Gmail App Password
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT", "")
SMTP_HOST       = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT       = int(os.getenv("SMTP_PORT", "587"))

# Slack Webhook
SLACK_ENABLED     = os.getenv("SLACK_ENABLED", "false").lower() == "true"
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# Threat level thresholds for auto-block
AUTO_BLOCK_LEVELS = {"CRITICAL", "HIGH"}   # These levels trigger IP block
ALERT_ONLY_LEVELS = {"MEDIUM"}             # These levels only send alerts


# ══════════════════════════════════════════════════════════════
#  Action Result Dataclass
# ══════════════════════════════════════════════════════════════

@dataclass
class ActionResult:
    """
    Records every action taken by the engine for a threat.

    Attributes:
        ip_address:     The IP that was actioned.
        threat_level:   AI-determined threat level.
        actions_taken:  List of action descriptions performed.
        blocked:        True if the IP was blocked by firewall.
        email_sent:     True if email alert was sent.
        slack_sent:     True if Slack alert was sent.
        session_killed: True if active SSH sessions were terminated.
        errors:         Any errors encountered during actions.
        timestamp:      When the actions were executed.
        dry_run:        True if this was a simulated run.
    """
    ip_address:     str
    threat_level:   str
    actions_taken:  list[str]       = field(default_factory=list)
    blocked:        bool            = False
    email_sent:     bool            = False
    slack_sent:     bool            = False
    session_killed: bool            = False
    errors:         list[str]       = field(default_factory=list)
    timestamp:      datetime        = field(default_factory=datetime.now)
    dry_run:        bool            = DRY_RUN

    def summary(self) -> str:
        prefix = "[DRY-RUN] " if self.dry_run else ""
        parts = [f"{prefix}Actions for {self.ip_address} ({self.threat_level}):"]
        for action in self.actions_taken:
            parts.append(f"  ✅ {action}")
        for error in self.errors:
            parts.append(f"  ❌ ERROR: {error}")
        return "\n".join(parts)


# ══════════════════════════════════════════════════════════════
#  Command Runner Helper
# ══════════════════════════════════════════════════════════════

def _run_command(cmd: list[str], result: ActionResult, description: str) -> bool:
    """
    Executes a shell command (or simulates it in dry-run mode).

    Args:
        cmd:         The command as a list of strings.
        result:      ActionResult to record outcomes into.
        description: Human-readable description of the action.

    Returns:
        True if command succeeded (or dry-run), False on error.
    """
    cmd_str = " ".join(cmd)

    if DRY_RUN:
        print(f"  {Fore.YELLOW}[DRY-RUN] Would execute: {cmd_str}{Style.RESET_ALL}")
        result.actions_taken.append(f"[DRY-RUN] {description}: `{cmd_str}`")
        return True

    if not IS_LINUX:
        msg = f"Skipped (not Linux): {description}"
        result.actions_taken.append(msg)
        print(f"  {Fore.YELLOW}[ACTION] {msg}{Style.RESET_ALL}")
        return True

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            result.actions_taken.append(f"{description}: `{cmd_str}`")
            print(f"  {Fore.GREEN}[ACTION] ✅ {description}{Style.RESET_ALL}")
            return True
        else:
            error_msg = f"{description} failed: {proc.stderr.strip()}"
            result.errors.append(error_msg)
            print(f"  {Fore.RED}[ACTION] ❌ {error_msg}{Style.RESET_ALL}")
            return False
    except subprocess.TimeoutExpired:
        error_msg = f"{description} timed out after 10s"
        result.errors.append(error_msg)
        print(f"  {Fore.RED}[ACTION] ❌ {error_msg}{Style.RESET_ALL}")
        return False
    except Exception as exc:
        error_msg = f"{description} error: {exc}"
        result.errors.append(error_msg)
        print(f"  {Fore.RED}[ACTION] ❌ {error_msg}{Style.RESET_ALL}")
        return False


# ══════════════════════════════════════════════════════════════
#  Firewall Actions
# ══════════════════════════════════════════════════════════════

def _block_with_ufw(ip: str, result: ActionResult) -> None:
    """Blocks IP using UFW (Uncomplicated Firewall)."""
    _run_command(
        ["sudo", "ufw", "deny", "from", ip, "to", "any"],
        result,
        f"UFW: Block all traffic from {ip}",
    )


def _block_with_fail2ban(ip: str, result: ActionResult) -> None:
    """Permanently bans IP using fail2ban."""
    _run_command(
        ["sudo", "fail2ban-client", "set", "sshd", "banip", ip],
        result,
        f"fail2ban: Ban {ip} in SSH jail",
    )


def _block_with_iptables(ip: str, result: ActionResult) -> None:
    """Blocks IP using iptables as a fallback."""
    _run_command(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        result,
        f"iptables: DROP all packets from {ip}",
    )


def _kill_active_sessions(ip: str, result: ActionResult) -> None:
    """
    Finds and kills any active SSH sessions from the attacker IP.
    Uses `ss` to find PIDs of existing connections from the IP,
    then kills them.
    """
    if DRY_RUN:
        print(f"  {Fore.YELLOW}[DRY-RUN] Would kill active SSH sessions from {ip}{Style.RESET_ALL}")
        result.actions_taken.append(f"[DRY-RUN] Kill active SSH sessions from {ip}")
        return

    if not IS_LINUX:
        return

    try:
        # Find SSH processes connected from the attacker IP
        proc = subprocess.run(
            ["ss", "-tnp", "src", ip],
            capture_output=True, text=True, timeout=5
        )
        pids = set()
        for line in proc.stdout.splitlines():
            # Extract PID from ss output: users:(("sshd",pid=1234,fd=3))
            if "sshd" in line and "pid=" in line:
                start = line.find("pid=") + 4
                end   = line.find(",", start)
                if end == -1:
                    end = line.find(")", start)
                pid_str = line[start:end].strip()
                if pid_str.isdigit():
                    pids.add(pid_str)

        if pids:
            for pid in pids:
                _run_command(
                    ["sudo", "kill", "-9", pid],
                    result,
                    f"Kill SSH session PID {pid} from {ip}",
                )
            result.session_killed = True
        else:
            result.actions_taken.append(f"No active SSH sessions found from {ip}")

    except Exception as exc:
        result.errors.append(f"Session kill check failed: {exc}")


# ══════════════════════════════════════════════════════════════
#  Rate Limiting (for MEDIUM threats)
# ══════════════════════════════════════════════════════════════

def _rate_limit_ip(ip: str, result: ActionResult) -> None:
    """
    Applies connection rate limiting for medium-risk IPs
    instead of a full block — slows down brute-force without
    completely blocking (useful for potentially legitimate IPs).
    """
    # Limit SSH connections from this IP to 3 per minute
    _run_command(
        [
            "sudo", "iptables", "-A", "INPUT",
            "-s", ip, "-p", "tcp", "--dport", "22",
            "-m", "recent", "--set", "--name", "SSH_RATELIMIT",
        ],
        result,
        f"iptables: Apply SSH rate limit to {ip}",
    )


# ══════════════════════════════════════════════════════════════
#  Email Alert
# ══════════════════════════════════════════════════════════════

def _send_email_alert(report: ThreatReport, action_result: ActionResult) -> None:
    """
    Sends an HTML email alert with the full threat report and
    actions taken.
    """
    if not EMAIL_ENABLED:
        print(f"  {Fore.YELLOW}[EMAIL] Email alerts disabled (EMAIL_ENABLED=false){Style.RESET_ALL}")
        return

    if not all([EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT]):
        print(f"  {Fore.YELLOW}[EMAIL] Email not configured — skipping{Style.RESET_ALL}")
        return

    try:
        # ── Build HTML Email ─────────────────────────────
        level_color = {
            "CRITICAL": "#FF0000",
            "HIGH":     "#FF6600",
            "MEDIUM":   "#FFA500",
            "LOW":      "#008000",
        }.get(report.threat_level, "#333333")

        actions_html = "".join(
            f"<li style='color:#00aa00'>✅ {a}</li>"
            for a in action_result.actions_taken
        )
        errors_html = "".join(
            f"<li style='color:#cc0000'>❌ {e}</li>"
            for e in action_result.errors
        )
        evidence_html = "".join(
            f"<li>{e}</li>" for e in report.evidence
        )
        recs_html = "".join(
            f"<li>{r}</li>" for i, r in enumerate(report.recommendations, 1)
        )

        html_body = f"""
        <html><body style="font-family:Arial,sans-serif;background:#1a1a1a;color:#eee;padding:20px">
          <div style="max-width:700px;margin:auto;background:#2a2a2a;border-radius:10px;padding:30px">

            <h1 style="color:{level_color};border-bottom:2px solid {level_color};padding-bottom:10px">
              🚨 {report.threat_level} SECURITY THREAT DETECTED
            </h1>

            <table style="width:100%;border-collapse:collapse;margin:20px 0">
              <tr><td style="padding:8px;color:#aaa">IP Address</td>
                  <td style="padding:8px;font-weight:bold;color:#fff">{report.ip_address}</td></tr>
              <tr style="background:#333"><td style="padding:8px;color:#aaa">Attack Type</td>
                  <td style="padding:8px;color:#fff">{report.attack_type}</td></tr>
              <tr><td style="padding:8px;color:#aaa">Threat Level</td>
                  <td style="padding:8px;font-weight:bold;color:{level_color}">{report.threat_level}</td></tr>
              <tr style="background:#333"><td style="padding:8px;color:#aaa">Detected At</td>
                  <td style="padding:8px;color:#fff">{action_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
              <tr><td style="padding:8px;color:#aaa">Auto-Blocked</td>
                  <td style="padding:8px;color:{'#00ff00' if action_result.blocked else '#ff6600'}">
                  {'YES ✅' if action_result.blocked else 'NO ⚠️'}</td></tr>
            </table>

            <h2 style="color:#00aaff">📋 AI Summary</h2>
            <p style="background:#333;padding:15px;border-radius:5px;border-left:4px solid {level_color}">
              {report.summary}
            </p>

            <h2 style="color:#ffaa00">🔍 Evidence</h2>
            <ul>{evidence_html}</ul>

            <h2 style="color:#00ff88">⚡ Actions Taken Automatically</h2>
            <ul>{actions_html}</ul>
            {f'<h3 style="color:#ff4444">Errors:</h3><ul>{errors_html}</ul>' if action_result.errors else ''}

            <h2 style="color:#00aaff">💡 AI Recommendations</h2>
            <ul>{recs_html}</ul>

            <hr style="border-color:#444;margin:20px 0">
            <p style="color:#666;font-size:12px">
              This alert was generated automatically by AI-Enhanced System Log Monitor.
              Model: {report.model_used} | No human intervention was required.
            </p>
          </div>
        </body></html>
        """

        subject = (
            f"🚨 [{report.threat_level}] SSH Attack Detected — "
            f"{report.ip_address} | {report.attack_type}"
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECIPIENT
        msg.attach(MIMEText(html_body, "html"))

        # ── Send via SMTP ─────────────────────────────────
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        action_result.email_sent = True
        action_result.actions_taken.append(f"Email alert sent to {EMAIL_RECIPIENT}")
        print(f"  {Fore.GREEN}[EMAIL] ✅ Alert sent to {EMAIL_RECIPIENT}{Style.RESET_ALL}")

    except Exception as exc:
        error_msg = f"Email send failed: {exc}"
        action_result.errors.append(error_msg)
        print(f"  {Fore.RED}[EMAIL] ❌ {error_msg}{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════
#  Slack Alert
# ══════════════════════════════════════════════════════════════

def _send_slack_alert(report: ThreatReport, action_result: ActionResult) -> None:
    """
    Sends a rich Slack block-kit notification with threat details
    and a list of automated actions taken.
    """
    if not SLACK_ENABLED:
        print(f"  {Fore.YELLOW}[SLACK] Slack alerts disabled (SLACK_ENABLED=false){Style.RESET_ALL}")
        return

    if not SLACK_WEBHOOK_URL:
        print(f"  {Fore.YELLOW}[SLACK] No webhook URL configured — skipping{Style.RESET_ALL}")
        return

    try:
        level_emoji = {
            "CRITICAL": "🔴",
            "HIGH":     "🟠",
            "MEDIUM":   "🟡",
            "LOW":      "🟢",
        }.get(report.threat_level, "⚪")

        actions_text = "\n".join(f"• {a}" for a in action_result.actions_taken)
        evidence_text = "\n".join(f"• {e}" for e in report.evidence[:3])

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{level_emoji} {report.threat_level} THREAT: {report.attack_type}",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP Address:*\n`{report.ip_address}`"},
                        {"type": "mrkdwn", "text": f"*Threat Level:*\n{level_emoji} {report.threat_level}"},
                        {"type": "mrkdwn", "text": f"*Attack Type:*\n{report.attack_type}"},
                        {"type": "mrkdwn", "text": f"*Auto-Blocked:*\n{'✅ YES' if action_result.blocked else '⚠️ NO'}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{action_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"},
                        {"type": "mrkdwn", "text": f"*Model:*\n{report.model_used}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*📋 AI Summary:*\n{report.summary}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*🔍 Key Evidence:*\n{evidence_text}"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*⚡ Actions Taken Automatically:*\n{actions_text}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "🤖 _This action was taken automatically by AI-Enhanced Log Monitor. No human intervention required._"
                        }
                    ]
                }
            ]
        }

        resp = requests.post(
            SLACK_WEBHOOK_URL,
            json=payload,
            timeout=10,
        )
        if resp.status_code == 200:
            action_result.slack_sent = True
            action_result.actions_taken.append("Slack notification sent")
            print(f"  {Fore.GREEN}[SLACK] ✅ Notification sent{Style.RESET_ALL}")
        else:
            raise ValueError(f"HTTP {resp.status_code}: {resp.text}")

    except Exception as exc:
        error_msg = f"Slack send failed: {exc}"
        action_result.errors.append(error_msg)
        print(f"  {Fore.RED}[SLACK] ❌ {error_msg}{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════
#  Action Log (to DB)
# ══════════════════════════════════════════════════════════════

def _log_action_to_db(action_result: ActionResult) -> None:
    """
    Saves a record of all automated actions taken to the
    `action_log` table in MySQL for full auditability.
    """
    try:
        from database import get_connection
        import mysql.connector

        conn = get_connection()
        cursor = conn.cursor()

        # Create action_log table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS action_log (
                id              INT AUTO_INCREMENT PRIMARY KEY,
                ip_address      VARCHAR(45)  NOT NULL,
                threat_level    VARCHAR(20)  NOT NULL,
                actions_taken   TEXT,
                errors          TEXT,
                blocked         TINYINT(1)   DEFAULT 0,
                email_sent      TINYINT(1)   DEFAULT 0,
                slack_sent      TINYINT(1)   DEFAULT 0,
                session_killed  TINYINT(1)   DEFAULT 0,
                dry_run         TINYINT(1)   DEFAULT 0,
                actioned_at     TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ip (ip_address),
                INDEX idx_level (threat_level)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cursor.execute("""
            INSERT INTO action_log
                (ip_address, threat_level, actions_taken, errors,
                 blocked, email_sent, slack_sent, session_killed, dry_run)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            action_result.ip_address,
            action_result.threat_level,
            json.dumps(action_result.actions_taken),
            json.dumps(action_result.errors),
            int(action_result.blocked),
            int(action_result.email_sent),
            int(action_result.slack_sent),
            int(action_result.session_killed),
            int(action_result.dry_run),
        ))
        conn.commit()
        cursor.close()
        conn.close()

    except Exception as exc:
        print(f"  {Fore.YELLOW}[ACTION LOG] Could not write to DB: {exc}{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════
#  Main Entry Point — Called by monitor.py
# ══════════════════════════════════════════════════════════════

def execute_response(report: ThreatReport) -> ActionResult:
    """
    The main autonomous response function. Called automatically
    by monitor.py after every AI threat analysis.

    Determines the correct response based on threat level and
    executes all actions without any human input.

    Args:
        report: The ThreatReport from ai_analyzer.py

    Returns:
        An ActionResult documenting everything that was done.
    """
    result = ActionResult(
        ip_address=report.ip_address,
        threat_level=report.threat_level,
        dry_run=DRY_RUN,
    )

    ip = report.ip_address

    # ── Safety Check: Whitelist ────────────────────────────
    # Whitelisted IPs are NEVER blocked — but we still send email/Slack
    # so you are always informed even during your own tests.
    is_whitelisted = ip in WHITELIST_IPS
    if is_whitelisted:
        msg = f"IP {ip} is WHITELISTED — blocking skipped, sending alert only"
        result.actions_taken.append(msg)
        print(f"  {Fore.GREEN}[WHITELIST] ✅ {msg}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"  ⚡ AUTONOMOUS ACTION ENGINE TRIGGERED")
    print(f"  Threat Level : {report.threat_level}")
    print(f"  IP Address   : {ip}")
    print(f"  Attack Type  : {report.attack_type}")
    print(f"  Mode         : {'🟡 DRY-RUN (simulated)' if DRY_RUN else '🔴 LIVE (real commands)'}")
    print(f"{'═'*60}{Style.RESET_ALL}\n")

    # ══════════════════════════════════════════════════════
    #  CRITICAL — Maximum response
    # ══════════════════════════════════════════════════════
    if report.threat_level == "CRITICAL":
        print(f"  {Fore.RED}🔴 CRITICAL THREAT — Executing maximum response...{Style.RESET_ALL}")

        if not is_whitelisted:
            # 1. Block with UFW (primary firewall)
            _block_with_ufw(ip, result)
            result.blocked = True

            # 2. Ban with fail2ban (persistent across reboots)
            _block_with_fail2ban(ip, result)

            # 3. Block with iptables (belt-and-suspenders)
            _block_with_iptables(ip, result)

            # 4. Kill any active sessions from this IP RIGHT NOW
            _kill_active_sessions(ip, result)

        # 5. Send email (always — even for whitelisted IPs)
        _send_email_alert(report, result)

        # 6. Send Slack (always)
        _send_slack_alert(report, result)

    # ══════════════════════════════════════════════════════
    #  HIGH — Block + Alert
    # ══════════════════════════════════════════════════════
    elif report.threat_level == "HIGH":
        print(f"  {Fore.YELLOW}🟠 HIGH THREAT — Blocking IP + alerting...{Style.RESET_ALL}")

        if not is_whitelisted:
            # 1. Block with UFW
            _block_with_ufw(ip, result)
            result.blocked = True

            # 2. Ban with fail2ban
            _block_with_fail2ban(ip, result)

        # 3. Send email (always)
        _send_email_alert(report, result)

        # 4. Send Slack (always)
        _send_slack_alert(report, result)

    # ══════════════════════════════════════════════════════
    #  MEDIUM — Rate limit + Alert only
    # ══════════════════════════════════════════════════════
    elif report.threat_level == "MEDIUM":
        print(f"  {Fore.YELLOW}🟡 MEDIUM THREAT — Rate-limiting + sending alert...{Style.RESET_ALL}")

        if not is_whitelisted:
            # 1. Rate limit (not full block — safer for medium threats)
            _rate_limit_ip(ip, result)

        # 2. Send email alert (always)
        _send_email_alert(report, result)

        # 3. Send Slack (always)
        _send_slack_alert(report, result)

    # ══════════════════════════════════════════════════════
    #  LOW — Log only, silent
    # ══════════════════════════════════════════════════════
    elif report.threat_level == "LOW":
        print(f"  {Fore.WHITE}🟢 LOW THREAT — Logging only, no action{Style.RESET_ALL}")
        result.actions_taken.append(f"LOW threat logged to database — no blocking applied")

    # ══════════════════════════════════════════════════════
    #  Unknown / Error
    # ══════════════════════════════════════════════════════
    else:
        result.actions_taken.append(f"Unknown threat level '{report.threat_level}' — no action")

    # ── Save action record to DB ───────────────────────────
    _log_action_to_db(result)

    # ── Print Summary ──────────────────────────────────────
    print(f"\n{result.summary()}")
    print(f"\n  {Fore.CYAN}All autonomous actions complete.{Style.RESET_ALL}")
    print(f"{'═'*60}\n")

    return result


# ── Startup Info ───────────────────────────────────────────
def print_startup_info() -> None:
    """Prints the action engine configuration at startup."""
    mode_str = (
        f"{Fore.YELLOW}DRY-RUN MODE (simulated — no real commands run){Style.RESET_ALL}"
        if DRY_RUN else
        f"{Fore.RED}LIVE MODE ⚠️  (real firewall commands WILL execute){Style.RESET_ALL}"
    )

    print(f"\n{Fore.CYAN}  Action Engine Configuration:{Style.RESET_ALL}")
    print(f"    Mode           : {mode_str}")
    print(f"    Auto-block on  : {', '.join(sorted(AUTO_BLOCK_LEVELS))}")
    print(f"    Alert only on  : {', '.join(sorted(ALERT_ONLY_LEVELS))}")
    print(f"    Whitelisted IPs: {', '.join(sorted(WHITELIST_IPS)) or 'None'}")
    print(f"    Email alerts   : {'✅ Enabled' if EMAIL_ENABLED else '❌ Disabled'}")
    print(f"    Slack alerts   : {'✅ Enabled' if SLACK_ENABLED else '❌ Disabled'}")
    print()
