"""
============================================================
 ai_analyzer.py — Google Gemini AI Threat Analyzer
============================================================
 Integrates with the modern `google-genai` SDK to analyze
 suspicious SSH activity and generate human-readable threat
 intelligence summaries.

 SDK Usage (correct modern syntax):
   from google import genai
   client = genai.Client()   # reads GEMINI_API_KEY from env

 Model: gemini-2.5-flash (fast, cost-effective reasoning)

 Responsibilities:
   - Build structured security prompts from DB context
   - Call Gemini API with retry logic
   - Parse and validate the AI response
   - Return a structured ThreatReport dataclass
============================================================
"""

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from colorama import Fore, Style, init

# Load .env before importing google.genai so the API key is in the env
load_dotenv()
init(autoreset=True)

# ── Google GenAI SDK ───────────────────────────────────────
try:
    from google import genai
    from google.genai import errors as genai_errors
except ImportError:
    print(
        f"{Fore.RED}[AI ERROR] 'google-genai' package not found.\n"
        f"  Run: pip install google-genai{Style.RESET_ALL}"
    )
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────
MODEL_ID          = "gemini-2.5-flash"
MAX_RETRIES       = 3
RETRY_DELAY_SEC   = 2.0    # Base delay for exponential back-off
MAX_PROMPT_LOGS   = 20     # Cap on how many DB rows to include in prompt


# ══════════════════════════════════════════════════════════════
#  Threat Report Dataclass
# ══════════════════════════════════════════════════════════════

@dataclass
class ThreatReport:
    """
    Structured result from an AI threat analysis.

    Attributes:
        ip_address:      The attacker's IP address.
        threat_level:    One of: CRITICAL / HIGH / MEDIUM / LOW / INFO.
        attack_type:     Short label (e.g. 'SSH Brute-Force').
        summary:         1–2 sentence human-readable overview.
        evidence:        List of key log lines that triggered the alert.
        recommendations: List of remediation steps from the AI.
        raw_response:    Full unprocessed text from the Gemini API.
        analyzed_at:     UTC datetime of the analysis.
        model_used:      The Gemini model ID that generated this report.
        error:           If not None, contains the error message.
    """
    ip_address:      str
    threat_level:    str                  = "UNKNOWN"
    attack_type:     str                  = "Unknown"
    summary:         str                  = ""
    evidence:        list[str]            = field(default_factory=list)
    recommendations: list[str]            = field(default_factory=list)
    raw_response:    str                  = ""
    analyzed_at:     datetime             = field(default_factory=datetime.utcnow)
    model_used:      str                  = MODEL_ID
    error:           Optional[str]        = None

    def to_db_string(self) -> str:
        """
        Serializes the report to a compact string for storage in the
        `ai_threat_summary` database column.
        """
        lines = [
            f"[{self.threat_level}] {self.attack_type}",
            f"Analyzed: {self.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Model: {self.model_used}",
            "",
            "SUMMARY:",
            self.summary,
            "",
            "RECOMMENDATIONS:",
        ]
        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"  {i}. {rec}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  Prompt Builder
# ══════════════════════════════════════════════════════════════

def _build_analysis_prompt(
    ip_address: str,
    recent_logs: list[dict],
    failure_count: int,
    threshold: int,
) -> str:
    """
    Constructs a structured cybersecurity analysis prompt.

    Args:
        ip_address:    The source IP of the suspicious activity.
        recent_logs:   List of DB row dicts (from fetch_recent_logs_by_ip).
        failure_count: Number of failed attempts that triggered the alert.
        threshold:     The configured anomaly threshold.

    Returns:
        A multi-part prompt string ready to send to Gemini.
    """
    # Format log entries for the prompt
    log_block_lines = []
    for i, row in enumerate(recent_logs[:MAX_PROMPT_LOGS], 1):
        ts    = row.get("log_timestamp", "N/A")
        user  = row.get("target_user", "N/A")
        event = row.get("event_status", "N/A")
        raw   = row.get("raw_log", "")
        log_block_lines.append(f"  [{i:>2}] {ts} | {event:<28} | user={user}")
        log_block_lines.append(f"       {raw}")

    log_block = "\n".join(log_block_lines) if log_block_lines else "  (No log context available)"

    prompt = f"""
You are an expert Linux server security analyst and incident responder.
Your task is to analyze the following suspicious SSH activity and produce
a structured threat intelligence report.

═══════════════════════════════════════════════════════════════
INCIDENT DETAILS
═══════════════════════════════════════════════════════════════
Source IP Address  : {ip_address}
Failed Attempts    : {failure_count} (Threshold: {threshold})
Detection Time     : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
Alert Reason       : Failure count exceeded anomaly detection threshold

═══════════════════════════════════════════════════════════════
RECENT LOG EVIDENCE (last {len(recent_logs)} entries from this IP)
═══════════════════════════════════════════════════════════════
{log_block}

═══════════════════════════════════════════════════════════════
YOUR ANALYSIS TASK
═══════════════════════════════════════════════════════════════
Please provide a security analysis with the following sections.
Be concise, actionable, and use precise security terminology.

**THREAT_LEVEL**: (Choose exactly one: CRITICAL / HIGH / MEDIUM / LOW)
  - CRITICAL: Active exploitation or successful breach indicators
  - HIGH: Aggressive brute-force, credential stuffing, sustained attack
  - MEDIUM: Moderate scanning or occasional failures from single IP
  - LOW: Light probing or single isolated failure

**ATTACK_TYPE**: A short label (e.g., "SSH Brute-Force", "Credential Stuffing",
  "Dictionary Attack", "Port Scanning", "Targeted Attack")

**SUMMARY**: 2–3 sentences describing what happened, the attacker's likely
  tactics, and the potential impact.

**KEY_EVIDENCE**: List 3–5 specific observations from the log data that
  support your assessment.

**RECOMMENDATIONS**: List 4–6 specific, actionable remediation steps the
  system administrator should take immediately. Include specific Linux
  commands or configurations where relevant (e.g., `fail2ban`, `ufw`,
  `sshd_config` changes, IP block commands).

**RISK_CONTEXT**: One sentence on the broader risk context (e.g., known
  attack campaigns, typical actor profiles for this pattern).

Format your response clearly with each section on its own line prefixed
by the section name followed by a colon.
""".strip()

    return prompt


# ══════════════════════════════════════════════════════════════
#  Response Parser
# ══════════════════════════════════════════════════════════════

def _parse_gemini_response(raw_text: str, ip_address: str) -> ThreatReport:
    """
    Extracts structured fields from the Gemini free-text response.

    Args:
        raw_text:   The full text response from the Gemini API.
        ip_address: The IP being analyzed (for the report).

    Returns:
        A populated ThreatReport dataclass.
    """
    report = ThreatReport(ip_address=ip_address, raw_response=raw_text)

    lines = raw_text.splitlines()
    current_section: Optional[str] = None
    buffer: list[str] = []

    def _flush_buffer(section: str, buf: list[str]) -> None:
        """Assigns accumulated buffer lines to the correct report field."""
        content = "\n".join(l.strip() for l in buf if l.strip())
        if section == "THREAT_LEVEL":
            # Extract just the keyword (CRITICAL/HIGH/MEDIUM/LOW)
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if level in content.upper():
                    report.threat_level = level
                    break
            else:
                report.threat_level = content.split()[0].upper() if content else "UNKNOWN"
        elif section == "ATTACK_TYPE":
            report.attack_type = content.strip('"').strip("'")
        elif section == "SUMMARY":
            report.summary = content
        elif section == "KEY_EVIDENCE":
            # Each line that starts with - or • or a number is a bullet
            for line in buf:
                stripped = line.strip().lstrip("-•*0123456789.) ").strip()
                if stripped:
                    report.evidence.append(stripped)
        elif section == "RECOMMENDATIONS":
            for line in buf:
                stripped = line.strip().lstrip("-•*0123456789.) ").strip()
                if stripped:
                    report.recommendations.append(stripped)

    # Section header prefixes to detect
    section_keys = {
        "THREAT_LEVEL":    "THREAT_LEVEL",
        "ATTACK_TYPE":     "ATTACK_TYPE",
        "SUMMARY":         "SUMMARY",
        "KEY_EVIDENCE":    "KEY_EVIDENCE",
        "RECOMMENDATIONS": "RECOMMENDATIONS",
        "RISK_CONTEXT":    "SUMMARY",   # append to summary
    }

    for line in lines:
        stripped = line.strip()
        matched_section = None

        for key, field_name in section_keys.items():
            if stripped.upper().startswith(f"**{key}**") or stripped.upper().startswith(f"{key}:"):
                if current_section:
                    _flush_buffer(current_section, buffer)
                current_section = field_name
                buffer = []
                # Inline value after the colon
                colon_idx = stripped.find(":")
                if colon_idx != -1:
                    inline = stripped[colon_idx + 1:].strip()
                    if inline:
                        buffer.append(inline)
                matched_section = field_name
                break

        if matched_section is None and current_section:
            buffer.append(stripped)

    # Flush the last section
    if current_section and buffer:
        _flush_buffer(current_section, buffer)

    # Fallback: if parsing completely failed, put the raw text in summary
    if not report.summary and raw_text:
        report.summary = raw_text[:500] + ("..." if len(raw_text) > 500 else "")

    return report


# ══════════════════════════════════════════════════════════════
#  AI Analyzer — Public Interface
# ══════════════════════════════════════════════════════════════

class AIAnalyzer:
    """
    Wraps the Google Gemini API client and exposes a single
    high-level `analyze_threat()` method.

    Usage:
        analyzer = AIAnalyzer()
        report = analyzer.analyze_threat(
            ip_address="203.0.113.42",
            recent_logs=[...],
            failure_count=8,
            threshold=5,
        )
    """

    def __init__(self) -> None:
        """
        Initializes the Gemini client.
        GEMINI_API_KEY must be set in the environment (via .env).
        """
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key or api_key == "your_gemini_api_key_here":
            print(
                f"{Fore.RED}[AI ERROR] GEMINI_API_KEY is not set in .env.\n"
                f"  Get your key at: https://aistudio.google.com/app/apikey{Style.RESET_ALL}"
            )
            sys.exit(1)

        # Modern google-genai client — automatically picks up GEMINI_API_KEY
        self.client = genai.Client()
        self.model  = MODEL_ID
        print(
            f"{Fore.CYAN}[AI] Gemini client initialized. "
            f"Model: {self.model}{Style.RESET_ALL}"
        )

    def analyze_threat(
        self,
        ip_address: str,
        recent_logs: list[dict],
        failure_count: int,
        threshold: int,
    ) -> ThreatReport:
        """
        Sends log context to Gemini and returns a structured ThreatReport.

        Args:
            ip_address:    The suspicious source IP address.
            recent_logs:   Recent log rows from the database for this IP.
            failure_count: Number of failures that exceeded the threshold.
            threshold:     The configured anomaly threshold.

        Returns:
            A ThreatReport with analysis results (may contain error field
            if the API call fails after all retries).
        """
        prompt = _build_analysis_prompt(
            ip_address=ip_address,
            recent_logs=recent_logs,
            failure_count=failure_count,
            threshold=threshold,
        )

        print(f"{Fore.CYAN}[AI] Analyzing threat from IP: {ip_address}...{Style.RESET_ALL}")

        # ── Retry loop with exponential back-off ──────────
        last_error: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                )

                raw_text = response.text
                if not raw_text:
                    raise ValueError("Gemini returned an empty response.")

                report = _parse_gemini_response(raw_text, ip_address)
                print(
                    f"{Fore.GREEN}[AI] Analysis complete. "
                    f"Threat level: {report.threat_level} — {report.attack_type}{Style.RESET_ALL}"
                )
                return report

            except Exception as exc:
                last_error = exc
                delay = RETRY_DELAY_SEC * (2 ** (attempt - 1))
                print(
                    f"{Fore.YELLOW}[AI] Attempt {attempt}/{MAX_RETRIES} failed: {exc}. "
                    f"Retrying in {delay:.1f}s...{Style.RESET_ALL}"
                )
                if attempt < MAX_RETRIES:
                    time.sleep(delay)

        # All retries exhausted
        error_msg = f"Gemini API failed after {MAX_RETRIES} attempts: {last_error}"
        print(f"{Fore.RED}[AI ERROR] {error_msg}{Style.RESET_ALL}")
        return ThreatReport(
            ip_address=ip_address,
            threat_level="ERROR",
            attack_type="API Failure",
            summary="AI analysis could not be completed due to API errors.",
            error=error_msg,
        )


# ── Manual Test Entry Point ────────────────────────────────
if __name__ == "__main__":
    print(f"{Fore.CYAN}[AI] Running standalone AI analyzer test...{Style.RESET_ALL}")

    # Fake DB rows for testing without a real database
    test_logs = [
        {
            "log_timestamp": "2026-06-22 14:30:00",
            "target_user": "root",
            "event_status": "Failed password",
            "raw_log": "Jun 22 14:30:00 server sshd[100]: Failed password for root from 203.0.113.42 port 51234 ssh2",
        },
        {
            "log_timestamp": "2026-06-22 14:30:02",
            "target_user": "admin",
            "event_status": "Invalid user",
            "raw_log": "Jun 22 14:30:02 server sshd[101]: Invalid user admin from 203.0.113.42 port 51235",
        },
        {
            "log_timestamp": "2026-06-22 14:30:04",
            "target_user": "oracle",
            "event_status": "Failed password",
            "raw_log": "Jun 22 14:30:04 server sshd[102]: Failed password for oracle from 203.0.113.42 port 51236 ssh2",
        },
        {
            "log_timestamp": "2026-06-22 14:30:06",
            "target_user": "postgres",
            "event_status": "Failed password",
            "raw_log": "Jun 22 14:30:06 server sshd[103]: Failed password for postgres from 203.0.113.42 port 51237 ssh2",
        },
        {
            "log_timestamp": "2026-06-22 14:30:08",
            "target_user": "ubuntu",
            "event_status": "Failed password",
            "raw_log": "Jun 22 14:30:08 server sshd[104]: Failed password for ubuntu from 203.0.113.42 port 51238 ssh2",
        },
    ]

    analyzer = AIAnalyzer()
    report = analyzer.analyze_threat(
        ip_address="203.0.113.42",
        recent_logs=test_logs,
        failure_count=5,
        threshold=5,
    )

    print("\n" + "=" * 60)
    print("  THREAT REPORT")
    print("=" * 60)
    print(f"  IP           : {report.ip_address}")
    print(f"  Threat Level : {report.threat_level}")
    print(f"  Attack Type  : {report.attack_type}")
    print(f"  Summary      : {report.summary}")
    print(f"  Evidence     :")
    for e in report.evidence:
        print(f"    - {e}")
    print(f"  Recommendations:")
    for r in report.recommendations:
        print(f"    - {r}")
    print("=" * 60)
    print("\n  DB String Preview:")
    print(report.to_db_string())
