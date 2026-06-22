# 🛡️ AI-Enhanced System Log Monitor

An automated, real-time Linux server security monitor that **tails SSH auth logs**, **parses events with regex**, **stores them in MySQL**, **detects brute-force anomalies**, and triggers **Google Gemini 2.5 Flash** to generate structured threat intelligence reports — all in a beautiful color-coded terminal dashboard.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     monitor.py (Orchestrator)                 │
│                                                              │
│  [LogTailer] ──▶ [Parser] ──▶ [Database (MySQL)]            │
│                                      │                       │
│                              [AnomalyDetector]               │
│                                      │ threshold exceeded    │
│                             [AIAnalyzer (Gemini)] ──▶ [DB]  │
└──────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
ai_log_monitor/
├── .env                 # Environment variables (credentials, keys)
├── requirements.txt     # Python dependencies
├── database.py          # MySQL schema, CRUD operations
├── log_generator.py     # Mock auth.log generator with burst simulation
├── parser.py            # Regex SSH log parser
├── ai_analyzer.py       # Google Gemini integration & ThreatReport
└── monitor.py           # Main event loop & orchestrator
```

---

## ⚙️ Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| MySQL Server | 8.0+ |
| Google Gemini API Key | [Get one free](https://aistudio.google.com/app/apikey) |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd ai_log_monitor
pip install -r requirements.txt
```

### 2. Configure Environment

Edit `.env` with your credentials:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=ai_log_monitor_db
GEMINI_API_KEY=your_gemini_api_key_here
```

> **Get a free Gemini API key:** https://aistudio.google.com/app/apikey

### 3. Start the Mock Log Generator (Terminal 1)

```bash
python log_generator.py
```

This simulates a live Linux server writing to `mock_auth.log` with:
- Random failed/successful SSH attempts
- Periodic **burst attacks** (5–10 failures from one IP) to trigger AI analysis

Optional flags:
```bash
python log_generator.py --interval 0.5    # Faster log generation
python log_generator.py --burst-prob 0.3  # More frequent bursts (30%)
python log_generator.py --burst-now       # Write a single burst and exit
```

### 4. Start the Monitor (Terminal 2)

```bash
python monitor.py
```

---

## 🖥️ What You'll See

### Normal Events (color-coded):
```
14:32:01 [Failed password             ] IP=203.0.113.42    User=root
14:32:05 [Invalid user                ] IP=203.0.113.42    User=admin
14:33:00 [Accepted password           ] IP=10.0.0.5        User=deploy
```

### Anomaly Alert:
```
──────────────────────────────────────────────────────────────────────
14:32:08 [ALERT] Anomaly detected! 6 failures from 203.0.113.42 (threshold=5). Dispatching AI analysis...
──────────────────────────────────────────────────────────────────────
```

### AI Threat Report:
```
══════════════════════════════════════════════════════════════════════
  ⚠  THREAT ALERT — HIGH: SSH Brute-Force
  IP Address    : 203.0.113.42
  Failure Count : 6 in last 5 minutes
  Summary       : The IP 203.0.113.42 is conducting a systematic SSH
                  brute-force attack targeting common administrative
                  usernames. This is consistent with automated scanning.

  Key Evidence:
    • 6 failed attempts across 4 different usernames in under 10 seconds
    • Usernames targeted match common default/admin account names
    • No successful authentication observed
    • Rapid port cycling indicates automated tooling

  Recommendations:
    1. Block IP immediately: sudo ufw deny from 203.0.113.42 to any
    2. Install fail2ban: sudo apt install fail2ban
    3. Disable password auth: PasswordAuthentication no in /etc/ssh/sshd_config
    4. Enable key-only logins and restart SSH
    5. Review /var/log/auth.log for any successful logins from this IP
══════════════════════════════════════════════════════════════════════
```

---

## 🧩 Module Reference

### `database.py`
| Function | Description |
|---|---|
| `initialize_database()` | Creates DB + table if not exists |
| `insert_log_entry(...)` | Inserts a parsed log row, returns row ID |
| `update_ai_summary(id, text)` | Writes AI analysis to a row |
| `fetch_recent_logs_by_ip(ip, limit)` | Gets recent rows for context |
| `fetch_log_stats()` | Returns aggregate statistics |

### `parser.py`
| Function | Description |
|---|---|
| `parse_log_line(raw)` | Parses one line → `ParsedLogEntry` or `None` |
| `is_failure_event(entry)` | Returns `True` for threat-class events |

Supported event types: `Failed password`, `Accepted password/publickey`, `Invalid user`, `No identification`, `Connection closed`, `Disconnected`, `Session opened/closed`, `Max auth attempts exceeded`, `PAM event`, `sudo/su/CRON events`

### `ai_analyzer.py`
| Component | Description |
|---|---|
| `AIAnalyzer` class | Wraps Gemini client with retry logic |
| `ThreatReport` dataclass | Structured AI response with threat level, attack type, evidence, recommendations |
| `analyze_threat(...)` | Main method: builds prompt → calls Gemini → parses response |

### `monitor.py`
| Component | Description |
|---|---|
| `LogTailer` | Efficient file tail with offset tracking + rotation detection |
| `AnomalyDetector` | Thread-safe sliding-window failure counter per IP |
| `LogMonitor` | Main orchestrator with graceful shutdown |
| `_ai_analysis_worker()` | Background thread for non-blocking AI calls |

---

## 🔧 Configuration Reference

All settings in `.env`:

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | `localhost` | MySQL host |
| `DB_USER` | `root` | MySQL username |
| `DB_PASSWORD` | _(required)_ | MySQL password |
| `DB_NAME` | `ai_log_monitor_db` | Database name (auto-created) |
| `GEMINI_API_KEY` | _(required)_ | Gemini API key |
| `LOG_FILE_PATH` | `mock_auth.log` | Path to tail |
| `ANOMALY_THRESHOLD` | `5` | Failures before AI alert |
| `MONITOR_POLL_INTERVAL` | `2` | Seconds between polls |
| `AI_CONTEXT_LOG_LIMIT` | `20` | DB rows sent to Gemini |

**Hard-coded in `monitor.py`:**
- `FAILURE_WINDOW_SEC = 300` — 5-minute rolling window for failure counting
- `AI_COOLDOWN_SEC = 300` — 5-minute cooldown before same IP triggers again

---

## 🗄️ Database Schema

```sql
CREATE TABLE system_logs (
    id                INT          AUTO_INCREMENT PRIMARY KEY,
    log_timestamp     DATETIME     NOT NULL,
    ip_address        VARCHAR(45),          -- IPv4 or IPv6
    target_user       VARCHAR(50),
    event_status      VARCHAR(50)  NOT NULL, -- e.g. "Failed password"
    raw_log           TEXT         NOT NULL, -- Original log line
    ai_threat_summary TEXT,                  -- Gemini analysis output
    created_at        TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_address   (ip_address),
    INDEX idx_log_timestamp (log_timestamp),
    INDEX idx_event_status  (event_status)
);
```

---

## 🧪 Running Individual Modules

```bash
# Test the parser standalone
python parser.py

# Test the database connection
python database.py

# Test AI analyzer (requires valid GEMINI_API_KEY in .env)
python ai_analyzer.py

# Trigger a single burst immediately
python log_generator.py --burst-now
```

---

## 🔒 Production Hardening Notes

> These steps are for deploying on a real Linux server:

1. **Use the real log file**: Set `LOG_FILE_PATH=/var/log/auth.log` in `.env`
2. **Run with read permissions**: `sudo chmod o+r /var/log/auth.log`
3. **Store secrets securely**: Use a secrets manager instead of plain `.env`
4. **Run as a service**: Create a `systemd` unit file for `monitor.py`
5. **Rate-limit AI calls**: The 5-minute cooldown per IP is already implemented
6. **MySQL security**: Use a dedicated DB user with minimal privileges

---

## 📦 Dependencies

```
mysql-connector-python  — MySQL driver
google-genai            — Official modern Google GenAI SDK
python-dotenv           — .env file loader
colorama                — Cross-platform terminal colors
```

---

## 📄 License

MIT — Free to use, modify, and distribute.
