"""
============================================================
 database.py — MySQL Connection & Schema Management
============================================================
 Responsibilities:
   - Connect to MySQL using credentials from .env
   - Auto-create the database and `system_logs` table
   - Insert parsed log entries
   - Update rows with AI-generated threat summaries
   - Fetch recent logs by IP for AI context gathering
============================================================
"""

import os
import sys
import mysql.connector
from mysql.connector import Error, errorcode
from datetime import datetime
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Initialize colorama for cross-platform terminal colors
init(autoreset=True)

# Load environment variables from .env
load_dotenv()

# ── Database Configuration ─────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "user":     os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
}
DB_NAME = os.getenv("DB_NAME", "ai_log_monitor_db")

# ── Schema Definition ──────────────────────────────────────
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS system_logs (
    id               INT           NOT NULL AUTO_INCREMENT,
    log_timestamp    DATETIME      NOT NULL,
    ip_address       VARCHAR(45)   DEFAULT NULL,
    target_user      VARCHAR(50)   DEFAULT NULL,
    event_status     VARCHAR(50)   NOT NULL,
    raw_log          TEXT          NOT NULL,
    ai_threat_summary TEXT         DEFAULT NULL,
    created_at       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_ip_address  (ip_address),
    INDEX idx_log_timestamp (log_timestamp),
    INDEX idx_event_status  (event_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


# ══════════════════════════════════════════════════════════════
#  Connection Helper
# ══════════════════════════════════════════════════════════════

def get_connection(include_db: bool = True) -> mysql.connector.MySQLConnection:
    """
    Return an active MySQL connection.

    Args:
        include_db: If True, connects directly to DB_NAME.
                    If False, connects without selecting a database
                    (used during initial DB creation).

    Returns:
        A mysql.connector connection object.

    Raises:
        SystemExit: If the connection cannot be established.
    """
    config = dict(DB_CONFIG)
    if include_db:
        config["database"] = DB_NAME

    try:
        conn = mysql.connector.connect(**config)
        return conn
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Could not connect to MySQL: {e}{Style.RESET_ALL}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════
#  Schema Initializer
# ══════════════════════════════════════════════════════════════

def initialize_database() -> None:
    """
    Creates the database (if it doesn't exist) and ensures
    the `system_logs` table is provisioned with the correct schema.
    Called once at application startup.
    """
    # Step 1: Connect without selecting a DB to create it if absent
    conn = get_connection(include_db=False)
    cursor = conn.cursor()

    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
        cursor.execute(f"USE `{DB_NAME}`;")
        cursor.execute(CREATE_TABLE_SQL)
        conn.commit()
        print(
            f"{Fore.GREEN}[DB] Database '{DB_NAME}' and table 'system_logs' "
            f"are ready.{Style.RESET_ALL}"
        )
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Schema initialization failed: {e}{Style.RESET_ALL}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()


# ══════════════════════════════════════════════════════════════
#  CRUD Operations
# ══════════════════════════════════════════════════════════════

def insert_log_entry(
    log_timestamp: datetime,
    ip_address: str | None,
    target_user: str | None,
    event_status: str,
    raw_log: str,
) -> int | None:
    """
    Inserts a newly parsed log entry into `system_logs`.

    Args:
        log_timestamp: Parsed datetime of the log event.
        ip_address:    Source IP address (can be None for local events).
        target_user:   The SSH target username (can be None).
        event_status:  Event classification string (e.g. 'Failed password').
        raw_log:       The original, unmodified log line.

    Returns:
        The auto-incremented row ID on success, None on failure.
    """
    sql = """
        INSERT INTO system_logs
            (log_timestamp, ip_address, target_user, event_status, raw_log)
        VALUES
            (%s, %s, %s, %s, %s)
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (log_timestamp, ip_address, target_user, event_status, raw_log))
        conn.commit()
        row_id = cursor.lastrowid
        cursor.close()
        return row_id
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Failed to insert log entry: {e}{Style.RESET_ALL}")
        return None
    finally:
        if conn and conn.is_connected():
            conn.close()


def update_ai_summary(row_id: int, ai_summary: str) -> bool:
    """
    Updates the `ai_threat_summary` column for a specific log row
    after the AI analysis completes.

    Args:
        row_id:     The primary key of the row to update.
        ai_summary: The AI-generated threat analysis text.

    Returns:
        True if the update succeeded, False otherwise.
    """
    sql = "UPDATE system_logs SET ai_threat_summary = %s WHERE id = %s"
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(sql, (ai_summary, row_id))
        conn.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Failed to update AI summary for row {row_id}: {e}{Style.RESET_ALL}")
        return False
    finally:
        if conn and conn.is_connected():
            conn.close()


def fetch_recent_logs_by_ip(ip_address: str, limit: int = 20) -> list[dict]:
    """
    Fetches the most recent log entries from a specific IP address.
    Used to build context for the AI threat analysis prompt.

    Args:
        ip_address: The IP address to filter by.
        limit:      Maximum number of rows to return.

    Returns:
        A list of dictionaries, each representing one log row.
        Returns an empty list on error.
    """
    sql = """
        SELECT id, log_timestamp, ip_address, target_user, event_status, raw_log
        FROM system_logs
        WHERE ip_address = %s
        ORDER BY log_timestamp DESC
        LIMIT %s
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql, (ip_address, limit))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Failed to fetch logs for IP {ip_address}: {e}{Style.RESET_ALL}")
        return []
    finally:
        if conn and conn.is_connected():
            conn.close()


def fetch_log_stats() -> dict:
    """
    Returns aggregate statistics from the system_logs table.
    Useful for the monitor's startup summary display.

    Returns:
        A dictionary with keys: total, failed, accepted, ai_analyzed.
    """
    sql = """
        SELECT
            COUNT(*)                                             AS total,
            SUM(event_status LIKE 'Failed%')                    AS failed,
            SUM(event_status LIKE 'Accepted%')                  AS accepted,
            SUM(ai_threat_summary IS NOT NULL)                  AS ai_analyzed
        FROM system_logs
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql)
        result = cursor.fetchone()
        cursor.close()
        return result or {}
    except Error as e:
        print(f"{Fore.RED}[DB ERROR] Failed to fetch stats: {e}{Style.RESET_ALL}")
        return {}
    finally:
        if conn and conn.is_connected():
            conn.close()


# ── Manual test entry point ────────────────────────────────
if __name__ == "__main__":
    print(f"{Fore.CYAN}[DB] Running schema initialization test...{Style.RESET_ALL}")
    initialize_database()

    # Insert a test row
    test_id = insert_log_entry(
        log_timestamp=datetime.now(),
        ip_address="192.168.1.100",
        target_user="admin",
        event_status="Failed password",
        raw_log="Jun 22 14:00:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 54321 ssh2",
    )
    if test_id:
        print(f"{Fore.GREEN}[DB] Inserted test row with ID: {test_id}{Style.RESET_ALL}")
        update_ai_summary(test_id, "TEST: Simulated brute-force attempt from local network.")
        print(f"{Fore.GREEN}[DB] Updated AI summary for row {test_id}.{Style.RESET_ALL}")

    rows = fetch_recent_logs_by_ip("192.168.1.100", limit=5)
    print(f"{Fore.CYAN}[DB] Fetched {len(rows)} rows for 192.168.1.100.{Style.RESET_ALL}")

    stats = fetch_log_stats()
    print(f"{Fore.CYAN}[DB] Stats: {stats}{Style.RESET_ALL}")
