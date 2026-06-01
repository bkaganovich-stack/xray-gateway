"""
SQLite database layer for xray-gateway.
Handles analytics, subscription rules, terminal audit, scheduler history.
Uses stdlib sqlite3 + asyncio.get_event_loop().run_in_executor() for async access.
"""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

# Resolved at import time from main.py's BASE constant;
# fall back to a test-friendly value.
_DB_PATH: Optional[Path] = None


def set_db_path(path: Path) -> None:
    global _DB_PATH
    _DB_PATH = path


def _get_db_path() -> Path:
    if _DB_PATH is not None:
        return _DB_PATH
    return Path("/opt/xray-proxy/config/gateway.db")


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    """Context manager: open, yield, commit/rollback, close."""
    p = _get_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA_VERSION = 1

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- Analytics: aggregated per-hour traffic counts
CREATE TABLE IF NOT EXISTS traffic_hourly (
    hour        TEXT    NOT NULL,   -- YYYY-MM-DD HH
    src_ip      TEXT    NOT NULL,
    dst_host    TEXT    NOT NULL,
    outbound    TEXT    NOT NULL,
    proto       TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (hour, src_ip, dst_host, outbound, proto)
);
CREATE INDEX IF NOT EXISTS idx_traffic_hour ON traffic_hourly(hour);
CREATE INDEX IF NOT EXISTS idx_traffic_src  ON traffic_hourly(src_ip);

-- Access log checkpoint: last byte offset processed
CREATE TABLE IF NOT EXISTS log_checkpoint (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    offset   INTEGER NOT NULL DEFAULT 0,
    log_size INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO log_checkpoint (id, offset, log_size) VALUES (1, 0, 0);

-- Subscription rules: domain/IP lists fetched from URLs
CREATE TABLE IF NOT EXISTS subscription_rules (
    sub_id   TEXT NOT NULL,
    rule     TEXT NOT NULL,
    PRIMARY KEY (sub_id, rule)
);
CREATE INDEX IF NOT EXISTS idx_sub_rules_id ON subscription_rules(sub_id);

-- Terminal audit log
CREATE TABLE IF NOT EXISTS terminal_sessions (
    session_id  TEXT    PRIMARY KEY,
    user        TEXT    NOT NULL,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    mode        TEXT    NOT NULL,
    commands    TEXT    NOT NULL DEFAULT '[]'  -- JSON array of {cmd, ts, exit}
);
CREATE INDEX IF NOT EXISTS idx_term_started ON terminal_sessions(started_at);

-- Scheduler run history
CREATE TABLE IF NOT EXISTS scheduler_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id    TEXT    NOT NULL,
    task_name  TEXT    NOT NULL,
    ran_at     INTEGER NOT NULL,
    duration_s REAL,
    result     TEXT    NOT NULL,  -- ok|error|skip
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sched_task ON scheduler_history(task_id);
CREATE INDEX IF NOT EXISTS idx_sched_ran  ON scheduler_history(ran_at);

-- Update history
CREATE TABLE IF NOT EXISTS update_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    component    TEXT    NOT NULL,  -- gateway|xray-core
    from_version TEXT,
    to_version   TEXT,
    status       TEXT    NOT NULL,  -- ok|error|rolled_back
    detail       TEXT
);
"""


def init_db() -> None:
    """Create tables and run migrations if needed."""
    with get_conn() as conn:
        conn.executescript(_SCHEMA_SQL)
        row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        current = row["version"] if row else 0
        if current < SCHEMA_VERSION:
            conn.execute("DELETE FROM schema_version")
            conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION,))


# ── Analytics helpers ─────────────────────────────────────────────────────────
def upsert_traffic(hour: str, src_ip: str, dst_host: str,
                   outbound: str, proto: str, count: int = 1) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO traffic_hourly (hour, src_ip, dst_host, outbound, proto, count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(hour, src_ip, dst_host, outbound, proto)
            DO UPDATE SET count = count + excluded.count
        """, (hour, src_ip, dst_host, outbound, proto, count))


def get_traffic_summary(hours: int = 24) -> dict:
    """Return aggregated traffic stats for the last N hours."""
    cutoff = time.strftime("%Y-%m-%d %H", time.gmtime(time.time() - hours * 3600))
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT src_ip, dst_host, outbound, proto, SUM(count) as total
            FROM traffic_hourly
            WHERE hour >= ?
            GROUP BY src_ip, dst_host, outbound, proto
        """, (cutoff,)).fetchall()

    total = vpn = direct = blocked = 0
    clients: dict[str, int] = {}
    destinations: dict[str, int] = {}
    outbound_counts: dict[str, int] = {}

    for r in rows:
        n = r["total"]
        total += n
        ob = r["outbound"]
        outbound_counts[ob] = outbound_counts.get(ob, 0) + n
        if ob == "proxy":   vpn     += n
        elif ob == "direct": direct += n
        elif ob == "block":  blocked += n
        src = r["src_ip"]
        clients[src] = clients.get(src, 0) + n
        dst = r["dst_host"]
        destinations[dst] = destinations.get(dst, 0) + n

    top_clients = sorted(clients.items(), key=lambda x: -x[1])[:10]
    top_dests   = sorted(destinations.items(), key=lambda x: -x[1])[:15]
    return {
        "total": total, "vpn": vpn, "direct": direct, "blocked": blocked,
        "top_clients": [{"ip": ip, "count": n} for ip, n in top_clients],
        "top_destinations": [{"host": h, "count": n} for h, n in top_dests],
        "outbound_counts": outbound_counts,
        "hours": hours,
    }


def get_hourly_series(hours: int = 24) -> list[dict]:
    """Return VPN+Direct counts per hour for the last N hours."""
    cutoff = time.strftime("%Y-%m-%d %H", time.gmtime(time.time() - hours * 3600))
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT hour, outbound, SUM(count) as total
            FROM traffic_hourly
            WHERE hour >= ?
            GROUP BY hour, outbound
            ORDER BY hour
        """, (cutoff,)).fetchall()
    buckets: dict[str, dict] = {}
    for r in rows:
        h = r["hour"]
        if h not in buckets:
            buckets[h] = {"hour": h, "vpn": 0, "direct": 0, "blocked": 0}
        ob = r["outbound"]
        if ob == "proxy":    buckets[h]["vpn"]     += r["total"]
        elif ob == "direct": buckets[h]["direct"]  += r["total"]
        elif ob == "block":  buckets[h]["blocked"] += r["total"]
    return list(buckets.values())


def get_log_checkpoint() -> tuple[int, int]:
    with get_conn() as conn:
        row = conn.execute("SELECT offset, log_size FROM log_checkpoint WHERE id=1").fetchone()
        return (row["offset"], row["log_size"]) if row else (0, 0)


def set_log_checkpoint(offset: int, log_size: int) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE log_checkpoint SET offset=?, log_size=? WHERE id=1",
                     (offset, log_size))


def purge_old_traffic(retention_days: int) -> int:
    cutoff = time.strftime("%Y-%m-%d %H",
                           time.gmtime(time.time() - retention_days * 86400))
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM traffic_hourly WHERE hour < ?", (cutoff,))
        return cur.rowcount


# ── Subscription rule helpers ─────────────────────────────────────────────────
def replace_subscription_rules(sub_id: str, rules: list[str]) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM subscription_rules WHERE sub_id = ?", (sub_id,))
        conn.executemany(
            "INSERT OR IGNORE INTO subscription_rules (sub_id, rule) VALUES (?, ?)",
            [(sub_id, r) for r in rules])


def get_subscription_rules(sub_id: str) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT rule FROM subscription_rules WHERE sub_id = ?", (sub_id,)).fetchall()
        return [r["rule"] for r in rows]


def delete_subscription_rules(sub_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM subscription_rules WHERE sub_id = ?", (sub_id,))


def count_subscription_rules(sub_id: str) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as n FROM subscription_rules WHERE sub_id = ?", (sub_id,)).fetchone()
        return row["n"] if row else 0


def get_all_subscription_rules_by_type(settings: dict) -> dict[str, list[str]]:
    """Return {type: [rules]} merged from all enabled subscriptions."""
    result: dict[str, list[str]] = {"direct": [], "vpn": [], "block": [], "adblock": []}
    for sub in settings.get("subscriptions", []):
        if not sub.get("enabled"):
            continue
        rules = get_subscription_rules(sub["id"])
        t = sub.get("type", "direct")
        if t in result:
            result[t].extend(rules)
    return result


# ── Terminal audit helpers ────────────────────────────────────────────────────
def start_terminal_session(session_id: str, user: str, mode: str) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO terminal_sessions
            (session_id, user, started_at, mode, commands)
            VALUES (?, ?, ?, ?, '[]')
        """, (session_id, user, int(time.time()), mode))


def end_terminal_session(session_id: str) -> None:
    with get_conn() as conn:
        conn.execute("UPDATE terminal_sessions SET ended_at=? WHERE session_id=?",
                     (int(time.time()), session_id))


def log_terminal_command(session_id: str, cmd: str, exit_code: Optional[int] = None) -> None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT commands FROM terminal_sessions WHERE session_id=?",
            (session_id,)).fetchone()
        if not row:
            return
        cmds = json.loads(row["commands"])
        cmds.append({"cmd": cmd[:500], "ts": int(time.time()), "exit": exit_code})
        # Keep last 200 commands per session
        if len(cmds) > 200:
            cmds = cmds[-200:]
        conn.execute("UPDATE terminal_sessions SET commands=? WHERE session_id=?",
                     (json.dumps(cmds), session_id))


def list_terminal_sessions(limit: int = 50) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT session_id, user, started_at, ended_at, mode,
                   json_array_length(commands) as cmd_count
            FROM terminal_sessions
            ORDER BY started_at DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ── Scheduler history helpers ─────────────────────────────────────────────────
def log_scheduler_run(task_id: str, task_name: str, duration_s: float,
                      result: str, detail: str = "") -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO scheduler_history
            (task_id, task_name, ran_at, duration_s, result, detail)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (task_id, task_name, int(time.time()), duration_s, result, detail[:500]))
        # Keep last 500 runs total
        conn.execute("""
            DELETE FROM scheduler_history
            WHERE id NOT IN (
                SELECT id FROM scheduler_history ORDER BY id DESC LIMIT 500
            )
        """)


def list_scheduler_history(task_id: Optional[str] = None, limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        if task_id:
            rows = conn.execute("""
                SELECT * FROM scheduler_history WHERE task_id=?
                ORDER BY ran_at DESC LIMIT ?
            """, (task_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM scheduler_history ORDER BY ran_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ── Update history helpers ────────────────────────────────────────────────────
def log_update(component: str, from_ver: str, to_ver: str,
               status: str, detail: str = "") -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO update_history
            (ts, component, from_version, to_version, status, detail)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (int(time.time()), component, from_ver, to_ver, status, detail[:500]))


def list_update_history(limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM update_history ORDER BY ts DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
