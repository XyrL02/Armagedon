"""
Armagedon Database — SQLite-based persistence for targets, sessions, loot, creds.
"""
import sqlite3
import json
import logging
import os
from datetime import datetime
from pathlib import Path

log = logging.getLogger("armagedon.core.database")


class Database:
    def __init__(self, db_path=None):
        if db_path is None:
            user_dir = Path.home() / ".armagedon"
            user_dir.mkdir(parents=True, exist_ok=True)
            db_path = user_dir / "armagedon.db"
        self.db_path = db_path
        log.info("Database: %s", db_path)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        c = self.conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                os TEXT,
                domain TEXT,
                os_version TEXT,
                architecture TEXT,
                sessions INTEGER DEFAULT 0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                session_type TEXT,
                platform TEXT,
                username TEXT,
                process TEXT,
                pid INTEGER,
                arch TEXT,
                opened TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT DEFAULT 'active',
                data TEXT,
                FOREIGN KEY(target_ip) REFERENCES targets(ip)
            );

            CREATE TABLE IF NOT EXISTS loot (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                type TEXT NOT NULL,
                data TEXT,
                source TEXT,
                date TIMESTAMP,
                FOREIGN KEY(target_ip) REFERENCES targets(ip)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                username TEXT,
                credential TEXT,
                type TEXT,
                source TEXT,
                date TIMESTAMP,
                FOREIGN KEY(target_ip) REFERENCES targets(ip)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                cve TEXT,
                title TEXT,
                severity TEXT,
                description TEXT,
                proof TEXT,
                date TIMESTAMP,
                status TEXT DEFAULT 'confirmed',
                FOREIGN KEY(target_ip) REFERENCES targets(ip)
            );

            CREATE TABLE IF NOT EXISTS module_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_name TEXT NOT NULL,
                target_ip TEXT,
                status TEXT,
                output TEXT,
                date TIMESTAMP
            );
        """)
        self.conn.commit()

    def add_target(self, ip, hostname="", os="", domain="", os_version="", arch=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("add_target: %s (os=%s)", ip, os)
        c.execute("""
            INSERT INTO targets (ip, hostname, os, domain, os_version, architecture, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                hostname = COALESCE(NULLIF(excluded.hostname, ''), targets.hostname),
                os = COALESCE(NULLIF(excluded.os, ''), targets.os)
        """, (ip, hostname, os, domain, os_version, arch, now, now))
        self.conn.commit()

    def get_targets(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM targets ORDER BY last_seen DESC")
        return [dict(row) for row in c.fetchall()]

    def add_session(self, target_ip, session_type, platform, username="", process="", pid=0, arch=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("add_session: %s type=%s user=%s", target_ip, session_type, username)
        c.execute("""
            INSERT INTO sessions (target_ip, session_type, platform, username, process, pid, arch, opened, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (target_ip, session_type, platform, username, process, pid, arch, now, now))
        self.conn.commit()
        c.execute("UPDATE targets SET sessions = sessions + 1 WHERE ip = ?", (target_ip,))
        self.conn.commit()
        return c.lastrowid

    def get_sessions(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM sessions WHERE status='active' ORDER BY last_seen DESC")
        return [dict(row) for row in c.fetchall()]

    def add_loot(self, target_ip, loot_type, data, source=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("add_loot: %s type=%s source=%s", target_ip, loot_type, source)
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        c.execute("""
            INSERT INTO loot (target_ip, type, data, source, date)
            VALUES (?, ?, ?, ?, ?)
        """, (target_ip, loot_type, str(data), source, now))
        self.conn.commit()

    def get_loot(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM loot ORDER BY date DESC LIMIT 50")
        return [dict(row) for row in c.fetchall()]

    def add_cred(self, target_ip, username, credential, cred_type, source=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("add_cred: %s user=%s type=%s", target_ip, username, cred_type)
        c.execute("""
            INSERT INTO credentials (target_ip, username, credential, type, source, date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target_ip, username, credential, cred_type, source, now))
        self.conn.commit()

    def get_creds(self):
        c = self.conn.cursor()
        c.execute("SELECT * FROM credentials ORDER BY date DESC LIMIT 50")
        return [dict(row) for row in c.fetchall()]

    def add_finding(self, target_ip, cve, title, severity, description, proof=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("add_finding: %s cve=%s severity=%s", target_ip, cve, severity)
        c.execute("""
            INSERT INTO findings (target_ip, cve, title, severity, description, proof, date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target_ip, cve, title, severity, description, proof, now))
        self.conn.commit()

    def log_module(self, module_name, target_ip, status, output=""):
        c = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        log.info("log_module: %s target=%s status=%s", module_name, target_ip, status)
        if isinstance(output, dict):
            output = json.dumps(output)
        c.execute("""
            INSERT INTO module_history (module_name, target_ip, status, output, date)
            VALUES (?, ?, ?, ?, ?)
        """, (module_name, target_ip, status, str(output)[:5000], now))
        self.conn.commit()

    def save_host(self, target: str, scan_data: dict):
        """Save/update a host from scan results (used by pipeline)."""
        os_name = scan_data.get("os", "")
        log.debug("save_host: %s os=%s", target, os_name)
        self.add_target(
            ip=target,
            os=os_name,
        )
        if scan_data.get("open_ports"):
            self.add_loot(
                target,
                "scan_ports",
                {"ports": scan_data["open_ports"], "services": scan_data.get("services", {})},
                source="nexus_scan",
            )

    def log_finding(self, target: str, module: str, success: bool, data: str = ""):
        """Log a module execution result (used by pipeline)."""
        log.info("log_finding: %s module=%s success=%s", target, module, success)
        self.log_module(
            module_name=module,
            target_ip=target,
            status="success" if success else "failed",
            output=data[:5000],
        )

    def save_state(self, engine):
        pass

    def run_session_command(self, session_id, cmd):
        return f"[Session {session_id}] Command execution not yet implemented in interactive mode"
