from datetime import datetime
import json
from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = str(BASE_DIR / "scanner.db")


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            domain TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            report_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_scan(target_url, domain, risk_score, risk_level, report_data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        """
        INSERT INTO scans (target_url, domain, scan_date, risk_score, risk_level, report_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (target_url, domain, scan_date, risk_score, risk_level, json.dumps(report_data)),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, target_url, domain, scan_date, risk_score, risk_level FROM scans ORDER BY id DESC"
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        data = dict(row)
        data["report"] = json.loads(data["report_json"])
        return data
    return None


def delete_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted