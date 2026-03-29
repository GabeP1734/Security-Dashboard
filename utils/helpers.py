import sqlite3
import socket
import re

DB_NAME = "database.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def add_alert(alert_type, severity, message):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (alert_type, severity, message)
        VALUES (?, ?, ?)
    """, (alert_type, severity, message))

    conn.commit()
    conn.close()


def get_all_alerts():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
    """)

    alerts = cursor.fetchall()
    conn.close()
    return alerts


def get_alerts_by_severity(severity):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM alerts
        WHERE severity = ?
        ORDER BY timestamp DESC
    """, (severity,))

    alerts = cursor.fetchall()
    conn.close()
    return alerts


def delete_alert(alert_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))

    conn.commit()
    conn.close()


def parse_log_file(file_path):
    alerts = []

    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    for line in lines:
        if "failed" in line.lower() or "invalid" in line.lower():
            alerts.append({
                "alert_type": "Failed Login Attempt",
                "severity": "High",
                "message": line.strip()
            })

    return alerts


def scan_common_ports(target):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP"
    }

    results = []

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))

        if result == 0:
            results.append(f"Port {port} ({service}) is open")

        sock.close()

    return results


def save_scan_result(target, result):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (target, result)
        VALUES (?, ?)
    """, (target, result))

    conn.commit()
    conn.close()


def get_all_scans():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scans
        ORDER BY timestamp DESC
    """)

    scans = cursor.fetchall()
    conn.close()
    return scans


def is_valid_ip(ip):
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        return False

    parts = ip.split(".")
    return all(0 <= int(part) <= 255 for part in parts)


def create_user(username, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
    """, (username, password_hash))

    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users
        WHERE username = ?
    """, (username,))

    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users
        WHERE id = ?
    """, (user_id,))

    user = cursor.fetchone()
    conn.close()
    return user