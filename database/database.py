import sqlite3

DATABASE = "database/sentinel_trap.db"


def create_database():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    # Security alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT
        )
    """)

    # Performance indexes
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_timestamp
        ON login_attempts(timestamp)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_source_ip
        ON login_attempts(source_ip)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_status
        ON login_attempts(status)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alert_source_status
        ON alerts(source_ip, status)
    """)

    connection.commit()
    connection.close()


def save_login_attempt(
    username,
    source_ip,
    timestamp,
    status
):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO login_attempts
        (username, source_ip, timestamp, status)
        VALUES (?, ?, ?, ?)
    """, (
        username,
        source_ip,
        timestamp,
        status
    ))

    connection.commit()
    connection.close()


def save_alert(
    alert_type,
    source_ip,
    severity,
    status,
    attempt_count,
    risk_score,
    first_seen,
    last_seen,
    resolved_at=None
):
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            alert_type,
            source_ip,
            severity,
            status,
            attempt_count,
            risk_score,
            first_seen,
            last_seen,
            resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_type,
        source_ip,
        severity,
        status,
        attempt_count,
        risk_score,
        first_seen,
        last_seen,
        resolved_at
    ))

    connection.commit()
    connection.close()
