import sqlite3

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from analyzer.statistics import (
    get_total_attempts,
    get_successful_logins,
    get_failed_logins,
    get_unique_ips,
    get_success_rate,
    get_active_alerts,
    get_resolved_alerts,
)


DATABASE = "database/sentinel_trap.db"


# ==================================================
# FASTAPI APPLICATION
# ==================================================

app = FastAPI(
    title="SentinelTrap API",
    description="Security monitoring API for the SentinelTrap honeypot",
    version="1.0.0"
)


# ==================================================
# CORS CONFIGURATION
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ==================================================
# ROOT ENDPOINT
# ==================================================

@app.get("/")
def root():

    return {
        "project": "SentinelTrap",
        "status": "online",
        "message": "Security monitoring API is running"
    }


# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/api/health")
def health_check():

    return {
        "status": "healthy"
    }


# ==================================================
# SECURITY STATISTICS
# ==================================================

@app.get("/api/stats")
def get_stats():

    return {
        "total_attempts": get_total_attempts(),
        "successful_logins": get_successful_logins(),
        "failed_logins": get_failed_logins(),
        "unique_ips": get_unique_ips(),
        "success_rate": round(
            get_success_rate(),
            2
        ),
        "active_alerts": get_active_alerts(),
        "resolved_alerts": get_resolved_alerts()
    }


# ==================================================
# LOGIN EVENTS
# ==================================================

@app.get("/api/login-events")
def get_login_events():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            source_ip,
            timestamp,
            status
        FROM login_attempts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "events": [
            dict(row)
            for row in rows
        ]
    }


# ==================================================
# SECURITY ALERTS
# ==================================================

@app.get("/api/alerts")
def get_alerts():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            alert_type,
            source_ip,
            severity,
            status,
            attempt_count,
            risk_score,
            first_seen,
            last_seen,
            resolved_at
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return {
        "count": len(rows),
        "alerts": [
            dict(row)
            for row in rows
        ]
    }


# ==================================================
# IP INTELLIGENCE
# ==================================================

@app.get("/api/ip-intelligence")
def get_ip_intelligence():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,

            COUNT(*) AS total_attempts,

            SUM(
                CASE
                    WHEN status = 'FAILED'
                    THEN 1
                    ELSE 0
                END
            ) AS failed_attempts,

            SUM(
                CASE
                    WHEN status = 'SUCCESS'
                    THEN 1
                    ELSE 0
                END
            ) AS successful_attempts,

            COUNT(DISTINCT username)
                AS unique_usernames,

            MIN(timestamp)
                AS first_seen,

            MAX(timestamp)
                AS last_seen

        FROM login_attempts

        GROUP BY source_ip

        ORDER BY failed_attempts DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    results = []

    for row in rows:

        data = dict(row)

        total_attempts = data["total_attempts"]

        failed_attempts = data["failed_attempts"]

        if total_attempts > 0:

            failure_rate = (
                failed_attempts
                / total_attempts
            ) * 100

        else:

            failure_rate = 0

        data["failure_rate"] = round(
            failure_rate,
            2
        )

        results.append(data)

    return {
        "count": len(results),
        "sources": results
    }


# ==================================================
# APPLICATION START
# ==================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
