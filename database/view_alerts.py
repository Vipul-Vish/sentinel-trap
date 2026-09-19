import sqlite3

DATABASE = "database/sentinel_trap.db"


def show_alerts():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
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

    alerts = cursor.fetchall()

    connection.close()

    if not alerts:
        print("No security alerts found.")
        return

    print()
    print("=" * 110)
    print("                         SENTINELTRAP SECURITY ALERTS")
    print("=" * 110)

    for alert in alerts:
        (
            alert_id,
            source_ip,
            severity,
            status,
            attempt_count,
            risk_score,
            first_seen,
            last_seen,
            resolved_at
        ) = alert

        print()
        print(f"Alert ID        : {alert_id}")
        print(f"Source IP       : {source_ip}")
        print(f"Severity        : {severity}")
        print(f"Status          : {status}")
        print(f"Attempts        : {attempt_count}")
        print(f"Risk Score      : {risk_score}")
        print(f"First Seen      : {first_seen}")
        print(f"Last Seen       : {last_seen}")
        print(f"Resolved At     : {resolved_at}")
        print("-" * 110)


if __name__ == "__main__":
    show_alerts()
