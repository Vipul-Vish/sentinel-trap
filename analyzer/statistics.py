import sqlite3

DATABASE = "database/sentinel_trap.db"


def get_connection():
    return sqlite3.connect(DATABASE)


def get_total_attempts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_successful_logins():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'SUCCESS'
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_failed_logins():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE status = 'FAILED'
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_unique_ips():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip)
        FROM login_attempts
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_success_rate():
    total_attempts = get_total_attempts()
    successful_logins = get_successful_logins()

    if total_attempts == 0:
        return 0.0

    return (
        successful_logins / total_attempts
    ) * 100


def get_active_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE status = 'ACTIVE'
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_resolved_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE status = 'RESOLVED'
    """)

    result = cursor.fetchone()[0]

    connection.close()

    return result


def get_severity_counts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM alerts
        GROUP BY severity
        ORDER BY COUNT(*) DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


def show_statistics():
    total_attempts = get_total_attempts()
    successful_logins = get_successful_logins()
    failed_logins = get_failed_logins()
    unique_ips = get_unique_ips()
    success_rate = get_success_rate()
    active_alerts = get_active_alerts()
    resolved_alerts = get_resolved_alerts()
    severity_counts = get_severity_counts()

    print()
    print("=" * 60)
    print("              SENTINELTRAP SECURITY STATISTICS")
    print("=" * 60)

    print()
    print(f"Total Login Attempts : {total_attempts}")
    print(f"Successful Logins    : {successful_logins}")
    print(f"Failed Logins        : {failed_logins}")
    print(f"Unique Source IPs    : {unique_ips}")
    print(f"Success Rate         : {success_rate:.2f}%")
    print(f"Active Alerts        : {active_alerts}")
    print(f"Resolved Alerts      : {resolved_alerts}")

    print()
    print("Alert Severity Distribution")
    print("-" * 40)

    if severity_counts:
        for severity, count in severity_counts:
            print(f"{severity:<15}: {count}")
    else:
        print("No alerts found.")

    print("=" * 60)


if __name__ == "__main__":
    show_statistics()
