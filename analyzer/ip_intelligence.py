import sqlite3

DATABASE = "database/sentinel_trap.db"


def analyze_ips():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            COUNT(*) AS total_attempts,
            SUM(
                CASE
                    WHEN status = 'FAILED' THEN 1
                    ELSE 0
                END
            ) AS failed_attempts,
            SUM(
                CASE
                    WHEN status = 'SUCCESS' THEN 1
                    ELSE 0
                END
            ) AS successful_attempts,
            COUNT(DISTINCT username) AS unique_usernames,
            MIN(timestamp) AS first_seen,
            MAX(timestamp) AS last_seen
        FROM login_attempts
        GROUP BY source_ip
        ORDER BY failed_attempts DESC
    """)

    results = cursor.fetchall()

    connection.close()

    return results


def show_ip_intelligence():
    results = analyze_ips()

    if not results:
        print("No login activity found.")
        return

    print()
    print("=" * 100)
    print("                 SENTINELTRAP IP INTELLIGENCE")
    print("=" * 100)

    for result in results:
        (
            source_ip,
            total_attempts,
            failed_attempts,
            successful_attempts,
            unique_usernames,
            first_seen,
            last_seen
        ) = result

        if total_attempts > 0:
            failure_rate = (
                failed_attempts / total_attempts
            ) * 100
        else:
            failure_rate = 0

        print()
        print(f"Source IP          : {source_ip}")
        print(f"Total Attempts     : {total_attempts}")
        print(f"Failed Attempts    : {failed_attempts}")
        print(f"Successful Logins  : {successful_attempts}")
        print(f"Unique Usernames   : {unique_usernames}")
        print(f"Failure Rate       : {failure_rate:.2f}%")
        print(f"First Seen         : {first_seen}")
        print(f"Last Seen          : {last_seen}")
        print("-" * 100)


if __name__ == "__main__":
    show_ip_intelligence()
