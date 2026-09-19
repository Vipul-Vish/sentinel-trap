import sqlite3

DATABASE = "database/sentinel_trap.db"


def show_login_attempts():
    connection = sqlite3.connect(DATABASE)
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

    attempts = cursor.fetchall()

    connection.close()

    if not attempts:
        print("No login events found.")
        return

    print()
    print("=" * 100)
    print("                 SENTINELTRAP LOGIN EVENTS")
    print("=" * 100)

    for attempt in attempts:
        (
            attempt_id,
            username,
            source_ip,
            timestamp,
            status
        ) = attempt

        print()
        print(f"ID          : {attempt_id}")
        print(f"Username    : {username}")
        print(f"Source IP   : {source_ip}")
        print(f"Timestamp   : {timestamp}")
        print(f"Status      : {status}")
        print("-" * 100)


if __name__ == "__main__":
    show_login_attempts()
