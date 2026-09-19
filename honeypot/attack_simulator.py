import time
from datetime import datetime

from database.database import save_login_attempt
from analyzer.detection_engine import detect_threats


# ==================================================
# SENTINELTRAP ATTACK SIMULATOR
# Controlled Local Security Testing
# ==================================================

SOURCE_IP = "127.0.0.1"


# ==================================================
# DISPLAY HEADER
# ==================================================

def show_header():

    print()
    print("=" * 60)
    print("           SENTINELTRAP ATTACK SIMULATOR")
    print("=" * 60)
    print()
    print("This is a controlled local simulation.")
    print("No real network attack is performed.")
    print()


# ==================================================
# CREATE FAILED LOGIN EVENT
# ==================================================

def generate_failed_attempt(
    username,
    delay=0.5
):

    timestamp = datetime.now().isoformat()

    save_login_attempt(
        username=username,
        source_ip=SOURCE_IP,
        timestamp=timestamp,
        status="FAILED"
    )

    print(
        f"[FAILED] "
        f"username={username:<15} "
        f"time={timestamp}"
    )

    time.sleep(delay)


# ==================================================
# CREATE SUCCESSFUL LOGIN EVENT
# ==================================================

def generate_successful_attempt():

    timestamp = datetime.now().isoformat()

    save_login_attempt(
        username="admin",
        source_ip=SOURCE_IP,
        timestamp=timestamp,
        status="SUCCESS"
    )

    print(
        f"[SUCCESS] "
        f"username={'admin':<15} "
        f"time={timestamp}"
    )


# ==================================================
# BRUTE FORCE SIMULATION
# ==================================================

def simulate_brute_force():

    print()
    print("-" * 60)
    print("BRUTE FORCE SIMULATION")
    print("-" * 60)

    usernames = [
        "admin",
        "root",
        "user",
        "test",
        "guest",
        "administrator",
        "ubuntu",
        "support",
        "developer",
        "backup",
        "oracle",
        "postgres",
        "service",
        "operator",
        "manager",
        "security",
        "dev",
        "demo",
        "server",
        "admin"
    ]

    for username in usernames:

        generate_failed_attempt(
            username=username,
            delay=0.3
        )

        # Analyze after every event
        detect_threats()

    print()
    print("Brute force simulation completed.")


# ==================================================
# FAST ATTACK SIMULATION
# ==================================================

def simulate_high_velocity():

    print()
    print("-" * 60)
    print("HIGH VELOCITY ATTACK SIMULATION")
    print("-" * 60)

    usernames = [
        "admin",
        "root",
        "test",
        "guest",
        "user",
        "support",
        "admin",
        "root",
        "test",
        "guest"
    ]

    for username in usernames:

        generate_failed_attempt(
            username=username,
            delay=0.05
        )

    print()
    print("Running threat detection...")

    detect_threats()

    print()
    print("High velocity simulation completed.")


# ==================================================
# NORMAL SUCCESSFUL LOGIN
# ==================================================

def simulate_success():

    print()
    print("-" * 60)
    print("SUCCESSFUL LOGIN SIMULATION")
    print("-" * 60)

    generate_successful_attempt()

    print()
    print("Successful login event created.")


# ==================================================
# MENU
# ==================================================

def show_menu():

    print()
    print("Choose simulation:")
    print()
    print("1. Brute Force Attack")
    print("2. High Velocity Attack")
    print("3. Successful Login")
    print("4. Exit")
    print()


# ==================================================
# MAIN
# ==================================================

def main():

    show_header()

    while True:

        show_menu()

        choice = input(
            "Enter choice: "
        ).strip()

        if choice == "1":

            simulate_brute_force()

        elif choice == "2":

            simulate_high_velocity()

        elif choice == "3":

            simulate_success()

        elif choice == "4":

            print()
            print(
                "Attack simulator stopped."
            )
            break

        else:

            print()
            print(
                "Invalid choice."
            )


if __name__ == "__main__":

    main()
