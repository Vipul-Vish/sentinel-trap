from datetime import datetime

from database.database import save_login_attempt
from analyzer.detection_engine import detect_threats


# ==================================================
# DEMO CREDENTIALS
# ==================================================

VALID_USERNAME = "admin"
VALID_PASSWORD = "sentinel123"


# ==================================================
# HONEYPOT
# ==================================================

print("================================")
print("      SENTINELTRAP HONEYPOT")
print("================================")
print()

print("Fake SSH service started...")
print()


# ==================================================
# AUTHENTICATION INPUT
# ==================================================

username = input(
    "Username: "
)

password = input(
    "Password: "
)


# ==================================================
# EVENT INFORMATION
# ==================================================

source_ip = "127.0.0.1"

timestamp = (
    datetime.now().isoformat()
)


# ==================================================
# AUTHENTICATION CHECK
# ==================================================

if (
    username == VALID_USERNAME
    and password == VALID_PASSWORD
):

    status = "SUCCESS"

else:

    status = "FAILED"


# ==================================================
# SAVE LOGIN EVENT
# ==================================================

save_login_attempt(

    username,

    source_ip,

    timestamp,

    status
)


print()


# ==================================================
# AUTHENTICATION RESULT
# ==================================================

if status == "SUCCESS":

    print(
        "Authentication successful!"
    )

else:

    print(
        "Authentication failed!"
    )


print(
    f"Username   : {username}"
)

print(
    f"Source IP  : {source_ip}"
)

print(
    f"Timestamp   : {timestamp}"
)

print(
    f"Status     : {status}"
)

print(
    "Login event saved to database."
)


# ==================================================
# AUTOMATIC THREAT DETECTION
# ==================================================

if status == "FAILED":

    print()

    print(
        "Running threat detection..."
    )

    detect_threats()

    print()

    print(
        "Threat analysis completed."
    )
