import sqlite3
from datetime import datetime, timedelta

from database.database import save_alert


DATABASE = "database/sentinel_trap.db"

ANALYSIS_WINDOW_SECONDS = 300

ALERT_THRESHOLD = 5

RISK_MEDIUM = 30
RISK_HIGH = 60
RISK_CRITICAL = 85


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_connection():
    return sqlite3.connect(DATABASE)


# ==================================================
# GET RECENT FAILED ATTEMPTS
# ==================================================

def get_recent_attempts():

    connection = get_connection()
    cursor = connection.cursor()

    cutoff_time = (
        datetime.now()
        - timedelta(
            seconds=ANALYSIS_WINDOW_SECONDS
        )
    ).isoformat()

    cursor.execute("""
        SELECT
            username,
            source_ip,
            timestamp,
            status
        FROM login_attempts
        WHERE status = 'FAILED'
        AND timestamp >= ?
        ORDER BY timestamp ASC
    """, (cutoff_time,))

    results = cursor.fetchall()

    connection.close()

    return results


# ==================================================
# FREQUENCY SCORE
# ==================================================

def calculate_frequency_score(
    attempt_count
):

    if attempt_count >= 20:
        return 40

    if attempt_count >= 10:
        return 30

    if attempt_count >= 5:
        return 20

    if attempt_count >= 3:
        return 10

    return 0


# ==================================================
# USERNAME DIVERSITY SCORE
# ==================================================

def calculate_username_score(
    usernames
):

    unique_usernames = len(
        set(usernames)
    )

    if unique_usernames >= 10:
        return 30

    if unique_usernames >= 5:
        return 20

    if unique_usernames >= 3:
        return 10

    return 0


# ==================================================
# VELOCITY SCORE
# ==================================================

def calculate_velocity_score(
    timestamps
):

    if len(timestamps) < 3:
        return 0

    parsed_times = [
        datetime.fromisoformat(timestamp)
        for timestamp in timestamps
    ]

    total_seconds = (
        parsed_times[-1]
        - parsed_times[0]
    ).total_seconds()

    if total_seconds <= 5:
        return 30

    if total_seconds <= 15:
        return 20

    if total_seconds <= 30:
        return 10

    return 0


# ==================================================
# RISK LEVEL
# ==================================================

def calculate_risk_level(
    score,
    attempt_count
):

    if score >= RISK_CRITICAL:
        return "CRITICAL"

    if score >= RISK_HIGH:
        return "HIGH"

    if (
        score >= RISK_MEDIUM
        or attempt_count >= ALERT_THRESHOLD
    ):
        return "MEDIUM"

    return "LOW"


# ==================================================
# ANALYZE SOURCE IP
# ==================================================

def analyze_source_ip(
    source_ip,
    attempts
):

    usernames = [
        attempt[0]
        for attempt in attempts
    ]

    timestamps = [
        attempt[2]
        for attempt in attempts
    ]

    attempt_count = len(attempts)

    frequency_score = (
        calculate_frequency_score(
            attempt_count
        )
    )

    username_score = (
        calculate_username_score(
            usernames
        )
    )

    velocity_score = (
        calculate_velocity_score(
            timestamps
        )
    )

    risk_score = (
        frequency_score
        + username_score
        + velocity_score
    )

    risk_level = calculate_risk_level(
        risk_score,
        attempt_count
    )

    return {
        "source_ip": source_ip,
        "attempt_count": attempt_count,
        "unique_usernames":
            len(set(usernames)),
        "frequency_score":
            frequency_score,
        "username_score":
            username_score,
        "velocity_score":
            velocity_score,
        "risk_score":
            risk_score,
        "risk_level":
            risk_level,
        "first_seen":
            timestamps[0],
        "last_seen":
            timestamps[-1]
    }


# ==================================================
# GET ACTIVE ALERT
# ==================================================

def get_active_alert(
    source_ip
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            severity,
            status,
            attempt_count,
            risk_score,
            first_seen,
            last_seen
        FROM alerts
        WHERE source_ip = ?
        AND status = 'ACTIVE'
        ORDER BY id DESC
        LIMIT 1
    """, (source_ip,))

    result = cursor.fetchone()

    connection.close()

    return result


# ==================================================
# UPDATE ACTIVE ALERT
# ==================================================

def update_active_alert(
    alert_id,
    severity,
    attempt_count,
    risk_score,
    last_seen
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE alerts
        SET
            severity = ?,
            attempt_count = ?,
            risk_score = ?,
            last_seen = ?
        WHERE id = ?
        AND status = 'ACTIVE'
    """, (
        severity,
        attempt_count,
        risk_score,
        last_seen,
        alert_id
    ))

    connection.commit()
    connection.close()


# ==================================================
# CREATE OR UPDATE ALERT
# ==================================================

def create_or_update_alert(
    result
):

    source_ip = result[
        "source_ip"
    ]

    active_alert = get_active_alert(
        source_ip
    )

    if active_alert:

        alert_id = active_alert[0]

        update_active_alert(
            alert_id=alert_id,
            severity=result[
                "risk_level"
            ],
            attempt_count=result[
                "attempt_count"
            ],
            risk_score=result[
                "risk_score"
            ],
            last_seen=result[
                "last_seen"
            ]
        )

        print(
            f"Existing alert updated "
            f"for {source_ip}"
        )

        return


    save_alert(
        alert_type=
            "SUSPICIOUS_LOGIN_ACTIVITY",

        source_ip=
            source_ip,

        severity=
            result["risk_level"],

        status=
            "ACTIVE",

        attempt_count=
            result["attempt_count"],

        risk_score=
            result["risk_score"],

        first_seen=
            result["first_seen"],

        last_seen=
            result["last_seen"]
    )

    print()

    print(
        f"🚨 New "
        f"{result['risk_level']} "
        f"alert created for "
        f"{source_ip}"
    )


# ==================================================
# RESOLVE INACTIVE ALERTS
# ==================================================

def resolve_inactive_alerts(
    active_source_ips
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            source_ip
        FROM alerts
        WHERE status = 'ACTIVE'
    """)

    active_alerts = cursor.fetchall()

    for alert_id, source_ip in active_alerts:

        if source_ip in active_source_ips:
            continue

        resolved_at = (
            datetime.now().isoformat()
        )

        cursor.execute("""
            UPDATE alerts
            SET
                status = 'RESOLVED',
                resolved_at = ?
            WHERE id = ?
            AND status = 'ACTIVE'
        """, (
            resolved_at,
            alert_id
        ))

        print()

        print(
            f"✅ Alert resolved for "
            f"IP: {source_ip}"
        )

    connection.commit()
    connection.close()


# ==================================================
# DETECT THREATS
# ==================================================

def detect_threats():

    attempts = get_recent_attempts()

    if not attempts:

        print(
            "No recent failed "
            "login attempts."
        )

        resolve_inactive_alerts(
            set()
        )

        return


    attempts_by_ip = {}


    for attempt in attempts:

        source_ip = attempt[1]

        if source_ip not in attempts_by_ip:

            attempts_by_ip[
                source_ip
            ] = []

        attempts_by_ip[
            source_ip
        ].append(attempt)


    active_source_ips = set()


    for (
        source_ip,
        ip_attempts
    ) in attempts_by_ip.items():

        result = analyze_source_ip(
            source_ip,
            ip_attempts
        )

        attempt_count = result[
            "attempt_count"
        ]


        print()

        print("=" * 60)

        print(
            f"IP Address       : "
            f"{result['source_ip']}"
        )

        print(
            f"Failed Attempts  : "
            f"{result['attempt_count']}"
        )

        print(
            f"Unique Usernames : "
            f"{result['unique_usernames']}"
        )

        print(
            f"Frequency Score  : "
            f"{result['frequency_score']}"
        )

        print(
            f"Username Score   : "
            f"{result['username_score']}"
        )

        print(
            f"Velocity Score   : "
            f"{result['velocity_score']}"
        )

        print(
            f"Risk Score       : "
            f"{result['risk_score']}"
        )

        print(
            f"Risk Level       : "
            f"{result['risk_level']}"
        )

        print("=" * 60)


        if attempt_count >= ALERT_THRESHOLD:

            active_source_ips.add(
                source_ip
            )

            create_or_update_alert(
                result
            )


    resolve_inactive_alerts(
        active_source_ips
    )


# ==================================================
# DIRECT EXECUTION
# ==================================================

if __name__ == "__main__":

    detect_threats()
