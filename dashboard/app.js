const API_BASE_URL = "http://127.0.0.1:8000";

let loginActivityChart = null;
let threatSeverityChart = null;


/* =========================================================
   HELPERS
========================================================= */

function getElement(id) {
    return document.getElementById(id);
}


function escapeHTML(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


function formatTimestamp(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleString();
}


function updateLastUpdated() {

    const element = getElement("lastUpdated");

    if (!element) {
        return;
    }

    element.textContent =
        new Date().toLocaleTimeString();
}


function updateAPIStatus(connected) {

    const element = getElement("apiStatus");

    if (!element) {
        return;
    }

    if (connected) {

        element.innerHTML = `
            <span class="status-dot"></span>
            API Connected
        `;

    } else {

        element.innerHTML = `
            <span
                class="status-dot"
                style="
                    background:#e05b62;
                    box-shadow:0 0 8px rgba(224,91,98,.6);
                "
            ></span>
            API Offline
        `;
    }
}


async function fetchJSON(endpoint) {

    const response = await fetch(
        `${API_BASE_URL}${endpoint}`
    );

    if (!response.ok) {

        throw new Error(
            `HTTP ${response.status}`
        );
    }

    return await response.json();
}


/* =========================================================
   STATISTICS
========================================================= */

async function loadStats() {

    const data = await fetchJSON(
        "/api/stats"
    );

    getElement("totalAttempts").textContent =
        data.total_attempts ?? 0;

    getElement("failedLogins").textContent =
        data.failed_logins ?? 0;

    getElement("successfulLogins").textContent =
        data.successful_logins ?? 0;

    getElement("activeAlerts").textContent =
        data.active_alerts ?? 0;
}


/* =========================================================
   LOGIN EVENTS
========================================================= */

async function loadLoginEvents() {

    const data = await fetchJSON(
        "/api/login-events"
    );

    const table =
        getElement("loginEventsTable");

    if (
        !data.events ||
        data.events.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="5">
                    No login events found.
                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML =
        data.events
            .slice(0, 25)
            .map(event => {

                const statusClass =
                    event.status === "SUCCESS"
                        ? "status-success"
                        : "status-failed";


                return `
                    <tr>

                        <td>
                            ${escapeHTML(event.id)}
                        </td>

                        <td>
                            ${escapeHTML(event.username)}
                        </td>

                        <td class="ip-address">
                            ${escapeHTML(event.source_ip)}
                        </td>

                        <td>
                            ${escapeHTML(
                                formatTimestamp(
                                    event.timestamp
                                )
                            )}
                        </td>

                        <td class="${statusClass}">
                            ${escapeHTML(event.status)}
                        </td>

                    </tr>
                `;

            })
            .join("");
}


/* =========================================================
   SECURITY ALERTS
========================================================= */

async function loadAlerts() {

    const data = await fetchJSON(
        "/api/alerts"
    );

    const container =
        getElement("alertsContainer");


    if (
        !data.alerts ||
        data.alerts.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No security alerts detected.
            </div>
        `;

        return;
    }


    container.innerHTML =
        data.alerts
            .slice(0, 20)
            .map(alert => {

                const severity =
                    String(
                        alert.severity || "LOW"
                    ).toLowerCase();


                const statusClass =
                    alert.status === "ACTIVE"
                        ? "alert-active"
                        : "alert-resolved";


                return `
                    <div
                        class="alert-card ${severity}"
                    >

                        <div class="alert-top">

                            <div class="alert-title">
                                ${escapeHTML(
                                    alert.alert_type
                                )}
                            </div>

                            <div class="alert-severity">
                                ${escapeHTML(
                                    alert.severity
                                )}
                            </div>

                        </div>


                        <div class="alert-details">

                            <div class="alert-detail">

                                <span>
                                    Source IP
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        alert.source_ip
                                    )}
                                </strong>

                            </div>


                            <div class="alert-detail">

                                <span>
                                    Attempts
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        alert.attempt_count
                                    )}
                                </strong>

                            </div>


                            <div class="alert-detail">

                                <span>
                                    Risk Score
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        alert.risk_score
                                    )}
                                </strong>

                            </div>


                            <div class="alert-detail">

                                <span>
                                    Status
                                </span>

                                <strong
                                    class="${statusClass}"
                                >
                                    ${escapeHTML(
                                        alert.status
                                    )}
                                </strong>

                            </div>


                            <div class="alert-detail">

                                <span>
                                    Last Seen
                                </span>

                                <strong>
                                    ${escapeHTML(
                                        formatTimestamp(
                                            alert.last_seen
                                        )
                                    )}
                                </strong>

                            </div>

                        </div>

                    </div>
                `;

            })
            .join("");
}


/* =========================================================
   IP INTELLIGENCE
========================================================= */

async function loadIPIntelligence() {

    const data = await fetchJSON(
        "/api/ip-intelligence"
    );

    const table =
        getElement("ipIntelligenceTable");


    if (
        !data.sources ||
        data.sources.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="6">
                    No IP intelligence available.
                </td>
            </tr>
        `;

        return;
    }


    table.innerHTML =
        data.sources
            .map(source => {

                return `
                    <tr>

                        <td class="ip-address">
                            ${escapeHTML(
                                source.source_ip
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                source.total_attempts
                            )}
                        </td>

                        <td class="status-failed">
                            ${escapeHTML(
                                source.failed_attempts
                            )}
                        </td>

                        <td class="status-success">
                            ${escapeHTML(
                                source.successful_attempts
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                source.unique_usernames
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                source.failure_rate
                            )}%
                        </td>

                    </tr>
                `;

            })
            .join("");
}


/* =========================================================
   LOGIN ACTIVITY CHART
========================================================= */

async function loadLoginActivityChart() {

    const data = await fetchJSON(
        "/api/login-events"
    );


    const events =
        [...(data.events || [])]
            .reverse()
            .slice(-20);


    const labels =
        events.map((event, index) => {

            const date =
                new Date(event.timestamp);


            if (Number.isNaN(date.getTime())) {
                return index + 1;
            }


            return date.toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            );

        });


    const failedData =
        events.map(event =>
            event.status === "FAILED"
                ? 1
                : 0
        );


    const successData =
        events.map(event =>
            event.status === "SUCCESS"
                ? 1
                : 0
        );


    const canvas =
        getElement("loginActivityChart");


    if (!canvas) {
        return;
    }


    if (loginActivityChart) {
        loginActivityChart.destroy();
    }


    loginActivityChart =
        new Chart(canvas, {

            type: "line",

            data: {

                labels: labels,

                datasets: [

                    /* FAILED = RED */

                    {
                        label: "Failed",

                        data: failedData,

                        tension: 0.35,

                        borderWidth: 2,

                        pointRadius: 3,

                        borderColor: "#e05b62",

                        backgroundColor:
                            "rgba(224, 91, 98, 0.15)",

                        pointBackgroundColor:
                            "#e05b62",

                        pointBorderColor:
                            "#e05b62"
                    },


                    /* SUCCESSFUL = GREEN */

                    {
                        label: "Successful",

                        data: successData,

                        tension: 0.35,

                        borderWidth: 2,

                        pointRadius: 3,

                        borderColor: "#31d17c",

                        backgroundColor:
                            "rgba(49, 209, 124, 0.15)",

                        pointBackgroundColor:
                            "#31d17c",

                        pointBorderColor:
                            "#31d17c"
                    }

                ]

            },


            options: {

                responsive: true,

                maintainAspectRatio: false,


                plugins: {

                    legend: {

                        labels: {

                            color: "#9aa7b5"

                        }

                    }

                },


                scales: {

                    x: {

                        ticks: {

                            color: "#687583"

                        },

                        grid: {

                            color:
                                "rgba(255,255,255,0.04)"

                        }

                    },


                    y: {

                        beginAtZero: true,

                        ticks: {

                            color: "#687583",

                            stepSize: 1

                        },

                        grid: {

                            color:
                                "rgba(255,255,255,0.04)"

                        }

                    }

                }

            }

        });
}


/* =========================================================
   THREAT SEVERITY CHART
========================================================= */

async function loadThreatSeverityChart() {

    const data = await fetchJSON(
        "/api/alerts"
    );


    const counts = {

        LOW: 0,

        MEDIUM: 0,

        HIGH: 0,

        CRITICAL: 0

    };


    (data.alerts || [])
        .forEach(alert => {

            const severity =
                String(
                    alert.severity || ""
                ).toUpperCase();


            if (
                Object.prototype.hasOwnProperty
                    .call(counts, severity)
            ) {

                counts[severity]++;

            }

        });


    const canvas =
        getElement("threatSeverityChart");


    if (!canvas) {
        return;
    }


    if (threatSeverityChart) {
        threatSeverityChart.destroy();
    }


    threatSeverityChart =
        new Chart(canvas, {

            type: "doughnut",


            data: {

                labels: [

                    "Low",

                    "Medium",

                    "High",

                    "Critical"

                ],


                datasets: [

                    {

                        data: [

                            counts.LOW,

                            counts.MEDIUM,

                            counts.HIGH,

                            counts.CRITICAL

                        ],


                        /*

                        LOW      = GREEN
                        MEDIUM   = YELLOW
                        HIGH     = ORANGE
                        CRITICAL = RED

                        */

                        backgroundColor: [

                            "#31d17c",

                            "#d5aa5f",

                            "#e18a55",

                            "#e05b62"

                        ],


                        borderColor: "#11171f",

                        borderWidth: 2

                    }

                ]

            },


            options: {

                responsive: true,

                maintainAspectRatio: false,

                cutout: "65%",


                plugins: {

                    legend: {

                        position: "bottom",

                        labels: {

                            color: "#9aa7b5",

                            padding: 18

                        }

                    }

                }

            }

        });
}


/* =========================================================
   LOAD COMPLETE DASHBOARD
========================================================= */

async function loadDashboard() {

    try {

        await Promise.all([

            loadStats(),

            loadLoginEvents(),

            loadAlerts(),

            loadIPIntelligence(),

            loadLoginActivityChart(),

            loadThreatSeverityChart()

        ]);


        updateAPIStatus(true);

        updateLastUpdated();


    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

        updateAPIStatus(false);

    }
}


/* =========================================================
   NAVIGATION
========================================================= */

document
    .querySelectorAll(".nav-item")
    .forEach(item => {

        item.addEventListener(
            "click",
            () => {

                document
                    .querySelectorAll(".nav-item")
                    .forEach(nav => {

                        nav.classList.remove(
                            "active"
                        );

                    });


                item.classList.add(
                    "active"
                );

            }
        );

    });


/* =========================================================
   INITIAL LOAD
========================================================= */

loadDashboard();


/* =========================================================
   AUTO REFRESH
========================================================= */

setInterval(
    loadDashboard,
    5000
);
