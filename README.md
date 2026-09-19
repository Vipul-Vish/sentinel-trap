# 🛡️ SentinelTrap

## Linux-Based Cybersecurity Honeypot & Threat Monitoring System

SentinelTrap is a controlled local cybersecurity simulation that mimics an SSH authentication service, records login activity, analyzes suspicious behavior, calculates risk scores, generates security alerts, and visualizes security events through a SOC-style web dashboard.

The project demonstrates an end-to-end security monitoring pipeline built with Python, SQLite, FastAPI, JavaScript, HTML, CSS, and Chart.js.

> **Safety Note:** SentinelTrap is designed for controlled local experimentation and portfolio demonstration. It does not operate as a public internet-facing SSH honeypot.

---

## 🎯 Project Objective

The main objective of SentinelTrap is to demonstrate how a security monitoring system can:

- Capture authentication events
- Store security events in a database
- Detect repeated failed login activity
- Analyze suspicious behavior
- Calculate a risk score
- Generate security alerts
- Track source IP activity
- Expose monitoring data through REST APIs
- Visualize security events through a SOC-style dashboard

---

# 🏗️ System Architecture

```text
┌──────────────────────────────┐
│     Fake SSH Honeypot        │
│                              │
│  Username + Password Input   │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       SQLite Database        │
│                              │
│  Login Events                │
│  Security Alerts             │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│     Threat Detection Engine  │
│                              │
│  Frequency Analysis          │
│  Username Diversity          │
│  Attack Velocity             │
│  Risk Scoring                │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│          FastAPI             │
│        REST API Layer        │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│       SOC Dashboard          │
│                              │
│  Charts                      │
│  Login Events                │
│  Security Alerts             │
│  IP Intelligence             │
└──────────────────────────────┘

🚀 Key Features
1. Fake SSH Honeypot

SentinelTrap includes a simulated SSH authentication service.

The service accepts:

Username
Password

Each authentication attempt is classified as:

SUCCESS
FAILED

The event is then stored in the SQLite database.

The simulated service uses:

127.0.0.1

as the source IP for the controlled local environment.

2. Login Event Tracking

Every authentication attempt is recorded with:

Event ID
Username
Source IP
Timestamp
Authentication status

Example:

Username   : test
Source IP  : 127.0.0.1
Timestamp  : 2026-09-19T10:40:13
Status     : FAILED
🔍 Threat Detection Engine

The detection engine analyzes recent failed authentication activity.

Events are grouped by source IP and evaluated using multiple behavioral signals.

Detection Signals

The system considers:

Failed login frequency
Username diversity
Attack velocity

These signals are combined to produce a risk score.

📈 Frequency Analysis

Repeated failed authentication attempts increase the frequency score.

Example thresholds used by the detection engine:

3+ attempts   → frequency signal
5+ attempts   → alert threshold
10+ attempts  → stronger frequency signal
20+ attempts  → critical frequency signal
👤 Username Diversity

Multiple usernames from the same source can indicate automated login activity.

Example:

admin
root
test
guest
ubuntu
support
developer
oracle
postgres

A higher number of unique usernames contributes to the overall risk score.

⚡ Attack Velocity

The detection engine also considers how quickly failed login attempts occur.

For example:

10 failed attempts in a few seconds

represents a higher-velocity pattern than:

10 failed attempts spread across a long period

Higher velocity contributes additional risk points.

📊 Risk Scoring

The overall risk score is calculated using multiple behavioral signals:

Risk Score =
    Frequency Score
  + Username Diversity Score
  + Velocity Score

The resulting score is mapped to a severity level:

LOW
MEDIUM
HIGH
CRITICAL

The alert threshold and scoring rules are implemented in:

analyzer/detection_engine.py
🚨 Security Alert Lifecycle

SentinelTrap maintains the state of generated security alerts.

Alerts can have the following states:

ACTIVE
RESOLVED

When suspicious activity reaches the configured threshold:

Login Events
     ↓
Threat Detection
     ↓
Risk Calculation
     ↓
Security Alert
     ↓
ACTIVE

When the suspicious activity is no longer detected during analysis:

ACTIVE
   ↓
No longer detected
   ↓
RESOLVED

This provides a basic alert lifecycle instead of creating an independent alert for every failed login.

🌐 FastAPI REST API

SentinelTrap exposes monitoring information through FastAPI.

Root Endpoint
GET /

Returns basic project and API information.

Health Check
GET /api/health

Returns the API health status.

Security Statistics
GET /api/stats

Provides:

Total login attempts
Successful logins
Failed logins
Unique source IPs
Success rate
Active alerts
Resolved alerts
Login Events
GET /api/login-events

Returns captured authentication events.

Security Alerts
GET /api/alerts

Returns generated security alerts including:

Alert type
Source IP
Severity
Status
Attempt count
Risk score
First seen
Last seen
Resolved time
IP Intelligence
GET /api/ip-intelligence

Provides source-IP-based activity analysis including:

Total attempts
Failed attempts
Successful attempts
Unique usernames
Failure rate
First seen
Last seen
📊 SOC Dashboard

SentinelTrap includes a dark SOC-style monitoring dashboard.

The dashboard provides:

Security Overview
Total Login Attempts
Failed Logins
Successful Logins
Active Alerts
Visualizations
Login Activity Chart
Threat Severity Chart
Monitoring Tables
Recent Login Activity
Security Alerts
IP Intelligence

The dashboard communicates with the FastAPI backend and automatically refreshes monitoring data.

⚔️ Attack Simulator

SentinelTrap includes a controlled local attack simulator for testing the detection engine.

Available simulations:

1. Brute Force Attack
2. High Velocity Attack
3. Successful Login
4. Exit

The simulator generates synthetic authentication events.

It does not perform a real network attack.

Example workflow:

Attack Simulator
       ↓
Failed Login Events
       ↓
SQLite
       ↓
Detection Engine
       ↓
Risk Score
       ↓
Security Alert
       ↓
FastAPI
       ↓
Dashboard
🛠️ Technology Stack
Technology	Purpose
Python	Core application logic
SQLite	Event and alert storage
FastAPI	REST API
Uvicorn	API server
HTML	Dashboard structure
CSS	Dashboard styling
JavaScript	Dashboard functionality
Chart.js	Data visualization
Linux / WSL2	Development environment


📁 Project Structure

sentinel-trap/
│
├── analyzer/
│   ├── detection_engine.py
│   ├── statistics.py
│   └── ip_intelligence.py
│
├── api/
│   ├── __init__.py
│   └── main.py
│
├── database/
│   ├── __init__.py
│   ├── database.py
│   ├── view_alerts.py
│   └── view_login_attempts.py
│
├── dashboard/
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── honeypot/
│   ├── __init__.py
│   ├── fake_ssh.py
│   └── attack_simulator.py
│
├── .gitignore
├── requirements.txt
└── README.md


The SQLite database is generated locally at runtime:

database/sentinel_trap.db

The database is excluded from version control through .gitignore.

⚙️ Installation
1. Clone the repository
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd sentinel-trap
2. Create a virtual environment
python3 -m venv .venv

Activate it:

source .venv/bin/activate
3. Install dependencies
pip install -r requirements.txt
▶️ Running the Project

SentinelTrap uses separate processes for the API and dashboard.

Start the API

From the project root:

python -m api.main

The API runs at:

http://127.0.0.1:8000
Start the Dashboard

Open another terminal:

cd ~/sentinel-trap
source .venv/bin/activate
python -m http.server 5500 --directory dashboard

Open the dashboard:

http://127.0.0.1:5500
🧪 Test the Honeypot

Run:

python -m honeypot.fake_ssh

Enter a username and password.

Example:

Username: test
Password: 12345

A failed authentication event will be stored in the database.

⚔️ Run the Attack Simulator

Run:

python -m honeypot.attack_simulator

Select:

1

to run the brute-force simulation.

The detection pipeline will process the generated events.

🔎 Useful Commands
View Login Events
python -m database.view_login_attempts
View Security Alerts
python -m database.view_alerts
View Security Statistics
python -m analyzer.statistics
View IP Intelligence
python -m analyzer.ip_intelligence
🔐 Security & Safety

SentinelTrap is intentionally implemented as a controlled local simulation.

It does not provide a public internet-facing SSH honeypot.

The simulated source IP is:

127.0.0.1

The attack simulator generates synthetic events locally for testing the detection pipeline.

Do not expose this simulated service to the public internet without appropriate isolation, network controls, monitoring, and security hardening.

🧠 What This Project Demonstrates

This project demonstrates practical experience with:

Python application development
Linux-based development
SQL and SQLite
Database design
REST API development
FastAPI
Authentication event logging
Security monitoring concepts
Behavioral threat detection
Risk scoring
Alert lifecycle management
Data visualization
Dashboard development
API-to-frontend integration
Modular project architecture
Controlled security simulation
🔮 Future Improvements

Potential future improvements include:

Multiple simulated source IPs
GeoIP enrichment
More detailed attack-pattern classification
Real log ingestion
Machine-learning-based anomaly detection
Background detection workers
WebSocket-based live monitoring
API authentication
Docker deployment
Automated security testing
Advanced security event correlation
⚠️ Disclaimer

SentinelTrap is an educational cybersecurity project designed for controlled local experimentation, learning, and portfolio demonstration.

It should only be used in environments where you have authorization to perform security testing.

👨‍💻 Project Summary

SentinelTrap — Linux-Based Cybersecurity Honeypot & Threat Monitoring System

Built using:

Python
SQLite
FastAPI
JavaScript
HTML
CSS
Chart.js
Linux

The project demonstrates an end-to-end security monitoring workflow:

Capture
   ↓
Store
   ↓
Analyze
   ↓
Score
   ↓
Alert
   ↓
Expose through API
   ↓
Visualize

