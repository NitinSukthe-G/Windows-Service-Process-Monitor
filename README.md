# Windows Service & Process Monitoring Agent

A defensive Windows endpoint monitoring project designed to detect suspicious process behavior, abnormal parent-child relationships, unauthorized processes, and potentially suspicious Windows services.

## Project Overview

The Windows Service & Process Monitoring Agent collects endpoint telemetry from a Windows system and analyzes it using rule-based security detections.

The project focuses on:

- Process enumeration
- Parent-child process relationship analysis
- Unauthorized process detection
- Suspicious executable path detection
- Windows service auditing
- Security alert generation
- CSV and JSON reporting
- Web-based security dashboard

## Objectives

The main objectives of this project are:

1. Monitor active Windows processes.
2. Collect PID, PPID, process name, executable path, username, and status.
3. Analyze parent-child process relationships.
4. Detect potentially suspicious process chains.
5. Audit Windows services and their executable paths.
6. Detect processes running from suspicious user-writable directories.
7. Generate severity-based security alerts.
8. Generate structured CSV and JSON reports.
9. Display detection results through a Streamlit dashboard.

## Architecture

```text
                    WINDOWS ENDPOINT
                           |
                           v
               +-----------------------+
               |   Monitoring Agent    |
               |      monitor.py       |
               +-----------+-----------+
                           |
            +--------------+--------------+
            |              |              |
            v              v              v
      Process Monitor  Process Tree  Service Monitor
            |              |              |
            v              v              v
      Process Rules  Relationship    Service Rules
                           Rules
            |              |              |
            +--------------+--------------+
                           |
                           v
                   Alert Management
                           |
             +-------------+-------------+
             |                           |
             v                           v
      CSV Reports                  JSON Reports
             |                           |
             +-------------+-------------+
                           |
                           v
                 Streamlit Dashboard
```

## Detection Capabilities

### 1. Process Monitoring

The agent collects:

- PID
- Parent PID
- Process name
- Executable path
- Username
- Process status
- Timestamp

### 2. Parent-Child Detection

The agent checks process relationships for suspicious combinations.

Examples of relationships that may require investigation:

```text
winword.exe -> powershell.exe
excel.exe   -> cmd.exe
outlook.exe -> powershell.exe
```

These relationships are treated as detection rules rather than automatic proof of malicious activity.

### 3. Unauthorized Process Detection

The project uses a configurable process allowlist.

Processes not present in the allowlist can be flagged for investigation.

### 4. Suspicious Path Detection

Processes and services running from potentially user-writable locations can receive additional risk scoring.

Examples:

```text
AppData\Local\Temp
AppData\Roaming
Temp
Users\Public
Downloads
```

### 5. Windows Service Auditing

The service monitor collects:

- Service name
- Display name
- State
- Startup mode
- Start account
- Executable path

The project checks service executable paths for potentially suspicious locations.

## Severity Model

The project uses rule-based severity classification.

| Severity | Meaning |
|---|---|
| LOW | Low-risk or informational event |
| MEDIUM | Unusual or unauthorized activity requiring investigation |
| HIGH | Multiple suspicious indicators or a higher-risk behavior |
| CRITICAL | Multiple high-confidence suspicious indicators |

The detections are designed as defensive investigation triggers and should not be interpreted as automatic malware confirmation.

## Project Structure

```text
Windows-Service-Process-Monitor/
│
├── agent/
│   ├── process_monitor.py
│   ├── export_processes.py
│   ├── detection_rules.py
│   ├── process_tree.py
│   ├── alert_report.py
│   ├── service_monitor.py
│   ├── export_services.py
│   ├── service_rules.py
│   ├── service_detection.py
│   ├── service_alert_report.py
│   ├── allowed_processes.py
│   ├── process_rules.py
│   ├── unauthorized_process.py
│   ├── unauthorized_report.py
│   ├── severity.py
│   ├── monitor.py
│   ├── alert_manager.py
│   ├── continuous_monitor.py
│   └── process_change_detector.py
│
├── dashboard/
│   └── app.py
│
├── reports/
│   ├── process_report.csv
│   ├── alerts.csv
│   ├── service_report.csv
│   ├── service_alerts.csv
│   ├── unauthorized_processes.csv
│   ├── monitoring_summary.json
│   └── alerts.json
│
├── screenshots/
├── docs/
├── requirements.txt
├── README.md
└── LICENSE
```

## Technologies Used

- Python
- psutil
- pandas
- Streamlit
- PowerShell / Windows Management Instrumentation
- CSV
- JSON
- Git
- GitHub

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Windows-Service-Process-Monitor.git
```

Enter the project directory:

```bash
cd Windows-Service-Process-Monitor
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment on Windows:

```bash
venv\Scripts\activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

## Running the Monitoring Agent

Run a single monitoring scan:

```bash
python agent\monitor.py
```

## Running Continuous Monitoring

Run:

```bash
python agent\continuous_monitor.py
```

The continuous monitor performs repeated scans.

Press `CTRL+C` to stop monitoring.

## Running the Dashboard

Start Streamlit:

```bash
streamlit run dashboard\app.py
```

Then open:

```text
http://localhost:8501
```

## Reports

The monitoring agent produces the following reports.

### Process Report

```text
reports/process_report.csv
```

Contains process telemetry collected from the Windows endpoint.

### Service Report

```text
reports/service_report.csv
```

Contains Windows service information.

### Alert Report

```text
reports/alerts.json
```

Contains consolidated security alerts.

### Monitoring Summary

```text
reports/monitoring_summary.json
```

Contains monitoring statistics and severity counts.

## Dashboard Features

The dashboard provides:

- Process count
- Service count
- Total security alerts
- Critical alerts
- High alerts
- Medium alerts
- Low alerts
- Alerts by severity
- Alerts by type
- Security alert table
- High-priority alert table
- Process inventory
- Windows service inventory
- Process search
- Service search
- Alert filtering

## Defensive Security Use Case

This project demonstrates endpoint visibility and rule-based detection techniques commonly used in defensive security environments.

It can help analysts investigate:

- Suspicious process execution
- Abnormal process lineage
- Possible persistence mechanisms
- Unauthorized applications
- Suspicious service configurations
- Processes running from unusual locations

## Limitations

This project is a learning and defensive monitoring implementation.

A detection alert does not automatically mean that a process or service is malicious.

A production endpoint detection and response platform would normally include additional telemetry and analysis such as:

- Digital signature verification
- File hashing
- Windows Event Log analysis
- PowerShell logging
- Network telemetry
- Persistence monitoring
- Threat intelligence enrichment
- Behavioral correlation
- Centralized log collection

## Future Improvements

Possible future improvements include:

- Real-time event monitoring
- Windows Event Log integration
- Digital signature validation
- SHA-256 file hashing
- YARA-based detection
- Threat intelligence integration
- Email or webhook notifications
- Authentication for the dashboard
- Centralized endpoint monitoring
- Database-backed alert storage
- Advanced behavioral scoring

## Learning Outcomes

This project provides practical experience with:

- Windows process architecture
- Parent-child process relationships
- Windows service architecture
- Endpoint monitoring
- Rule-based detection
- Security alert generation
- Python automation
- Security reporting
- Streamlit dashboards
- Git and GitHub

## Screenshots

Project screenshots will be added to:

```text
screenshots/
```

Planned screenshots:

```text
01-process-monitor.png
02-process-tree.png
03-service-audit.png
04-unauthorized-process.png
05-continuous-monitor.png
06-alert-report.png
07-dashboard.png
```

## Author

Developed as a cybersecurity internship project.

## Disclaimer

This project is intended for defensive security monitoring, learning, testing, and authorized environments only.
