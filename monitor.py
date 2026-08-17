import os
import sys
import json
import csv
from datetime import datetime

# Allow imports from the agent directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from process_monitor import get_process_details
from process_tree import get_process_tree, analyze_process_relationships
from service_monitor import get_windows_services
from service_detection import analyze_services
from unauthorized_process import analyze_processes
from alert_manager import save_all_alerts


REPORT_DIR = "reports"


def ensure_report_directory():
    os.makedirs(REPORT_DIR, exist_ok=True)


def save_process_report(processes):
    output_file = os.path.join(
        REPORT_DIR,
        "process_report.csv"
    )

    fieldnames = [
        "timestamp",
        "pid",
        "ppid",
        "name",
        "path",
        "username",
        "status",
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(processes)

    return output_file


def save_service_report(services):
    output_file = os.path.join(
        REPORT_DIR,
        "service_report.csv"
    )

    fieldnames = [
        "timestamp",
        "name",
        "display_name",
        "state",
        "start_mode",
        "start_name",
        "path",
    ]

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(services)

    return output_file


def generate_summary(
    processes,
    process_alerts,
    service_alerts,
    unauthorized_alerts,
    services,
):
    critical_alerts = 0
    high_alerts = 0
    medium_alerts = 0
    low_alerts = 0

    all_alerts = (
        process_alerts
        + service_alerts
        + unauthorized_alerts
    )

    for alert in all_alerts:

        severity = (
            alert.get("severity", "LOW")
            .upper()
        )

        if severity == "CRITICAL":
            critical_alerts += 1

        elif severity == "HIGH":
            high_alerts += 1

        elif severity == "MEDIUM":
            medium_alerts += 1

        else:
            low_alerts += 1

    return {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "processes_detected": len(
            processes
        ),

        "services_detected": len(
            services
        ),

        "process_relationship_alerts": len(
            process_alerts
        ),

        "service_alerts": len(
            service_alerts
        ),

        "unauthorized_process_alerts": len(
            unauthorized_alerts
        ),

        "total_alerts": len(
            all_alerts
        ),

        "critical_alerts": critical_alerts,

        "high_alerts": high_alerts,

        "medium_alerts": medium_alerts,

        "low_alerts": low_alerts,
    }


def save_json_report(summary):
    output_file = os.path.join(
        REPORT_DIR,
        "monitoring_summary.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            indent=4
        )

    return output_file


def print_banner():

    print("\n" + "=" * 100)
    print(
        "WINDOWS SERVICE & PROCESS MONITORING AGENT"
    )
    print("=" * 100)


def print_summary(summary):

    print("\n" + "=" * 100)
    print("MONITORING SUMMARY")
    print("=" * 100)

    print(
        "Timestamp                    :",
        summary["timestamp"]
    )

    print(
        "Processes detected           :",
        summary["processes_detected"]
    )

    print(
        "Services detected            :",
        summary["services_detected"]
    )

    print(
        "Process relationship alerts  :",
        summary[
            "process_relationship_alerts"
        ]
    )

    print(
        "Service alerts               :",
        summary[
            "service_alerts"
        ]
    )

    print(
        "Unauthorized process alerts  :",
        summary[
            "unauthorized_process_alerts"
        ]
    )

    print(
        "Total alerts                 :",
        summary["total_alerts"]
    )

    print(
        "Critical alerts              :",
        summary["critical_alerts"]
    )

    print(
        "High severity alerts         :",
        summary["high_alerts"]
    )

    print(
        "Medium severity alerts       :",
        summary["medium_alerts"]
    )

    print(
        "Low severity alerts          :",
        summary["low_alerts"]
    )


def main():

    print_banner()

    ensure_report_directory()

    # -------------------------------------------------------
    # 1. Collect processes
    # -------------------------------------------------------

    print(
        "\n[1/4] Collecting Windows processes..."
    )

    processes = get_process_details()

    process_report = save_process_report(
        processes
    )

    print(
        f"      {len(processes)} processes collected."
    )

    print(
        f"      Process report saved to: "
        f"{process_report}"
    )

    # -------------------------------------------------------
    # 2. Analyze process relationships
    # -------------------------------------------------------

    print(
        "\n[2/4] Analyzing parent-child relationships..."
    )

    process_tree = get_process_tree()

    process_relationship_alerts = (
        analyze_process_relationships(
            process_tree
        )
    )

    print(
        f"      {len(process_relationship_alerts)} "
        "parent-child alerts detected."
    )

    # -------------------------------------------------------
    # 3. Audit Windows services
    # -------------------------------------------------------

    print(
        "\n[3/4] Auditing Windows services..."
    )

    services = get_windows_services()

    service_report = save_service_report(
        services
    )

    service_alerts = analyze_services(
        services
    )

    print(
        f"      {len(services)} services checked."
    )

    print(
        f"      Service report saved to: "
        f"{service_report}"
    )

    print(
        f"      {len(service_alerts)} "
        "service alerts detected."
    )

    # -------------------------------------------------------
    # 4. Unauthorized process detection
    # -------------------------------------------------------

    print(
        "\n[4/4] Detecting unauthorized/suspicious processes..."
    )

    unauthorized_alerts = (
        analyze_processes(
            processes
        )
    )

    print(
        f"      {len(unauthorized_alerts)} "
        "unauthorized/suspicious process "
        "alerts detected."
    )

    # -------------------------------------------------------
    # Save combined alerts
    # -------------------------------------------------------

    alert_file = save_all_alerts(
        process_relationship_alerts,
        service_alerts,
        unauthorized_alerts,
    )

    # -------------------------------------------------------
    # Create summary
    # -------------------------------------------------------

    summary = generate_summary(
        processes=processes,
        process_alerts=process_relationship_alerts,
        service_alerts=service_alerts,
        unauthorized_alerts=unauthorized_alerts,
        services=services,
    )

    # -------------------------------------------------------
    # Save summary
    # -------------------------------------------------------

    summary_file = save_json_report(
        summary
    )

    # -------------------------------------------------------
    # Print summary
    # -------------------------------------------------------

    print_summary(summary)

    print("\n" + "=" * 100)
    print("MONITORING COMPLETE")
    print("=" * 100)

    print(
        f"Process report : {process_report}"
    )

    print(
        f"Service report : {service_report}"
    )

    print(
        f"Summary report : {summary_file}"
    )

    print(
        f"Alert report   : {alert_file}"
    )


if __name__ == "__main__":
    main()