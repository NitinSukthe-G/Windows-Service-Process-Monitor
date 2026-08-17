import os
import sys
import time
from datetime import datetime

# Allow imports from the agent directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from process_monitor import get_process_details
from process_tree import get_process_tree, analyze_process_relationships
from service_monitor import get_windows_services
from service_detection import analyze_services
from unauthorized_process import analyze_processes
from alert_manager import save_all_alerts
from process_change_detector import ProcessChangeDetector


INTERVAL_SECONDS = 10


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def run_monitoring_cycle(change_detector):
    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    print("=" * 100)
    print("WINDOWS SERVICE & PROCESS MONITORING AGENT")
    print("=" * 100)
    print(f"Scan time: {timestamp}")
    print()

    # ---------------------------------------------------------
    # 1. Process collection
    # ---------------------------------------------------------
    print("[1/5] Collecting processes...")

    processes = get_process_details()

    print(
        f"      Processes detected: {len(processes)}"
    )

    # ---------------------------------------------------------
    # 2. Detect newly started processes
    # ---------------------------------------------------------
    print("\n[2/5] Detecting process changes...")

    new_processes = change_detector.compare(processes)

    print(
        f"      New processes detected: "
        f"{len(new_processes)}"
    )

    for process in new_processes:
        print(
            f"      NEW PROCESS: "
            f"{process['name']} "
            f"(PID {process['pid']})"
        )

    # ---------------------------------------------------------
    # 3. Parent-child analysis
    # ---------------------------------------------------------
    print(
        "\n[3/5] Analyzing parent-child relationships..."
    )

    process_tree = get_process_tree()

    process_alerts = analyze_process_relationships(
        process_tree
    )

    print(
        f"      Parent-child alerts: "
        f"{len(process_alerts)}"
    )

    # ---------------------------------------------------------
    # 4. Windows service audit
    # ---------------------------------------------------------
    print("\n[4/5] Auditing Windows services...")

    services = get_windows_services()

    service_alerts = analyze_services(services)

    print(
        f"      Services checked: {len(services)}"
    )

    print(
        f"      Service alerts: {len(service_alerts)}"
    )

    # ---------------------------------------------------------
    # 5. Unauthorized process detection
    # ---------------------------------------------------------
    print(
        "\n[5/5] Detecting unauthorized/suspicious processes..."
    )

    unauthorized_alerts = analyze_processes(
        processes
    )

    print(
        f"      Unauthorized/suspicious process alerts: "
        f"{len(unauthorized_alerts)}"
    )

    # ---------------------------------------------------------
    # Combine security alerts
    # ---------------------------------------------------------
    alert_file = save_all_alerts(
        process_alerts,
        service_alerts,
        unauthorized_alerts,
    )

    total_alerts = (
        len(process_alerts)
        + len(service_alerts)
        + len(unauthorized_alerts)
    )

    print("\n" + "-" * 100)
    print("SCAN SUMMARY")
    print("-" * 100)

    print(
        f"Processes detected       : {len(processes)}"
    )

    print(
        f"New processes            : {len(new_processes)}"
    )

    print(
        f"Services checked         : {len(services)}"
    )

    print(
        f"Parent-child alerts      : {len(process_alerts)}"
    )

    print(
        f"Service alerts           : {len(service_alerts)}"
    )

    print(
        f"Unauthorized alerts      : "
        f"{len(unauthorized_alerts)}"
    )

    print(
        f"Total security alerts    : {total_alerts}"
    )

    print(
        f"Alert report             : {alert_file}"
    )

    print("-" * 100)


def main():
    print("Starting continuous monitoring...")
    print(
        f"Scanning every {INTERVAL_SECONDS} seconds."
    )
    print("Press CTRL+C to stop.")
    print()

    change_detector = ProcessChangeDetector()

    try:
        while True:
            clear_screen()

            run_monitoring_cycle(
                change_detector
            )

            print(
                f"\nNext scan in "
                f"{INTERVAL_SECONDS} seconds..."
            )

            time.sleep(INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print(
            "\n\nMonitoring stopped by user."
        )


if __name__ == "__main__":
    main()