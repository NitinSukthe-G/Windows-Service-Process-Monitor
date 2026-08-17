import csv

from process_monitor import get_process_details
from unauthorized_process import analyze_processes


def save_report(alerts):
    output_file = "reports/unauthorized_processes.csv"

    fieldnames = [
        "timestamp",
        "severity",
        "pid",
        "ppid",
        "name",
        "path",
        "username",
        "status",
        "reason",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nUnauthorized process report saved to: {output_file}")
    print(f"Alerts recorded: {len(alerts)}")


if __name__ == "__main__":
    processes = get_process_details()

    alerts = analyze_processes(processes)

    save_report(alerts)