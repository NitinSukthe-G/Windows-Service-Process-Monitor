import csv

from service_monitor import get_windows_services
from service_detection import analyze_services


def save_service_alerts(alerts):
    output_file = "reports/service_alerts.csv"

    fieldnames = [
        "timestamp",
        "severity",
        "service_name",
        "display_name",
        "state",
        "start_mode",
        "start_name",
        "path",
        "reason",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nService alert report saved to: {output_file}")
    print(f"Alerts recorded: {len(alerts)}")


if __name__ == "__main__":
    services = get_windows_services()

    alerts = analyze_services(services)

    save_service_alerts(alerts)