import csv
from service_monitor import get_windows_services


def save_service_report(services):
    output_file = "reports/service_report.csv"

    fieldnames = [
        "timestamp",
        "name",
        "display_name",
        "state",
        "start_mode",
        "start_name",
        "path",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(services)

    print(f"\nService report saved to: {output_file}")
    print(f"Services recorded: {len(services)}")


if __name__ == "__main__":
    services = get_windows_services()

    save_service_report(services)