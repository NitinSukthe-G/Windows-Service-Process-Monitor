import csv
from process_tree import get_process_tree, analyze_process_relationships


def save_alert_report(alerts):
    output_file = "reports/alerts.csv"

    fieldnames = [
        "timestamp",
        "severity",
        "parent_pid",
        "parent_name",
        "child_pid",
        "child_name",
        "child_path",
        "reason",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nAlert report saved to: {output_file}")


if __name__ == "__main__":
    processes = get_process_tree()

    alerts = analyze_process_relationships(processes)

    save_alert_report(alerts)

    print(f"Alerts recorded: {len(alerts)}")