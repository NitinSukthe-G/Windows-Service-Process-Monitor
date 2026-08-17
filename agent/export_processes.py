import csv
from process_monitor import get_process_details


def save_process_report(processes):
    output_file = "reports/process_report.csv"

    fieldnames = [
        "timestamp",
        "pid",
        "ppid",
        "name",
        "path",
        "username",
        "status",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(processes)

    print(f"\nProcess report saved to: {output_file}")


if __name__ == "__main__":
    process_list = get_process_details()

    save_process_report(process_list)

    print(f"Processes recorded: {len(process_list)}")