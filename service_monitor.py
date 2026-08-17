import csv
import subprocess
from datetime import datetime


def get_windows_services():
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-CimInstance Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
        ConvertTo-Csv -NoTypeInformation
        """
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if result.returncode != 0:
        print("Failed to collect Windows services.")
        print(result.stderr)
        return []

    lines = result.stdout.strip().splitlines()

    if len(lines) < 2:
        return []

    reader = csv.DictReader(lines)

    services = []

    for row in reader:
        services.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "name": row.get("Name"),
                "display_name": row.get("DisplayName"),
                "state": row.get("State"),
                "start_mode": row.get("StartMode"),
                "start_name": row.get("StartName"),
                "path": row.get("PathName"),
            }
        )

    return services


def print_services(services):
    print("\n" + "=" * 120)
    print("WINDOWS SERVICE AUDIT")
    print("=" * 120)

    print(
        f"{'SERVICE NAME':<30}"
        f"{'STATE':<12}"
        f"{'START MODE':<15}"
        f"{'START ACCOUNT':<25}"
    )

    print("-" * 120)

    for service in services:
        print(
            f"{str(service['name'] or 'Unknown')[:28]:<30}"
            f"{str(service['state'] or 'Unknown'):<12}"
            f"{str(service['start_mode'] or 'Unknown'):<15}"
            f"{str(service['start_name'] or 'Unknown')[:23]:<25}"
        )

    print("\nTotal services detected:", len(services))


if __name__ == "__main__":
    services = get_windows_services()

    print_services(services)