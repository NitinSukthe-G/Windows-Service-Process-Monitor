from datetime import datetime

from process_monitor import get_process_details
from allowed_processes import is_allowed_process
from process_rules import is_suspicious_path


def analyze_processes(processes):
    alerts = []

    for process in processes:
        name = process.get("name")
        path = process.get("path")

        if not name:
            continue

        unauthorized = not is_allowed_process(name)
        suspicious_location = is_suspicious_path(path)

        reasons = []

        if unauthorized:
            reasons.append("Process is not present in the configured allowlist.")

        if suspicious_location:
            reasons.append("Executable is running from a suspicious user-writable directory.")

        if not reasons:
            continue

        severity = "MEDIUM"

        # Upgrade severity when both conditions are present.
        if unauthorized and suspicious_location:
            severity = "HIGH"

        alerts.append(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": severity,
                "pid": process.get("pid"),
                "ppid": process.get("ppid"),
                "name": name,
                "path": path,
                "username": process.get("username"),
                "status": process.get("status"),
                "reason": " ".join(reasons),
            }
        )

    return alerts


def print_alerts(alerts):
    print("\n" + "=" * 110)
    print("UNAUTHORIZED / SUSPICIOUS PROCESS DETECTION")
    print("=" * 110)

    if not alerts:
        print("No unauthorized or suspicious processes detected.")
        return

    for alert in alerts:
        print("\n[" + alert["severity"] + "]")
        print("Process :", alert["name"])
        print("PID     :", alert["pid"])
        print("PPID    :", alert["ppid"])
        print("Path    :", alert["path"])
        print("User    :", alert["username"])
        print("Reason  :", alert["reason"])


if __name__ == "__main__":
    processes = get_process_details()

    alerts = analyze_processes(processes)

    print_alerts(alerts)

    print(f"\nTotal alerts: {len(alerts)}")