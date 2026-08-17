import psutil
from datetime import datetime

from detection_rules import is_suspicious_parent_child


def get_process_tree():
    processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            processes[info["pid"]] = {
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"],
                "path": info["exe"],
                "username": info["username"],
            }

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes


def analyze_process_relationships(processes):
    alerts = []

    for pid, process in processes.items():
        parent_pid = process["ppid"]
        parent = processes.get(parent_pid)

        if not parent:
            continue

        parent_name = parent["name"]
        child_name = process["name"]

        if is_suspicious_parent_child(parent_name, child_name):
            alerts.append(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH",
                    "parent_pid": parent["pid"],
                    "parent_name": parent_name,
                    "child_pid": pid,
                    "child_name": child_name,
                    "child_path": process["path"],
                    "reason": (
                        f"Suspicious parent-child relationship: "
                        f"{parent_name} -> {child_name}"
                    ),
                }
            )

    return alerts


def print_alerts(alerts):
    print("\n" + "=" * 100)
    print("PROCESS RELATIONSHIP ALERTS")
    print("=" * 100)

    if not alerts:
        print("No suspicious parent-child relationships detected.")
        return

    for alert in alerts:
        print("\n[HIGH]")
        print("Parent :", alert["parent_name"])
        print("Parent PID :", alert["parent_pid"])
        print("Child  :", alert["child_name"])
        print("Child PID :", alert["child_pid"])
        print("Path   :", alert["child_path"])
        print("Reason :", alert["reason"])


if __name__ == "__main__":
    process_data = get_process_tree()

    alerts = analyze_process_relationships(process_data)

    print_alerts(alerts)

    print(f"\nTotal alerts: {len(alerts)}")