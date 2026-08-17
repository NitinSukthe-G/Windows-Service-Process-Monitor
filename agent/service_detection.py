from datetime import datetime

from service_monitor import get_windows_services
from service_rules import is_suspicious_service_path


def analyze_services(services):
    alerts = []

    for service in services:
        path = service.get("path")

        if is_suspicious_service_path(path):
            alerts.append(
                {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH",
                    "service_name": service.get("name"),
                    "display_name": service.get("display_name"),
                    "state": service.get("state"),
                    "start_mode": service.get("start_mode"),
                    "start_name": service.get("start_name"),
                    "path": path,
                    "reason": "Service executable is located in a suspicious user-writable directory.",
                }
            )

    return alerts


def print_service_alerts(alerts):
    print("\n" + "=" * 110)
    print("SERVICE SECURITY ALERTS")
    print("=" * 110)

    if not alerts:
        print("No suspicious services detected.")
        return

    for alert in alerts:
        print("\n[HIGH]")
        print("Service :", alert["service_name"])
        print("Display :", alert["display_name"])
        print("State   :", alert["state"])
        print("Start   :", alert["start_mode"])
        print("Account :", alert["start_name"])
        print("Path    :", alert["path"])
        print("Reason  :", alert["reason"])


if __name__ == "__main__":
    services = get_windows_services()

    alerts = analyze_services(services)

    print_service_alerts(alerts)

    print(f"\nTotal service alerts: {len(alerts)}")