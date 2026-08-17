import json
import os
from datetime import datetime


REPORT_DIR = "reports"


def save_all_alerts(
    process_alerts,
    service_alerts,
    unauthorized_alerts,
):
    all_alerts = []

    for alert in process_alerts:
        alert["alert_type"] = "PROCESS_RELATIONSHIP"
        all_alerts.append(alert)

    for alert in service_alerts:
        alert["alert_type"] = "SERVICE"
        all_alerts.append(alert)

    for alert in unauthorized_alerts:
        alert["alert_type"] = "UNAUTHORIZED_PROCESS"
        all_alerts.append(alert)

    output = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts": len(all_alerts),
        "alerts": all_alerts,
    }

    output_file = os.path.join(REPORT_DIR, "alerts.json")

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    return output_file