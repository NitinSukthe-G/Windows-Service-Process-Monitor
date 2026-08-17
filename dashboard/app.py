import json
import os

import pandas as pd
import streamlit as st


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Windows Security Monitoring Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports"
)

SUMMARY_FILE = os.path.join(
    REPORT_DIR,
    "monitoring_summary.json"
)

ALERTS_FILE = os.path.join(
    REPORT_DIR,
    "alerts.json"
)

PROCESS_FILE = os.path.join(
    REPORT_DIR,
    "process_report.csv"
)

SERVICE_FILE = os.path.join(
    REPORT_DIR,
    "service_report.csv"
)


# =========================================================
# DATA LOADING FUNCTIONS
# =========================================================

def load_json(file_path):
    """
    Load JSON data from a file.
    Returns an empty dictionary if the file does not exist
    or cannot be read.
    """

    if not os.path.exists(file_path):
        return {}

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):
        return {}


def load_csv(file_path):
    """
    Load CSV data into a pandas DataFrame.
    Returns an empty DataFrame if the file does not exist
    or cannot be read.
    """

    if not os.path.exists(file_path):
        return pd.DataFrame()

    try:
        return pd.read_csv(file_path)

    except (
        pd.errors.EmptyDataError,
        OSError
    ):
        return pd.DataFrame()


# =========================================================
# LOAD REPORT DATA
# =========================================================

summary = load_json(
    SUMMARY_FILE
)

alerts_data = load_json(
    ALERTS_FILE
)

process_data = load_csv(
    PROCESS_FILE
)

service_data = load_csv(
    SERVICE_FILE
)

alerts = alerts_data.get(
    "alerts",
    []
)


# =========================================================
# PAGE HEADER
# =========================================================

st.title(
    "🛡️ Windows Security Monitoring Dashboard"
)

st.caption(
    "Windows endpoint process and service monitoring"
)


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title(
    "Monitoring Controls"
)

st.sidebar.write(
    "Use the controls below to filter security events."
)


# =========================================================
# LAST SCAN INFORMATION
# =========================================================

last_scan = summary.get(
    "timestamp",
    "No scan available"
)

st.info(
    f"Last monitoring scan: {last_scan}"
)


# =========================================================
# METRICS
# =========================================================

process_count = summary.get(
    "processes_detected",
    len(process_data)
)

service_count = summary.get(
    "services_detected",
    len(service_data)
)

total_alerts = summary.get(
    "total_alerts",
    len(alerts)
)

critical_alerts = summary.get(
    "critical_alerts",
    0
)

high_alerts = summary.get(
    "high_alerts",
    0
)

medium_alerts = summary.get(
    "medium_alerts",
    0
)

low_alerts = summary.get(
    "low_alerts",
    0
)


col1, col2, col3, col4, col5, col6 = st.columns(6)


with col1:

    st.metric(
        "Processes",
        process_count
    )


with col2:

    st.metric(
        "Services",
        service_count
    )


with col3:

    st.metric(
        "Total Alerts",
        total_alerts
    )


with col4:

    st.metric(
        "Critical",
        critical_alerts
    )


with col5:

    st.metric(
        "High",
        high_alerts
    )


with col6:

    st.metric(
        "Medium",
        medium_alerts
    )


# =========================================================
# ALERT DATAFRAME
# =========================================================

if alerts:

    alert_records = []

    for alert in alerts:

        process_or_service = (
            alert.get("name")
            or alert.get("service_name")
            or alert.get("child_name")
            or alert.get("display_name")
            or "Unknown"
        )

        pid = (
            alert.get("pid")
            or alert.get("child_pid")
            or ""
        )

        alert_records.append(
            {
                "Timestamp": alert.get(
                    "timestamp",
                    ""
                ),

                "Alert Type": alert.get(
                    "alert_type",
                    "UNKNOWN"
                ),

                "Severity": alert.get(
                    "severity",
                    "UNKNOWN"
                ).upper(),

                "Process / Service": process_or_service,

                "PID": pid,

                "Path": alert.get(
                    "path"
                ) or alert.get(
                    "child_path"
                ) or "",

                "Reason": alert.get(
                    "reason",
                    ""
                ),
            }
        )

    alerts_df = pd.DataFrame(
        alert_records
    )

else:

    alerts_df = pd.DataFrame(
        columns=[
            "Timestamp",
            "Alert Type",
            "Severity",
            "Process / Service",
            "PID",
            "Path",
            "Reason",
        ]
    )


# =========================================================
# SIDEBAR FILTERS
# =========================================================

severity_options = [
    "ALL",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
]

selected_severity = st.sidebar.selectbox(
    "Severity",
    severity_options
)


alert_type_options = [
    "ALL"
]

if not alerts_df.empty:

    alert_types = sorted(
        alerts_df["Alert Type"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    alert_type_options.extend(
        alert_types
    )


selected_alert_type = st.sidebar.selectbox(
    "Alert Type",
    alert_type_options
)


search_text = st.sidebar.text_input(
    "Search Process / Service",
    ""
)


# =========================================================
# FILTER ALERTS
# =========================================================

filtered_alerts = alerts_df.copy()


if selected_severity != "ALL":

    filtered_alerts = filtered_alerts[
        filtered_alerts["Severity"]
        == selected_severity
    ]


if selected_alert_type != "ALL":

    filtered_alerts = filtered_alerts[
        filtered_alerts["Alert Type"]
        == selected_alert_type
    ]


if search_text.strip():

    search_value = search_text.strip().lower()

    filtered_alerts = filtered_alerts[
        filtered_alerts[
            "Process / Service"
        ]
        .astype(str)
        .str.lower()
        .str.contains(
            search_value,
            na=False
        )
    ]


# =========================================================
# ALERT STATISTICS
# =========================================================

st.divider()

st.subheader(
    "Alert Statistics"
)

stat_col1, stat_col2 = st.columns(2)


with stat_col1:

    severity_chart = pd.DataFrame(
        {
            "Severity": [
                "Critical",
                "High",
                "Medium",
                "Low",
            ],
            "Count": [
                critical_alerts,
                high_alerts,
                medium_alerts,
                low_alerts,
            ],
        }
    )

    st.write(
        "Alerts by Severity"
    )

    st.bar_chart(
        severity_chart.set_index(
            "Severity"
        )
    )


with stat_col2:

    if not alerts_df.empty:

        type_counts = (
            alerts_df["Alert Type"]
            .value_counts()
            .rename_axis("Alert Type")
            .reset_index(
                name="Count"
            )
        )

        st.write(
            "Alerts by Type"
        )

        st.bar_chart(
            type_counts.set_index(
                "Alert Type"
            )
        )

    else:

        st.info(
            "No alert type data available."
        )


# =========================================================
# FILTERED ALERTS
# =========================================================

st.divider()

st.subheader(
    "Security Alerts"
)

st.caption(
    f"Showing {len(filtered_alerts)} "
    f"of {len(alerts_df)} total alerts."
)


if filtered_alerts.empty:

    st.success(
        "No alerts match the selected filters."
    )

else:

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True,
    )


# =========================================================
# HIGH / CRITICAL ALERTS
# =========================================================

st.divider()

st.subheader(
    "High Priority Alerts"
)


if alerts_df.empty:

    st.info(
        "No security alerts available."
    )

else:

    high_priority = alerts_df[
        alerts_df["Severity"].isin(
            [
                "CRITICAL",
                "HIGH",
            ]
        )
    ]

    if high_priority.empty:

        st.success(
            "No critical or high-severity alerts detected."
        )

    else:

        st.dataframe(
            high_priority,
            use_container_width=True,
            hide_index=True,
        )


# =========================================================
# RUNNING PROCESS INVENTORY
# =========================================================

st.divider()

st.subheader(
    "Running Process Inventory"
)


if process_data.empty:

    st.warning(
        "Process report is not available."
    )

else:

    process_search = st.text_input(
        "Search Process Name",
        key="process_search"
    )

    filtered_processes = process_data.copy()

    if process_search.strip():

        search_value = (
            process_search
            .strip()
            .lower()
        )

        if "name" in filtered_processes.columns:

            filtered_processes = (
                filtered_processes[
                    filtered_processes[
                        "name"
                    ]
                    .astype(str)
                    .str.lower()
                    .str.contains(
                        search_value,
                        na=False
                    )
                ]
            )

    st.caption(
        f"{len(filtered_processes)} "
        f"process records displayed."
    )

    st.dataframe(
        filtered_processes,
        use_container_width=True,
        hide_index=True,
    )


# =========================================================
# WINDOWS SERVICE INVENTORY
# =========================================================

st.divider()

st.subheader(
    "Windows Service Inventory"
)


if service_data.empty:

    st.warning(
        "Service report is not available."
    )

else:

    service_search = st.text_input(
        "Search Service Name",
        key="service_search"
    )

    filtered_services = service_data.copy()

    if service_search.strip():

        search_value = (
            service_search
            .strip()
            .lower()
        )

        if "name" in filtered_services.columns:

            filtered_services = (
                filtered_services[
                    filtered_services[
                        "name"
                    ]
                    .astype(str)
                    .str.lower()
                    .str.contains(
                        search_value,
                        na=False
                    )
                ]
            )

    st.caption(
        f"{len(filtered_services)} "
        f"service records displayed."
    )

    st.dataframe(
        filtered_services,
        use_container_width=True,
        hide_index=True,
    )


# =========================================================
# SYSTEM INFORMATION
# =========================================================

st.divider()

st.subheader(
    "Monitoring Information"
)

info_col1, info_col2, info_col3 = st.columns(3)


with info_col1:

    st.write(
        "**Monitoring Status**"
    )

    st.success(
        "Agent data available"
    )


with info_col2:

    st.write(
        "**Report Directory**"
    )

    st.code(
        "reports/"
    )


with info_col3:

    st.write(
        "**Dashboard Data Sources**"
    )

    st.write(
        "Processes • Services • Alerts"
    )


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "Windows Service & Process Monitoring Agent"
)

st.caption(
    "Defensive security monitoring and "
    "rule-based anomaly detection."
)