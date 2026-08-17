# Monitoring Workflow

```mermaid
flowchart TD

    A[START] --> B[Enumerate Windows Processes]

    B --> C[Collect PID PPID Name Path User Status]

    C --> D[Build Parent-Child Process Tree]

    D --> E[Analyze Process Relationships]

    E --> F[Audit Windows Services]

    F --> G[Check Startup Mode and Service Path]

    G --> H[Detect Unauthorized Processes]

    H --> I[Check Allowlist and Suspicious Paths]

    I --> J[Generate Security Alerts]

    J --> K[Assign Severity]

    K --> L[Generate CSV and JSON Reports]

    L --> M[Update Streamlit Dashboard]

    M --> N[Security Analyst Review]

    N --> O[END]