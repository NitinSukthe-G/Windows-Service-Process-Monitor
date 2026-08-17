# System Architecture

```mermaid
flowchart TD

    A[Windows Endpoint] --> B[Monitoring Agent]

    B --> C[Process Monitor]
    B --> D[Parent-Child Analyzer]
    B --> E[Windows Service Monitor]
    B --> F[Unauthorized Process Detector]

    C --> C1[PID / PPID]
    C --> C2[Process Name]
    C --> C3[Executable Path]
    C --> C4[Username]
    C --> C5[Process Status]

    D --> D1[Process Tree]
    D1 --> D2[Relationship Detection Rules]

    E --> E1[Service Name]
    E --> E2[Service State]
    E --> E3[Startup Mode]
    E --> E4[Service Account]
    E --> E5[Executable Path]

    F --> F1[Allowlist]
    F --> F2[Suspicious Path Detection]

    C2 --> G[Detection & Alert Engine]
    D2 --> G
    E5 --> G
    F2 --> G

    G --> H[Severity Classification]

    H --> I[CSV Reports]
    H --> J[JSON Reports]

    I --> K[Streamlit Dashboard]
    J --> K

    K --> L[Security Analyst / User]