# Built-in Reporter Diagrams

This document provides visual diagrams of the ASH built-in reporter architecture and workflows using Mermaid.

## Reporter Architecture Overview

The following diagram shows the high-level architecture of the ASH built-in reporters:

```mermaid
flowchart TD
    A[ASH Core] --> B[Plugin Manager]
    B --> C[Reporter Registry]

    C --> D[Built-in Reporters]

    D --> E[CSV Reporter]
    D --> F[CycloneDX Reporter]
    D --> G[Flat JSON Reporter]
    D --> H[GitLab SAST Reporter]
    D --> I[HTML Reporter]
    D --> J[JUnit XML Reporter]
    D --> K[Markdown Reporter]
    D --> L[OCSF Reporter]
    D --> M[SARIF Reporter]
    D --> N[SPDX Reporter]
    D --> O[Text Reporter]
    D --> P[YAML Reporter]

    Q[Aggregated Results] --> D

    E --> R[Output Files]
    F --> R
    G --> R
    H --> R
    I --> R
    J --> R
    K --> R
    L --> R
    M --> R
    N --> R
    O --> R
    P --> R
```

## Reporter Execution Flow

The following diagram shows the execution flow of the built-in reporters:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant RR as Reporter Registry
    participant RP as Reporter
    participant FS as File System
    participant ES as Event System

    ASH->>PM: Load Reporters
    PM->>RR: Get Registered Reporters
    RR-->>PM: Return Reporter List

    ASH->>ES: Emit ReportingStarted Event

    loop For Each Reporter
        ASH->>RP: Validate Reporter
        RP-->>ASH: Return Validation Status

        alt Reporter Valid
            ASH->>RP: report(aggregated_results)
            RP->>RP: Process Results
            RP->>FS: Write Report File
            RP-->>ASH: Return Report Path/URL
        else Reporter Invalid
            ASH->>ES: Emit ReporterError Event
        end
    end

    ASH->>ES: Emit ReportingCompleted Event
```

## Reporter Format Classification

The following diagram shows the classification of built-in reporters by output format:

```mermaid
flowchart TD
    A[Built-in Reporters] --> B[Human-Readable]
    A --> C[Machine-Readable]
    A --> D[Compliance]
    A --> E[CI/CD Integration]

    B --> F[Text Reporter]
    B --> G[HTML Reporter]
    B --> H[Markdown Reporter]

    C --> I[JSON Reporter]
    C --> J[YAML Reporter]
    C --> K[CSV Reporter]

    D --> L[SPDX Reporter]
    D --> M[CycloneDX Reporter]
    D --> N[OCSF Reporter]

    E --> O[SARIF Reporter]
    E --> P[JUnit XML Reporter]
    E --> Q[GitLab SAST Reporter]
```

## Reporter Data Flow

The following diagram shows the data flow through the built-in reporters:

```mermaid
flowchart LR
    A[ASH Aggregated Results] --> B[Reporter]

    B --> C{Format Type}

    C -->|Text-based| D[Text Formatter]
    C -->|Structured| E[Data Formatter]
    C -->|Visual| F[Visual Formatter]

    D --> G[Text Output]
    D --> H[Markdown Output]

    E --> I[JSON Output]
    E --> J[YAML Output]
    E --> K[XML Output]
    E --> L[CSV Output]

    F --> M[HTML Output]

    G --> N[Output Files]
    H --> N
    I --> N
    J --> N
    K --> N
    L --> N
    M --> N
```

## Reporter Configuration Flow

The following diagram shows how configuration flows through the built-in reporters:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Reporter Configuration]

    E --> F[Global Reporter Settings]
    E --> G[Reporter-Specific Settings]

    F --> H[Output Directory]
    F --> I[Include Suppressed]
    F --> J[Output Format]

    G --> K[HTML Config]
    G --> L[SARIF Config]
    G --> M[CSV Config]
    G --> N[Other Reporter Configs]

    K --> O[HTML Reporter]
    L --> P[SARIF Reporter]
    M --> Q[CSV Reporter]
    N --> R[Other Reporters]
```

## Multi-Reporter Workflow

The following diagram shows the workflow when multiple reporters are enabled:

```mermaid
flowchart TD
    A[ASH Scan Results] --> B[Results Aggregator]

    B --> C[HTML Reporter]
    B --> D[SARIF Reporter]
    B --> E[Text Reporter]
    B --> F[CSV Reporter]

    C --> G[HTML Report]
    D --> H[SARIF Report]
    E --> I[Text Report]
    F --> J[CSV Report]

    G --> K[Developer Review]
    H --> L[IDE Integration]
    I --> M[Console Output]
    J --> N[Data Analysis]

    K --> O[Security Team]
    L --> O
    M --> O
    N --> O
```

## Reporter Integration Points

The following diagram shows the integration points of built-in reporters:

```mermaid
flowchart LR
    A[ASH Reports] --> B[Development Tools]
    A --> C[CI/CD Systems]
    A --> D[Security Tools]
    A --> E[Compliance Systems]

    B --> F[IDEs]
    B --> G[Code Review Tools]

    C --> H[GitHub Actions]
    C --> I[GitLab CI]
    C --> J[Jenkins]

    D --> K[SIEM Systems]
    D --> L[Security Dashboards]

    E --> M[Compliance Dashboards]
    E --> N[Audit Systems]

    F --> O[VS Code]
    F --> P[IntelliJ]

    G --> Q[GitHub PR Comments]
    G --> R[GitLab MR Comments]

    H --> S[GitHub Security Tab]
    I --> T[GitLab Security Dashboard]
    J --> U[Jenkins Test Results]

    K --> V[Splunk]
    K --> W[ELK Stack]

    L --> X[Security Metrics]

    M --> Y[Compliance Reports]
    N --> Z[Audit Logs]
```

## Reporter Output Organization

The following diagram shows the organization of reporter outputs:

```mermaid
flowchart TD
    A[Output Directory] --> B[reports/]

    B --> C[html/]
    B --> D[sarif/]
    B --> E[csv/]
    B --> F[json/]
    B --> G[xml/]
    B --> H[markdown/]

    C --> I[index.html]
    C --> J[assets/]

    D --> K[results.sarif]

    E --> L[findings.csv]
    E --> M[summary.csv]

    F --> N[results.json]
    F --> O[summary.json]

    G --> P[junit.xml]
    G --> Q[spdx.xml]

    H --> R[report.md]
    H --> S[summary.md]
```

## Reporter Error Handling

The following diagram shows the error handling flow in reporters:

```mermaid
flowchart TD
    A[Start Reporting] --> B{Reporter Available?}

    B -->|Yes| C[Run Reporter]
    B -->|No| D[Log Error]

    C --> E{Reporting Successful?}

    E -->|Yes| F[Return Report Path/URL]
    E -->|No| G{Error Type?}

    G -->|Dependency Missing| H[Log Dependency Error]
    G -->|File System Error| I[Log File System Error]
    G -->|Formatting Error| J[Log Formatting Error]
    G -->|Other| K[Log Generic Error]

    F --> L[End]
    H --> L
    I --> L
    J --> L
    K --> L
    D --> L
```