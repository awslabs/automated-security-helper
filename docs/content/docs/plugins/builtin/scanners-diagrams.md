# Built-in Scanner Diagrams

This document provides visual diagrams of the ASH built-in scanner architecture and workflows using Mermaid.

## Scanner Architecture Overview

The following diagram shows the high-level architecture of the ASH built-in scanners:

```mermaid
flowchart TD
    A[ASH Core] --> B[Plugin Manager]
    B --> C[Scanner Registry]

    C --> D[Built-in Scanners]

    D --> E[Bandit]
    D --> F[CDK-Nag]
    D --> G[CFN-Nag]
    D --> H[Checkov]
    D --> I[Detect-Secrets]
    D --> J[Grype]
    D --> K[NPM Audit]
    D --> L[Opengrep]
    D --> M[Semgrep]
    D --> N[Syft]

    E --> O[SARIF Results]
    F --> O
    G --> O
    H --> O
    I --> O
    J --> O
    K --> O
    L --> O
    M --> O
    N --> O

    O --> P[Results Aggregator]
    P --> Q[Reporter Plugins]
```

## Scanner Execution Flow

The following diagram shows the execution flow of the built-in scanners:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant SR as Scanner Registry
    participant SC as Scanner
    participant FS as File System
    participant ES as Event System

    ASH->>PM: Load Scanners
    PM->>SR: Get Registered Scanners
    SR-->>PM: Return Scanner List

    loop For Each Scanner
        ASH->>ES: Emit ScannerStarted Event
        ASH->>SC: Validate Scanner
        SC-->>ASH: Return Validation Status

        alt Scanner Valid
            ASH->>SC: scan(target, target_type)
            SC->>FS: Read Target Files
            FS-->>SC: Return File Contents

            SC->>SC: Process Files
            Note over SC: Run Security Analysis

            SC->>FS: Write SARIF Report
            SC-->>ASH: Return ScanResultsContainer

            ASH->>ES: Emit ScannerCompleted Event
        else Scanner Invalid
            ASH->>ES: Emit ScannerError Event
        end
    end

    ASH->>ES: Emit ScanCompleted Event
```

## Scanner Dependency Graph

The following diagram shows the dependency relationships between the built-in scanners:

```mermaid
flowchart LR
    A[ASH Core] --> B[Scanner Base]

    B --> C[Bandit]
    B --> D[CDK-Nag]
    B --> E[CFN-Nag]
    B --> F[Checkov]
    B --> G[Detect-Secrets]
    B --> H[Grype]
    B --> I[NPM Audit]
    B --> J[Opengrep]
    B --> K[Semgrep]
    B --> L[Syft]

    C -.-> M[bandit Python package]
    D -.-> N[AWS CDK CLI]
    E -.-> O[cfn-nag Ruby gem]
    F -.-> P[checkov Python package]
    G -.-> Q[detect-secrets Python package]
    H -.-> R[grype binary]
    I -.-> S[Node.js & npm]
    J -.-> T[opengrep binary]
    K -.-> U[semgrep Python package]
    L -.-> V[syft binary]

    H -.-> L
```

## Scanner Configuration Flow

The following diagram shows how configuration flows through the built-in scanners:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Scanner Configuration]

    E --> F[Global Scanner Settings]
    E --> G[Scanner-Specific Settings]

    F --> H[Severity Threshold]
    F --> I[Ignore Paths]
    F --> J[Max Workers]

    G --> K[Bandit Config]
    G --> L[Semgrep Config]
    G --> M[Checkov Config]
    G --> N[Other Scanner Configs]

    K --> O[Bandit Scanner]
    L --> P[Semgrep Scanner]
    M --> Q[Checkov Scanner]
    N --> R[Other Scanners]
```

## Scanner Type Classification

The following diagram shows the classification of built-in scanners by type:

```mermaid
flowchart TD
    A[Built-in Scanners] --> B[Static Analysis]
    A --> C[Dependency Analysis]
    A --> D[Secret Detection]
    A --> E[Infrastructure Analysis]
    A --> F[Container Analysis]

    B --> G[Bandit]
    B --> H[Semgrep]
    B --> I[Opengrep]

    C --> J[NPM Audit]
    C --> K[Syft]

    D --> L[Detect-Secrets]

    E --> M[CDK-Nag]
    E --> N[CFN-Nag]
    E --> O[Checkov]

    F --> P[Grype]
    F --> Q[Syft]
```

## Scanner Language Support

The following diagram shows the language support of built-in scanners:

```mermaid
flowchart TD
    A[Languages] --> B[Python]
    A --> C[JavaScript/TypeScript]
    A --> D[Infrastructure as Code]
    A --> E[Multiple Languages]
    A --> F[Container/Binary]

    B --> G[Bandit]

    C --> H[NPM Audit]

    D --> I[CDK-Nag]
    D --> J[CFN-Nag]
    D --> K[Checkov]

    E --> L[Semgrep]
    E --> M[Opengrep]
    E --> N[Detect-Secrets]

    F --> O[Grype]
    F --> P[Syft]
```

## Scanner Result Processing

The following diagram shows how scanner results are processed:

```mermaid
flowchart LR
    A[Scanner Output] --> B{Format?}

    B -->|SARIF| C[Direct Integration]
    B -->|JSON| D[SARIF Converter]
    B -->|XML| E[SARIF Converter]
    B -->|Text| F[SARIF Converter]

    C --> G[Results Container]
    D --> G
    E --> G
    F --> G

    G --> H[Results Aggregator]
    H --> I[Reporter Plugins]
```

## Scanner Parallel Execution

The following diagram shows the parallel execution of scanners:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant WP as Worker Pool
    participant W1 as Worker 1
    participant W2 as Worker 2
    participant W3 as Worker 3

    ASH->>WP: Create Worker Pool (max_workers)

    par Parallel Execution
        WP->>W1: Run Bandit Scanner
        WP->>W2: Run Semgrep Scanner
        WP->>W3: Run Checkov Scanner
    end

    W1-->>WP: Return Results
    W2-->>WP: Return Results
    W3-->>WP: Return Results

    WP-->>ASH: Aggregate Results
```

## Scanner Error Handling

The following diagram shows the error handling flow in scanners:

```mermaid
flowchart TD
    A[Start Scan] --> B{Scanner Available?}

    B -->|Yes| C[Run Scanner]
    B -->|No| D[Log Error]

    C --> E{Scan Successful?}

    E -->|Yes| F[Process Results]
    E -->|No| G{Error Type?}

    G -->|Dependency Missing| H[Log Dependency Error]
    G -->|Timeout| I[Log Timeout Error]
    G -->|Parsing Error| J[Log Parsing Error]
    G -->|Other| K[Log Generic Error]

    F --> L[Return Results Container]
    H --> M[Return Empty Container with Error]
    I --> M
    J --> M
    K --> M
    D --> M

    L --> N[End]
    M --> N
```