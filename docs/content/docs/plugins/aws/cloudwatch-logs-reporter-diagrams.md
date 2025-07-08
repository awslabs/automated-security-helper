# CloudWatch Logs Reporter Diagrams

This document provides visual diagrams of the ASH CloudWatch Logs Reporter architecture and workflows using Mermaid.

## Architecture Overview

The following diagram shows the high-level architecture of the CloudWatch Logs Reporter:

```mermaid
flowchart TD
    A[ASH Core] --> B[CloudWatch Logs Reporter]
    B --> C[AWS SDK for Python]
    C --> D[CloudWatch Logs API]

    B --> E[Scan Results]
    E --> F[JSON Formatter]
    F --> G[Log Event Creator]
    G --> C

    D --> H[CloudWatch Logs]
    H --> I[CloudWatch Dashboards]
    H --> J[CloudWatch Alarms]
    H --> K[CloudWatch Insights]

    subgraph "AWS Cloud"
        D
        H
        I
        J
        K
    end

    subgraph "Local Processing"
        A
        B
        E
        F
        G
    end
```

## Sequence Diagram

The following diagram shows the sequence of operations in the CloudWatch Logs Reporter:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant CLR as CloudWatch Logs Reporter
    participant SDK as AWS SDK
    participant CWL as CloudWatch Logs

    ASH->>CLR: report(aggregated_results)
    CLR->>CLR: Process Scan Results
    CLR->>CLR: Convert to JSON

    CLR->>SDK: Create Log Stream Request
    SDK->>CWL: API Call
    CWL-->>SDK: Response
    SDK-->>CLR: Return Response

    CLR->>CLR: Create Log Event
    CLR->>SDK: Put Log Events Request
    SDK->>CWL: API Call
    CWL-->>SDK: Response
    SDK-->>CLR: Return Response

    CLR->>CLR: Process API Response
    CLR->>CLR: Handle Errors

    CLR-->>ASH: Return Report Status
```

## Log Event Creation Process

The following diagram shows the log event creation process:

```mermaid
flowchart TD
    A[ASH Aggregated Results] --> B[Extract Metadata]
    A --> C[Convert to Simple Dict]

    B --> D[Generate Timestamp]
    C --> E[Serialize to JSON]

    D --> F[Create Log Event]
    E --> F

    F --> G[Log Event Object]
    G --> H[CloudWatch Logs API]
```

## Error Handling Flow

The following diagram shows the error handling flow with retry logic:

```mermaid
flowchart TD
    A[Start API Call] --> B{API Call Successful?}

    B -->|Yes| C[Process Response]
    B -->|No| D{Error Type?}

    D -->|Throttling| E[Apply Exponential Backoff]
    D -->|Access Denied| F[Check IAM Permissions]
    D -->|Resource Not Found| G[Log Resource Error]
    D -->|Other| H[Log Error Details]

    E --> I[Retry API Call]
    F --> J[Log Permission Error]
    G --> K[Return Error Status]
    H --> K

    I --> L{Retry Successful?}
    L -->|Yes| C
    L -->|No| M{Max Retries Reached?}

    M -->|Yes| K
    M -->|No| E

    C --> N[Return Success Response]
    J --> O[Return Error Message]
    K --> O

    N --> P[End]
    O --> P
```

> **Note**: The implementation now includes retry logic with exponential backoff, improving the reliability of the CloudWatch Logs Reporter.

## Integration with CloudWatch Services

The following diagram shows how the CloudWatch Logs Reporter integrates with other CloudWatch services:

```mermaid
flowchart LR
    A[ASH Scan Results] --> B[CloudWatch Logs Reporter]

    B --> C[CloudWatch Logs]

    C --> D[CloudWatch Dashboards]
    C --> E[CloudWatch Alarms]
    C --> F[CloudWatch Insights]
    C --> G[CloudWatch Metrics]

    D --> H[Visualization]
    E --> I[Notifications]
    F --> J[Log Analysis]
    G --> K[Metrics Analysis]

    subgraph "CloudWatch Ecosystem"
        C
        D
        E
        F
        G
        H
        I
        J
        K
    end
```

## Log Group and Stream Management

The following diagram shows the log group and stream management process:

```mermaid
flowchart TD
    A[Start] --> B{Log Group Exists?}

    B -->|Yes| C[Use Existing Log Group]
    B -->|No| D[Error: Log Group Required]

    C --> E{Log Stream Exists?}

    E -->|Yes| F[Use Existing Log Stream]
    E -->|No| G[Create Log Stream with Retry]

    G --> H{Creation Successful?}

    H -->|Yes| F
    H -->|No| I[Log Error and Continue]

    F --> J[Put Log Events with Retry]
    I --> J

    J --> K{API Call Successful?}

    K -->|Yes| L[Return Success]
    K -->|No| M[Log Error]

    M --> N[Return Error]
    L --> O[End]
    N --> O
    D --> O
```

## Configuration Flow

The following diagram shows the configuration flow:

```mermaid
flowchart TD
    A[Start] --> B{AWS Region Set?}

    B -->|Yes| C{Log Group Name Set?}
    B -->|No| D[Use AWS_REGION Environment Variable]

    D --> E{Environment Variable Set?}

    E -->|Yes| C
    E -->|No| F[Validation Fails]

    C -->|Yes| G[Validation Succeeds]
    C -->|No| H[Use ASH_CLOUDWATCH_LOG_GROUP_NAME Environment Variable]

    H --> I{Environment Variable Set?}

    I -->|Yes| G
    I -->|No| F

    G --> J[Reporter Ready]
    F --> K[Reporter Disabled]

    J --> L[End]
    K --> L
```