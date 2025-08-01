# Security Hub Reporter Diagrams

This document provides visual diagrams of the ASH Security Hub Reporter architecture and workflows using Mermaid.

## Architecture Overview

The following diagram shows the high-level architecture of the Security Hub Reporter:

```mermaid
flowchart LR
    A[ASH Core] --> B[Security Hub Reporter]
    B --> C[AWS SDK for Python]
    C --> D[AWS Security Hub API]

    B --> E[Scan Results]
    E --> F[ASFF Converter]
    F --> G[Batch Processor]
    G --> C

    D --> H[Security Hub Findings]
    H --> I[Security Hub Console]
    H --> J[EventBridge Rules]
    J --> K[Automated Response]

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

The following diagram shows the sequence of operations in the Security Hub Reporter:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant SHR as Security Hub Reporter
    participant SDK as AWS SDK
    participant SH as AWS Security Hub
    participant EB as EventBridge
    participant AR as Automated Response

    ASH->>SHR: report(aggregated_results)
    SHR->>SHR: Process Scan Results
    SHR->>SHR: Convert to ASFF Format

    SHR->>SHR: Group Findings into Batches

    loop For Each Batch
        SHR->>SDK: BatchImportFindings Request
        SDK->>SH: API Call
        SH-->>SDK: Response
        SDK-->>SHR: Return Response
    end

    SH->>EB: Emit Finding Events
    EB->>AR: Trigger Automated Response

    SHR->>SHR: Process API Responses
    SHR->>SHR: Handle Errors

    SHR-->>ASH: Return Report Status
```

## ASFF Conversion Process

The following diagram shows the ASFF conversion process:

```mermaid
flowchart TD
    A[ASH Finding] --> B[Extract Metadata]
    A --> C[Extract Vulnerability Details]
    A --> D[Extract Resource Information]

    B --> E[Generate ASFF Base Fields]
    C --> F[Generate ASFF Vulnerability Fields]
    D --> G[Generate ASFF Resource Fields]

    E --> H[Create ASFF Finding]
    F --> H
    G --> H

    H --> I[Add AWS Account ID]
    I --> J[Add Product ARN]
    J --> K[Add Finding ID]

    K --> L[Add Severity Mapping]
    L --> M[Add Types Mapping]
    M --> N[Add Compliance Status]

    N --> O[Final ASFF Finding]
```

## Batch Processing Flow

The following diagram shows the batch processing flow:

```mermaid
flowchart TD
    A[All Findings] --> B[Group by Max Batch Size]

    B --> C[Batch 1]
    B --> D[Batch 2]
    B --> E[Batch 3]

    C --> F[Process Batch 1]
    D --> G[Process Batch 2]
    E --> H[Process Batch 3]

    F --> I{API Call Successful?}
    G --> I
    H --> I

    I -->|Yes| J[Record Success]
    I -->|No| K{Retryable Error?}

    K -->|Yes| L[Apply Backoff]
    K -->|No| M[Record Failure]

    L --> N[Retry Batch]
    N --> I

    J --> O[Aggregate Results]
    M --> O

    O --> P[Final Report]
```

## Finding Lifecycle Management

The following diagram shows the finding lifecycle management process:

```mermaid
flowchart TD
    A[Start] --> B{Finding Exists?}

    B -->|Yes| C[Get Existing Finding]
    B -->|No| D[Create New Finding]

    C --> E{Status Changed?}
    E -->|Yes| F[Update Status]
    E -->|No| G{Details Changed?}

    G -->|Yes| H[Update Details]
    G -->|No| I[No Update Needed]

    D --> J[Set Initial Status]
    F --> K[Update Finding]
    H --> K

    J --> L[Import New Finding]
    K --> L
    I --> M[Skip Update]

    L --> N[End]
    M --> N
```

## Integration with Security Hub

The following diagram shows the integration with AWS Security Hub:

```mermaid
flowchart LR
    A[ASH Findings] --> B[Security Hub Reporter]

    B --> C[Security Hub]

    C --> D[Security Hub Console]
    C --> E[Security Hub API]
    C --> F[Security Hub Insights]

    C --> G[EventBridge]
    G --> H[Lambda Functions]
    G --> I[SNS Topics]
    G --> J[Step Functions]

    H --> K[Automated Remediation]
    I --> L[Notifications]
    J --> M[Workflows]

    C --> N[Security Standards]
    N --> O[Compliance Status]

    subgraph "AWS Security Hub"
        C
        D
        E
        F
        N
        O
    end

    subgraph "Integration Points"
        G
        H
        I
        J
        K
        L
        M
    end
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
    D -->|Invalid Format| G[Fix ASFF Format]
    D -->|Other| H[Log Error Details]

    E --> I[Retry API Call]
    F --> J[Log Permission Error]
    G --> K[Retry with Fixed Format]
    H --> L[Return Error Status]

    I --> M{Retry Successful?}
    M -->|Yes| C
    M -->|No| N{Max Retries Reached?}

    N -->|Yes| L
    N -->|No| E

    K --> O{Format Fix Successful?}
    O -->|Yes| P[Retry with Fixed Format]
    O -->|No| L

    P --> Q{Retry Successful?}
    Q -->|Yes| C
    Q -->|No| L

    C --> R[Complete Processing]
    J --> S[End with Error]
    L --> S
    R --> T[End Successfully]
```

## Cross-Account Integration

The following diagram shows the cross-account integration flow:

```mermaid
flowchart TD
    A[ASH in Account A] --> B[Security Hub Reporter]

    B --> C{Cross-Account Mode?}

    C -->|Yes| D[Assume Role in Target Account]
    C -->|No| E[Use Local Account]

    D --> F[Security Hub in Account B]
    E --> G[Security Hub in Account A]

    F --> H[Findings in Central Account]
    G --> I[Findings in Local Account]

    H --> J[Cross-Account Aggregation]
    I --> J

    J --> K[Centralized View]
```

## Compliance Framework Mapping

The following diagram shows the compliance framework mapping:

```mermaid
flowchart LR
    A[ASH Finding] --> B[Extract Vulnerability Type]

    B --> C{Mapping Available?}

    C -->|Yes| D[Map to Compliance Controls]
    C -->|No| E[Use Default Mapping]

    D --> F[AWS Foundational Security Best Practices]
    D --> G[CIS AWS Foundations]
    D --> H[PCI DSS]
    D --> I[NIST 800-53]

    E --> J[Generic Security Finding]

    F --> K[Security Hub Standards]
    G --> K
    H --> K
    I --> K
    J --> K

    K --> L[Compliance Dashboard]
```

## Cost Optimization Strategy

The following diagram shows the cost optimization strategy:

```mermaid
flowchart TD
    A[Start] --> B[Analyze Scan Results]

    B --> C{Finding Count > Threshold?}
    C -->|Yes| D[Apply Filtering]
    C -->|No| E[Use All Findings]

    D --> F[Filter by Severity]
    D --> G[Filter by Type]
    D --> H[Filter by Resource]

    F --> I[Combine Filters]
    G --> I
    H --> I

    I --> J[Selected Findings]
    E --> J

    J --> K[Batch Processing]
    K --> L[Import to Security Hub]

    L --> M[Monitor Costs]
    M --> N[End]
```