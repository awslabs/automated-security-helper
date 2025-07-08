# S3 Reporter Diagrams

This document provides visual diagrams of the ASH S3 Reporter architecture and workflows using Mermaid.

## Architecture Overview

The following diagram shows the high-level architecture of the S3 Reporter:

```mermaid
flowchart LR
    A[ASH Core] --> B[S3 Reporter]
    B --> C[AWS SDK for Python]
    C --> D[Amazon S3 API]

    B --> E[Scan Results]
    E --> F[Format Converter]
    F --> G[S3 Object Creator]
    G --> C

    D --> H[S3 Bucket]
    H --> I[S3 Object]

    subgraph "AWS Cloud"
        D
        H
        I
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

The following diagram shows the sequence of operations in the S3 Reporter:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant SR as S3 Reporter
    participant SDK as AWS SDK
    participant S3 as Amazon S3
    participant FS as File System

    ASH->>SR: report(aggregated_results)
    SR->>SR: Process Scan Results

    alt JSON Format
        SR->>SR: Convert to JSON
    else YAML Format
        SR->>SR: Convert to YAML
    end

    SR->>SR: Generate S3 Key with Timestamp

    SR->>SDK: Create S3 Session
    SR->>SDK: Put Object Request with Retry
    SDK->>S3: API Call
    S3-->>SDK: Response
    SDK-->>SR: Return Response

    SR->>FS: Write Local Copy

    SR->>SR: Process API Response
    SR->>SR: Handle Errors

    SR-->>ASH: Return S3 URL or Error
```

## Format Conversion Process

The following diagram shows the format conversion process:

```mermaid
flowchart TD
    A[ASH Aggregated Results] --> B[Convert to Simple Dict]

    B --> C{Format Type?}

    C -->|JSON| D[Serialize to JSON]
    C -->|YAML| E[Serialize to YAML]

    D --> F[Set Content Type to application/json]
    E --> G[Set Content Type to application/yaml]

    F --> H[S3 Object Content]
    G --> H

    H --> I[S3 API]
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
    D -->|No Such Bucket| G[Check Bucket Exists]
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

    C --> N[Generate S3 URL]
    J --> O[Return Error Message]
    K --> O

    N --> P[Return S3 URL]

    P --> Q[End]
    O --> Q
```

> **Note**: The implementation now includes retry logic with exponential backoff, improving the reliability of the S3 Reporter.

## S3 Object Naming and Organization

The following diagram shows the S3 object naming and organization process:

```mermaid
flowchart TD
    A[Start] --> B[Get Timestamp from Scan Results]

    B --> C[Get Key Prefix from Configuration]

    C --> D{File Format?}

    D -->|JSON| E[Set Extension to .json]
    D -->|YAML| F[Set Extension to .yaml]

    E --> G[Generate S3 Key]
    F --> G

    G --> H[Final S3 Key: prefix/ash-report-timestamp.extension]

    H --> I[End]
```

## Configuration Flow

The following diagram shows the configuration flow:

```mermaid
flowchart TD
    A[Start] --> B{AWS Region Set?}

    B -->|Yes| C{Bucket Name Set?}
    B -->|No| D[Use AWS_REGION Environment Variable]

    D --> E{Environment Variable Set?}

    E -->|Yes| C
    E -->|No| F[Validation Fails]

    C -->|Yes| G[Validation Succeeds]
    C -->|No| H[Use ASH_S3_BUCKET_NAME Environment Variable]

    H --> I{Environment Variable Set?}

    I -->|Yes| G
    I -->|No| F

    G --> J{AWS Profile Set?}

    J -->|Yes| K[Use Configured Profile]
    J -->|No| L[Use Default Profile]

    K --> M[Reporter Ready]
    L --> M

    F --> N[Reporter Disabled]

    M --> O[End]
    N --> O
```

## Local File Output

The following diagram shows the local file output process:

```mermaid
flowchart TD
    A[Start] --> B[Generate Report Content]

    B --> C[Upload to S3 with Retry]

    C --> D[Create Reports Directory]

    D --> E[Write Local Copy]

    E --> F[Return S3 URL]

    F --> G[End]
```

## Integration with Other AWS Services

The following diagram shows how the S3 Reporter can integrate with other AWS services:

```mermaid
flowchart LR
    A[ASH Scan Results] --> B[S3 Reporter]

    B --> C[Amazon S3]

    C --> D[Amazon Athena]
    C --> E[AWS Lambda]
    C --> F[Amazon QuickSight]
    C --> G[AWS Glue]

    D --> H[SQL Analysis]
    E --> I[Automated Processing]
    F --> J[Visualization]
    G --> K[ETL Processing]

    subgraph "AWS Ecosystem"
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