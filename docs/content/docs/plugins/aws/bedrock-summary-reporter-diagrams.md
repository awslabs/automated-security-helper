# Bedrock Summary Reporter Diagrams

This document provides visual diagrams of the ASH Bedrock Summary Reporter architecture and workflows using Mermaid.

## Architecture Overview

The following diagram shows the high-level architecture of the Bedrock Summary Reporter:

```mermaid
flowchart TD
    A[ASH Core] --> B[Bedrock Summary Reporter]
    B --> C[AWS SDK for Python]
    C --> D[Amazon Bedrock API]
    D --> E[Foundation Models]

    B --> F[Scan Results]
    F --> G[Findings Processor]
    G --> H[Prompt Generator]
    H --> C

    E --> I[AI-Generated Summary]
    I --> J[Report Formatter]
    J --> K[Markdown Reports]

    subgraph "AWS Cloud"
        D
        E
    end

    subgraph "Local Processing"
        A
        B
        F
        G
        H
        J
        K
    end
```

## Sequence Diagram

The following diagram shows the sequence of operations in the Bedrock Summary Reporter:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant BSR as Bedrock Summary Reporter
    participant SDK as AWS SDK for Python
    participant Bedrock as Amazon Bedrock
    participant FM as Foundation Model
    participant FS as File System

    ASH->>BSR: report(aggregated_results)
    BSR->>BSR: Process Scan Results
    BSR->>BSR: Generate Prompt

    BSR->>SDK: _invoke_bedrock_model()
    SDK->>Bedrock: bedrock_runtime.converse()
    Bedrock->>FM: Process Prompt

    alt Streaming Response
        FM-->>Bedrock: Stream Chunks
        Bedrock-->>SDK: Stream Response
        SDK-->>BSR: Process Chunks
        BSR->>BSR: Accumulate Response
    else Standard Response
        FM-->>Bedrock: Complete Response
        Bedrock-->>SDK: Return Response
        SDK-->>BSR: Return Response
    end

    BSR->>BSR: Format AI Response
    BSR->>FS: Write Executive Summary
    BSR->>FS: Write Technical Analysis
    BSR->>FS: Write Full Report

    BSR-->>ASH: Return Report Path
```

## Chunking and Processing Flow

The following diagram shows how the Bedrock Summary Reporter processes large scan results in chunks:

```mermaid
flowchart TD
    A[Scan Results] --> B[Findings Processor]

    B --> C[Group by Severity]
    C --> D[Critical Findings]
    C --> E[High Findings]
    C --> F[Medium Findings]
    C --> G[Low Findings]

    D --> H[Chunk 1: Critical]
    E --> I[Chunk 2: High]
    F --> J[Chunk 3: Medium]
    G --> K[Chunk 4: Low]

    H --> L[Generate Prompt 1]
    I --> M[Generate Prompt 2]
    J --> N[Generate Prompt 3]
    K --> O[Generate Prompt 4]

    L --> P[Bedrock API Call 1]
    M --> Q[Bedrock API Call 2]
    N --> R[Bedrock API Call 3]
    O --> S[Bedrock API Call 4]

    P --> T[Response 1]
    Q --> U[Response 2]
    R --> V[Response 3]
    S --> W[Response 4]

    T --> X[Merge Responses]
    U --> X
    V --> X
    W --> X

    X --> Y[Final Report]
```

## Report Generation Process

The following diagram shows the report generation process:

```mermaid
flowchart TD
    A[Scan Results] --> B[Extract Metadata]
    A --> C[Extract Findings]

    B --> D[Project Context]
    C --> E[Findings Analysis]

    D --> F[Generate Executive Context]
    E --> G[Generate Technical Context]

    F --> H[Executive Prompt]
    G --> I[Technical Prompt]

    H --> J[Bedrock API]
    I --> J

    J --> K[Executive Summary]
    J --> L[Technical Analysis]

    K --> M[Executive Report]
    L --> N[Technical Report]

    M --> O[Final Report]
    N --> O
```

## Model Selection Logic

The following diagram shows the model selection logic with fallback support:

```mermaid
flowchart TD
    A[Start] --> B{Config has model_id?}
    B -->|Yes| C[Use configured model]
    B -->|No| D{Environment variable set?}

    D -->|Yes| E[Use env var model]
    D -->|No| F[Use default model]

    C --> G[Validate Model Access]
    E --> G
    F --> G

    G -->|Access OK| H[Use Selected Model]
    G -->|No Access| I{Fallback Enabled?}

    I -->|Yes| J[Get Fallback Model]
    I -->|No| K[Raise Error]

    J --> L[Validate Fallback]
    L -->|Access OK| H
    L -->|No Access| K

    H --> M[End]
    K --> N[End with Error]
```

## Cost Optimization Strategy

The following diagram shows the cost optimization strategy:

```mermaid
flowchart TD
    A[Start] --> B[Analyze Scan Results]

    B --> C{Group by Severity?}
    C -->|Yes| D[Group Findings by Severity]
    C -->|No| E[Use All Findings]

    D --> F[Process Each Severity Group]
    E --> G[Process All Findings Together]

    F --> H[Apply Finding Limits]
    G --> H

    H --> I[Generate Prompt]
    I --> J[Execute API Call]
    J --> K[End]
```

## Integration with AWS Services

The following diagram shows how the Bedrock Summary Reporter integrates with other AWS services:

```mermaid
flowchart LR
    A[ASH Core] --> B[Bedrock Summary Reporter]

    B --> C[Amazon Bedrock]
    B --> D[Amazon S3]
    B --> E[AWS CloudWatch]

    C --> F[Foundation Models]
    D --> G[Report Storage]
    E --> H[Usage Metrics]

    I[IAM] -.-> C
    I -.-> D
    I -.-> E

    J[AWS SDK for Python] -.-> C
    J -.-> D
    J -.-> E

    K[AWS CLI] -.-> L[Configure]
    L -.-> I
```

## Error Handling Flow

The following diagram shows the error handling flow with retry logic and fallback models:

```mermaid
flowchart TD
    A[Start API Call] --> B{API Call Successful?}

    B -->|Yes| C[Process Response]
    B -->|No| D{Error Type?}

    D -->|Throttling| E[Apply Exponential Backoff]
    D -->|Access Denied| F[Check IAM Permissions]
    D -->|Model Not Found| G[Check Model Availability]
    D -->|Other| H[Log Error Details]

    E --> I[Retry API Call]
    F --> J[Log Permission Error]
    G --> K{Fallback Enabled?}
    H --> L[Return Error Status]

    K -->|Yes| M[Try Fallback Model]
    K -->|No| L

    I --> N{Retry Successful?}
    N -->|Yes| C
    N -->|No| O{Max Retries Reached?}

    O -->|Yes| L
    O -->|No| E

    M --> P{Fallback Available?}
    P -->|Yes| Q[Use Fallback]
    P -->|No| L

    Q --> R{Fallback Successful?}
    R -->|Yes| C
    R -->|No| L

    C --> S[Complete Processing]
    J --> T[End with Error]
    L --> T
    S --> U[End Successfully]
```

## Custom Prompt Flow

The following diagram shows the custom prompt generation flow:

```mermaid
flowchart TD
    A[Start Prompt Generation] --> B{Custom Prompt Provided?}

    B -->|Yes| C[Use Custom Prompt Template]
    B -->|No| D{Summary Style?}

    D -->|Executive| E[Use Executive Template]
    D -->|Technical| F[Use Technical Template]
    D -->|Detailed| G[Use Detailed Template]

    C --> H[Insert Scan Metadata]
    E --> H
    F --> H
    G --> H

    H --> I[Insert Finding Data]
    I --> J{Include Code Snippets?}

    J -->|Yes| K[Add Code Snippets]
    J -->|No| L[Skip Code Snippets]

    K --> M[Format Final Prompt]
    L --> M

    M --> N{Prompt Size > Limit?}
    N -->|Yes| O[Apply Truncation Strategy]
    N -->|No| P[Use Full Prompt]

    O --> Q[Final Prompt]
    P --> Q

    Q --> R[End]
```