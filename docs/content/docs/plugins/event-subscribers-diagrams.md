# Event Subscriber Diagrams

This document provides visual diagrams of the ASH event system architecture using Mermaid.

## Event System Overview

The following diagram shows the high-level architecture of the ASH event system:

```mermaid
flowchart TD
    A[ASH Core] --> B[Event Emitter]
    B --> C[Event Registry]
    C --> D[Event Subscribers]

    E[Scanner Plugins] -.-> B
    F[Converter Plugins] -.-> B
    G[Reporter Plugins] -.-> B

    D --> H[Custom Actions]
    D --> I[Notifications]
    D --> J[Logging]
    D --> K[Metrics]
    D --> L[External Systems]
```

## Event Flow Sequence

The following diagram shows the sequence of events during an ASH scan:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant EM as Event Manager
    participant ES as Event Subscribers
    participant CP as Converter Plugins
    participant SP as Scanner Plugins
    participant RP as Reporter Plugins

    ASH->>EM: Emit ScanStarted
    EM->>ES: Notify ScanStarted
    ES-->>EM: Handle ScanStarted

    ASH->>EM: Emit ConversionStarted
    EM->>ES: Notify ConversionStarted
    ES-->>EM: Handle ConversionStarted

    ASH->>CP: Convert Files
    CP-->>ASH: Return Converted Files

    ASH->>EM: Emit ConversionCompleted
    EM->>ES: Notify ConversionCompleted
    ES-->>EM: Handle ConversionCompleted

    ASH->>EM: Emit ScannerStarted
    EM->>ES: Notify ScannerStarted
    ES-->>EM: Handle ScannerStarted

    ASH->>SP: Scan Files
    SP-->>ASH: Return Scan Results

    ASH->>EM: Emit ScannerCompleted
    EM->>ES: Notify ScannerCompleted
    ES-->>EM: Handle ScannerCompleted

    ASH->>EM: Emit ScanCompleted
    EM->>ES: Notify ScanCompleted
    ES-->>EM: Handle ScanCompleted

    ASH->>EM: Emit ReportingStarted
    EM->>ES: Notify ReportingStarted
    ES-->>EM: Handle ReportingStarted

    ASH->>RP: Generate Reports
    RP-->>ASH: Return Reports

    ASH->>EM: Emit ReportingCompleted
    EM->>ES: Notify ReportingCompleted
    ES-->>EM: Handle ReportingCompleted
```

## Event Subscriber Registration

The following diagram shows how event subscribers are registered:

```mermaid
flowchart TD
    A[Plugin Module] --> B[__init__.py]
    B --> C[ASH_EVENT_HANDLERS]

    C --> D[Event Type 1]
    C --> E[Event Type 2]
    C --> F[Event Type 3]

    D --> G[Handler Function 1]
    D --> H[Handler Function 2]
    E --> I[Handler Function 3]
    F --> J[Handler Function 4]

    K[Plugin Manager] --> L[Load Modules]
    L --> M[Discover Event Handlers]
    M --> N[Register Handlers]

    C -.-> N
```

## Event Data Flow

The following diagram shows the data flow through the event system:

```mermaid
flowchart LR
    A[ASH Core] --> B[Event Data]
    B --> C[Event Emitter]

    C --> D[Event Type]
    D --> E[Event Handlers]

    E --> F[Handler 1]
    E --> G[Handler 2]
    E --> H[Handler 3]

    F --> I[Custom Action 1]
    G --> J[Custom Action 2]
    H --> K[Custom Action 3]

    L[Event Context] -.-> B
    M[Plugin Context] -.-> B
    N[Phase Data] -.-> B
```

## Event Handler Execution

The following diagram shows the execution flow of event handlers:

```mermaid
flowchart TD
    A[Event Triggered] --> B{Has Handlers?}
    B -->|Yes| C[Get Handler List]
    B -->|No| D[End]

    C --> E[Execute Handler 1]
    E --> F{Success?}
    F -->|Yes| G[Execute Handler 2]
    F -->|No| H[Log Error]
    H --> G

    G --> I{Success?}
    I -->|Yes| J[Execute Handler 3]
    I -->|No| K[Log Error]
    K --> J

    J --> L{Success?}
    L -->|Yes| M[All Handlers Complete]
    L -->|No| N[Log Error]
    N --> M

    M --> D
```

## Integration with External Systems

The following diagram shows how event subscribers can integrate with external systems:

```mermaid
flowchart LR
    A[ASH Event] --> B[Event Subscriber]

    B --> C[Slack Notifications]
    B --> D[Email Alerts]
    B --> E[Metrics Database]
    B --> F[Logging System]
    B --> G[CI/CD Pipeline]
    B --> H[Issue Tracker]

    subgraph External Systems
        C
        D
        E
        F
        G
        H
    end
```