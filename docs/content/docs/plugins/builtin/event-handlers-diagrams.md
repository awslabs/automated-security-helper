# Built-in Event Handler Diagrams

This document provides visual diagrams of the ASH built-in event handler architecture and workflows using Mermaid.

## Event System Architecture

The following diagram shows the high-level architecture of the ASH event system:

```mermaid
flowchart TD
    A[ASH Core] --> B[Event Emitter]

    B --> C[Event Registry]

    C --> D[Built-in Event Handlers]
    C --> E[Custom Event Handlers]

    D --> F[Scan Completion Logger]
    D --> G[Suppression Expiration Checker]

    H[Scanner Plugins] -.-> |Emit Events| B
    I[Converter Plugins] -.-> |Emit Events| B
    J[Reporter Plugins] -.-> |Emit Events| B

    F -.-> |Log Messages| K[Console Output]
    G -.-> |Warning Messages| K
```

## Event Flow Sequence

The following diagram shows the sequence of events during an ASH scan:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant EM as Event Manager
    participant SCL as Scan Completion Logger
    participant SEC as Suppression Expiration Checker
    participant SP as Scanner Plugins
    participant CP as Converter Plugins
    participant RP as Reporter Plugins

    ASH->>EM: Emit EXECUTION_START
    EM->>SEC: Notify EXECUTION_START
    SEC->>SEC: Check Suppression Expirations
    SEC-->>ASH: Log Expiration Warnings

    ASH->>EM: Emit CONVERSION_START
    EM->>CP: Notify CONVERSION_START

    CP->>CP: Convert Files
    CP-->>ASH: Return Converted Files

    ASH->>EM: Emit CONVERSION_COMPLETE

    ASH->>EM: Emit SCAN_START

    loop For Each Scanner
        SP->>SP: Scan Files
        SP-->>ASH: Return Results

        ASH->>EM: Emit SCAN_COMPLETE
        EM->>SCL: Notify SCAN_COMPLETE
        SCL->>SCL: Process Completion
        SCL-->>ASH: Log Remaining Scanners
    end

    ASH->>EM: Emit REPORTING_START

    RP->>RP: Generate Reports
    RP-->>ASH: Return Reports

    ASH->>EM: Emit REPORTING_COMPLETE

    ASH->>EM: Emit EXECUTION_COMPLETE
```

## Event Handler Registration

The following diagram shows how event handlers are registered:

```mermaid
flowchart TD
    A[ASH Core] --> B[Plugin Manager]

    B --> C[Event Registry]

    D[Built-in Event Handlers] --> E[ASH_EVENT_HANDLERS Dictionary]
    F[Custom Event Handlers] --> G[User ASH_EVENT_HANDLERS Dictionary]

    E --> H[Event Type Mapping]
    G --> H

    H --> I[SCAN_COMPLETE Handlers]
    H --> J[EXECUTION_START Handlers]
    H --> K[Other Event Type Handlers]

    I --> L[Scan Completion Logger]
    J --> M[Suppression Expiration Checker]

    C --> I
    C --> J
    C --> K
```

## Scan Completion Logger Flow

The following diagram shows the flow of the Scan Completion Logger:

```mermaid
flowchart TD
    A[SCAN_COMPLETE Event] --> B[Scan Completion Logger]

    B --> C[Extract Event Data]

    C --> D[Get Scanner Name]
    C --> E[Get Completed Count]
    C --> F[Get Total Count]
    C --> G[Get Remaining Count]
    C --> H[Get Remaining Scanners]

    D --> I[Format Log Message]
    E --> I
    F --> I
    G --> I
    H --> I

    I --> J{Remaining Scanners?}

    J -->|Yes| K[Log Remaining Scanners]
    J -->|No| L[Log All Complete]

    K --> M[Return True]
    L --> M
```

## Suppression Expiration Checker Flow

The following diagram shows the flow of the Suppression Expiration Checker:

```mermaid
flowchart TD
    A[EXECUTION_START Event] --> B[Suppression Expiration Checker]

    B --> C[Extract Event Data]

    C --> D[Get Configuration]

    D --> E[Extract Suppressions]

    E --> F{Has Suppressions?}

    F -->|Yes| G[Check Expiration Dates]
    F -->|No| H[Skip Check]

    G --> I{Any Expiring Soon?}

    I -->|Yes| J[Format Warning Message]
    I -->|No| K[Skip Warning]

    J --> L[Log Warning Message]

    L --> M[Return True]
    H --> M
    K --> M
```

## Event Type Hierarchy

The following diagram shows the hierarchy of event types:

```mermaid
flowchart TD
    A[ASH Events] --> B[Phase Events]
    A --> C[Status Events]

    B --> D[EXECUTION_START]
    B --> E[EXECUTION_COMPLETE]
    B --> F[CONVERSION_START]
    B --> G[CONVERSION_COMPLETE]
    B --> H[SCAN_START]
    B --> I[SCAN_COMPLETE]
    B --> J[REPORTING_START]
    B --> K[REPORTING_COMPLETE]

    C --> L[INFO]
    C --> M[WARNING]
    C --> N[ERROR]

    D --> O[Suppression Expiration Checker]
    I --> P[Scan Completion Logger]
```

## Event Data Flow

The following diagram shows the data flow through the event system:

```mermaid
flowchart LR
    A[Event Source] --> B[Event Data]

    B --> C[Event Type]
    B --> D[Phase Data]
    B --> E[Plugin Context]
    B --> F[Additional Data]

    C --> G[Event Registry]

    G --> H[Event Handlers]

    D --> H
    E --> H
    F --> H

    H --> I[Handler Actions]

    I --> J[Logging]
    I --> K[Notifications]
    I --> L[Custom Logic]
```

## Custom Event Handler Integration

The following diagram shows how custom event handlers can be integrated:

```mermaid
flowchart TD
    A[Custom Plugin Module] --> B[__init__.py]

    B --> C[Define Event Handlers]
    C --> D[Create ASH_EVENT_HANDLERS Dictionary]

    D --> E{Event Type}

    E -->|SCAN_COMPLETE| F[Handler List 1]
    E -->|EXECUTION_START| G[Handler List 2]
    E -->|ERROR| H[Handler List 3]

    F --> I[Handler Function 1]
    F --> J[Handler Function 2]

    G --> K[Handler Function 3]

    H --> L[Handler Function 4]

    M[ASH Plugin Manager] --> N[Load Plugin Module]
    N --> O[Register Event Handlers]

    D --> O
```