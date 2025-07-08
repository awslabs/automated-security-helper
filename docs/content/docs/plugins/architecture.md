# ASH Plugin Architecture

This document provides visual diagrams of the ASH plugin architecture, workflows, and relationships.

> For more detailed diagrams specific to each plugin type, see:
> - [Scanner Plugin Diagrams](scanner-plugins-diagrams.md)
> - [Reporter Plugin Diagrams](reporter-plugins-diagrams.md)
> - [Converter Plugin Diagrams](converter-plugins-diagrams.md)
> - [Event Subscriber Diagrams](event-subscribers-diagrams.md)

## Plugin Architecture Overview

The following diagram shows the high-level architecture of the ASH plugin system:

```mermaid
graph TD
    A[ASH Core] --> B[Plugin Manager]
    B --> C[Scanner Plugins]
    B --> D[Reporter Plugins]
    B --> E[Converter Plugins]
    B --> F[Event Subscribers]

    C --> G[Scan Results]
    E --> H[Converted Files]
    G --> D
    H --> C

    subgraph "Plugin Types"
        C
        D
        E
        F
    end

    subgraph "Data Flow"
        G
        H
    end

```

## Plugin Lifecycle

The following diagram shows the lifecycle of plugins during an ASH scan:

```mermaid
sequenceDiagram
    participant User
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant CP as Converter Plugins
    participant SP as Scanner Plugins
    participant ES as Event Subscribers
    participant RP as Reporter Plugins

    User->>ASH: Start Scan
    ASH->>PM: Load Plugins
    PM->>CP: Initialize
    PM->>SP: Initialize
    PM->>ES: Initialize
    PM->>RP: Initialize

    ASH->>ES: Emit ScanStarted Event
    ES-->>ASH: Handle Event

    ASH->>CP: Convert Files
    CP-->>ASH: Converted Files

    ASH->>ES: Emit ConversionCompleted Event
    ES-->>ASH: Handle Event

    ASH->>SP: Scan Files
    SP-->>ASH: Scan Results

    ASH->>ES: Emit ScanCompleted Event
    ES-->>ASH: Handle Event

    ASH->>RP: Generate Reports
    RP-->>ASH: Reports

    ASH->>ES: Emit ReportingCompleted Event
    ES-->>ASH: Handle Event

    ASH-->>User: Scan Complete

```

## Data Flow Between Plugins

The following diagram shows the data flow between different types of plugins:

```mermaid
flowchart LR
    A[Source Files] --> B[Converter Plugins]
    B --> C[Converted Files]
    C --> D[Scanner Plugins]
    A --> D
    D --> E[Scan Results]
    E --> F[Reporter Plugins]
    F --> G[Reports]

    H[Event Subscribers] -.-> B
    H -.-> D
    H -.-> F

    subgraph "Input"
        A
    end

    subgraph "Processing"
        B
        C
        D
        E
        H
    end

    subgraph "Output"
        F
        G
    end

```

## Plugin Registration and Discovery

The following diagram shows how plugins are registered and discovered:

```mermaid
graph TD
    A[Plugin Module] --> B[__init__.py]
    B --> C[ASH_SCANNERS]
    B --> D[ASH_REPORTERS]
    B --> E[ASH_CONVERTERS]
    B --> F[ASH_EVENT_SUBSCRIBERS]

    G[ASH Configuration] --> H[ash_plugin_modules]
    H --> I[Plugin Manager]

    C --> I
    D --> I
    E --> I
    F --> I

    I --> J[Load Plugins]
    J --> K[Initialize Plugins]
    K --> L[Execute Plugins]

```

## Plugin Configuration Flow

The following diagram shows how plugin configuration flows through the system:

```mermaid
graph TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    B --> C[Global Configuration]
    B --> D[Scanner Configuration]
    B --> E[Reporter Configuration]
    B --> F[Converter Configuration]

    C --> G[Plugin Manager]
    D --> G
    E --> G
    F --> G

    G --> H[Scanner Plugins]
    G --> I[Reporter Plugins]
    G --> J[Converter Plugins]

    K[CLI Overrides] --> B

```

## Event System

The following diagram shows the event system in ASH:

```mermaid
graph TD
    A[ASH Core] --> B[Event Emitter]
    B --> C[ScanStarted]
    B --> D[ConversionStarted]
    B --> E[ConversionCompleted]
    B --> F[ScannerStarted]
    B --> G[ScannerCompleted]
    B --> H[ScanCompleted]
    B --> I[ReportingStarted]
    B --> J[ReportingCompleted]

    C --> K[Event Subscribers]
    D --> K
    E --> K
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K

    K --> L[Custom Actions]

```