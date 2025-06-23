# Reporter Plugin Diagrams

This document provides visual diagrams of the ASH reporter plugin architecture using Mermaid.

## Reporter Plugin Lifecycle

The following diagram shows the lifecycle of a reporter plugin during an ASH scan:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant RP as Reporter Plugin
    participant FS as File System
    participant ES as Event System
    participant EXT as External Systems

    ASH->>PM: Load Reporter Plugins
    PM->>RP: Initialize
    RP-->>PM: Return Initialized Plugin

    ASH->>ES: Emit ReportingStarted Event

    ASH->>RP: Validate Reporter
    RP-->>ASH: Return Validation Status

    ASH->>RP: report(aggregated_results)
    RP->>RP: Process Results

    alt Local Report
        RP->>FS: Write Report File
        FS-->>RP: File Written
    else External Report
        RP->>EXT: Send Report Data
        EXT-->>RP: Confirmation
    end

    RP-->>ASH: Return Report URL/Path

    ASH->>ES: Emit ReportingCompleted Event
```

## Reporter Plugin Data Flow

The following diagram shows the data flow through a reporter plugin:

```mermaid
flowchart LR
    A[AshAggregatedResults] --> B[Reporter Plugin]

    subgraph Reporter Plugin
        C[Results Processor] --> D[Format Converter]
        D --> E[Output Generator]
    end

    B --> F[Local File]
    B --> G[External System]
    B --> H[Console Output]

    F --> I[Report Path]
    G --> J[External URL]
    H --> K[Terminal Display]
```

## Reporter Plugin Class Hierarchy

The following diagram shows the class hierarchy for reporter plugins:

```mermaid
classDiagram
    class PluginBase {
        +context: PluginContext
        +config: Any
        +validate() bool
        +model_post_init(context)
        #_plugin_log(message, level, target_type, append_to_stream)
        #_run_subprocess(cmd, stdout_preference, stderr_preference)
    }

    class ReporterPluginBase {
        +report(model) str
        +dependencies_satisfied: bool
    }

    class ReporterPluginConfigBase {
        +name: str
        +extension: str
        +enabled: bool
        +options: ReporterOptionsBase
    }

    class ReporterOptionsBase {
        +include_details: bool
        +max_findings: int
    }

    class CustomReporter {
        +report(model) str
    }

    PluginBase <|-- ReporterPluginBase
    ReporterPluginBase <|-- CustomReporter
    ReporterPluginConfigBase -- CustomReporter : configures
    ReporterOptionsBase -- ReporterPluginConfigBase : contains
```

## Reporter Plugin Configuration Flow

The following diagram shows how configuration flows through a reporter plugin:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Reporter Configuration]
    E --> F[Reporter Plugin]

    subgraph Reporter Plugin
        G[Validate Config] --> H[Apply Config]
        H --> I[Use in Report Logic]
    end

    F --> J[Report Output]
```

## Reporter Integration with External Systems

The following diagram shows how reporter plugins can integrate with external systems:

```mermaid
flowchart LR
    A[ASH Core] --> B[Reporter Plugin]

    B --> C[Local File System]
    B --> D[Cloud Storage]
    B --> E[Issue Trackers]
    B --> F[CI/CD Systems]
    B --> G[Dashboards]
    B --> H[Notification Systems]

    subgraph External Systems
        D
        E
        F
        G
        H
    end

    C --> I[HTML Reports]
    C --> J[JSON Reports]
    C --> K[SARIF Reports]
    C --> L[CSV Reports]
    C --> M[Markdown Reports]
```