# Scanner Plugin Diagrams

This document provides visual diagrams of the ASH scanner plugin architecture using Mermaid.

## Scanner Plugin Lifecycle

The following diagram shows the lifecycle of a scanner plugin during an ASH scan:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant SP as Scanner Plugin
    participant FS as File System
    participant ES as Event System

    ASH->>PM: Load Scanner Plugins
    PM->>SP: Initialize
    SP-->>PM: Return Initialized Plugin

    ASH->>ES: Emit ScanStarted Event

    ASH->>SP: Validate Scanner
    SP-->>ASH: Return Validation Status

    ASH->>SP: scan(target, target_type)
    SP->>FS: Read Target Files
    FS-->>SP: Return File Contents

    SP->>SP: Process Files
    Note over SP: Run Security Analysis

    SP->>FS: Write SARIF Report
    SP-->>ASH: Return ScanResultsContainer

    ASH->>ES: Emit ScanCompleted Event
```

## Scanner Plugin Data Flow

The following diagram shows the data flow through a scanner plugin:

```mermaid
flowchart LR
    A[Source Files] --> B[Scanner Plugin]
    C[Converted Files] --> B

    subgraph Scanner Plugin
        D[File Reader] --> E[Security Analyzer]
        E --> F[Results Processor]
        F --> G[SARIF Generator]
    end

    B --> H[ScanResultsContainer]
    H --> I[SARIF Report]
    H --> J[Error Messages]
    H --> K[Metadata]

    I --> L[Reporter Plugins]
```

## Scanner Plugin Class Hierarchy

The following diagram shows the class hierarchy for scanner plugins:

```mermaid
classDiagram
    class PluginBase {
        +context: PluginContext
        +config: Any
        +validate_plugin_dependencies() bool
        +model_post_init(context)
        #_plugin_log(message, level, target_type, append_to_stream)
        #_run_subprocess(cmd, stdout_preference, stderr_preference)
    }

    class ScannerPluginBase {
        +scan(target, target_type, global_ignore_paths, config) ScanResultsContainer
        +results_dir: Path
        #_create_sarif_report(findings, tool_name) dict
        #_write_sarif_report(sarif_report, filename) Path
    }

    class ScannerPluginConfigBase {
        +name: str
        +enabled: bool
        +options: ScannerOptionsBase
    }

    class ScannerOptionsBase {
        +severity_threshold: str
        +include_tests: bool
    }

    class CustomScanner {
        +scan(target, target_type, global_ignore_paths, config) ScanResultsContainer
    }

    PluginBase <|-- ScannerPluginBase
    ScannerPluginBase <|-- CustomScanner
    ScannerPluginConfigBase -- CustomScanner : configures
    ScannerOptionsBase -- ScannerPluginConfigBase : contains
```

## Scanner Plugin Configuration Flow

The following diagram shows how configuration flows through a scanner plugin:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Scanner Configuration]
    E --> F[Scanner Plugin]

    subgraph Scanner Plugin
        G[Validate Config] --> H[Apply Config]
        H --> I[Use in Scan Logic]
    end

    F --> J[ScanResultsContainer]
```

## Scanner Integration with ASH Core

The following diagram shows how scanner plugins integrate with the ASH core:

```mermaid
flowchart TD
    A[ASH CLI] --> B[ASH Core]
    B --> C[Plugin Manager]
    C --> D[Scanner Registry]
    D --> E[Scanner Plugins]

    E --> F[Scan Results]
    F --> G[Results Aggregator]
    G --> H[Reporter Plugins]

    I[Event System] -.-> E
    I -.-> G
    I -.-> H
```