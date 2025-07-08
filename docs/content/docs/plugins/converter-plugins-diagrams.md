# Converter Plugin Diagrams

This document provides visual diagrams of the ASH converter plugin architecture using Mermaid.

## Converter Plugin Lifecycle

The following diagram shows the lifecycle of a converter plugin during an ASH scan:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant CP as Converter Plugin
    participant FS as File System
    participant ES as Event System

    ASH->>PM: Load Converter Plugins
    PM->>CP: Initialize
    CP-->>PM: Return Initialized Plugin

    ASH->>ES: Emit ConversionStarted Event

    ASH->>CP: Validate Converter
    CP-->>ASH: Return Validation Status

    ASH->>CP: convert(target)
    CP->>FS: Read Source Files
    FS-->>CP: Return File Contents

    CP->>CP: Process Files
    Note over CP: Transform File Content

    CP->>FS: Write Converted Files
    FS-->>CP: Files Written

    CP-->>ASH: Return Converted Path

    ASH->>ES: Emit ConversionCompleted Event
```

## Converter Plugin Data Flow

The following diagram shows the data flow through a converter plugin:

```mermaid
flowchart LR
    A[Source Files] --> B[Converter Plugin]

    subgraph Converter Plugin
        C[File Reader] --> D[Content Transformer]
        D --> E[File Writer]
    end

    B --> F[Converted Files]
    F --> G[Scanner Plugins]
```

## Converter Plugin Class Hierarchy

The following diagram shows the class hierarchy for converter plugins:

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

    class ConverterPluginBase {
        +convert(target) Path
        +converted_dir: Path
    }

    class ConverterPluginConfigBase {
        +name: str
        +enabled: bool
        +options: ConverterOptionsBase
    }

    class ConverterOptionsBase {
        +file_extensions: List[str]
        +preserve_line_numbers: bool
    }

    class CustomConverter {
        +convert(target) Path
    }

    PluginBase <|-- ConverterPluginBase
    ConverterPluginBase <|-- CustomConverter
    ConverterPluginConfigBase -- CustomConverter : configures
    ConverterOptionsBase -- ConverterPluginConfigBase : contains
```

## Converter Plugin Configuration Flow

The following diagram shows how configuration flows through a converter plugin:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Converter Configuration]
    E --> F[Converter Plugin]

    subgraph Converter Plugin
        G[Validate Config] --> H[Apply Config]
        H --> I[Use in Convert Logic]
    end

    F --> J[Converted Files]
```

## File Transformation Process

The following diagram shows the file transformation process in a converter plugin:

```mermaid
flowchart LR
    A[Source File] --> B[Converter Plugin]

    subgraph Converter Plugin
        C[Parse File] --> D[Transform Content]
        D --> E[Preserve Line Numbers]
        E --> F[Generate Output]
    end

    B --> G[Converted File]

    H[Source Line Mapping] -.-> B
    B -.-> I[Target Line Mapping]

    J[Original Line Numbers] -.-> H
    I -.-> K[Converted Line Numbers]
```

## Converter Integration with ASH Core

The following diagram shows how converter plugins integrate with the ASH core:

```mermaid
flowchart TD
    A[ASH CLI] --> B[ASH Core]
    B --> C[Plugin Manager]
    C --> D[Converter Registry]
    D --> E[Converter Plugins]

    E --> F[Converted Files]
    F --> G[Scanner Plugins]
    G --> H[Scan Results]

    I[Event System] -.-> E
    I -.-> G
```