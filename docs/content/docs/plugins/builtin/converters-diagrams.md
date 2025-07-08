# Built-in Converter Diagrams

This document provides visual diagrams of the ASH built-in converter architecture and workflows using Mermaid.

## Converter Architecture Overview

The following diagram shows the high-level architecture of the ASH built-in converters:

```mermaid
flowchart TD
    A[ASH Core] --> B[Plugin Manager]
    B --> C[Converter Registry]

    C --> D[Built-in Converters]

    D --> E[Archive Converter]
    D --> F[Jupyter Converter]

    G[Source Files] --> D

    E --> H[Extracted Files]
    F --> I[Python Files]

    H --> J[Scanner Plugins]
    I --> J
```

## Converter Execution Flow

The following diagram shows the execution flow of the built-in converters:

```mermaid
sequenceDiagram
    participant ASH as ASH Core
    participant PM as Plugin Manager
    participant CR as Converter Registry
    participant CV as Converter
    participant FS as File System
    participant ES as Event System

    ASH->>PM: Load Converters
    PM->>CR: Get Registered Converters
    CR-->>PM: Return Converter List

    ASH->>ES: Emit ConversionStarted Event

    loop For Each Converter
        ASH->>CV: Validate Converter
        CV-->>ASH: Return Validation Status

        alt Converter Valid
            ASH->>CV: convert(target)
            CV->>FS: Read Source Files
            FS-->>CV: Return File Contents

            CV->>CV: Process Files
            Note over CV: Transform File Content

            CV->>FS: Write Converted Files
            FS-->>CV: Files Written

            CV-->>ASH: Return Converted Path
        else Converter Invalid
            ASH->>ES: Emit ConverterError Event
        end
    end

    ASH->>ES: Emit ConversionCompleted Event
```

## Archive Converter Workflow

The following diagram shows the workflow of the Archive Converter:

```mermaid
flowchart TD
    A[Source Archive] --> B[Archive Converter]

    B --> C{Archive Type?}

    C -->|ZIP| D[Extract ZIP]
    C -->|TAR| E[Extract TAR]
    C -->|TAR.GZ| F[Extract TAR.GZ]

    D --> G[Extracted Files]
    E --> G
    F --> G

    G --> H{Contains Nested Archives?}

    H -->|Yes| I{Max Depth Reached?}
    H -->|No| J[Proceed to Scanning]

    I -->|Yes| K[Skip Nested Archives]
    I -->|No| L[Process Nested Archives]

    L --> B

    K --> J

    J --> M[Scanner Plugins]
```

## Jupyter Converter Workflow

The following diagram shows the workflow of the Jupyter Converter:

```mermaid
flowchart TD
    A[Jupyter Notebook] --> B[Jupyter Converter]

    B --> C[Parse Notebook JSON]

    C --> D[Extract Cells]

    D --> E{Cell Type?}

    E -->|Code| F[Extract Code]
    E -->|Markdown| G{Extract Markdown?}

    G -->|Yes| H[Convert to Comments]
    G -->|No| I[Skip Cell]

    F --> J[Combine Code]
    H --> J

    J --> K[Add Cell Markers]

    K --> L[Write Python File]

    L --> M[Scanner Plugins]
```

## Converter Configuration Flow

The following diagram shows how configuration flows through the built-in converters:

```mermaid
flowchart TD
    A[.ash/.ash.yaml] --> B[Configuration Parser]
    C[CLI Arguments] --> B
    B --> D[ASH Configuration]
    D --> E[Converter Configuration]

    E --> F[Global Converter Settings]
    E --> G[Converter-Specific Settings]

    F --> H[Converted Directory]
    F --> I[Enabled Converters]

    G --> J[Archive Converter Config]
    G --> K[Jupyter Converter Config]

    J --> L[Archive Converter]
    K --> M[Jupyter Converter]
```

## File Type Processing

The following diagram shows how different file types are processed by converters:

```mermaid
flowchart LR
    A[Source Files] --> B{File Type?}

    B -->|.zip, .tar, .tar.gz| C[Archive Converter]
    B -->|.ipynb| D[Jupyter Converter]
    B -->|Other| E[No Conversion]

    C --> F[Extracted Files]
    D --> G[Python Files]
    E --> H[Original Files]

    F --> I[Scanner Plugins]
    G --> I
    H --> I
```

## Converter Error Handling

The following diagram shows the error handling flow in converters:

```mermaid
flowchart TD
    A[Start Conversion] --> B{Converter Available?}

    B -->|Yes| C[Run Converter]
    B -->|No| D[Skip Conversion]

    C --> E{Conversion Successful?}

    E -->|Yes| F[Return Converted Path]
    E -->|No| G{Error Type?}

    G -->|File Format Error| H[Log Format Error]
    G -->|Extraction Error| I[Log Extraction Error]
    G -->|File System Error| J[Log File System Error]
    G -->|Other| K[Log Generic Error]

    H --> L{Continue on Error?}
    I --> L
    J --> L
    K --> L

    L -->|Yes| D
    L -->|No| M[Abort Conversion]

    F --> N[Proceed to Scanning]
    D --> N
    M --> O[End with Error]
```

## Converter Integration with Scanners

The following diagram shows how converters integrate with scanners:

```mermaid
flowchart LR
    A[Source Files] --> B[Converters]

    B --> C[Converted Files]

    C --> D[Scanner 1]
    C --> E[Scanner 2]
    C --> F[Scanner 3]

    D --> G[Results 1]
    E --> H[Results 2]
    F --> I[Results 3]

    G --> J[Results Aggregator]
    H --> J
    I --> J

    J --> K[Reporter Plugins]
```