# Built-in Converters

ASH includes 2 built-in converters that preprocess files to make them suitable for security scanning. Converters handle file format transformations and archive extraction automatically.

> For detailed visual diagrams of the built-in converter architecture and workflows, see [Built-in Converter Diagrams](converters-diagrams.md).

## Converter Overview

| Converter                                   | Purpose                     | Input Formats    | Output                                        |
|---------------------------------------------|-----------------------------|------------------|-----------------------------------------------|
| **[Archive Converter](#archive-converter)** | Extract compressed archives | zip, tar, tar.gz | Extracted files of known scannable extensions |
| **[Jupyter Converter](#jupyter-converter)** | Process Jupyter notebooks   | .ipynb           | Python source code                            |

## Converter Details

### Archive Converter

**Purpose**: Automatically extracts compressed archives to enable scanning of contained files.

**Supported Formats**:
- ZIP files (.zip)
- TAR archives (.tar, .tar.gz, .tgz)

**Configuration**:
```yaml
converters:
  archive:
    enabled: true
    # The archive converter exposes no options. It extracts supported archives
    # so their contents can be scanned; there is nothing to tune per run.
```

**Key Features**:
- Recursive extraction of nested archives
- Size and depth limits for security
- Permission preservation
- Automatic cleanup after scanning

**Use Cases**:
- Scanning packaged applications
- Analyzing deployment artifacts
- Processing downloaded dependencies
- Auditing compressed source code

---

### Jupyter Converter

**Purpose**: Extracts Python code from Jupyter notebooks for security analysis.

**Configuration**:
```yaml
converters:
  jupyter:
    enabled: true
    options:
      tool_version: null      # Version constraint for the conversion tool
      install_timeout: 300    # Seconds allowed for tool installation
```

**Key Features**:
- Code cell extraction
- Cell number preservation for accurate line mapping
- Markdown cell processing (optional)
- Python syntax validation

**Use Cases**:
- Data science project security
- ML model code analysis
- Educational content scanning
- Research code auditing

## Configuration Examples

### Basic Configuration

```yaml
converters:
  archive:
    enabled: true
  jupyter:
    enabled: true
```

### Advanced Configuration

```yaml
converters:
  archive:
    enabled: true
    # The archive converter exposes no options. It extracts supported archives
    # so their contents can be scanned; there is nothing to tune per run.

  jupyter:
    enabled: true
    options:
      tool_version: null
      install_timeout: 300
```

## Best Practices

### Archive Security

```yaml
converters:
  archive:
    enabled: false             # The only lever is whether extraction runs at all
```

### Jupyter Processing

```yaml
converters:
  jupyter:
    enabled: true                # Cell-to-line mapping is always preserved
```

## Integration with Scanners

Converters automatically prepare files for scanner consumption:

```bash
# Archives are extracted, then contents scanned
ash project.zip --scanners bandit,semgrep

# Jupyter notebooks converted to Python, then scanned
ash analysis.ipynb --scanners bandit,detect-secrets
```

## Troubleshooting

### Archive Issues

**Extraction failures**:
```yaml
converters:
  archive:
    enabled: true                # Extraction errors are logged and the scan continues
```

**Large archives**:
```yaml
converters:
  archive:
    enabled: true
```

### Jupyter Issues

**Malformed notebooks**:
```yaml
converters:
  jupyter:
    enabled: true                # A notebook that will not parse is reported, not skipped silently
```

## Next Steps

- **[Scanner Configuration](scanners.md)**: Configure security scanners
- **[File Processing](../../advanced-usage.md)**: Advanced file handling
