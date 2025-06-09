# Built-in Converters

ASH includes 2 built-in converters that preprocess files to make them suitable for security scanning. Converters handle file format transformations and archive extraction automatically.

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
    options:
      max_extraction_depth: 3
      max_file_size: "100MB"
      preserve_permissions: true
      extract_nested: true
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
      extract_code_cells: true
      extract_markdown_cells: false
      preserve_cell_numbers: true
      output_format: "python"
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
    options:
      max_extraction_depth: 2
      max_file_size: "50MB"
      allowed_extensions: [".zip", ".tar.gz", ".7z"]
      exclude_patterns: ["*.exe", "*.dll"]

  jupyter:
    enabled: true
    options:
      extract_code_cells: true
      extract_markdown_cells: true
      cell_separator: "# %%"
      validate_syntax: true
```

## Best Practices

### Archive Security

```yaml
converters:
  archive:
    options:
      max_extraction_depth: 3    # Prevent zip bombs
      max_file_size: "100MB"     # Limit resource usage
      scan_extracted_only: true  # Don't scan original archives
```

### Jupyter Processing

```yaml
converters:
  jupyter:
    options:
      preserve_cell_numbers: true  # Accurate line mapping
      validate_syntax: true        # Skip malformed cells
```

## Integration with Scanners

Converters automatically prepare files for scanner consumption:

```bash
# Archives are extracted, then contents scanned
ash scan project.zip --scanners bandit,semgrep

# Jupyter notebooks converted to Python, then scanned
ash scan analysis.ipynb --scanners bandit,detect-secrets
```

## Troubleshooting

### Archive Issues

**Extraction failures**:
```yaml
converters:
  archive:
    options:
      ignore_extraction_errors: true
      log_extraction_details: true
```

**Large archives**:
```yaml
converters:
  archive:
    options:
      max_file_size: "500MB"
      max_extraction_depth: 1
```

### Jupyter Issues

**Malformed notebooks**:
```yaml
converters:
  jupyter:
    options:
      skip_invalid_cells: true
      validate_json: true
```

## Next Steps

- **[Scanner Configuration](scanners.md)**: Configure security scanners
- **[File Processing](../../advanced-usage.md)**: Advanced file handling
