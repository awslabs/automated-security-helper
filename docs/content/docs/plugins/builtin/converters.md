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

**How conversion runs**: nbconvert is given a copy of the notebook in a directory
that holds nothing else, and runs there rather than in the scanned tree, so neither a
module nor a template directory in the tree is used. The copy is named
`notebook.ipynb`, whatever the notebook is called, because nbconvert reads its notebook
argument as a glob pattern; the converted file is named after the original. ASH picks
the exporter: `python` for a Python notebook or one that names no language, `script`
otherwise. The copy has `metadata.language_info.nbconvert_exporter` removed, so the
notebook does not choose the exporter class, and keeps
`metadata.language_info.file_extension` only when it is a plain extension such as
`.r`.

nbconvert is run with `uv tool run`. When uv cannot start, or reports that it could
not run nbconvert (offline with nbconvert not in its cache, for one), ASH runs an
installed `jupyter-nbconvert` by the absolute path it found on PATH or in ASH's own bin
directories (`$ASH_BIN_PATH`, by default `~/.ash/bin`, and off Windows `/usr/local/bin`). It does not look for one
in the working directory or through a relative PATH entry, and one inside the scanned
tree, such as in an activated `.venv/bin` in the repository, is not run unless you
allow it; see [Tools inside the scanned directory](../../advanced-usage.md#tools-inside-the-scanned-directory).

**Under `--sandbox`**: nbconvert, its version probe and its dependency check run in
the scanner sandbox, and nbconvert is never installed (`install_timeout` does not
apply); install it first with `ash dependencies install`. When no sandbox backend can
be used, no notebook is converted and each is listed in `refused_inputs`. See
[Converters](../../scanner-sandbox.md#converters) in the sandbox page.

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

## Inputs a converter does not read

A converter reads a file only if it is a regular file inside the scanned tree. It
skips, with one warning naming the file:

- a symlink, wherever it points, and any file under a symlinked directory;
- a path outside the scanned tree;
- a directory, FIFO, socket or device;
- a file with more than one hard link.

Inside an archive, the archive converter also skips members that are symlinks, hard
links or special files, and members whose names are absolute or contain `..`.

Each skipped input is recorded in `ash_aggregated_results.json` under
`converter_results.<converter>.refused_inputs`, with its path relative to the scanned
tree, the archive member's name where there is one, and the reason:

```json
"refused_inputs": [
  {"path": "notebooks/report.ipynb", "member": null, "reason": "it is a symbolic link"},
  {"path": "dist/app.tar", "member": "../setup.py", "reason": "its path contains a '..' component"}
]
```

To have a skipped file converted, replace the link with the file itself.

## Inputs a converter could not convert

A notebook nbconvert could not convert (it exited non-zero, timed out, or wrote no
output) and an archive that could not be extracted are recorded under
`converter_results.<converter>.failed_inputs`, with the reason:

```json
"failed_inputs": [
  {"path": "notebooks/report.ipynb", "reason": "nbconvert exited with code 1"}
]
```

Other errors are recorded the same way, as `<Type>: <message>`. The progress line and
the convert-complete event say how many files could not be converted.

The scanners never saw those files in converted form, so with
`fail_on_incomplete_scanners` on (the default) the scan exits 1 and names the
converter and the files, as it does for a converter whose tool is missing while it
had inputs.
`ash merge` combines every shard's failed inputs, and workspace mode reports them
per project in `incomplete_converters`.

The archive converter takes `.zip`, `.tar` and `.gz` files. One that neither zipfile
nor tarfile can read is a failed input, except a `.gz` that is a single compressed
file rather than a tarball, such as `data.json.gz`: that is not an archive, has
nothing to extract, and is skipped.

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
    enabled: true                # An archive that fails to extract is a failed input
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
    enabled: true                # A notebook that will not parse is a failed input
```

## Next Steps

- **[Scanner Configuration](scanners.md)**: Configure security scanners
- **[File Processing](../../advanced-usage.md)**: Advanced file handling
