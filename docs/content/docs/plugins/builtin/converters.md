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
- TAR archives (.tar, .tar.gz). A file is selected by its last suffix only, so a
  `.tgz` is not extracted.

**Configuration**:
```yaml
converters:
  archive:
    enabled: true
    options:
      max_members: 100000             # members, directories included
      max_member_bytes: 268435456     # 256 MiB, one member's declared size
      max_total_bytes: 1073741824     # 1 GiB, all members' declared sizes added up
      max_compression_ratio: 100      # that total over the archive's size on disk
```

**Key Features**:
- One level of extraction. A member that is itself an archive (a `.zip`, `.tar` or
  `.gz` suffix, in any case) is not extracted; it is recorded as not scanned.
- Extraction limits, described below
- Only members with a scannable extension are written, as regular files
- Automatic cleanup after scanning

#### Extraction limits

Before anything is written, every member of an archive is checked against four
limits. Each is an inclusive maximum on what the archive declares:

| Option                  | Default             | Bounds                                                  |
|-------------------------|---------------------|---------------------------------------------------------|
| `max_members`           | 100000              | the number of members, directories included             |
| `max_member_bytes`      | 268435456 (256 MiB) | the size one member declares                            |
| `max_total_bytes`       | 1073741824 (1 GiB)  | the sizes all members declare, added up                 |
| `max_compression_ratio` | 100                 | that total divided by the archive's size on disk        |

Every member counts, including members that would not be extracted, because reading
a compressed tar means decompressing every member to reach the next header. An
archive over any limit is refused whole: nothing from it is written or scanned, and
it is recorded once, with the limit named, under
`converter_results.archive.refused_inputs` (see below). Such a refusal counts as
incomplete conversion, so with `fail_on_incomplete_scanners` on (the default) the
scan exits 1 and names the archive and the limit. The refusal is also listed in the
console summary, `ash.summary.txt`, `ash.summary.md`, `ash.flat.json`
(`converter_refusals`) and `ash.sarif` (an execution notification at level `error`).

While copying, no member is written past the size it declares. For a sparse tar
member, whose map tarfile writes before it truncates the file to its declared size,
a map that places data past that size refuses the member.

The defaults let ordinary source archives through. GitHub refuses files larger than
100 MiB in a repository, and an AWS Lambda deployment package may hold up to 250 MB
unzipped, so a member of 256 MiB and a total of 1 GiB leave room above both. Source
code compresses by a few times (2 MiB of ASH's own Python sources: 3.1 times as a
zip, 3.7 as a tar.gz), while a file of zeros compresses by about 1000. Apache POI
refuses a zip part that compresses better than 1%, a ratio of 100, by default; the
ratio here is taken over the whole archive, so one very compressible member among
ordinary ones does not reach it.

**Who can raise a limit**: an operator, with `--config-overrides` (for example
`--config-overrides converters.archive.options.max_total_bytes=4294967296`) or a
config file outside the scanned tree, such as `ASH_CONFIG`'s or one passed with
`--config`. A config file the scanned repository wrote (`.ash/.ash.yaml` in the
tree, or a workspace project's own config) and a config an MCP client supplied can
lower a limit but not raise it: a higher value is replaced by the trusted one, with
a warning naming the option. A repository's own config file replaces `ASH_CONFIG`
as any selected config file does, so a limit it leaves out is the default. MCP
runtime overrides of the four options, or of a section holding them, are refused by
the default `global_settings.mcp.runtime_overrides.denied_paths`.

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
apply); install it first with `ash dependencies install`. nbconvert may read its copy
of the notebook and its tools, not the source tree or the output directory (under
Landlock and firejail, a tree inside a directory those backends show stays
readable). When no sandbox backend can
be used, no notebook is converted and each is listed in `refused_inputs`; such a
notebook, and one nbconvert fails on inside the sandbox, is listed in the row's
`failed_inputs` and fails the scan while `fail_on_incomplete_scanners` is on. See
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
    options:
      max_total_bytes: 268435456   # A lower limit than the default is always kept

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
    enabled: true
    options:
      max_compression_ratio: 50  # Lower a limit; only an operator can raise one
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
links or special files, members whose names are absolute or contain `..`, sparse
members whose map reaches past their declared size, and members that are themselves
archives, which are not extracted. An archive over an extraction limit is skipped
whole.

Each skipped input is recorded in `ash_aggregated_results.json` under
`converter_results.<converter>.refused_inputs`, with its path relative to the scanned
tree, the archive member's name where there is one, and the reason:

```json
"refused_inputs": [
  {"path": "notebooks/report.ipynb", "member": null, "reason": "it is a symbolic link"},
  {"path": "dist/app.tar", "member": "../setup.py", "reason": "its path contains a '..' component"},
  {"path": "dist/app.zip", "member": "vendor/lib.tar.gz", "reason": "it is named as an archive (.zip, .tar or .gz), and an archive inside an archive is not extracted, so its contents are not scanned"},
  {"path": "data/dump.zip", "member": null, "reason": "its members declare more than 1073741824 bytes, the max_total_bytes extraction limit", "limit": "max_total_bytes"}
]
```

`limit` is present only for an archive refused for an extraction limit, which is the
one kind of refusal that leaves the scan incomplete. The others are reported in the
summaries and reports as well, and do not change the exit code.

To have a skipped file converted, replace the link with the file itself. To have a
nested archive's contents scanned, extract it into the tree before the scan.

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

**Large archives**: an archive over an extraction limit is refused and the scan exits
1, naming the archive and the limit. Raise the limit as an operator:
```bash
ash scan --config-overrides 'converters.archive.options.max_total_bytes=4294967296'
```
or exclude the archive with `global_settings.ignore_paths` if its contents need not
be scanned.

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
