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
      max_compression_ratio: 100      # that total over the archive's size, above 512 KiB
```

**Key Features**:
- One level of extraction. A member that is itself an archive or compressed file is
  not extracted; it is recorded as not scanned. That is a last suffix, in any case,
  of `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.tbz`, `.tbz2`, `.xz`, `.txz`, `.zst`,
  `.lzma`, `.7z`, `.rar`, `.jar`, `.war`, `.ear`, `.whl` or `.egg`.
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
| `max_compression_ratio` | 100                 | that total divided by the archive's size on disk, once the total is over 512 KiB |

Every member counts, including members that would not be extracted, because reading
a compressed tar means decompressing every member to reach the next header, and each
member counts as at least 512 bytes (a tar header) toward `max_total_bytes`, so an
archive of empty members is not free.

All the archives one scan extracts (one project, in workspace mode) also share a
budget of four times `max_members` members and four times `max_total_bytes` bytes:
400,000 members and 4 GiB with the defaults, four archives at the per-archive limits,
and under the 5 GB GitHub strongly recommends a whole repository stays below. The
archive that would take the scan over it is refused, naming `max_members` or
`max_total_bytes` as the limit to raise, and does not use up the budget, so a later
archive that still fits is extracted. Raising the per-archive limit raises the shared
budget with it. An
archive over any limit is refused whole: nothing from it is written or scanned, and
it is recorded once, with the limit named, under
`converter_results.archive.refused_inputs` (see below). Such a refusal counts as
incomplete conversion, so with `fail_on_incomplete_scanners` on (the default) the
scan exits 1 and names the archive and the limit. The refusal is also listed in the
console summary, `ash.summary.txt`, `ash.summary.md`, `ash.flat.json`
(`converter_refusals`) and `ash.sarif` (an execution notification at level `error`).
Names come from the archive, so they are shown as inert text: in `ash.summary.md`
each refusal is a code span, so a name such as `@someone` or a URL is not a mention
or a link, and in `ash.summary.txt`, on the console and in the log every control
or bidirectional-formatting character in a name is written as an escape (`\x1b`,
`\u202e`).

Reading a tar's headers is bounded as well, because tarfile reads an extended (pax)
header, a GNU long name or a sparse map into memory while it parses the header,
before any of the limits above can be checked. The decompressor is chosen from the
archive's leading bytes (gzip, bzip2, xz, and zstd on Python 3.14), a single read
of more than 1 MiB while parsing headers is refused, and the header pass may read
4 MiB plus 2 KiB per member in all. An archive over either is refused as one that
cannot be read. Real headers are a few hundred bytes; GNU tar's pax format, which
writes an extended header for every member, reads about 1.5 KiB per member.

While copying, no member is written past the size it declares. For a sparse tar
member, whose map tarfile writes before it truncates the file to its declared size,
a map that places data past that size, or whose entries overlap or are out of order,
refuses the member.

The defaults let ordinary source archives through. GitHub refuses files larger than
100 MiB in a repository, and an AWS Lambda deployment package may hold up to 250 MB
unzipped, so a member of 256 MiB and a total of 1 GiB leave room above both. Source
code compresses by a few times (2 MiB of ASH's own Python sources: 3.1 times as a
zip, 3.7 as a tar.gz), while a file of zeros compresses by about 1000. Apache POI
refuses a zip part that compresses better than 1%, a ratio of 100, by default; the
ratio here is taken over the whole archive, so one very compressible member among
ordinary ones does not reach it. The ratio is not checked until the members declare
more than 512 KiB in all: below that an archive can write no more than 512 KiB
whatever it compresses to, and a small fixture archive of indented JSON can compress
140 times. POI likewise skips its ratio check for an entry of 100 KiB or less; the
floor here is higher because it applies to a whole archive rather than one entry.

**Who can raise a limit**: an operator, with `--config-overrides` (for example
`--config-overrides converters.archive.options.max_total_bytes=4294967296`) or a
config file outside the scanned tree, such as `ASH_CONFIG`'s or one passed with
`--config`. A config file the scanned repository wrote (`.ash/.ash.yaml` in the
tree, or a workspace project's own config) and a config an MCP client supplied can
lower a limit but not raise it: a higher value is replaced by the trusted one, with
a warning naming the option. A repository's own config file replaces `ASH_CONFIG`
as any selected config file does, so a limit it leaves out is the default. MCP
runtime overrides of the four options, or of a section holding them, are refused by
the default `global_settings.mcp.runtime_overrides.denied_paths`, and still refused
when a profile sets its own `denied_paths` list.

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
  {"path": "dist/app.zip", "member": "vendor/lib.tar.gz", "reason": "it is named as an archive or compressed file (such as .zip, .tar.gz, .jar or .7z), and an archive inside an archive is not extracted, so its contents are not scanned"},
  {"path": "data/dump.zip", "member": null, "reason": "its members declare more than 1073741824 bytes, the max_total_bytes extraction limit", "limit": "max_total_bytes", "scan_incomplete": true},
  {"path": "dist/old.tar", "member": null, "reason": "it could not be read as an archive (ReadError: unexpected end of data)", "scan_incomplete": true}
]
```

Within one archive, the first 20 members refused for each reason are listed one by
one, with a warning each. The rest are one record, with `member` null and
`unlisted_members` set to how many more there were, and one warning, so an archive
of thousands of links or nested archives does not produce thousands of records.

`limit` is present only for an archive refused for an extraction limit. That record
and the record of an archive that could not be read carry `"scan_incomplete": true`:
those are the refusals that leave a whole archive unscanned, and the completeness
gate counts them. The others are reported in the summaries and reports as well, and
do not change the exit code.

A `.gz` that is one gzip-compressed file rather than a tarball, such as
`data.json.gz`, is decompressed to the name without `.gz` (`data.json`) and that file
is scanned, within the extraction limits and the scan's budget like an archive with
one member. Its size is known only by reading it, so at most the limit is written
before it is refused. A name ending `.tar.gz` says the content is a tarball, and a
`.tar.gz` that holds no tar is refused as unreadable.

A Git LFS pointer named like an archive, which is what a checkout without its LFS
objects holds in place of each LFS-tracked `.zip` or `.tar.gz`, is recorded as a
refused input naming the file, with the remedy: fetch the LFS objects (`git lfs
pull`, or `lfs: true` on the CI checkout step) before the scan. It does not fail the
completeness gate, because the archive is not in the tree to scan. Only a whole file
in the pointer format counts: under 1024 bytes, UTF-8 text, the
`version https://git-lfs.github.com/spec/v1` line first, `key value` lines, and an
`oid sha256:` and a `size` line.

Any other archive that zipfile and tarfile cannot read is refused whole: a bad CRC, a
truncated or damaged stream (a damaged single-file gzip included), an empty file, or
headers over the read limits above. Anything already written from it is removed, so
the scanners never read a partial extraction as the archive, and the scan exits 1
with `fail_on_incomplete_scanners` on. Exclude such a file with
`global_settings.ignore_paths` if its contents need not be scanned.

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
    enabled: true                # An archive that cannot be read is refused and fails the completeness gate
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
