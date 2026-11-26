# govulncheck captured output

Real output of govulncheck v1.9.0 on linux/amd64, run on 2026-11-26. The binary was
built with `go install golang.org/x/vuln/cmd/govulncheck@v1.9.0` and Go 1.27.4, and the
module it fetched hashes to the checksum database's line for it,
`golang.org/x/vuln v1.9.0 h1:12VaqnI9kJfqwRoPptxoqsUhQtdfrSbdksT7X/KY/sc=`. Both runs
read the Go vulnerability database as last modified 2026-11-24T15:56:00Z, and each used
the argv the scanner builds by default, with the module as the working directory and
the inputs' `.fixture` suffixes dropped:

```
govulncheck -format=sarif -scan=symbol -- ./...
```

| File | What it is |
|---|---|
| `in/pos/go.mod.fixture`, `in/pos/main.go.fixture` | The positive input: a module that uses only the standard library, scanned with the Go 1.27.0 toolchain (`go1.27.0.linux-amd64.tar.gz` from go.dev, SHA256 `675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685`) on `PATH`. Its standard library has vulnerabilities fixed in later 1.27 releases. |
| `positive.sarif` | govulncheck's standard output for it, byte for byte (exit 0): fifteen vulnerabilities, five at level `error` (the code calls `Template.Execute` and `Reader.ReadMIMEHeader`, and govulncheck follows the calls into net/http) and ten at `warning` (packages imported, affected functions not reached). |
| `in/neg/go.mod.fixture`, `in/neg/main.go.fixture` | The negative input: `fmt` only, scanned with Go 1.27.4 (SHA256 `7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840`), the release that fixes every vulnerability the positive run reports. |
| `negative.sarif` | govulncheck's standard output for it (exit 0, no results and no rules). |

The inputs carry a `.fixture` suffix so that the repository's own dependency scanners do
not read a `go.mod` that names an affected Go release. The SARIF files are the corpus the
facets register's consistency gate reads, through `GovulncheckScanner.apply_severity_mapping`,
the one step the scanner applies to a root module's report.
