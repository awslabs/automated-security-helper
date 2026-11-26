# Capslock captured output

Real output of `capslock -output=json`, not hand-written JSON. The conversion tests in
`tests/unit/plugin_modules/ash_capslock_plugins/test_capslock_install_and_captured.py`
read these files, and the SARIF files here are the corpus the facets register's
consistency gate reads.

## How they were made

- Tool: Capslock v0.3.4, built on 2026-11-26 with
  `go install github.com/google/capslock/cmd/capslock@v0.3.4`. Before the build,
  `go mod download -json github.com/google/capslock@v0.3.4` reported the module digest
  `h1:eS3/PLl++R96+Ub8b7uIDgCWzQh8CsY1CzVQbnt+Vhs=`, the plugin's pin.
  `capslock -version` printed:

  ```text
  capslock version v0.3.4
  compiled with Go version go1.26.11
  includes Go tools version v0.51.0
  ```

- Go toolchain: go1.26.11 linux/amd64, the `go1.26.11.linux-amd64.tar.gz` archive with
  SHA256 `9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec`, the digest
  go.dev publishes for it. `GOTOOLCHAIN=local`; module cache and build cache in scratch
  directories of their own (the build cache empty before the captures). The modules
  came from their repositories (`GOPROXY=direct`), checked against the Go checksum
  database.
- The runs: offline (`GOPROXY=off`) with `GOFLAGS=-mod=readonly`, from the directory of
  each input module, with the argv the plugin passes:

  ```text
  capslock -packages=./... -output=json -force_local_module
  ```

| Report | Input module | Exit status |
|---|---|---|
| `positive.json` | `in/pos/` (`example.com/app`) | 0 |
| `dependency.json` | `in/dep/` (`example.com/dep`) | 0 |
| `negative.json` | `in/neg/` (`example.com/clean`) | 0 |

Capslock prints its JSON with tab indentation and keys in field order. The reports here
are re-serialized by the repository's JSON formatter (two-space indent, sorted keys); no
value changed.

## Inputs

- `in/pos/`: a module whose packages reach FILES (`store.Load` calls `os.ReadFile`),
  NETWORK (`server.Serve` calls `http.ListenAndServe`), READ_SYSTEM_STATE (the module
  root's own package, `app.Mode` calls `os.Getenv`), UNSAFE_POINTER (`util.FirstByte`),
  and EXEC, both direct (`internal/exe.Start` calls `exec.Command`) and transitive
  (`util.Run` calls `exe.Start`). Standard library only.
- `in/dep/`: a module with one dependency, `golang.org/x/sync` v0.23.0 (its `go.sum`
  is committed). `dep.Read` reads a file inside a closure it hands to an
  `errgroup.Group`. Re-running it needs that module in the module cache: run
  `go mod download golang.org/x/sync@v0.23.0` first, which also writes the `.info`
  record Capslock's package loader reads (`go mod tidy` with `GOPROXY=direct` did not,
  and the offline run then exited 2).
- `in/neg/`: a module whose one package adds two integers. Capslock reports no
  capability.

No input holds a secret or a credential.

## Facts the scanner relies on

- An entry's `path` starts at the reporting function, which has no `site`; each later
  step's `site` is the call into that step, with the file's base name only
  (`load.go`). The plugin locates an entry at the second step's site in the reporting
  package's directory.
- Two shapes have no site on the second step: a one-step path (`util.FirstByte`, which
  is itself the capability) and a function that reaches the capability through a
  closure it creates (`dep.Read`: the second step is the closure `dep.Read$1`, which
  has an entry of its own, located at its `os.ReadFile` call). Both are located at the
  module's `go.mod`.
- `line` and `column` are strings (protojson renders int64 that way). The column is the
  call's opening parenthesis, counting a tab as one column.
- `packageDir` is the reporting package's import path and `packageName` its short name;
  an entry carries no version. `moduleInfo` (dependency modules and their versions)
  appears only when the module has dependencies, and is not tied to an entry.
- A module with no capability prints `packageInfo` and no `capabilityInfo` key.
- A module whose packages cannot load makes Capslock exit 2 with nothing on stdout and
  the loader's errors on stderr (measured with a module requiring a module that is not
  in the cache).

## Files written from these

| File | What it is |
|---|---|
| `positive.sarif`, `dependency.sarif` | What `capslock_sarif_document(convert_capslock_output(...))` writes for the reports above, with the module directory as the scan target. Regenerate them with the test `test_the_committed_sarif_is_what_the_converter_writes`. |
| `../transcripts.json` | The three runs as recordings (argv, exit status, the report's digest, the input module's digest) for `ash plugin verify`, which reads each report through the same conversion. Both digests change when a report or an input file does, so a re-capture rewrites the recording too. |
