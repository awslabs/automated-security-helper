# Capslock schema-derived fixtures (NOT captured output)

These two documents were written by hand from what Capslock v0.3.4 prints, read
from its source at the tag's commit (29ad626): the protobuf schema
(`proto/capability.proto`, rendered by protojson: lowerCamelCase field names,
int64 values as strings, enums by name), `analyzer/analyzer.go`
(`GetCapabilityInfo`: `packageDir` is the reporting package's import path,
`packageName` its short name, `capabilityName` the capability without its
`CAPABILITY_` prefix) and `analyzer/util.go` (`addFunction`: each path step's
`site` is the call into that step, with the file's base name only, so the first
step carries none).

No Capslock binary was run to produce them: Capslock publishes no release
binaries, and the module could not be fetched and built on the hosts that
validated this plugin. They pin this plugin's reading of the tool's source, not
the tool's real output, and are deliberately not under a `captured/` directory.

| File | Models | Inputs |
| --- | --- | --- |
| `positive.json` | `capslock -packages=./... -output=json -force_local_module` over a module that reaches FILES, NETWORK, UNSAFE_POINTER and EXEC | a module `example.com/app` with `store/load.go`, `server/serve.go` and `util/run.go`; `util.Cast` is itself the capability, so its path has one step and no site |
| `negative.json` | the same run over a module that reaches no capability | a module `example.com/app` |

Argv: `capslock -packages=./... -output=json -force_local_module`, run with the
working directory at the `go.mod` directory and `GOFLAGS=-mod=readonly`.

Tool version: none (not run). Replace these with real captures, with the tool
version recorded here, once a Capslock v0.3.4 build is available: run the argv
above over a small module, redact nothing (the report holds no secrets), and
commit the output under `captured/`.
