# Capslock schema-derived fixtures (NOT captured output)

These two documents were written by hand from the protobuf schema Capslock
prints (`proto/capability.proto`, rendered by protojson: lowerCamelCase field
names, int64 values as strings, enums by name). No Capslock binary was run to
produce them: the build host has no Go toolchain, and Capslock publishes no
release binaries (`go install github.com/google/capslock/cmd/capslock@latest`).

They pin this plugin's reading of the documented schema, not the tool's real
output. They are deliberately not under a `captured/` directory.

| File | Models | Inputs |
| --- | --- | --- |
| `positive.json` | `capslock -packages=./... -output=json -force_local_module` over a small module that reaches NETWORK, EXEC and FILES | a module `example.com/app` with `server/serve.go` and `store/load.go`; site filenames are relative to the module directory |
| `negative.json` | the same run over a module that reaches no capability | a module `example.com/app` |

Argv: `capslock -packages=./... -output=json -force_local_module`, run with the
working directory at the `go.mod` directory and `GOFLAGS=-mod=readonly`.

Tool version: none (not run). Replace these with real captures, with the tool
version recorded here, when a Go toolchain is available: run the argv above over
a small module, redact nothing (the report holds no secrets), and commit the
output under `captured/`.
