# BinSkim reference log (NOT a capture)

`reference.sarif` is written by hand in the shape the sarif-sdk gives BinSkim
logs: `BA####` rule ids, `file://` artifact URIs, levels error/warning/note, and
kinds fail/pass. It is **not** the output of a real BinSkim run: BinSkim was not
available when the scanner was written.

It exists so the facets register consistency gate
(`tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`) has a
corpus for the four facets the scanner declares MAPPED (`rule_id`, `severity`,
`file_path`, `message`). Every other facet is declared n/a with the reason
"output not read; a sample run would settle it".

## What would replace it

Run BinSkim over a small tree holding one PE, one ELF and one Mach-O file built
without hardening, with the argv `BinskimScanner._build_arguments` builds:

```
BinSkim analyze --output=<file>.sarif --recurse=true --level=Error;Warning;Note \
  --kind=Fail --quiet=true --disable-telemetry=true --ignorePdbLoadError=true -- <dir>
```

Commit the log as `captured/binskim-<version>.sarif`, record the version and the
argv in a `captured/README.md`, re-read the n/a cells of the scanner's `facets`
row against it (regions, fingerprints, help URIs, rule tags), and delete this
file. Nothing in this directory is evidence of what BinSkim writes.
