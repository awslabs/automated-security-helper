# Captured capa 10.0.0 output

`positive.json` and `mapped.json` are the JSON documents capa 10.0.0 (`flare-capa`
10.0.0 from PyPI, Python 3.12, the `capa-rules` 10.0.0 release as `-r`) wrote on
linux/amd64 for two ELF files copied from the host: `positive.json` for a small
coreutils binary, `mapped.json` for a larger one. The unit tests serve them from a fake
subprocess, so they run on every platform without capa.

Argv, from the directory of each input (the standalone release's `capa` cannot run on
the capture host, whose glibc is older than the release needs, so the PyPI package and
the matching rules tarball were used; the document is the same `ResultDocument`):

```text
capa -q -j -r <capa-rules-10.0.0> -- <file>
```

Two edits only: the capture host's work directory in `meta.argv`, `meta.sample.path`
and `meta.analysis.rules` was replaced with `/work`, and the repository's JSON hook
pretty-printed the files. Nothing else was changed.

What the captures show, and the scanner relies on:

* `rules` maps a rule name to `{meta, source, matches}`; `meta.attack` and `meta.mbc`
  are lists of objects with an `id`. `mapped.json` holds rules with ATT&CK ids, with
  MBC ids only, and with neither (`get password database entry on Linux`).
* Library rules appear in the document with `meta.lib` true (`contain loop`), with no
  `namespace`.
* `meta.sample.sha256` is the only hash; there is no per-result fingerprint.
* An input that is not a supported executable (a one-line text file) makes capa exit
  16 with its message on stderr and nothing on stdout, which is why a non-zero exit is
  a failed target.

| File | What it is |
|---|---|
| `positive.sarif` | What `CapaScanner.scan` writes to `capa.sarif` when capa prints `positive.json` for a tree holding one ELF file, `sample.elf`. |
| `mapped.sarif` | The same for `mapped.json`. |

The SARIF files are the corpus the facets register's consistency gate reads. Regenerate
them with the test `test_the_committed_sarif_is_what_the_scanner_writes`, which fails
naming the difference when the scanner's output moves.
