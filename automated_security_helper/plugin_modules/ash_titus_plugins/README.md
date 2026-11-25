# Titus plugin for ASH

Secret detection over the scan target's files with
[Titus](https://github.com/praetorian-inc/titus) (Apache-2.0), Praetorian's Go port of
Nosey Parker. Where a builtin secret scanner finds the same secret, both report it.

## Enabling it

The plugin is off until its module is listed. Once listed, the scanner is on:

```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_titus_plugins
```

There is no license or service gate: Titus is a local binary, and the plugin passes no
flag that validates a secret or calls an outside API.

## Installing Titus

ASH does not install Titus yet. Download the release executable for your platform
(`titus-<os>-<arch>` at https://github.com/praetorian-inc/titus/releases, v1.3.0 was
the release read for this plugin), check it against the release's `checksums.txt`, and
put it on your `PATH` as `titus`. A scanner whose binary is not found is reported
`MISSING`.

### Owed to the integration lane

Central edits this alpha plugin does not make, because they touch shared files:

- `utils/tool_downloads.py`: a `titus` entry (`TOOL_VERSIONS["titus"] = "v1.3.0"`, a
  `_TITUS_ASSETS` table of bare executables for linux and darwin on amd64 and arm64
  and windows on amd64 (the release has no windows/arm64 asset), `_ASSET_TABLES`,
  `_RELEASE_BASE_URLS`, `_BARE_EXECUTABLE_TOOLS`, the pinned digests, and
  `THIRD_PARTY_LICENSES["titus"]`). The v1.3.0 linux/amd64 digest read for the
  captured fixture is `74c665b8222501793e9399052c4c4b6ffb3ecee1cd83a78950c759b2112fdabc`.
  Once it exists the plugin builds its install commands from it unchanged, and the
  `operational_facets` runtime row moves from `USER_INSTALLED_CLI` to `PINNED_BINARY`
  with `tool_versions_key="titus"`.
- `utils/scanner_names.py`: `"titus"` in `SCANNER_TOOL_TYPES`.
- `tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`:
  `"titus": CorpusSpec("titus", sarif=("captured/*.sarif",))` in `CORPORA`.
- `tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py`: the
  scanner count in `test_the_universe_is_the_twenty_two_shipped_scanners`.

## What it runs

`titus scan --format=sarif --output=:memory: --accessibility=private --context-lines=0 -- <path>`

- SARIF 2.1.0 is read from Titus' standard output.
- Titus' rules apply as built in. Rules marked noisy stay off.
- Matched text is replaced with `REDACTED` in every snippet.
- Severity comes from Titus' own 0-100 score: 80 and up CRITICAL, 60 up HIGH, 40 up
  MEDIUM, 20 up LOW, below 20 INFO.
- Only exit code 0 is accepted as a finished run.

## Configuration

The scanner takes the common scanner options (`severity_threshold`, `scan_timeout`,
`offline`) and no Titus-specific ones.

## Documentation

See https://awslabs.github.io/automated-security-helper/docs/plugins/community/titus-plugin/
