# Captured KICS reports

Reports written by a real `kics scan`, committed as the tool wrote them (one edit,
listed below). The scanner tests read them in `tests/unit/plugin_modules/ash_kics_plugins/`.

## Tool

- KICS v2.1.20, `linux/amd64` release archive
  (`kics_2.1.20_linux_amd64.tar.gz`, sha256
  `8a5aa375ccfdc0ddd1114eddf1f9638ad7f6122e98d12a592207509dbe6d81f8`, the digest in the
  release's `checksums.txt`).
- Queries and libraries: `assets/queries` and `assets/libraries` from the v2.1.20 source
  archive (`v2.1.20.tar.gz`, sha256
  `7424ca07901a8534f6aa9b9d21b4c3aa873a027cf22e4bf334c5cf7fba134ae3`). 1100 queries ran.
- Captured 2026-11-25.

## Argv

The argv the scanner builds, run from inside the fixture directory, with `<assets>` the
directory holding `queries` and `libraries` and `<out>` the report directory:

```
kics scan --no-progress --no-color --silent --disable-secrets \
  --ignore-on-exit=results --exclude-gitignore --report-formats=json,sarif \
  --output-name=kics --output-path=<out> --config=<out>/stub.json \
  --queries-path=<assets>/queries --libraries-path=<assets>/libraries --path=.
```

`stub.json` holds `{}`. Both runs exited 0.

## Files

| File | Source tree | What it holds |
|---|---|---|
| `positive.sarif`, `positive.json` | `../fixture_repo/positive/` (one Terraform file, a bucket with `acl = "public-read"`) | five results: CRITICAL, two MEDIUM, LOW, INFO |
| `negative.sarif`, `negative.json` | `../fixture_repo/negative/` (no infrastructure-as-code) | no results |

The SARIF puts the level on the rule and none on the result, and maps CRITICAL and HIGH
both to `error`. The JSON report names each query's exact severity, which is why the
scanner reads both.

## Edit made after capture

`positive.json` listed the two absolute asset directories of the capture host under
`paths`; they are replaced with `<assets>/queries` and `<assets>/libraries`. Nothing else
was changed.

## Refresh

Install the pinned release and its assets, run the argv above over each fixture tree, and
replace the files. A change in KICS' report shape fails the captured-report tests.
