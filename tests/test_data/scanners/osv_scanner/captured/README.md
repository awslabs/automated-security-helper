# Captured OSV-Scanner 2.7.1 output

`positive.sarif` is the SARIF a real OSV-Scanner wrote (osv-scanner version 2.7.1,
osv-scalibr 0.5.3, linux/amd64 release asset, checked against the SHA256 the release
publishes), unedited. The unit tests serve it from a fake subprocess, so they run on
every platform without the binary.

Argv, from the directory holding the input (the working directory ASH uses):

```text
osv-scanner scan source --recursive --format=sarif --output-file=<file> --config=<empty file> .
```

The input was one `package-lock.json` (lockfileVersion 3) naming `lodash` 4.17.15 and
nothing else. Exit status was 1. The report holds five results (CVE-2020-28500,
CVE-2021-23337, CVE-2020-8203, CVE-2026-4800 and CVE-2025-13465), all `level: warning`,
each rule carrying `properties["security-severity"]` (5.3 on the first). The advisory
set is the OSV database's on the capture day, so the tests that read the file assert on
shape and mapping, not on the advisory list.

Facts the capture shows and the scanner relies on:

- every location's `artifactLocation.uri` is an absolute `file:///` URI of the lockfile,
  here under `/tmp/ash-osv-fixture-lane/pos/`, whatever the working directory;
- locations carry no `region`, so a finding has a file and no line;
- every result carries `partialFingerprints["primaryLocationLineHash"]`;
- every rule carries `deprecatedIds` (the CVE and GHSA ids of the advisory), `help` and
  `fullDescription`, and no `helpUri`.

No negative SARIF is kept, because a lockfile with no dependencies makes OSV-Scanner
exit 128 ("no packages found") and write no report file at all. That run (a
`package-lock.json` with an empty `packages` entry) is what the scanner's "128 and no
file is an empty scan" branch rests on.
