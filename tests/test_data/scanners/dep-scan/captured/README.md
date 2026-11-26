# Captured dep-scan VDR

`positive.vdr.json` is a real Vulnerability Disclosure Report written by dep-scan
(OWASP dep-scan, MIT) and committed upstream as `test/data/jinja-report.vdr.json` at
the `v6.3.2` tag. The report itself says it was written by `owasp-depscan` 5.0.4 with
`@cyclonedx/cdxgen` 9.9.9 (CycloneDX spec 1.5, document version 2), for a Maven project.
The unit tests serve it to the converter, so they run on every platform without
dep-scan, cdxgen or a vulnerability database.

What was changed, with `python -I` and `json.dumps(separators=(",", ":"))`:

- `components` keeps only the two components the vulnerabilities affect
  (`io.netty/netty-codec-http2@4.1.94.Final`, `org.eclipse.parsson/parsson@1.1.2`);
  the other 226 were dropped.
- `services`, `dependencies` and `metadata.component` were removed.
- Nothing inside a kept component or a vulnerability was edited.

`negative.vdr.json` is `positive.vdr.json` with `vulnerabilities` set to `[]`. It is a
derived control, not a second capture: it has the shape dep-scan writes for a project
with no known vulnerability, which the converter must read as a clean scan.

`positive.sarif` is not a capture: it is the scanner's own conversion of
`positive.vdr.json` (`sarif_document(*convert_vdr(...))` in `dep_scan_scanner.py`, the
document `_read_results_file` returns), committed so the register's corpus gate reads
the findings through the same flat-row path as every other scanner's SARIF. A
regeneration test keeps it equal to what the converter writes. All three files are
stored as the repository's JSON hook formats them (two-space indent, sorted keys).

The argv that produced the original is not recorded upstream. The argv ASH runs is
in the scanner module's docstring.

Facts the captures show and the scanner relies on:

- Both vulnerabilities carry exactly one rating, `high` (CVSSv31 7.5), so this report
  exercises one row of the severity table. The other rows are exercised by setting
  `ratings[0].severity` on these same records in the tests.
- The kept components carry no `evidence.occurrences` and no `SrcFile` property, so
  the findings are located on the scan root `.`.
- One id is a `BIT-` id (Bitnami), which osv.dev does not serve, so its rule has no
  help link.
- `cwes` is a list of integers (`[400]`, `[834]`); ASH writes them as `CWE-<n>` tags.
- A 5.0.4 report is the oldest shape the converter reads. A 6.3.2 report was not
  captured: it needs cdxgen and a downloaded vulnerability database.
