# CodeQL sample report (hand-built, not captured)

`codeql-python.sarif` is NOT output of a real CodeQL run. The CodeQL CLI's terms bar
generating a database for automated analysis outside open-source code on GitHub.com,
and ASH neither installs nor runs it, so no real report is committed. The file is
written to the shape the CodeQL CLI manual and GitHub's SARIF support page document for
`codeql database analyze --format=sarifv2.1.0 --sarif-add-snippets`:

- rule tables in `tool.driver.rules[]`, with `properties.tags` (including
  `external/cwe/cwe-<n>`), `problem.severity` and, for security queries,
  `security-severity`;
- results with `ruleId`, `ruleIndex`, a physical location with a region and snippet, and
  `partialFingerprints.primaryLocationLineHash`.

It holds two results: a security result (`security-severity` 8.8) and a quality result
(`problem.severity` recommendation, no score), so the severity mapping has both paths.

The facets register's corpus gate reads this file, and the scanner's unit tests grade it.
When a maintainer with a licence that permits the run captures a real report, add it
beside this one under `captured/` and re-point the corpus row.
