# Captured PMD 7.29.0 output

`positive.sarif` and `negative.sarif` are the SARIF the pinned PMD (7.29.0, the
`pmd-dist-7.29.0-bin.zip` release the plugin installs, checked against ASH's digest) wrote
during the scanner's build, kept as the build recorded them (pretty-printed). The unit tests
serve them from a fake subprocess, so they run on every platform without PMD or a JVM.
They were not re-captured when the scanner moved onto the facet model; no scanner behavior
changed with that move.

Argv, from the source directory (the working directory ASH uses):

```text
pmd check --no-progress --no-cache --rulesets=category/java/security.xml \
  --format=sarif --report-file=<file> --dir=<dir>
```

ASH's own run adds `--minimum-priority=5`, `--suppress-marker=ASH_PMD_NO_INLINE_SUPPRESSION`
and one `--exclude=` per ASH output directory inside the target; none of these changes the
report's shape.

Inputs: a `Crypto.java` holding a hard-coded AES key (line 7) and a hard-coded initialization
vector (line 10) for the positive run, and a clean tree for the negative run. Exit status was
4 (violations found) for the positive run and 0 for the negative one.

Facts the captures show and the scanner relies on:

- PMD writes absolute `file://` URIs (the capture's `/work/src` stands for the tree the run
  was made in; the tests substitute the tree under test), which `_post_process_sarif` rewrites
  to target-relative paths.
- Both Security rules are priority 3 and carry `level: warning`, so ASH rates them MEDIUM.
- The rule's `properties.priority` and `defaultConfiguration.level` are in the driver's
  `rules`; the result carries `level` itself.
- A clean run writes `results: []` and `executionSuccessful: true`.
