# Captured SpotBugs 4.10.5 output

`positive.sarif` and `negative.sarif` are the SARIF the pinned SpotBugs (4.10.5, release
file checked against ASH's digest) wrote with the pinned Find Security Bugs 1.14.0 jar in
its `plugin` directory, compacted to one line. The unit tests serve them from a fake
subprocess, so they run on every platform without Java.

Run on 2026-11-25 with a Temurin 17 JRE, over `dom4j-2.2.0.jar` from Maven Central (a
library with security-category and style results alike). Argv, as ASH builds it:

```text
spotbugs -textui -exitcode -medium -effort:default -sarif=<file> <abs path>/dom4j-2.2.0.jar
```

The negative run adds `-high -onlyAnalyze org.dom4j.Namespace`, which selects one class
with no high-confidence result; it is a real run, not an edited report.

What the captures show and the scanner relies on:

- `positive.sarif` holds 300 results: 270 `note`, 15 `warning`, 15 `error`. Thirteen belong
  to rules whose `properties.tags` is `["SECURITY"]` (3 error, 10 warning).
- Find Security Bugs is listed in `tool.extensions` as `com.h3xstream.findsecbugs`; the
  scanner fails a run whose report does not list it.
- Locations are source-style paths (`org/dom4j/DocumentFactory.java`) with `startLine`,
  and `endLine` on some results; there is no column, snippet or fingerprint.
- Rules carry `relationships` to a CWE id and a `helpUri`; ASH reads neither today.
- Exit status was 3 for the positive run (bugs found and classes missing) and 2 for the
  negative one (classes missing, no results).
