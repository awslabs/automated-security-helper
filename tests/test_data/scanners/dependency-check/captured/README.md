# dependency-check fixture

`template-shaped.sarif` is NOT a capture from a run of the tool. It was written
by hand to the shape of the tool's own `sarifReport.vsl` template at release
v13.0.0: the severity sits on the rules (`security-severity`, `cvssv2_severity`),
every result says `warning`, and every URI is an absolute `file://` URI. The
CVE ids, scores and file names are invented.

No host with a Java runtime was available when the plugin was written, and a
real run also needs the NVD database download. Replace this file with a real
`dependency-check --format=SARIF` capture when a host with Java can produce one;
the rating test and the facets corpus test read every `captured/*.sarif` here.
