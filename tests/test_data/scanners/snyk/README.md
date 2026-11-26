# snyk-code fixtures

`authored/snyk-code-shape.sarif` is authored, not captured. It follows the shape of
`snyk code test --sarif` that the characterization double and the adapter's tests
already pin: rule `properties.cwe`, `help.markdown`, result `fingerprints`
`{"0", "1"}`, `%SRCROOT%` locations and `priorityScore` properties. It holds two
invented findings over invented source. Every id, hash and path in it is a
placeholder; no real finding, token, organization or customer data is in it.

Because it is written to match the adapter, it is not evidence of what the tool
writes. The facets corpus gate
(`tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`) therefore
does not read it, snyk-code has no corpus there, and the register's snyk-code
cells are unconfirmed.

A licensed `snyk code test --sarif` capture, committed under `captured/`, would
become the corpus: point the gate's `CORPORA` row at `captured/*.sarif` with
`prep="snyk-code"` (the prep applies the adapter's own `normalize_rule_cwe_into_tags`
first), then settle the cells the capture shows.
