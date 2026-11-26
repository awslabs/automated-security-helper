# snyk-code corpus

`authored/snyk-code-shape.sarif` is authored, not captured. It follows the shape of
`snyk code test --sarif` that the characterization double and the adapter's tests
already pin: rule `properties.cwe`, `help.markdown`, result `fingerprints`
`{"0", "1"}`, `%SRCROOT%` locations and `priorityScore` properties. It holds two
invented findings over invented source. Every id, hash and path in it is a
placeholder; no real finding, token, organization or customer data is in it.

The facets corpus gate (`tests/unit/plugin_modules/test_scanner_facets_corpus_consistency.py`)
reads it through the `snyk-code` prep, which applies the adapter's own
`normalize_rule_cwe_into_tags` first. Cells it settles are settled over this shape.
A licensed `snyk code test --sarif` capture, committed under `captured/`, would
replace it as the observed corpus (the gate's `CORPORA` row names the glob).
