# Handwritten Psalm SARIF (not a capture)

`positive.sarif` is written by hand to the shape of Psalm's own SARIF writer
(`Psalm\Report\SarifReport`, 6.x): SARIF 2.1.0, rules keyed by the numeric issue
shortcode with `properties.tags` of `security`, `level` of `error` or `note` only, a bare
`artifactLocation.uri`, no result `properties` and no `partialFingerprints`.

No PHP runtime was available when the plugin was written, so no real run is committed.
This file stands in for one until a run on a host with PHP 8.2 or newer and Psalm 6 is
captured; the scanner's facets declaration marks every cell this file does not carry as
n/a with the reason "output not read", and a capture is what would settle them.
