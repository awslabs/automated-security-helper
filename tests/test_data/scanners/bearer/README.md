# Bearer test data

`reference/positive.json` is a hand-written Bearer `--format=json` report, built from
the field list of Bearer's report types. It is not captured from a binary: Bearer is
licensed under the Elastic License 2.0, so ASH does not install or run it in CI.

The file is a fixed input for the severity-mapping and conversion tests. It does not
confirm what a Bearer binary writes. A real capture (`bearer scan --format=json
--scanner=sast --exit-code=2 --output=<file> -- <sample dir>` over a sample with a
finding of each severity) would replace it and settle the facet cells that read as
unconfirmed.
