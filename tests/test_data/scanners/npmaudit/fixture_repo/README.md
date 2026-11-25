# npm-audit corpus fixture tree

The install tree the facets corpus gate pairs with the committed `npm.json`
audit capture: `package-lock.json.fixture` names two of that report's
vulnerable packages (`node_modules/bootstrap` at 4.6.2 and
`node_modules/braces` at 3.0.2, each inside its advisory's vulnerable range)
at the node paths the report lists, so the adapter's lockfile resolution
(`package_version`, `package_path`) is observable over committed data.

The lockfile carries the `.fixture` suffix for the reason
`tests/utils/trivy_fixture.py` records for trivy's: a lockfile naming
advisory-bearing versions under its real name would be flagged by dependency
scanners of this repository itself. The gate's prep materializes it under a
temporary directory with the suffix stripped.
