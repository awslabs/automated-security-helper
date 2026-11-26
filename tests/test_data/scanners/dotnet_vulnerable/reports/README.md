# dotnet-vulnerable report fixtures (hand-built, not captures)

`positive.json` and `negative.json` are written by hand in the shape NuGet's
`ListPackageJsonRenderer` produces for `dotnet list <project> package --vulnerable
--include-transitive --format json --output-version 1`: `version`, `parameters`,
`sources`, `projects[].path`, `frameworks[].framework`, `topLevelPackages` and
`transitivePackages` with `id`, `requestedVersion`, `resolvedVersion` and
`vulnerabilities[]` of `{severity, advisoryurl}`. The property names were read from
the renderer's documented output, not from a run.

They are NOT captures of a real SDK run, so this directory is named `reports`, not
`captured`. The real capture is in `../captured/` (SDK 10.0.404, see its README): it
has the same property names as `positive.json`. A real run leaves `frameworks` out of a
project with nothing vulnerable, where `negative.json` lists a framework with one clean
package; both convert to no result.

These files stay because a real run cannot be made to produce every row the severity
mapping has. `positive.json` covers every NuGet severity name the scanner maps (Critical,
High, Moderate, Low), an unrated advisory (empty severity, a non-GHSA URL), a name the
scanner does not know (Catastrophic), a package seen under two target frameworks, and a
transitive package. `negative.json` is a project with no vulnerable package. The facets
corpus gate reads the captured SARIF, not these files.
