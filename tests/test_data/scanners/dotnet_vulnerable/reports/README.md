# dotnet_vulnerable report fixtures (hand-built, not captures)

`positive.json` and `negative.json` are written by hand in the shape NuGet's
`ListPackageJsonRenderer` produces for `dotnet list <project> package --vulnerable
--include-transitive --format json --output-version 1`: `version`, `parameters`,
`sources`, `projects[].path`, `frameworks[].framework`, `topLevelPackages` and
`transitivePackages` with `id`, `requestedVersion`, `resolvedVersion` and
`vulnerabilities[]` of `{severity, advisoryurl}`. The property names were read from
the renderer's documented output, not from a run.

They are NOT captures of a real SDK run: no .NET SDK was available on the build
host, so this directory is named `reports`, not `captured`. A real capture
(`dotnet --version`, the argv, the exit status, the raw stdout) replaces these files
the first time someone runs the scanner against a restored project. Until then the
checklist row for captured fixtures stays unmet.

`positive.json` covers every NuGet severity name the scanner maps (Critical, High,
Moderate, Low), an unrated advisory (empty severity, a non-GHSA URL), a name the
scanner does not know (Catastrophic), a package seen under two target frameworks, and
a transitive package. `negative.json` is a project with no vulnerable package.
