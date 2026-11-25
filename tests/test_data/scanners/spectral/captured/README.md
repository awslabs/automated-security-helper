# Captured Spectral 6.17.1 output

`positive.sarif` and `negative.sarif` are the SARIF Spectral 6.17.1 (the
`spectral-linux-x64` release asset, sha256
`0196c72234478e4e23df28b662afa7c9f80a47cfd31dc697e674151ad060bb35`) wrote, compacted to
one line. The unit tests serve them from a fake subprocess, so they run on every
platform without the binary.

Argv, from the root of each input (the working directory ASH uses), with the ruleset
file holding `extends: ["spectral:oas", "spectral:asyncapi"]`:

```text
spectral lint --ruleset=<ruleset.yaml> --format=sarif --output=<file> \
  --fail-severity=hint --ignore-unknown-format --quiet '**/*.{json,yaml,yml}'
```

The positive input was two OpenAPI 3.0.3 files: `api.yaml` (a single `GET /pets` with
only a title, a version and a 200 response, so six warnings: `oas3-api-servers`,
`info-contact`, `info-description`, `operation-description`, `operation-operationId`,
`operation-tags`) and `broken.yaml` (a complete description except that
`/pets/{petId}` declares no `petId` parameter, so one `path-params` error). Exit status
was 1. The negative input was one YAML file that is not an API description; Spectral
wrote a report with no results and exited 0.

Facts the captures show and the scanner relies on: `tool.driver.rules` lists all 112
rules of the two rulesets whether or not they fired; every result carries a `level`
(`warning` or `error` here); `artifactLocation.uri` is relative to the working
directory; the results carry no `partialFingerprints`, no `properties` and no `snippet`.
