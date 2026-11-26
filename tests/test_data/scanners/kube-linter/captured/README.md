# kube-linter captured fixtures

`positive.sarif` and `negative.sarif` are the files a real KubeLinter run wrote. Nothing in
them was edited after the run.

- Tool: `kube-linter 0.8.3` (`kube-linter version` prints `0.8.3`), the `v0.8.3` release asset
  `kube-linter-linux.tar.gz` from github.com/stackrox/kube-linter, fetched 2026-11-25. The
  release publishes no checksum file; the asset's sha256 as fetched was
  `1a6d8419b11971372971fdbc22682b684ebfb7cf1c39591662d1b6ca736c41df` and the extracted
  `kube-linter` binary's was
  `618d299a3e2839c8ca9d86fce0db617be0fba41f0fecbbbfb7fbf1c04299fae1`.
- Host: Linux x86_64, run from a scratch directory under `/tmp` on a development desktop,
  with the extracted binary and the inputs kept apart.
- The argv is the one the scanner builds (every option one `--flag=value` token, the path
  after `--`), run from the directory that holds `positive/`, `negative/` and the config:

  ```
  kube-linter lint --format=sarif --output=../positive.sarif --config=empty-config.yaml -- positive
  kube-linter lint --format=sarif --output=../negative.sarif --config=empty-config.yaml -- negative
  ```

- `empty-config.yaml` is the stub the scanner writes (`{}`).

| fixture | input | exit | stderr |
|---|---|---|---|
| `positive.sarif` | `positive/deployment.yaml`: a Deployment with a privileged container, no CPU or memory requests | 1 | `Wrote sarif output to ../positive.sarif`, `Error: found 6 lint errors` |
| `negative.sarif` | `negative/configmap.yaml`: a ConfigMap | 0 | `Wrote sarif output to ../negative.sarif` |

What the capture shows, and the tests pin:

- Exit 1 with a report on disk is "found problems"; exit 0 with a report on disk and
  `results: []` is a clean run.
- A result carries `ruleId`, `ruleIndex`, `message` and `locations` and nothing else: no
  `level`, no fingerprint.
- `message.text` is the diagnostic, a newline, then
  `object: <namespace>/<name> <apiVersion>, Kind=<Kind>`.
- Every region is `startLine: 1`; `artifactLocation.uri` is relative to the working directory.
- Each location also carries `logicalLocations` (object name, namespace and the group, version
  and kind of the object). The scanner does not read them.
- The rule text (description, remediation, help URI) is on `tool.driver.rules`, not on the
  results; the file lists all 31 default checks, so it is large.
- `invocations[].workingDirectory` and `endTimeUtc` are the capture host's and time.
