# kube_linter fixtures

These two SARIF files are NOT captured from a run of the binary. kube-linter is not
installed on the hosts this plugin was built and validated on and ASH ships no pinned
release for it, so the files are written by hand to the shape KubeLinter v0.8.3's SARIF
formatter produces (`pkg/command/lint/sarif_format.go` at the `v0.8.3` tag of
github.com/stackrox/kube-linter):

- `ruleId` is the check name; results carry no `level`.
- every region is `startLine: 1`.
- the message is the diagnostic, a newline, then `object: <namespace>/<name>`.

The directory is named `recorded/`, not `captured/`, on purpose: a `captured/` directory
means output a real run wrote. When the binary is available, run
`kube-linter lint --format=sarif --output=positive.sarif --config=<file holding {}> -- <manifests>`
over a Deployment with a privileged container and no CPU request, save the output under
`captured/` with the manifest it linted, and replace the files here.

- `positive.sarif`: a HIGH check (`privileged-container`) and a MEDIUM check
  (`unset-cpu-requirements`) on one object.
- `negative.sarif`: a run that found nothing.
