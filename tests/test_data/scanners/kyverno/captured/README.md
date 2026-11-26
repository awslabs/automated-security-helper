# Kyverno captured fixtures

Captured from the real tool, not written by hand.

- Tool: kyverno CLI 1.19.2 (git commit e63308f1e16c05cd009ac4864be6ec25c66b49be), the
  pinned release, linux x86_64 (archive sha256
  357eaf1df8bc24ddd5a73979fadeaae6a032e8710f11af264229756e4956bf4a).
- Command, run in a directory holding `k8s/bad.yaml`, `k8s/good.yaml` and
  `policies/high.yaml`:
  `kyverno apply --policy-report --remove-color --output-format=yaml --resource=k8s/bad.yaml --resource=k8s/good.yaml -- policies/high.yaml`
  (exit status 1: one failed result).
- `bad.yaml` is the manifest that fails. `good.yaml` is the same Pod named `good-pod`
  with a `team: platform` label.
- The policy is a `kyverno.io/v1` ClusterPolicy with the annotations
  `policies.kyverno.io/severity: high` and `policies.kyverno.io/category: Best Practices`,
  and one validate rule `check-team-label` requiring the label `team`.
- `kyverno-1.19.2-high.report.yaml` is stdout verbatim: the deprecation warning line,
  then the `ClusterReport` document.
- `kyverno-1.19.2-high.sarif` is what `convert_report_results` makes of that report
  with a manifest index that places `Pod default/bad-pod` in `k8s/bad.yaml` at line 1.
  A test rebuilds it from the report and compares, so a change to the adapter or to
  the report shape fails loudly.
