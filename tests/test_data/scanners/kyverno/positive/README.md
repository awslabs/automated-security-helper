# Kyverno CI fixture

The tree the alpha kyverno legs scan, in `.github/actions/run-scan-test` on every OS
and in `.github/actions/validate-nix`: `k8s/bad.yaml` is a Pod without the `team`
label and fails the one rule of `policies/require-team.yaml` (severity `high`);
`k8s/good.yaml` is the same Pod with the label and passes. The legs name the policy
directory with `--config-overrides "scanners.kyverno.options.policy_paths=[policies]"`,
because kyverno applies only the policies the operator names, and expect one finding.
