# Homebrew install check fixture

Scanned by `.github/actions/validate-install/scan-committed-fixture.sh`, which
`homebrew.sh` runs after installing ASH from `Formula/ash.rb`, on every Homebrew
leg of CI and in the `homebrew-macos` job of `ash-unified-ci.yml`.

- `template.yaml` is a CloudFormation template with an S3 bucket that has no
  encryption, logging or TLS-only policy, so cdk-nag reports findings on it. cdk-nag
  needs ASH's `cdk` extra and Node.js, which the formula has to install.
- `app.py` is Python with nothing for bandit to report, so bandit, which ASH
  installs with the keg's uv at scan time, has to run and pass.

The scan has to exit 2, write `ash_aggregated_results.json` and `reports/ash.sarif`,
and record cdk-nag FAILED and bandit PASSED. A scan that ran nothing would pass a
fixture with no findings, which is why this one has some.
