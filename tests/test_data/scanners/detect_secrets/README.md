# detect-secrets corpus fixtures

- `fixture_repo/m0_planted.txt`: a two-line planted sample whose second line is
  a keyword-shaped placeholder (`m0-planted-not-a-secret`); never a real
  credential.
- `captured/detect-secrets-worker-m0.json`: the output of one real run of
  ASH's own worker
  (`python -m automated_security_helper.utils.detect_secrets_worker`) over
  that sample with detect-secrets 1.x's `KeywordDetector`
  (`settings = {"plugins_used": [{"name": "KeywordDetector"}]}`, no baseline,
  `verify` false), captured on 2026-11-25. The worker writes each secret in
  `PotentialSecret.json()` form -- hashed only, the value never leaves the
  worker -- plus the `ash_start_column` the worker computes. The one scrub,
  the same kind the guarddog captures record: the capture lane's absolute
  directory prefix is cut from the key and `filename`, leaving the sample's
  name, so the fixture carries no machine-specific path.

The facets corpus gate's detect-secrets prep drives these records through
`DetectSecretsScanner.build_secret_result`, the adapter's own pure
result-shaping function.
