# Scorecard sample result

`scorecard_result.json` is **not a capture from a running binary**. It follows the
`JSONScorecardResultV2` shape in ossf/scorecard `pkg/scorecard/json.go` (`date`,
`repo`, `scorecard`, `score`, `checks[{name, score, reason, details, documentation}]`,
`metadata`) with invented values for the repository `example-org/example-repo`.

Why it is not a capture: `scorecard --repo=... --format=json --show-details` calls the
GitHub API and needs a token in `GITHUB_AUTH_TOKEN`, `GITHUB_TOKEN`, `GH_AUTH_TOKEN` or
`GH_TOKEN`; the build and desk runs that produced this module had none.

- argv a real run would use: `scorecard --repo=github.com/example-org/example-repo --format=json --show-details`
- version field: `v5.7.0` (the value in the sample, not a measured pin)
- inputs: none beyond the repository name and a token

It holds one check at each band edge (0, 3, 5, 6, 9), one passing check (10) and one
inconclusive check (-1), so the severity table is tested at every boundary. Replace it
with a recorded run when one is available: run the command above with a token against a
public repository and commit the stdout.
