# Who uses ASH

ASH runs open-source security scanners and aggregates their findings into one
verdict and one set of reports. That one scan serves three jobs. A developer
wants the answer before pushing, in seconds, without leaving the terminal. A
security reviewer wants the pull request gate to be trustworthy, and every
exception to it visible and time-bounded. A security analyst wants the same
results across many repositories, in formats the organization's systems
already read.

ASH keeps those three honest with each other because they share everything
that matters: the scan is the same `ash` from the pre-commit hook to the CI
job to the MCP server an AI agent calls; the gate is the scan's
[exit code](../reference/exit-codes.md) everywhere; and every accepted risk is
a [suppression](../how-to/suppress-findings.md) in the repository's
configuration, with a reason and an expiration date, reviewed in the diff like
any other change. What passes on a laptop is what passes in CI, and what an
analyst aggregates is what the developer saw.

Each page below starts from one role's day and shows the ASH setup that fits
it, with the commands and configuration to copy.

| Role | The job | Page |
|---|---|---|
| Developer | Find and fix findings before they reach the pull request, with a feedback loop fast enough to keep on | [ASH for developers](developer.md) |
| Security reviewer | Gate pull requests on a verdict that cannot be quietly loosened, and review exceptions like code | [ASH for security reviewers](security-reviewer.md) |
| Security analyst | Run one policy across many repositories and feed the findings to the systems the organization reads | [ASH for security analysts](security-analyst.md) |

The lifecycle view, including how the same checkpoints map onto AI-assisted
development and the AI-DLC methodology, is on
[ASH across the SDLC and AI-DLC](sdlc-aidlc.md).

## Where the lines blur

The roles are jobs, not departments. A developer who owns a service's pipeline
does the reviewer's setup too; a reviewer who answers for a fleet needs the
analyst's rollout. Read the page for the job in front of you, and follow the
cross-links where your work crosses over:

- Developers meet the reviewer's world the first time a suppression they wrote
  shows up in a pull request diff.
- Reviewers meet the analyst's world when the same gate has to hold across
  repositories that their own pull requests cannot change
  ([Roll out across repositories](../getting-started/platform-teams.md)).
- Analysts meet the developer's world whenever a control is slow enough that
  people route around it; the developer page is the cost model for that.
