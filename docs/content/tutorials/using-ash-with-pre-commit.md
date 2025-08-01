# Using `ash` with `pre-commit`

The `ash` tool can be used interactively on a workstation or run using the [`pre-commit`](https://pre-commit.com/) command.
If `pre-commit` is used to run `ash`, then the `pre-commit` processing takes care of installing
a copy of the `ash` git repository and setting up to run the `ash` program from that installed
repository.  Using `pre-commit` still requires usage of WSL 2 when running on Windows.

Using `ash` as a [`pre-commit`](https://pre-commit.com/) hook enables development teams to use the `ash` tool
in two ways.  First, developers can use `ash` as a part of their local development process on whatever
development workstation or environment they are using.  Second, `ash` can be run in a build automation stage
by running `pre-commit run --hook-stage manual ash` in build automation stage.
When using `pre-commit`, run the `pre-commit` commands while in a folder/directory within the git repository that is
configured with `pre-commit` hooks.

Refer to the [pre-commit-hooks](https://github.com/awslabs/automated-security-helper/blob/main/.pre-commit-hooks.yaml) file for information about the `pre-commit`
hook itself.

## Configuration

To configure a git repository to use the `ash` hook, start with the following `pre-commit-config` configuration:

```yaml
repos:
  - repo: https://github.com/awslabs/automated-security-helper
    rev: v3.0.0  # update with the latest tagged version in the repository
    hooks:
      - id: ash-simple-scan
```

## Running the Pre-commit Hook

Once the `.pre-commit-config.yaml` file is updated, the `ash` tool can be run using the following command:

```bash
pre-commit run ash-simple-scan --all-files
```

## Output Files

Results from the run of the `ash` tool can be found in the `.ash/ash_output/` directory:

- `ash_aggregated_results.json`: Complete machine-readable results
- `reports/ash.summary.txt`: Human-readable text summary
- `reports/ash.summary.md`: Markdown summary for GitHub PRs and other platforms
- `reports/ash.html`: Interactive HTML report
- `reports/ash.csv`: CSV report for filtering and sorting findings
