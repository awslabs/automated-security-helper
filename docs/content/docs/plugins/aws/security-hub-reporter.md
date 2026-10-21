# Security Hub Reporter

The `aws-security-hub` reporter imports ASH's findings into AWS Security Hub. It converts each finding to the [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html), sends the findings with the Security Hub `BatchImportFindings` API, archives the findings an earlier scan imported that this scan no longer reports, and writes a receipt to `reports/ash.aws-security-hub.asff.json`.

The reporter is off by default. Loading the AWS plugins for another reporter (S3, CloudWatch Logs, Bedrock) does not turn it on; see [Enable it](#enable-it).

> For diagrams of the import flow, see [Security Hub Reporter Diagrams](security-hub-reporter-diagrams.md).

## What it sends

One ASFF finding per finding in ASH's SARIF results, including suppressed findings. The findings go out in requests of at most 100, the per-request maximum of [`BatchImportFindings`](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html).

Each finding carries:

| ASFF field | Value |
|---|---|
| `Id` | `ash/` followed by a SHA-256 of the finding's identity (see [Finding identity](#finding-identity)) |
| `ProductArn` | The account's default product ARN, `arn:<partition>:securityhub:<region>:<account-id>:product/<account-id>/default`, where the partition is the Region's (`aws`, `aws-us-gov`, `aws-cn`) |
| `AwsAccountId` | The account that owns the credentials, or `account_id` if set |
| `GeneratorId` | `ash/<scanner>/<rule id>` |
| `Title` | `<rule id>: <first line of the finding message>`, up to 256 characters |
| `Description` | The finding message without its fenced code blocks, up to 1024 characters |
| `Severity.Label` and `FindingProviderFields.Severity.Label` | ASH's severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFORMATIONAL` for ASH's `INFO` |
| `Types` and `FindingProviderFields.Types` | `Software and Configuration Checks/Vulnerabilities/CVE` when the rule id is a CVE, otherwise `Software and Configuration Checks/Vulnerabilities` |
| `Resources` | One resource of type `Other` whose `Id` is `<scan target>/<file path>` |
| `CreatedAt` | The scan's time. With `archive_resolved_findings: true`, kept from Security Hub for a finding that already exists there |
| `UpdatedAt` | The time the scan started (`generated_at` in `ash_aggregated_results.json`), in UTC as `YYYY-MM-DDTHH:MM:SS.sssZ` |
| `RecordState` | `ARCHIVED` for a suppressed finding, `ACTIVE` otherwise |
| `ProductName`, `CompanyName` | `Automated Security Helper`, `AWS Labs` |
| `ProductFields` | `ash/target`, `ash/scope`, `ash/scanner`, `ash/ruleId`, `ash/severity`, `ash/suppressed`, `ash/file`, `ash/startLine`, `ash/endLine`, and where they apply `ash/workspaceProject`, `ash/suppressionJustification`, `ash/packageName`, `ash/packageVersion` |

This reporter is disabled by default: it sends findings to AWS with the host's credentials, so it runs only when your config sets `enabled: true` for it (see [Enabling the AWS reporters](index.md#enabling-the-aws-reporters)).

### Basic Configuration

The severity is the one ASH's own summary counts and `severity_threshold` gate use. A SARIF `error` result that has no explicit severity is therefore `CRITICAL`.

What is removed from the message before it is sent:

- the quoted password in bandit's hardcoded-password messages (rules `B105`, `B106` and `B107`, `Possible hardcoded password: '...'`), which ASH masks the way the flat-json and CSV reports do;
- every fenced code block (```` ``` ````), which ASH treats as a code snippet.

Nothing else in a message is masked, and no code snippet from the SARIF result is sent. A scanner message that names a file by its absolute path, or quotes a value outside a fenced block, is sent as written.

### Finding identity

Security Hub keys a finding on its `Id` within the product ARN. A later import with the same `Id` and a later `UpdatedAt` updates the finding instead of adding a second one. The `Id` is `"ash/" + sha256(json.dumps([target, key], sort_keys=True))`, where the target is the reporter's `findings_scope` option (see [Enable it](#enable-it)). The key is the identity the `id` of a finding in `ash.flat.json` and `ash.csv` is a hash of. `ash report` uses the configuration it runs with, so it produces a scan's `Id`s only with the same `findings_scope`. `ash merge` takes no `findings_scope` from the configuration the shards recorded (see [Options only the operator sets](#options-only-the-operator-sets)). The key holds:

- the scanner and the rule id;
- the file path, spelled one way: in a path written on Windows each backslash is a separator and becomes `/`, a path inside the scan root is made relative, and `.` and `..` segments are resolved. Anywhere else a backslash is part of the file name, so on Linux or macOS `a\b.py` and `a/b.py` are two files with two `Id`s. A file a converter wrote (a converted notebook, a file inside an archive) is identified by its path under the converted files instead, marked as converted, so its findings keep their `Id` wherever the output directory is;
- for dependency findings, the package name and path;
- in a workspace, the project's key;
- the result's SARIF `fingerprints`, or its `partialFingerprints` when it has no usable `fingerprints`. When it has neither, the start line and end line instead.

A fingerprint value counts as absent when it is a placeholder (semgrep without a login writes `requires login` on every result) or when results at different locations in the same scan share it, because then it does not identify one finding.

### Where these options can be set

`aws_region`, `aws_profile` and `account_id` choose where findings are sent and which
credentials send them, and `findings_scope` and `archive_resolved_findings` choose
which findings the reporter imports and whether it archives the ones that are
resolved, so they are the operator's. They take effect only from the
defaults (`AWS_REGION`, `AWS_DEFAULT_REGION` and `AWS_PROFILE`), `--config-overrides`,
or a config file outside the scanned tree. A config file inside the scanned tree, or
one an MCP client delivered, cannot set them: from the tree they are ignored with a
warning, and under the MCP server they are default `denied_paths` entries, so a
delivered config that changes one is refused.

Whether the reporter runs is the operator's too: a config file inside the scanned tree
neither turns it on nor turns it off. Under the MCP server every setting of the
section is a default `denied_paths` entry (`/reporters/aws-security-hub/**`), so a
delivered config that turns the reporter on, or changes any of its settings, is
refused. A client's `enabled: false` is not refused, but the server's `enabled`
applies. See
[Settings only the operator can set](index.md#settings-only-the-operator-can-set).

The reporter is in the `ash_aws_plugins` package, which only the operator can load,
with `--ash-plugin-modules`, `ASH_PLUGIN_MODULES` or the operator's own config, never
a repository's. See [Loading the plugins](index.md#loading-the-plugins).

## Prerequisites

The `id` and the `Id` are keyed differently in one case: a path that is absolute in the results and lies inside the scan root. The `id` keys it as written, because `ash.flat.json` and `ash.csv` are built without the scan root, and the `Id` makes it relative first. So when one result names a file by its absolute path and another names the same file by its relative path, a fingerprint value both carry is shared for the `Id`, which sees one file, but not for the `id`, which sees two.

The scan time, the report id, the message and the severity are not part of the key, so a re-scan, a reworded message or a re-rated finding updates the existing finding. Nor are the column, which most scanners do not report, and the package version, so upgrading a package to a release that still has the vulnerability updates the finding. The account and Region are not part of it either, because the product ARN already contains them.

A finding identified by its lines gets a new `Id` when an edit moves it to another line. A finding with fingerprints keeps its `Id`.

When findings without fingerprints share a key (two secrets on one line, for example), each gets an `occurrence` suffix computed from its own column and message: the first 8 hex digits of `sha256(json.dumps([column, message]))`, with `-1` as the column when the scanner reports none. A newcomer therefore never takes an existing finding's `Id`, and removing one finding never hands its `Id` to another. A finding alone with its key has no suffix. Only exact duplicates, with the same column and message, are told apart by their order: the first has no `ordinal`, the next `1`, then `2`. Two results with the same fingerprints at the same place are one finding: it is sent once and the scan logs a WARNING.

### Suppressed findings

A suppressed finding is sent with `RecordState: ARCHIVED`, so a finding that an earlier scan imported as `ACTIVE` is archived by the first scan after it is suppressed. If the suppression is removed, the next scan sends it as `ACTIVE` again, which reactivates it. ASH does not set `Workflow`: Security Hub ignores `BatchImportFindings` changes to `Workflow` once a finding exists.

### Findings a scan no longer reports

By default, a finding that a later scan no longer reports stays `ACTIVE` in Security Hub until Security Hub's retention removes it, 90 days after its last update. A finding a scan did not report is not always fixed: the scanner may have failed on the file, the scan may have covered less of the repository, or a new `ignore_paths` entry or rule change may hide it. So archiving them is opt-in.

With `archive_resolved_findings: true`, the reporter reads the findings already in Security Hub for this scan target (`GetFindings`, filtered on the product ARN and the `ash/target` product field) and re-imports, with `RecordState: ARCHIVED` and the scan's `UpdatedAt`, each one that:

- is `ACTIVE` and has an `Id` that starts with `ash/`;
- this scan did not produce;
- came from a scanner that finished in this scan (status `PASSED` or `FAILED`, not excluded) without failing on a single target. A scanner that failed on some of its targets (cdk-nag on 4 of 10 templates, for example) still rolls up to `FAILED`; its findings are left alone, as are those of a scanner that errored, was missing or was skipped;
- belongs to this scan's target and workspace project (`ash/target` and `ash/workspaceProject`). Both are compared because `ash/target` is `<findings_scope>/<project key>`: scope `org` with project `repo` reads the same as scope `org/repo` with none;
- has this scan's scope (`ash/scope`): the same scanned directory relative to the repository root, and the converted tree (archives, notebooks) scanned in both or in neither. A scan of `services/api` under the same `findings_scope` does not archive what a scan of the whole repository found. Deleting the last notebook or archive changes the scope as well (`converted=yes` becomes `converted=no`), so the findings recorded under the earlier scope stay `ACTIVE` until Security Hub's retention removes them;
- was last updated before this scan. A finding a later scan wrote is never archived by re-reporting an older one.

The scanned directory is the one the scan recorded in its results (`scan_source` in the metadata), not one the reporter works out where it runs. So `ash report` on another host, or on the output of `ash merge` on a collector without the checkout, compares the scan's scope. `ash merge` records no directory, and so the report archives nothing, when the shards recorded different ones; it records `changed_files_only: true` when any shard was filtered to changed files.

In container mode the scanned directory is always `/src` inside the container, where git sees only the mount. `ash` works the directory out on the host and always passes it in, empty when it has none. Running the ASH image yourself (as a CI job image, for example) is not container mode in this sense, unless it mounts the directory at `/src` or sets `ASH_ACTUAL_SOURCE_DIR`, as the legacy `./ash` and PowerShell (`Invoke-ASH`) wrappers do.

A scan the legacy `./ash` or `Invoke-ASH` wrapper starts records no directory, so with `archive_resolved_findings: true` it never archives. The wrappers pass no directory into the container, and git there sees only the mount, so it cannot tell a repository's root from a clone nested in another repository. Such a run prints a notice to stderr, once, whatever the log level. To archive, use `ash --mode container`, or run ASH directly.

A linked worktree of the same repository inside its checkout (`git worktree add`, one that the outer repository's `git worktree list` names) records its directory relative to the worktree's own root. The scan records no directory, and so archives nothing, when:

- the directory's repository sits below another repository: a git submodule, a repository cloned inside another one's work tree, any repository under an enclosing one (a home directory kept in git, for example), or a directory whose `.git` file or symlink points into the outer repository's git directory without being one of its listed worktrees. git would call each of their roots `.`, like the outer repository's. `GIT_CEILING_DIRECTORIES` is read as git reads it (an entry after an empty entry is compared as written, without resolving symlinks), and it hides the repository above a listed directory only when that repository neither tracks the directory's repository, or a path between them (a submodule's gitlink, for example), nor lists it as untracked and not ignored. That is the opt-out for a checkout under an enclosing repository that ignores it, such as a home directory kept in git whose `.gitignore` leaves out `src/`: with the ceiling at the home directory, the checkout records its own directory. Where the enclosing repository tracks the checkout or would list it in `git status`, the ceiling changes nothing and the scan records no directory;
- in container mode, the host directory is not inside a git repository, or git on the host refuses the repository (for example because another user owns it), or the directory's path relative to the repository root contains `;`, `\`, a control character or bytes that are not UTF-8, or starts with a segment that reads as a drive (`C:` or `a:b`);
- the directory is in a linked worktree, and the repository's git directory holds a FIFO or a symlink where `git worktree list` reads (a worktree's admin dir, a `HEAD` or a ref one names, or `packed-refs`): the list is not read, so the worktree counts as nested;
- in container mode, a workspace project's mount is not a repository's root;
- the legacy `./ash` or `Invoke-ASH` wrapper started the scan, or you ran the ASH image yourself with the directory mounted at `/src` or `ASH_ACTUAL_SOURCE_DIR` set, and no `ASH_SCAN_SOURCE`;
- the directory it would record is not UTF-8: its path relative to the repository root or, outside a repository, its own path. No scan starts on a directory whose path is not UTF-8, in any mode: a scan run on the host (local, precommit or nix mode) would write that path into its results and SARIF, so `ash` exits 1 at once, and container mode cannot bind-mount it, so `ash` exits 3 before any runtime call; either way it writes nothing and says to rename the directory.

With archiving on, results that record no directory print a notice to stderr, once per `ash` command (an MCP server prints it for its first such scan; every receipt still gives the reason), that nothing is archived and why.

Nothing is archived from one shard of a split scan (`--shard-index`), from a scan run with `--changed-files-only`, or from results that do not record whether they were filtered or which directory was scanned (results from an older ASH lack both). The receipt's `archive_skipped` says why when archiving did not apply, and `archive_scanners` lists the scanners it applied to.

Archiving cannot tell a fixed finding from one that a new `ignore_paths` entry or a scanner rule change stopped reporting; both are archived. Turn archiving on only for scans whose configuration you control, and run them from one branch (see [Enable it](#enable-it)).

A finding that comes back in a later scan is imported as `ACTIVE` again. Security Hub then sets its workflow status back to `NEW` if it was `NOTIFIED` or `RESOLVED`.

The same read keeps `CreatedAt` for every finding that already exists in Security Hub. With archiving off nothing is read, and `CreatedAt` is the scan's time on every import.

## Enable it

1. Enable Security Hub in the account and Region that should receive the findings:

   ```bash
   aws securityhub enable-security-hub --region us-east-1
   ```

2. Load the AWS plugins, enable the reporter, and set the Region and the findings scope in the operator's ASH configuration, a config file outside the scanned tree:

   ```yaml
   ash_plugin_modules:
     - automated_security_helper.plugin_modules.ash_aws_plugins
   reporters:
     aws-security-hub:
       enabled: true
       options:
         aws_region: us-east-1
         findings_scope: my-org/my-service
   ```

   The same settings from the command line:

   ```bash
   ash --config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_aws_plugins"]' \
       --config-overrides 'reporters.aws-security-hub.enabled=true' \
       --config-overrides 'reporters.aws-security-hub.options.aws_region=us-east-1' \
       --config-overrides 'reporters.aws-security-hub.options.findings_scope=my-org/my-service'
   ```

3. Provide AWS credentials for that account: environment variables, a profile (`aws_profile` or `AWS_PROFILE`), or an instance or task role.

4. Import from one branch. Every scan of the repository updates the same findings, so a scan of a feature branch overwrites, and with archiving on archives, what the default branch reported. In CI, enable the reporter only for the default branch, for example with `--config-overrides 'reporters.aws-security-hub.enabled=true'` on that job alone, and pass `--config-overrides 'reporters.aws-security-hub.enabled=false'` on every other job. A pull request can change the repository's `.ash/.ash.yaml`, and the override wins over what it says.

`findings_scope` is required. Choose a name unique to the repository among those that import into the same account and Region, such as its `owner/name` on the code host: every finding's `Id` and its `ash/target` field come from it, archiving touches only the findings recorded with it, and two repositories with the same scope would overwrite, and archive, each other's findings. It is at most 1024 characters. The reporter does not fall back to `project_name`, which the scanned repository's own configuration can set, or to the directory name, which is not unique (in container mode it is always `/src`).

### Options only the operator sets

`enabled`, `aws_region`, `aws_profile`, `account_id`, `findings_scope` and `archive_resolved_findings` decide whether a scan sends findings, to which account and Region, with which credentials, and which findings in the account it updates and archives. They are the operator's: set them with `--config-overrides`, in the file `ASH_CONFIG` names, or in another config file outside the scanned tree, never in the scanned repository's own configuration (a discovered `.ash/.ash.yaml`, a `--config` inside the tree, an `extends` base, or `ASH_CONFIG` naming a file inside the tree). A repository that could set them could turn the import on from a pull request, pick another profile on the operator's machine, send its findings to another account or Region, or name another repository's `findings_scope` and overwrite or archive its findings. On a job that must not import, `--config-overrides 'reporters.aws-security-hub.enabled=false'` turns the reporter off whatever the repository's configuration says.

ASH enforces this for `findings_scope` and `archive_resolved_findings`. When the configuration was read from a file inside the scanned tree, a value either option has there is ignored with a warning, unless `--config-overrides` or the operator's own config file outside the tree (the file `ASH_CONFIG` names, or a workspace's default config) sets it. A config file outside the tree that `extends` a file inside it, or a file a link inside the tree leads to, counts as inside for this. An ignored `findings_scope` leaves it unset, so the reporter refuses before any AWS call; an ignored `archive_resolved_findings` is `false`. A `--config-overrides` key with a dot-separated part that is empty, holds whitespace, or holds a character that does not print is refused (exit 3) rather than written to a key the reporter never reads. `ash report` judges its `--config` against the repository that holds the results as well as against the working directory. The MCP `get_config` tool shows both options from a config file in a checkout as `<operator only; ignored from this file: VALUE>`, since a scan of that checkout ignores them. `ash merge` ignores both in the configuration the shards recorded, since a file in a shard's repository could have set them; it imports into Security Hub only as the operator's own `--config` sets the reporter up. More generally, the whole section of a reporter that sends findings off the host, Security Hub's included, comes only from the operator: see [Enabling the AWS reporters](index.md#enabling-the-aws-reporters).

Before the report phase, ASH checks the dependencies of every enabled reporter. For this one the check needs the Region, calls `securityhub:DescribeHub`, and calls `sts:GetCallerIdentity` when `account_id` is not set. If the Region or the credentials are missing, or Security Hub is not enabled, it logs an ERROR and the reporter does not run.

When the reporter runs, it checks the rest before it reads from or writes to Security Hub: that `findings_scope` is set, and, with `sts:GetCallerIdentity`, that `account_id` (when set) is the credentials' account. If either fails, the reporter fails with a message that says what to set, and nothing is sent. The same checks run in `ash report --format aws-security-hub`, which skips the dependency check.

`ash report --format aws-security-hub` refuses unless the reporter is enabled in the configuration, and refuses a workspace's unified results file: run it once per project, with `--output-dir` set to `projects/<key>/` under the workspace output.

`--output-formats` accepts `aws-security-hub`: with the AWS plugin module loaded and the reporter enabled, a scan that names it imports that scan's findings. A scan whose `--output-formats` leave it out neither checks nor runs the reporter, so the dependency check above, `DescribeHub` and STS included, runs only for a scan that will run the reporter. To import an earlier scan's results, run `ash report --format aws-security-hub` in the directory that holds `.ash/ash_output`, with the reporter enabled in the configuration.

### Options

| Option | Default | Meaning |
|---|---|---|
| `findings_scope` | none | Name of this repository's findings in the account and Region; the `Id`s and archiving follow it. Required, at most 1024 characters. Operator only. |
| `aws_region` | `AWS_REGION`, then `AWS_DEFAULT_REGION` | Region whose Security Hub receives the findings. Required. Operator only. |
| `aws_profile` | `AWS_PROFILE` | Named profile for the credentials. Operator only. |
| `account_id` | the credentials' account | Account that receives the findings. Must be the credentials' account; with the default product ARN, Security Hub accepts a finding only from the account it names. An unquoted number is read as a 12-digit id, with the leading zeros YAML drops put back. Operator only. |
| `archive_resolved_findings` | `false` | Archive findings this scan no longer reports (see [Findings a scan no longer reports](#findings-a-scan-no-longer-reports)), and keep `CreatedAt` for existing findings. Needs `securityhub:GetFindings`. Operator only. |
| `max_retries` | `3` | Retries for a throttled or failed request |
| `base_delay` | `1.0` | Base delay in seconds between retries, doubled on each retry, plus up to one second of jitter |
| `max_delay` | `60.0` | Longest delay in seconds between retries |

The defaults of `aws_region` and `aws_profile` are read from the environment when ASH starts.

```yaml
reporters:
  aws-security-hub:
    enabled: true
    options:
      findings_scope: my-org/my-service
      aws_region: us-west-2
      aws_profile: security-scanning
      account_id: "123456789012"
      archive_resolved_findings: true
      max_retries: 5
```

## IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ImportFindings",
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchImportFindings",
        "securityhub:DescribeHub"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ArchiveResolvedFindings",
      "Effect": "Allow",
      "Action": "securityhub:GetFindings",
      "Resource": "*"
    }
  ]
}
```

- `securityhub:BatchImportFindings` imports the findings and the archive records.
- `securityhub:DescribeHub` is the dependency check that Security Hub is enabled.
- `securityhub:GetFindings` reads the existing findings for archiving and for `CreatedAt`. Only `archive_resolved_findings: true` needs it, so leave the `ArchiveResolvedFindings` statement out when archiving is off.
- `sts:GetCallerIdentity` finds the account, and checks `account_id` before anything is sent. It [needs no permission](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html).

## Results and failures

When every finding is imported, `reports/ash.aws-security-hub.asff.json` holds the receipt and the findings exactly as they were sent. With archiving on:

```json
{
  "product_arn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
  "aws_account_id": "123456789012",
  "region": "us-east-1",
  "imported": 12,
  "requests": 1,
  "duplicates_skipped": 0,
  "archived": 1,
  "archived_ids": ["ash/..."],
  "archive_scanners": ["bandit", "checkov"],
  "archive_skipped": null,
  "findings": []
}
```

`imported` counts the findings and the archive records Security Hub accepted. With no findings and nothing to archive, ASH makes no call and writes a receipt with `"imported": 0`.

If any finding is not imported, the reporter fails: the scan logs `Error in reporter SecurityHubReporter: ...` with the counts and the cause, no receipt is written, and `ash report` exits 1. The scan's exit code does not change. The causes and what the message tells you to do:

| Cause | Message |
|---|---|
| Reporter not enabled (`ash report --format aws-security-hub` without `enabled: true`) | Set `reporters.aws-security-hub.enabled: true`. |
| Invalid reporter configuration (for example `max_retries: three`) | The scan refuses the configuration with exit 3 when it loads the plugins, before anything is scanned, and names the option (`reporters.aws-security-hub.options.max_retries`); `ash report` exits 1 with the same field. Fix it. |
| A workspace's unified results (`ash report` over the workspace output) | Run `ash report` with `--output-dir` set to a project's directory, `projects/<key>/`. |
| No `findings_scope` | Set `reporters.aws-security-hub.options.findings_scope` in the operator's configuration (`--config-overrides`, or a config file outside the scanned tree). |
| No Region | Set `reporters.aws-security-hub.options.aws_region`, `AWS_REGION` or `AWS_DEFAULT_REGION`. |
| No credentials | Provide credentials for the account. |
| `account_id` is not the credentials' account | Use credentials for that account, or remove `account_id`. |
| Security Hub not enabled (`InvalidAccessException`, or every finding rejected with `InvalidAccess`) | Run `aws securityhub enable-security-hub --region <region>` in the account, and check that the credentials belong to it. |
| Access denied (`AccessDeniedException`) | Grant `securityhub:BatchImportFindings`. |
| `GetFindings` refused | The findings are still imported, then the reporter fails: grant `securityhub:GetFindings`, or set `archive_resolved_findings: false`. |
| Throttling (`LimitExceededException`, HTTP 429) after the retries | Retry later, or raise `max_retries` or `base_delay`. |
| Findings rejected in a successful response (`FailedCount`, `FailedFindings`) | Each rejected finding is logged with its `Id`, error code and message. `InvalidInput` means ASH built a finding Security Hub does not accept; report it. |
| A request botocore refuses before sending it | A defect in ASH's ASFF conversion; report it. |

A request that fails stops the import: the findings in later requests are not sent, and the message says how many were imported before it. When Security Hub rejects a whole request with `InvalidAccess`, the rest are not sent either.

`BatchImportFindings` is limited to 10 requests per second with a burst of 30, and `GetFindings` to 3 with a burst of 6 ([throttling limits](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#throttling-limits)). ASH retries a throttled request with exponential backoff.

## Viewing the findings

In the Security Hub console, filter findings by product name `Automated Security Helper`, or by the `ash/target` product field to see one repository. The same filter from the command line:

```bash
aws securityhub get-findings --region us-east-1 \
  --filters '{"ProductName": [{"Value": "Automated Security Helper", "Comparison": "EQUALS"}]}'
```

Security Hub sends a `Security Hub Findings - Imported` event to Amazon EventBridge for each finding it creates or updates, which you can route to a notification or a ticketing system.

## Workspace scans

In a workspace scan the reporter runs once per project, in that project's own report phase, and imports and archives that project's findings under the scan target `<findings_scope>/<project key>` (just `<findings_scope>` when the two are the same). It does not run again at workspace level, because that would import every finding a second time.

## Related documentation

- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [BatchImportFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html)
- [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
- [Required ASFF attributes](https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html)
- [ASH Configuration Guide](../../configuration-guide.md)
- [Other AWS Reporters](index.md)
