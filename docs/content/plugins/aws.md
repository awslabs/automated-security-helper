# AWS reporters

The `ash_aws_plugins` package that ships with ASH has four reporters that send scan data
to AWS services. Each one is off until an operator loads the package and turns that
reporter on, and only an operator can choose where they send data and which credentials
they use.

| Reporter | Sends to | What leaves the machine |
|---|---|---|
| `s3` | An S3 bucket | The scan summary and the resolved ASH configuration |
| `cloudwatch-logs` | A CloudWatch Logs log group | The same summary and configuration |
| `bedrock-summary-reporter` | Amazon Bedrock | Finding messages, file paths, and severity counts |
| `aws-security-hub` | AWS Security Hub | Nothing yet: the reporter checks its connection and writes a placeholder file ([details](#aws-security-hub)) |

The S3 and CloudWatch Logs reporters do not send individual findings. To collect findings
centrally, copy a findings file such as `reports/ash.ocsf.json` or `reports/ash.sarif` to
your storage yourself ([Export reports](../how-to/export-reports.md)).

## Load the package {#enable}

Loading the package turns none of the reporters on: each one runs only when the operator
sets `enabled: true` in its section. A section that sets a reporter's options but leaves
`enabled` out, or sets it to anything but the boolean `true`, such as the string `"true"`,
leaves the reporter off, and ASH logs a warning that says so, unless `--output-formats` or
`output_formats` leaves that reporter out anyway. Name the package in one of these places, all of which
belong to the operator:

- `--ash-plugin-modules automated_security_helper.plugin_modules.ash_aws_plugins`
- `ASH_PLUGIN_MODULES=automated_security_helper.plugin_modules.ash_aws_plugins`
- `--config-overrides 'ash_plugin_modules=[automated_security_helper.plugin_modules.ash_aws_plugins]'`
- `ash_plugin_modules` in a config file outside every git checkout and the scanned
  directory ([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided))

When a config file inside any git checkout or the scanned directory names the package, or a
module inside it, ASH drops that entry, logs a warning that says why, and runs the scan without it. Under
its default policy, the MCP server refuses a config an MCP client delivered whose
`ash_plugin_modules` list names it; in any other case it drops the entry the same way.

For `ash scan`, turn on the reporters you use in the same operator config. This one sends
to S3 and CloudWatch Logs only:

<!-- doctest: config kind=ash -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_aws_plugins
reporters:
  s3:
    enabled: true
    options:
      aws_region: us-west-2
      bucket_name: example-security-scan-results
      key_prefix: ash-reports/
  cloudwatch-logs:
    enabled: true
    options:
      aws_region: us-west-2
      log_group_name: /security/ash
```

Only the operator can turn these reporters on or off, with `--config-overrides`, such as
`--config-overrides 'reporters.s3.enabled=true'`, or in a config file outside every git
checkout and the scanned directory. A config file inside any git checkout or the scanned
directory, an ops repository of your own included, turns none of them on or off: each keeps
the operator's `enabled`, or its own default where the operator sets none, and a different
value in the file is ignored with a warning
([Configuration trust model](../concepts/trust-model.md#how-the-tier-is-decided)).
For a repository's own config that sets `reporters.aws-security-hub.enabled: true`, the
warning reads:

```text
Ignoring reporters.aws-security-hub.enabled from /home/me/repo/.ash/.ash.yaml: that config is inside a git checkout or the scanned tree, or was delivered by an MCP client, and these options choose whether findings are sent, where they are sent or written, and which credentials send them. To keep a setting, move the file outside every git checkout, or pass the setting with --config-overrides. A file inside the scanned directory has to move out of it as well.
```

Under its default policy, the MCP server refuses a delivered config that turns one of
these reporters on.

All of this is how `ash scan` reads the reporters' settings. `ash report` and `ash merge`
take whether these reporters run, and where they send, from `--config-overrides` only, and
ignore those settings in any config file ([Rendering a reporter from saved
results](#ash-report)).

A repository's own config file can still set the reporters' options that are not
operator-only ([below](#destinations)) when a scan reads it. If you load the package with
`--ash-plugin-modules` and let ASH read the repository's config, the repository can change
those options of your reporters. Pass your config with `--config` to prevent that; in a
scan of one directory, ASH then does not read the repository's config file.

In a scan, a reporter that has no credentials, or fails its pre-flight call, is dropped
from the run without changing the exit code. An enabled reporter that is missing a setting it needs
does not run either, and ASH logs an error that names the setting and how to set it, once
per run for each reporter and setting: the bucket for S3, the log group for CloudWatch
Logs, and the region (`aws_region`, else `AWS_REGION` or `AWS_DEFAULT_REGION`) for S3,
CloudWatch Logs, and Security Hub. A run is one `ash scan`, `ash report`, or `ash merge`,
and a workspace run gives each error once for all its projects.
Bedrock's region defaults to `us-east-1`, so it has no region only when a config sets
`aws_region` to `null`. For S3 with no region set:

```text
ERROR    Reporter 's3' is enabled but does not run: no aws_region is set. Set it with --config-overrides reporters.s3.options.aws_region=<value>, or set AWS_REGION or AWS_DEFAULT_REGION in the environment, which is read only when no config sets aws_region.
```

The exit code does not change, so check after each run that `reports/ash.s3.json` and
`reports/ash.cwlog.json` exist. A scan with
`--output-formats` runs only the reporters it names, so name the AWS reporters in that
list too, as in `--output-formats sarif,s3`.

## Destinations and credentials {#destinations}

These options choose where data goes, with which identity, what the Bedrock reporter
sends. ASH takes them only from operator
sources: the defaults below, an operator config file, or `--config-overrides`. `ash report`
and `ash merge` take them from the defaults and `--config-overrides` only.

The operator-only options of `s3`:

<!-- doctest: options of=reporters.s3 -->
| Option | Default |
|---|---|
| `aws_region` | from `AWS_REGION`, else from `AWS_DEFAULT_REGION`, else `null` |
| `aws_profile` | from `AWS_PROFILE`, else `null` |
| `bucket_name` | from `ASH_S3_BUCKET_NAME`, else `null` |
| `key_prefix` | `ash-reports/` |

Of `cloudwatch-logs`:

<!-- doctest: options of=reporters.cloudwatch-logs -->
| Option | Default |
|---|---|
| `aws_region` | from `AWS_REGION`, else from `AWS_DEFAULT_REGION`, else `null` |
| `log_group_name` | from `ASH_CLOUDWATCH_LOG_GROUP_NAME`, else `null` |
| `log_stream_name` | `ASHScanResults` |

Of `bedrock-summary-reporter`:

<!-- doctest: options of=reporters.bedrock-summary-reporter -->
| Option | Default |
|---|---|
| `aws_region` | from `AWS_REGION`, else from `AWS_DEFAULT_REGION`, else `us-east-1` |
| `aws_profile` | from `AWS_PROFILE`, else `null` |
| `model_id` | from `ASH_BEDROCK_MODEL_ID`, else `us.anthropic.claude-3-7-sonnet-20250219-v1:0` |
| `output_file` | `ash.bedrock.summary.md` |
| `output_executive_file` | `bedrock-executive.md` |
| `output_technical_file` | `bedrock-technical.md` |
| `include_code_snippets` | `false` |
| `custom_prompt` | `null` |

Of `aws-security-hub`:

<!-- doctest: options of=reporters.aws-security-hub -->
| Option | Default |
|---|---|
| `aws_region` | from `AWS_REGION`, else from `AWS_DEFAULT_REGION`, else `null` |
| `aws_profile` | from `AWS_PROFILE`, else `null` |
| `account_id` | `null` |

With no `account_id`, the Security Hub reporter uses the account of its credentials.
Turning a reporter on, `enabled`, is the operator's too ([above](#enable)).

When a config file inside any git checkout or the scanned directory sets one of these
options, under any spelling of the reporter's section, ASH ignores it, logs a warning that
names the option, and uses the operator's value. Under an MCP server's default policy, a
delivered config that sets any option of these four reporters to a value other than the
server's is refused.

Credentials come from the AWS SDK's default chain: environment variables, the shared
config and credentials files (with `aws_profile` where the reporter has it), and the
container or instance role. `cloudwatch-logs` has no profile option. Bedrock's region
falls back to `us-east-1`, so with only ambient credentials and no region set, the
Bedrock reporter still sends data.

In container mode, the scan runs inside the container, and the host's credential files and
credential variables, such as `AWS_ACCESS_KEY_ID`, are not passed in
([Run ASH in a container](../how-to/run-in-a-container.md#mounts)). `AWS_REGION`,
`AWS_DEFAULT_REGION`, and `AWS_PROFILE` are passed in only when your own config file
reads them and they are set ([The config file](../how-to/run-in-a-container.md#config)).
A role the container can reach through the instance metadata service may still be used;
use `--offline`, or a network that blocks the metadata service, if that matters.

## What each reporter sends {#what-is-sent}

The S3, CloudWatch Logs, and Bedrock reporters first call `sts:GetCallerIdentity`, which
needs no IAM permission. The Security Hub reporter calls it in its pre-flight check when
`account_id` is not set.

### `s3` {#s3}

Uploads one object per scan to `<key_prefix>ash-report-<generated_at>.json` (in workspace
mode `<key_prefix><project>/ash-report-<generated_at>.json`), or `.yaml` with
`file_format: yaml`. `key_prefix` is used as written: the object name follows it directly,
so `scans/repo/` places the object under `scans/repo/` and `scans/repo-` writes
`scans/repo-ash-report-<generated_at>.json`. End the prefix with `/` to use it as a
directory; ASH warns once per run about a prefix that does not. The object holds the scan summary: the report metadata and summary
counts, each scanner's and converter's status and finding counts, and the resolved ASH
configuration, which includes your suppressions and ignore paths. In the configuration and
the metadata, a value or key a config file read from the environment is the reference the
file wrote ([Read values from the environment](../how-to/configure.md#environment)). It holds no
individual findings.

Before the upload it calls `HeadBucket`. Locally it writes the uploaded content to
`reports/s3-report.json` and a receipt with the object URL to `reports/ash.s3.json`. When
ASH cannot write the local copy, the receipt's `local_copy` is `null`, ASH logs a warning,
and the upload still counts.

IAM: `s3:PutObject` on `arn:aws:s3:::<bucket>/<key_prefix>*`, and `s3:ListBucket` on the
bucket, which `HeadBucket` requires.

### `cloudwatch-logs` {#cloudwatch-logs}

Sends one log event per scan with the same summary and configuration as the S3 object,
to the stream `log_stream_name` in `log_group_name`. It creates the stream if needed;
the log group must already exist. Locally it writes the event and the API response to
`reports/ash.cwlog.json`.

IAM: `logs:CreateLogStream` and `logs:PutLogEvents` on the log group.

### `bedrock-summary-reporter` {#bedrock}

Asks a Bedrock model, through the Converse API, for an executive summary, a risk
assessment, recommendations, and a technical analysis, and writes them to
`reports/ash.bedrock.summary.md`, `reports/bedrock-executive.md`, and
`reports/bedrock-technical.md`. `output_file`, `output_executive_file`, and
`output_technical_file` change those names, and must be plain file names in `reports/`:
ASH does not write a file whose name leads anywhere else, and logs a warning. Two reports
cannot share a file: when two of the three options name one file, the later option takes
its default and ASH logs one warning, or refuses the configuration when that default is
taken too. Names that differ only in letter case count as one file, since the file systems
of macOS and Windows treat them so. Only reports that are written are compared, so a name
for a section in `exclude_sections`, or any name with `output_markdown: false`, is left
alone. A test scan of a small project with one finding made six
Converse calls; more severity levels in the results mean more calls.

The prompts contain the names of every scanner in the results, severity counts, and, for
each finding sent, its level, its message text, and its file paths. Line numbers are sent
where a scanner's message includes them. With `actionable_only` (default `true`) the
reporter sends only actionable findings: those that are not suppressed and whose severity
is at or above the threshold of the scanner that reported them. In a scan of one directory
those are the findings the exit code counts; a workspace verdict uses one threshold per
project, so there the two can differ. With `actionable_only: false` it sends every
finding, suppressed ones included. It sends a sample of them: up to
`max_findings_to_analyze` (default 10) per request and up to `max_findings_per_severity`
(default 5) per severity. With `batch_processing: true` and `group_by_severity: false` it
sends every actionable finding, in batches. `custom_prompt`, `custom_context`,
`industry_context`, and `compliance_frameworks` are added to the prompts. The Finding
Details section at the end of the summary lists every finding; ASH writes it from the
results, not from the model's answer.

Findings from secret scanners are sent with the others: the type of secret, the file and,
in the message, the line. Source code is sent only with `include_code_snippets: true`;
leave it off when the scanned code may hold credentials.

The reporter sends every request to `model_id`. Set it to a model or inference profile
your role can invoke in that Region.

IAM: `bedrock:ListFoundationModels` and `bedrock:ListInferenceProfiles`, which it calls
to check the model, and `bedrock:InvokeModel`, which the Converse API requires. The
default model is a cross-Region inference profile, so allow `bedrock:InvokeModel` on the
inference profile and on the foundation model in each Region the profile routes to, as
the [Bedrock inference profile prerequisites](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-prereq.html)
describe.

### `aws-security-hub` {#aws-security-hub}

The reporter is off until the operator turns it on. Security Hub must be enabled in the
account and Region you name. In the operator's config file:

<!-- doctest: config kind=ash -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_aws_plugins
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: us-east-1
```

This version of the reporter does not import findings yet. Its pre-flight check needs
the Region, calls `DescribeHub`, and calls `sts:GetCallerIdentity` when `account_id` is not
set; when one fails, ASH logs an error and the reporter does not run. When the checks pass,
`report()` logs a warning that the Security Hub import is not implemented, sends nothing to
Security Hub, and writes a placeholder file, `reports/ash.aws-security-hub.asff.json`,
that holds a message and the number of findings in the results. In a workspace scan the
reporter runs once per project.

IAM: `securityhub:DescribeHub`.

## Rendering a reporter from saved results {#ash-report}

`ash report --format s3`, or the name of any of the other three, runs that reporter
against the results of a previous scan, which sends the data again. Stored results do not
record which tree was scanned, so a config file `ash report` reads could be the scanned
repository's own, even one outside every git checkout. So `ash report` takes whether the
reporter runs, and its destination options, from `--config-overrides` only:

<!-- doctest: illustrative reason="sends the stored findings to an S3 bucket" -->
```bash
ash report --format s3 \
  --config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_aws_plugins]' \
  --config-overrides reporters.s3.enabled=true \
  --config-overrides reporters.s3.options.bucket_name=my-bucket
```

The config file that `--config` or `ASH_CONFIG` names still applies its other settings.
Its `enabled` and destination options for these reporters are ignored with a warning, and
a reporter that `--config-overrides` does not turn on is refused with exit code 1. With the
same settings in a file, `ash report --format s3 --config /etc/ash/ash.yaml` sends nothing
and prints:

```text
WARNING  Ignoring reporters.s3.options.aws_region, reporters.s3.options.bucket_name, reporters.s3.enabled from /etc/ash/ash.yaml: ash report cannot tell that config from the scanned repository's own, since stored results do not record which tree was scanned, and these options choose whether findings are sent, where they are sent or written, and which credentials send them. To send findings off the host from ash report, pass each of these settings with --config-overrides instead.
Error: reporter 's3' sends findings off the host and is not enabled. ash report takes whether it runs, and where it sends, from --config-overrides: pass --config-overrides reporters.s3.enabled=true and its destination options.
```

`ash merge` holds its `--config` file to the same rule, since the shards do not record the
tree either: the merged findings go off the host only with the reporter's `enabled` and
destination options in `ash merge`'s `--config-overrides`, and the file's values are
ignored with the same warning, naming `ash merge`. A reporter a plugin module adds is held
the same way for the options it declares as destinations. `ash merge` has these reporters
only when the package is named for the merge itself, in its `--config` file's
`ash_plugin_modules` or with
`--config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_aws_plugins]'`:
a package that only the shards' scan loaded is not loaded. It runs them only when
`--output-formats` is not given.

`ash report` runs the reporter's pre-flight check first, as a scan does. When the check
refuses, for a missing setting or for credentials it cannot find, the reporter sends
nothing, and `ash report` logs the reason and exits 1. For S3 with no region set:

```text
ERROR    Reporter 's3' is enabled but does not run: no aws_region is set. Set it with --config-overrides reporters.s3.options.aws_region=<value>, or set AWS_REGION or AWS_DEFAULT_REGION in the environment, which is read only when no config sets aws_region.
Error: reporter 's3' cannot run: its dependency check refused. See the log above for the reason.
```

`ash report` has no `--ash-plugin-modules` option and does
not read `ASH_PLUGIN_MODULES`, and without `--config` it reads the config file of the
directory you run it from. Run it from outside the repository, and load the package with
your config file (`--config`) or with
`--config-overrides 'ash_plugin_modules+=[automated_security_helper.plugin_modules.ash_aws_plugins]'`.

## Example IAM policy {#iam}

A policy for the configuration above (S3 and CloudWatch Logs only), with your account,
bucket, and log group:

<!-- doctest: config kind=other reason="IAM policy document, not an ASH config" -->
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::example-security-scan-results/ash-reports/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::example-security-scan-results"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:us-west-2:111122223333:log-group:/security/ash:*"
    }
  ]
}
```

Each reporter's full option list is in the [reporters reference](../reference/reporters.md#s3).
