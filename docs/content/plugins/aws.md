# AWS reporters

The `ash_aws_plugins` package that ships with ASH has four reporters that send scan data
to AWS services. They are off until an operator loads the package, and only an operator
can choose where they send data and which credentials they use.

| Reporter | Sends to | What leaves the machine |
|---|---|---|
| `s3` | An S3 bucket | The scan summary and the resolved ASH configuration |
| `cloudwatch-logs` | A CloudWatch Logs log group | The same summary and configuration |
| `bedrock-summary-reporter` | Amazon Bedrock | Finding messages, file paths, and severity counts |
| `aws-security-hub` | Nothing in this version | Nothing; see [aws-security-hub](#aws-security-hub) |

The S3 and CloudWatch Logs reporters do not send individual findings. To collect findings
centrally, copy a findings file such as `reports/ash.ocsf.json` or `reports/ash.sarif` to
your storage yourself ([Export reports](../how-to/export-reports.md)).

## Load the package {#enable}

Loading the package turns on all four reporters. Name it in one of these places, all of
which belong to the operator:

- `--ash-plugin-modules automated_security_helper.plugin_modules.ash_aws_plugins`
- `ASH_PLUGIN_MODULES=automated_security_helper.plugin_modules.ash_aws_plugins`
- `--config-overrides 'ash_plugin_modules=[automated_security_helper.plugin_modules.ash_aws_plugins]'`
- `ash_plugin_modules` in a config file outside every git checkout and outside the
  directory you scan

When a config file inside the scanned repository names the package, or a module inside
it, ASH drops that entry, logs a warning that says why, and runs the scan without it. The
MCP server refuses a config an MCP client delivered that names it.

Turn off the reporters you do not use in the same operator config. This one sends to S3
and CloudWatch Logs only:

<!-- doctest: config kind=ash -->
```yaml
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_aws_plugins
reporters:
  s3:
    options:
      aws_region: us-west-2
      bucket_name: example-security-scan-results
      key_prefix: ash-reports/
  cloudwatch-logs:
    options:
      aws_region: us-west-2
      log_group_name: /security/ash
  bedrock-summary-reporter:
    enabled: false
  aws-security-hub:
    enabled: false
```

A repository's own config file can also turn these reporters off and set the Bedrock
reporter's content options, such as `include_code_snippets` and `custom_prompt`, when a
scan reads it. If you load the package with `--ash-plugin-modules` and let ASH read the
repository's config, the repository can change what your reporters do. Pass your config
with `--config` to prevent that; in a scan of one directory, ASH then does not read the
repository's config file.

A reporter that is missing its destination or credentials, or fails its pre-flight call,
is dropped from the run without changing the exit code. S3 and CloudWatch Logs skip
without a log message when the bucket or log group is not set, so check after each run
that `reports/ash.s3.json` and `reports/ash.cwlog.json` exist.

## Destinations and credentials {#destinations}

These options choose where data goes and with which identity. ASH takes them only from
operator sources: the defaults below, an operator config file, or `--config-overrides`.

| Reporter | Operator-only options | Defaults |
|---|---|---|
| `s3` | `aws_region`, `aws_profile`, `bucket_name`, `key_prefix` | `AWS_REGION`, then `AWS_DEFAULT_REGION`; `AWS_PROFILE`; `ASH_S3_BUCKET_NAME`; `ash-reports/` |
| `cloudwatch-logs` | `aws_region`, `log_group_name`, `log_stream_name` | `AWS_REGION`, then `AWS_DEFAULT_REGION`; `ASH_CLOUDWATCH_LOG_GROUP_NAME`; `ASHScanResults` |
| `bedrock-summary-reporter` | `aws_region`, `aws_profile`, `model_id`, `output_file`, `output_executive_file`, `output_technical_file` | `AWS_REGION`, then `AWS_DEFAULT_REGION`, then `us-east-1`; `AWS_PROFILE`; `ASH_BEDROCK_MODEL_ID`, then `us.anthropic.claude-3-7-sonnet-20250219-v1:0` |
| `aws-security-hub` | `aws_region`, `aws_profile`, `account_id` | `AWS_REGION`, then `AWS_DEFAULT_REGION`; `AWS_PROFILE`; the caller's account |

When a config file inside the scanned repository sets one of these options, under any
spelling of the reporter's section, ASH ignores it, logs a warning that names the option,
and uses the operator's value. Under an MCP server's default policy, a delivered config
that sets one of them, or any `cloudwatch-logs` option, to a value other than the server's
is refused.

Credentials come from the AWS SDK's default chain: environment variables, the shared
config and credentials files (with `aws_profile` where the reporter has it), and the
container or instance role. `cloudwatch-logs` has no profile option. Bedrock's region
falls back to `us-east-1`, so with only ambient credentials and no region set, the
Bedrock reporter still sends data.

In container mode, the scan runs inside the container and the host's AWS environment
variables and credential files are not passed in ([Run ASH in a container](../how-to/run-in-a-container.md#mounts)).
A role the container can reach through the instance metadata service may still be used;
use `--offline`, or a network that blocks the metadata service, if that matters.

## What each reporter sends {#what-is-sent}

The S3, CloudWatch Logs, and Bedrock reporters first call `sts:GetCallerIdentity`, which
needs no IAM permission. The Security Hub reporter calls it only when `account_id` is not
set.

### `s3` {#s3}

Uploads one object per scan to `<key_prefix>ash-report-<generated_at>.json` (in workspace
mode `<key_prefix><project>/ash-report-<generated_at>.json`), or `.yaml` with
`file_format: yaml`. The object holds the scan summary: the report metadata and summary
counts, each scanner's and converter's status and finding counts, and the resolved ASH
configuration, which includes your suppressions and ignore paths. It holds no individual
findings.

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
ASH does not write a file whose name leads anywhere else, and logs a warning. A test scan of a small project with one finding made six
Converse calls; more severity levels in the results mean more calls.

The prompts contain the names of every scanner in the results, severity counts, and, for
each finding sent, its level, its message text, and its file paths. Line numbers are sent
where a scanner's message includes them. With `actionable_only` (default `true`) the
reporter leaves out suppressed findings; findings below the severity threshold are still
sent. It sends a sample of the rest: up to `max_findings_to_analyze` (default 10) per
request and up to `max_findings_per_severity` (default 5) per severity. With
`batch_processing: true` and `group_by_severity: false` it sends every actionable finding,
in batches. `custom_prompt`, `custom_context`, `industry_context`, and
`compliance_frameworks` are added to the prompts.

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

This version does not send findings to Security Hub. The reporter calls `DescribeHub` to
check that Security Hub is enabled, then logs a warning that findings have not been sent
and writes `reports/ash.aws-security-hub.asff.json` with a placeholder message and the
finding count. It needs `securityhub:DescribeHub`.

## Rendering a reporter from saved results {#ash-report}

`ash report --format s3`, or the name of any of the other three, runs that reporter
against the results of a previous scan, which sends the data again. It skips the
reporter's pre-flight call and uses the destinations of the configuration it resolves.
`ash report` has no `--ash-plugin-modules` option and does not read `ASH_PLUGIN_MODULES`,
and without `--config` it reads the config file of the directory you run it from. Run it
from outside the repository, and load the package with your config file
(`--config`) or with
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
