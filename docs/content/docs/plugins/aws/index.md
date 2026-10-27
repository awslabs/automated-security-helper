# AWS Plugins

ASH includes powerful AWS-specific plugins that extend security reporting capabilities with cloud-native services, enabling enterprise-scale security monitoring, AI-powered analysis, and seamless integration with AWS security services.

## Overview

AWS plugins provide:

- **Cloud-native integration** with AWS security and monitoring services
- **Scalable storage and processing** for large-scale security operations
- **AI-powered analysis** using Amazon Bedrock foundation models
- **Findings in AWS Security Hub**, next to the findings of other security services
- **Real-time monitoring** with CloudWatch Logs streaming

## Available Plugins

| Plugin                                                      | Purpose                      | Key Features                                                  | Use Cases                                             |
|-------------------------------------------------------------|------------------------------|---------------------------------------------------------------|-------------------------------------------------------|
| **[Security Hub Reporter](security-hub-reporter.md)**       | AWS Security Hub integration | ASFF findings via BatchImportFindings, stable finding Ids     | Centralized security monitoring                       |
| **[Bedrock Summary Reporter](bedrock-summary-reporter.md)** | AI-powered summaries         | Executive summaries, technical analysis, multiple models      | Management reporting, risk assessment                 |
| **[CloudWatch Logs Reporter](cloudwatch-logs-reporter.md)** | Real-time logging            | Structured logging, metric filters, alarms                    | Real-time monitoring, automated alerting              |
| **[S3 Reporter](s3-reporter.md)**                           | Cloud storage for reports    | Multiple formats, lifecycle management, analytics integration | Long-term archival, data analytics                    |

## Loading the plugins

ASH loads only its built-in plugins by default. The four AWS reporters are in the
`automated_security_helper.plugin_modules.ash_aws_plugins` package, and once it is
loaded each one that is enabled (see [Enabling the AWS reporters](#enabling-the-aws-reporters))
sends findings to AWS with the credentials of whoever runs ASH. So only the operator
running ASH can load it, in one of these ways:

- `--ash-plugin-modules automated_security_helper.plugin_modules.ash_aws_plugins`
- the `ASH_PLUGIN_MODULES` environment variable, set to the same module name
- `--config-overrides 'ash_plugin_modules+=["automated_security_helper.plugin_modules.ash_aws_plugins"]'`
- `ash_plugin_modules` in a config file outside the scanned tree, passed with
  `--config`

A repository's own config cannot load it. An `ash_plugin_modules` entry that names
the package, or a module inside it, in a config file inside the scanned tree (such as
the repository's `.ash/.ash.yaml`) is ignored with a warning naming the entry. Nor
can it select the reporters through another installed package that lists or imports
them: a reporter defined in this package is selected only when one of the ways above
loads the package, the reporter's module, or the package that lists it. Each one
that is not is named in a warning.

Under the MCP server, list the package in `ash_plugin_modules` of a profile registered
with `ash mcp --profile NAME=path/to/ash.yaml`; scans in a session bound to that
profile with `select_profile` load it. A config an MCP client delivered cannot add it.

## Enabling the AWS reporters

All four AWS reporters are **disabled by default**. Each sends findings to an AWS
service with the credentials of the host running ASH, so it runs only when your
configuration turns it on: `enabled: true` in its section of a config file you pass
with `--config` or `ASH_CONFIG`, or `--config-overrides
reporters.<name>.enabled=true`.

- An enabled AWS reporter runs in a scan that passes no `--output-formats`.
  `--output-formats` (`-f`) accepts `aws-security-hub`, `bedrock-summary-reporter`,
  `cloudwatch-logs` and `s3`, which `ash scan --help` lists apart from the other
  formats. With the AWS plugin module loaded and the reporter enabled, a scan that
  names the reporter runs it; naming it does not enable it. A scan whose
  `--output-formats` leave it out neither checks nor runs it. A reporter's
  dependency check (STS, Security Hub's `DescribeHub`, Bedrock's model list) runs
  only for a reporter the scan will run.
- A section that sets a reporter's options but not `enabled`, as a config written
  when these reporters were on by default does, leaves the reporter off. A scan
  or `ash merge` that would otherwise run it logs one warning naming the reporter
  and the key to set; the warning names no option value and changes nothing.
- `ash report --format <name>` refuses an AWS reporter that is not enabled, and
  exits 1 with the setting to change. For `ash report` that setting, and the
  reporter's destination options, come from `--config-overrides`: stored results
  do not record which tree was scanned, so a `--config` or `ASH_CONFIG` file may
  be the scanned repository's own, and its values for these reporters are ignored
  with a warning ([ash report](../../cli-reference.md#report-options)).
- `ash merge` runs an AWS reporter only when the operator's `--config-overrides`
  enable it, whatever the shards' recorded config says, in either direction. Its
  `--config` file does not enable or aim one, for the reason `ash report`'s does
  not.
- A reporter plugin that sends findings off the host declares
  `sends_off_host = True` on its class. ASH then runs it only when its section of
  the config sets `enabled: true`, whatever its own default is.
- A run uses only ASH's built-in reporters and those of the plugin modules it
  names (`ash_plugin_modules`), even in a process where another run loaded more.

## Settings only the operator can set

These reporter options choose where findings are sent or written, which
credentials send them, which findings Security Hub imports and archives, what the
Bedrock reporter sends to the model (which findings, how many, the text added to the
prompts, which model may receive them, and which of its calls are made), and how
long a reporter keeps calling its service when it is refused:

| Reporter section           | Options                                                                                                 |
|----------------------------|---------------------------------------------------------------------------------------------------------|
| `aws-security-hub`         | `aws_region`, `aws_profile`, `account_id`, `findings_scope`, `archive_resolved_findings`                |
| `bedrock-summary-reporter` | `aws_region`, `aws_profile`, `model_id`, `output_file`, `output_executive_file`, `output_technical_file`, `include_code_snippets`, `custom_prompt`, `exclude_scanner_types`, `actionable_only`, `max_findings_to_analyze`, `max_findings_per_severity`, `summarize_findings`, `batch_processing`, `industry_context`, `compliance_frameworks`, `custom_context`, `enable_fallback_models`, `add_section_headers`, `output_markdown`, `include_sections`, `exclude_sections`, `group_by_severity`, `max_retries`, `base_delay`, `max_delay` |
| `cloudwatch-logs`          | `aws_region`, `log_group_name`, `log_stream_name`, `max_retries`, `base_delay`, `max_delay`             |
| `s3`                       | `aws_region`, `aws_profile`, `bucket_name`, `key_prefix`, `max_retries`, `base_delay`, `max_delay`      |

They take effect only from the defaults (including the environment variables each
reporter's page lists), `--config-overrides`, or a config file outside the scanned
tree. A config file inside the scanned tree cannot set them: each one it sets is
ignored, with one warning naming them, and the operator's value applies; one that
repeats the operator's value is no change. This holds for every spelling of the
section ASH reads as that reporter's, such as `s3-reporter` or `BedrockSummary`, and
of the option, with `-` or `_`. Each reporter's options model also caps its
retries, from every source: `max_retries` at most 10, `max_delay` at most 60 seconds,
and `base_delay` at most `max_delay`. A larger value is a validation error naming the
option and its limit, and the reporter is not built.

Whether each reporter runs is the operator's too, in both directions. A config file
inside the scanned tree neither turns a reporter on nor turns one off: where its
`enabled: true` or `enabled: false` differs from the operator's settings, or from the
reporter's own default where those set none, it is ignored with a warning, and a tree
config that leaves the section out, which would return the reporter to its own
default, leaves it as the operator has it. To run or skip a reporter for one scan, set
it with `--config-overrides`, such as `--config-overrides reporters.s3.enabled=true`
or `reporters.s3.enabled=false`, or in a config file outside the tree. The reporters'
other options still apply from the tree.

Under the MCP server the whole section of each of these reporters is a default
`denied_paths` entry, `enabled` included: `/reporters/s3/**`,
`/reporters/aws-security-hub/**`, `/reporters/cloudwatch-logs/**` and
`/reporters/bedrock-summary-reporter/**`. So the settings the table leaves to a
repository's config, such as S3's `file_format` or the Bedrock reporter's model
parameters, are the operator's there too. A config an MCP client delivered, or a
client's runtime override, that changes one is refused with
`error_type: config_field_denied`; one that leaves them at the server's values
scans. One that sets `enabled: false` scans too, but the server's `enabled` applies
and a warning names the client's value. `enabled` of a reporter that writes only local files,
such as `sarif` or `html`, is not a default entry: a client's config may turn one on
or off.
See [Configs an MCP client delivered](../../configuration-guide.md#configs-an-mcp-client-delivered).

## Quick Start

### Basic Setup

1. **Configure AWS credentials**:
   ```bash
   aws configure
   # or use IAM roles (recommended)
   ```

2. **Write a config file outside the scanned tree** that loads the plugins and sets
   their destinations (see [Loading the plugins](#loading-the-plugins) and
   [Settings only the operator can set](#settings-only-the-operator-can-set)):
   ```yaml
   # /etc/ash/aws-reporters.yml
   ash_plugin_modules:
     - automated_security_helper.plugin_modules.ash_aws_plugins

   reporters:
     aws-security-hub:
       enabled: true
       options:
         aws_region: "us-east-1"
         findings_scope: "my-org/my-service"

     s3:
       enabled: true
       options:
         bucket_name: "my-security-reports"
         aws_region: "us-east-1"
   ```

3. **Run a scan with that config** (no `--output-formats`, so every enabled
   reporter runs):
   ```bash
   ash scan --source-dir /path/to/code --config /etc/ash/aws-reporters.yml
   ```

### Enterprise Setup

For enterprise deployments, combine multiple AWS plugins. As above, this goes in a
config file outside the scanned tree:

```yaml
# Enterprise configuration
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_aws_plugins
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-east-1"
      findings_scope: "my-org/my-service"

  bedrock-summary-reporter:
    enabled: true
    options:
      model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
      aws_region: "us-east-1"
      summary_style: "executive"

  cloudwatch-logs:
    enabled: true
    options:
      log_group_name: "/aws/ash/security-scans"
      aws_region: "us-east-1"

  s3-reporter:
    enabled: true
    options:
      bucket_name: "enterprise-security-reports"
      key_prefix: "ash-scans"
      aws_region: "us-east-1"
```

## Prerequisites

### AWS Account Setup

1. **AWS Account**: Active AWS account with appropriate permissions
2. **AWS CLI**: Installed and configured (`aws configure`)
3. **Service Access**: Enable required AWS services in your regions

### Required AWS Services

| Plugin                   | Required Services      | Optional Services              |
|--------------------------|------------------------|--------------------------------|
| Security Hub Reporter    | AWS Security Hub       | -                              |
| Bedrock Summary Reporter | Amazon Bedrock         | -                              |
| CloudWatch Logs Reporter | Amazon CloudWatch Logs | CloudWatch Alarms, EventBridge |
| S3 Reporter              | Amazon S3              | Amazon Athena, QuickSight      |

### IAM Permissions

Create an IAM policy for ASH AWS plugins:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:BatchImportFindings",
        "securityhub:DescribeHub",
        "bedrock:InvokeModel",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityHubArchiveResolvedFindings",
      "Effect": "Allow",
      "Action": "securityhub:GetFindings",
      "Resource": "*"
    }
  ]
}
```

The second statement is needed only when the Security Hub reporter runs with `archive_resolved_findings: true`.

## Authentication Methods

### 1. AWS CLI Configuration
```bash
aws configure
```

### 2. Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

### 3. IAM Roles (Recommended)
For EC2, ECS, Lambda, or other AWS services:
```yaml
# No explicit credentials needed
# IAM role attached to the service
```

### 4. AWS Profiles
```bash
export AWS_PROFILE="security-scanning"
# With aws-security-hub enabled in the ASH configuration
ash --source-dir /path/to/code
```

## Integration Patterns

### CI/CD Pipeline Integration

#### GitHub Actions
```yaml
name: Security Scan with AWS Integration
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # For OIDC
      contents: read

    steps:
    - uses: actions/checkout@v3

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: arn:aws:iam::123456789012:role/GitHubActions-ASH
        aws-region: us-east-1

    - name: Run ASH Security Scan
      env:
        # Security Hub imports only from the default branch: every scan of the
        # repository updates the same findings, so a pull request or a feature
        # branch would overwrite, and with archiving on archive, what the
        # default branch reported.
        IMPORT_TO_SECURITY_HUB: ${{ github.event_name == 'push' && github.ref_name == github.event.repository.default_branch }}
        # The repository's findings in Security Hub. Set here, by the job that
        # holds the credentials, and not in the repository's .ash config.
        FINDINGS_SCOPE: ${{ github.repository }}
      run: |
        # The other reporters are enabled in .ash/.ash.yaml
        if [ "$IMPORT_TO_SECURITY_HUB" = "true" ]; then
          ash --source-dir . \
            --config-overrides 'reporters.aws-security-hub.enabled=true' \
            --config-overrides "reporters.aws-security-hub.options.findings_scope=$FINDINGS_SCOPE"
        else
          # Off whatever .ash/.ash.yaml says: a pull request can change that file.
          ash --source-dir . \
            --config-overrides 'reporters.aws-security-hub.enabled=false'
        fi

    - name: Post AI Summary to PR
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          if (fs.existsSync('output/bedrock-summary.md')) {
            const summary = fs.readFileSync('output/bedrock-summary.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔒 Security Scan Summary\n\n${summary}`
            });
          }
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    environment {
        AWS_REGION = 'us-east-1'
        ASH_S3_BUCKET = 'jenkins-security-reports'
    }

    stages {
        // A multibranch pipeline, where `branch` matches BRANCH_NAME. Only the
        // default branch imports into Security Hub: every scan of the repository
        // updates the same findings, so another branch would overwrite them.
        // /etc/ash/aws-reporters.yml loads the AWS plugins (ash_plugin_modules:
        // [automated_security_helper.plugin_modules.ash_aws_plugins]) and sets
        // the Security Hub Region.
        stage('Security Scan (imports to Security Hub)') {
            when { branch 'main' }
            steps {
                withAWS(role: 'arn:aws:iam::123456789012:role/Jenkins-ASH') {
                    // The config file is on the agent, outside the checked-out
                    // workspace, and the scope is one name for this repository.
                    sh '''
                        ash --source-dir . \
                          --config /etc/ash/aws-reporters.yml \
                          --config-overrides 'reporters.aws-security-hub.enabled=true' \
                          --config-overrides 'reporters.aws-security-hub.options.findings_scope=my-org/my-service'
                    '''
                }
            }
        }

        stage('Security Scan') {
            when { not { branch 'main' } }
            steps {
                // The `when` above and the override below are what keep this
                // stage from importing; to enforce it, give branch builds a role
                // without securityhub:BatchImportFindings.
                withAWS(role: 'arn:aws:iam::123456789012:role/Jenkins-ASH') {
                    // Off whatever the checked-out configuration says.
                    sh '''
                        ash --source-dir . \
                          --config /etc/ash/aws-reporters.yml \
                          --config-overrides 'reporters.aws-security-hub.enabled=false'
                    '''
                }
            }
        }

        stage('Process Results') {
            steps {
                script {
                    // Archive results and send notifications
                    def reportUrl = "https://s3.console.aws.amazon.com/s3/buckets/${env.ASH_S3_BUCKET}"
                    currentBuild.description = "Security Report: ${reportUrl}"
                }
            }
        }
    }
}
```

### AWS Lambda Integration

Deploy ASH as a Lambda function for serverless scanning:

```python
import json
import subprocess
import boto3
from pathlib import Path


def lambda_handler(event, context):
    # Download code from S3 or CodeCommit
    # Run ASH scan
    # Results automatically go to configured AWS services

    try:
        # Example: Scan code from S3 trigger
        bucket = event["Records"][0]["s3"]["bucket"]["name"]
        key = event["Records"][0]["s3"]["object"]["key"]

        # Download and extract code
        s3 = boto3.client("s3")
        s3.download_file(bucket, key, "/tmp/code.zip")

        # Extract and scan
        subprocess.run(["unzip", "/tmp/code.zip", "-d", "/tmp/code"])

        # One findings_scope per repository, so two repositories never share
        # finding Ids in Security Hub. Here the object key names the repository,
        # for example "repos/my-service.zip". Set by this function, not by the
        # scanned code's own .ash config.
        findings_scope = Path(key).stem

        # Run ASH with AWS reporters
        result = subprocess.run(
            [
                "ash",
                "scan",
                "--source-dir",
                "/tmp/code",
                # The reporters are enabled in the config file.
                "--config",
                "/opt/ash-lambda-config.yml",
                "--config-overrides",
                f"reporters.aws-security-hub.options.findings_scope={findings_scope}",
            ],
            capture_output=True,
            text=True,
        )

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Scan completed successfully",
                    "findings_count": result.stdout.count("finding"),
                }
            ),
        }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
```

## Monitoring and Alerting

### CloudWatch Dashboards

Create dashboards to monitor security scan metrics:

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["ASH/Security", "CriticalFindings"],
          [".", "HighFindings"],
          [".", "TotalFindings"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "Security Findings Trend"
      }
    }
  ]
}
```

### EventBridge Rules

Automate responses to security findings:

```json
{
  "Rules": [
    {
      "Name": "ASH-Critical-Finding-Alert",
      "EventPattern": {
        "source": ["aws.securityhub"],
        "detail-type": ["Security Hub Findings - Imported"],
        "detail": {
          "findings": {
            "ProductName": ["ASH"],
            "Severity": {
              "Label": ["CRITICAL"]
            }
          }
        }
      },
      "Targets": [
        {
          "Id": "1",
          "Arn": "arn:aws:sns:us-east-1:123456789012:security-critical-alerts"
        },
        {
          "Id": "2",
          "Arn": "arn:aws:lambda:us-east-1:123456789012:function:SecurityIncidentResponse"
        }
      ]
    }
  ]
}
```

## Cost Management

### Cost Optimization Strategies

1. **Choose appropriate AWS regions** for your workloads
2. **Use S3 lifecycle policies** for long-term storage
3. **Select cost-effective Bedrock models** for AI analysis
4. **Implement CloudWatch log retention** policies
5. **Monitor usage** with AWS Cost Explorer

### Cost Estimation

| Plugin                   | Primary Cost Factors    | Estimated Monthly Cost* |
|--------------------------|-------------------------|-------------------------|
| Security Hub Reporter    | Finding ingestion events, see AWS Security Hub pricing | -   |
| Bedrock Summary Reporter | Model invocation tokens | $5-100                  |
| CloudWatch Logs Reporter | Log ingestion (GB)      | $5-25                   |
| S3 Reporter              | Storage and requests    | $1-10                   |

*Estimates based on typical usage patterns

### Cost Monitoring

Set up billing alerts:

```bash
aws budgets create-budget \
  --account-id 123456789012 \
  --budget '{
    "BudgetName": "ASH-AWS-Plugins",
    "BudgetLimit": {
      "Amount": "100",
      "Unit": "USD"
    },
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }'
```

## Troubleshooting

### Common Issues

**Authentication Errors**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/ash-user \
  --action-names securityhub:BatchImportFindings
```

**Service Not Available**
```bash
# Check service availability in region
aws securityhub describe-hub --region us-east-1
aws bedrock list-foundation-models --region us-east-1
```

**Permission Denied**
- Review IAM policies and roles
- Check service-specific permissions
- Verify resource-based policies (S3 bucket policies, etc.)

### Debug Mode

Enable comprehensive debugging:

```bash
# Debug logging for every enabled reporter, the AWS ones included
ash --source-dir /path/to/code --log-level DEBUG
```

## Best Practices

### Security
1. **Use IAM roles** instead of access keys when possible
2. **Apply least privilege** principle to IAM policies
3. **Enable CloudTrail** for audit logging
4. **Encrypt data** at rest and in transit
5. **Regularly rotate** access keys and credentials

### Performance
1. **Choose appropriate AWS regions** for latency
2. **Use batch processing** for large numbers of findings
3. **Implement retry logic** for transient failures
4. **Monitor API rate limits** and implement backoff
5. **Cache results** when appropriate

### Cost Management
1. **Monitor usage** regularly with AWS Cost Explorer
2. **Set up billing alerts** for unexpected costs
3. **Use appropriate storage classes** for S3
4. **Implement lifecycle policies** for log retention
5. **Choose cost-effective Bedrock models** for your use case

### Operations
1. **Implement monitoring** and alerting
2. **Set up automated responses** to critical findings
3. **Create runbooks** for common issues
4. **Test disaster recovery** procedures
5. **Document configurations** and processes

## Migration Guide

### From Legacy Reporting

If migrating from file-based reporting to AWS plugins:

1. **Assess current reporting needs**
2. **Plan AWS service setup** and permissions
3. **Test with non-production workloads**
4. **Gradually migrate** reporting workflows
5. **Update CI/CD pipelines** and automation

### Configuration Migration

```yaml
# Before: File-based reporting
reporters:
  sarif:
    enabled: true
    output_file: "results.sarif"

  html:
    enabled: true
    output_file: "report.html"

# After: AWS-integrated reporting
ash_plugin_modules:
  - automated_security_helper.plugin_modules.ash_aws_plugins
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-east-1"
      findings_scope: "my-org/my-service"

  s3-reporter:
    enabled: true
    options:
      bucket_name: "security-reports"
      file_format: "json"  # json or yaml

  bedrock-summary-reporter:
    enabled: true
    options:
      model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
```

## Next Steps

- **[Security Hub Reporter](security-hub-reporter.md)**: Centralized security monitoring
- **[Bedrock Summary Reporter](bedrock-summary-reporter.md)**: AI-powered analysis
- **[CloudWatch Logs Reporter](cloudwatch-logs-reporter.md)**: Real-time monitoring
- **[S3 Reporter](s3-reporter.md)**: Scalable storage and analytics
- **[ASH Configuration Guide](../../configuration-guide.md)**: Advanced configuration options
