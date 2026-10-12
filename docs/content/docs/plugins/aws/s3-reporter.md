# S3 Reporter

Uploads ASH security scan reports to Amazon S3 for centralized storage and archival.

## Overview

The S3 Reporter provides:

- **Simple upload** of ASH scan results to S3 buckets
- **JSON or YAML format** support for report files
- **Configurable S3 key prefixes** for organization
- **Retry logic** for reliable uploads
- **Local backup** of uploaded reports

## Configuration

This reporter is disabled by default: it sends findings to AWS with the host's credentials, so it runs only when your config sets `enabled: true` for it (see [Enabling the AWS reporters](index.md#enabling-the-aws-reporters)).

### Basic Configuration

```yaml
reporters:
  s3:
    enabled: true
    options:
      bucket_name: myorg-ash-reports
      aws_region: us-east-1
      file_format: json  # or yaml
      key_prefix: ash-reports/
```

### Advanced Configuration

```yaml
reporters:
  s3:
    enabled: true
    options:
      # Use environment variables to insert the bucket name. The braces are
      # required: `!ENV ASH_S3_BUCKET_NAME` resolves to the literal string
      # "ASH_S3_BUCKET_NAME". With no default, `${ASH_S3_BUCKET_NAME}` refuses
      # the configuration when the variable is not set; `:None` allows it.
      bucket_name: !ENV ${ASH_S3_BUCKET_NAME:None}
      aws_region: !ENV ${AWS_REGION:None}
      aws_profile: !ENV ${AWS_PROFILE:None}
      file_format: json
      key_prefix: security-scans/
      # Retry configuration
      max_retries: 5      # Default: 3, at most 10
      base_delay: 2.0     # Default: 1.0 seconds, at most max_delay
      max_delay: 30.0     # Default: 60.0 seconds, at most 60
```

### Environment Variables

```bash
# Required: S3 bucket name
export ASH_S3_BUCKET_NAME="my-security-reports"

# Required: AWS region
export AWS_REGION="us-east-1"

# Optional: AWS profile
export AWS_PROFILE="my-profile"
```

### Where these options can be set

`aws_region`, `aws_profile`, `bucket_name` and `key_prefix` choose where reports are
uploaded and which credentials upload them, and `max_retries`, `base_delay` and
`max_delay` how long the reporter keeps calling S3 when it is refused, so they are the
operator's. They take
effect only from the defaults (the environment variables above, and `AWS_DEFAULT_REGION`),
`--config-overrides`, or a config file outside the scanned tree, which is where the
advanced configuration above belongs. A config file inside the scanned tree, or one an
MCP client delivered, cannot set them: from the tree they are ignored with a warning,
and under the MCP server they are default `denied_paths` entries, so a delivered config
that changes one is refused.

Whether the reporter runs is the operator's too: a config file inside the scanned tree
neither turns it on nor turns it off, and under the MCP server the whole section,
`/reporters/s3/**`, is a default `denied_paths` entry, so a delivered config or a
client's runtime override that turns it on, or changes any of its settings,
`file_format` included, is refused. A client's `enabled: false` is not refused, but
the server's `enabled` applies. See
[Settings only the operator can set](index.md#settings-only-the-operator-can-set).

The reporter is in the `ash_aws_plugins` package, which only the operator can load,
with `--ash-plugin-modules`, `ASH_PLUGIN_MODULES` or the operator's own config, never
a repository's. See [Loading the plugins](index.md#loading-the-plugins).

## Prerequisites

### S3 Bucket Setup

1. **Create S3 bucket**:
   ```bash
   aws s3 mb s3://my-security-reports --region us-east-1
   ```

2. **Configure bucket policy** (optional):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::123456789012:role/ASH-Scanner-Role"
         },
         "Action": [
           "s3:PutObject",
           "s3:PutObjectAcl"
         ],
         "Resource": "arn:aws:s3:::my-security-reports/*"
       }
     ]
   }
   ```

3. **Enable versioning** (recommended):
   ```bash
   aws s3api put-bucket-versioning \
     --bucket my-security-reports \
     --versioning-configuration Status=Enabled
   ```

### IAM Permissions

The reporter requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:HeadBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-security-reports",
        "arn:aws:s3:::my-security-reports/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### AWS Credentials

Ensure AWS credentials are configured using one of:

- **AWS CLI**: `aws configure`
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **IAM roles** (recommended for EC2/ECS/Lambda)
- **AWS profiles**: `AWS_PROFILE=myprofile`

## Features

### File Format Support

The S3 reporter supports two output formats:

```yaml
options:
  file_format: json  # Default: JSON format
  # OR
  file_format: yaml  # YAML format
```

**Note**: Only one format can be selected per configuration. The reporter uploads the ASH aggregated results in the specified format.

## Usage Examples

### Basic Usage

```bash
# Store reports in S3
export ASH_S3_BUCKET_NAME="my-security-reports"
export AWS_REGION="us-east-1"
ash /path/to/code --reporters s3
```

### With Custom Configuration

```bash
# Set bucket and prefix via environment variables
export ASH_S3_BUCKET_NAME="security-reports-prod"
export AWS_REGION="us-east-1"
ash /path/to/code --reporters s3,sarif
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Security Scan
  env:
    AWS_REGION: us-east-1
    ASH_S3_BUCKET_NAME: "ci-security-reports"
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: |
    ash . --reporters s3,sarif

- name: Generate Report URL
  run: |
    echo "Report available at: https://s3.console.aws.amazon.com/s3/buckets/ci-security-reports"
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    environment {
        AWS_REGION = 'us-east-1'
        ASH_S3_BUCKET_NAME = 'jenkins-security-reports'
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'ash . --reporters s3,html --'
            }
        }
        stage('Archive Results') {
            steps {
                script {
                    def reportUrl = "https://s3.console.aws.amazon.com/s3/buckets/${env.ASH_S3_BUCKET_NAME}/"
                    currentBuild.description = "Security Report: ${reportUrl}"
                }
            }
        }
    }
}
```

## Output Format

The S3 reporter uploads ASH aggregated results in the specified format (JSON or YAML). The uploaded file contains:

- **Metadata**: Scan information, timestamps, and configuration
- **Findings**: Security issues discovered by scanners
- **Summary statistics**: Counts by severity level
- **Scanner details**: Information about which scanners were run

Its `ash_config` is the configuration the results record, as the settings that
were set. When the results record no configuration, `ash_config` is `null`. ASH's
defaults, or the file `ASH_CONFIG` names where `ash report` runs, are never put in
its place.

### File Naming

Files are uploaded with the following naming pattern:
```
{key_prefix}ash-report-{timestamp}.{extension}
```

For example:
- `ash-reports/ash-report-2024-01-15T10:30:00+00:00.json`
- `security-scans/ash-report-2024-01-15T10:30:00+00:00.yaml`

`{timestamp}` is the scan's `metadata.generated_at`, so each scan gets its own
object, and re-running `ash report --format s3` against the same results replaces
that scan's object rather than adding another. In a workspace scan the project key
is inserted after the prefix: `{key_prefix}{project}/ash-report-{timestamp}.{extension}`.

### Local Backup

The reporter also creates a local copy of the uploaded report in:
```
{output_dir}/reports/s3-report.{extension}
```

### Upload receipt

`{output_dir}/reports/ash.s3.json` records where the report went:

```json
{
  "url": "s3://my-security-reports/ash-reports/ash-report-2024-01-15T10:30:00+00:00.json",
  "bucket": "my-security-reports",
  "key": "ash-reports/ash-report-2024-01-15T10:30:00+00:00.json",
  "file_format": "json",
  "local_copy": "/path/to/output/reports/s3-report.json"
}
```

`local_copy` is `null` when the local copy could not be written, for example
because the reports directory is not writable. A warning is logged and the upload
still counts. If a symlink or directory junction is at `s3-report.json` (or
`s3-report.yaml`) when the report phase starts, the run stops with exit 1 before any
reporter writes, so nothing is uploaded.

If the upload fails, no receipt is written and the reporter is logged as having
produced no report.

## Troubleshooting

### Common Issues

**Access Denied**
- Verify that the AWS credentials have the required IAM permissions
- Check that the bucket exists and is in the correct region
- Ensure the bucket name is correctly configured

**Bucket Not Found**
- Verify the bucket name is correct
- Check that the bucket exists in the specified AWS region
- Ensure AWS credentials have access to the bucket

**Upload Failures**
- Check network connectivity to AWS
- Verify AWS credentials are valid and not expired
- Review the retry configuration if uploads are timing out

### Debug Mode

Enable debug logging to see detailed error information:

```bash
ash /path/to/code --reporters s3 --log-level DEBUG
```

### Retry Configuration

The reporter includes built-in retry logic. The operator configures it, with
`--config-overrides` or a config file outside the scanned tree, like the options in
[Where these options can be set](#where-these-options-can-be-set). `max_retries` is
at most 10, `max_delay` at most 60 seconds, and `base_delay` at most `max_delay`; a
larger value is a validation error naming the option and its limit.

```yaml
reporters:
  s3:
    enabled: true
    options:
      bucket_name: "my-security-reports"
      aws_region: "us-east-1"
      # Retry configuration
      max_retries: 5      # Default: 3, at most 10
      base_delay: 2.0     # Default: 1.0 seconds, at most max_delay
      max_delay: 30.0     # Default: 60.0 seconds, at most 60
```

## Best Practices

1. **Use descriptive bucket names** that reflect your organization
2. **Implement lifecycle policies** to manage costs
3. **Enable versioning** for important reports
4. **Set up monitoring** for upload failures
5. **Use appropriate storage classes** based on access patterns
6. **Implement proper access controls** with IAM
7. **Enable encryption** for sensitive data
8. **Monitor costs** and optimize storage regularly
9. **Set up automated cleanup** for old reports
10. **Use cross-region replication** for critical reports

## Related Documentation

- [Amazon S3 User Guide](https://docs.aws.amazon.com/s3/latest/userguide/)
- [S3 Storage Classes](https://aws.amazon.com/s3/storage-classes/)
- [S3 Lifecycle Management](https://docs.aws.amazon.com/s3/latest/userguide/object-lifecycle-mgmt.html)
- [ASH Configuration Guide](../../configuration-guide.md)
- [Other AWS Reporters](index.md)
