# Security Hub Reporter

Sends ASH security findings directly to AWS Security Hub in AWS Security Finding Format (ASFF), enabling centralized security monitoring and compliance reporting.

> For detailed visual diagrams of the Security Hub Reporter architecture and workflow, see [Security Hub Reporter Diagrams](security-hub-reporter-diagrams.md).

## Overview

The Security Hub Reporter integrates ASH scan results with AWS Security Hub by:

- **Converting findings to ASFF format** for standardized security reporting
- **Batch uploading findings** to Security Hub for efficient processing
- **Maintaining finding lifecycle** with proper status tracking
- **Supporting compliance frameworks** like AWS Foundational Security Standard

## Configuration

### Basic Configuration

```yaml
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-east-1"
      aws_profile: "default"  # optional
```

### Environment Variables

The reporter supports configuration via environment variables:

```bash
# AWS region (falls back to AWS_DEFAULT_REGION)
export AWS_REGION="us-east-1"

# AWS profile (optional)
export AWS_PROFILE="security-scanning"
```

### Complete Configuration Example

```yaml
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-west-2"
      aws_profile: "production"
```

## Prerequisites

### AWS Security Hub Setup

1. **Enable Security Hub** in your AWS account:
   ```bash
   aws securityhub enable-security-hub --region us-east-1
   ```

2. **Enable standards** (optional but recommended):
   ```bash
   aws securityhub batch-enable-standards \
     --standards-subscription-requests StandardsArn=arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard/v/1.0.0
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
        "securityhub:BatchImportFindings",
        "securityhub:GetFindings",
        "securityhub:UpdateFindings"
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

### ASFF Format Conversion

ASH findings are automatically converted to AWS Security Finding Format (ASFF):

```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "ash-finding-12345",
  "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
  "GeneratorId": "ASH",
  "AwsAccountId": "123456789012",
  "Types": ["Sensitive Data Identifications/PII"],
  "CreatedAt": "2024-06-11T00:00:00.000Z",
  "UpdatedAt": "2024-06-11T00:00:00.000Z",
  "Severity": {
    "Label": "HIGH",
    "Normalized": 70
  },
  "Title": "Hardcoded API Key Detected",
  "Description": "A hardcoded API key was found in the source code",
  "Resources": [
    {
      "Type": "Other",
      "Id": "file:///path/to/file.py",
      "Region": "us-east-1"
    }
  ]
}
```

### Batch Processing

- **Efficient uploads**: Findings are batched for optimal performance
- **Rate limiting**: Respects AWS API rate limits
- **Error handling**: Robust error handling with retry logic
- **Deduplication**: Prevents duplicate findings in Security Hub

### Finding Lifecycle Management

- **New findings**: Automatically created with appropriate severity
- **Updated findings**: Existing findings are updated when re-scanned
- **Status tracking**: Maintains finding status (NEW, NOTIFIED, RESOLVED)

## Usage Examples

### Basic Usage

```bash
# Run scan with Security Hub reporting
ash /path/to/code --reporters aws-security-hub
```

### With Multiple Reporters

```bash
# Generate both SARIF and Security Hub reports
ash /path/to/code --reporters sarif,aws-security-hub
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run ASH Security Scan
  env:
    AWS_REGION: us-east-1
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: |
    ash . --reporters aws-security-hub,sarif
```

## Security Hub Integration

### Viewing Findings

1. **AWS Console**: Navigate to Security Hub → Findings
2. **Filter by product**: Look for "ASH" or "Automated Security Helper"
3. **Review details**: Click on findings to see detailed information

### Custom Insights

Create custom insights to track ASH findings:

```bash
aws securityhub create-insight \
  --name "ASH Critical Findings" \
  --filters '{
    "ProductName": [{"Value": "ASH", "Comparison": "EQUALS"}],
    "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}]
  }' \
  --group-by-attribute "ResourceId"
```

### Automated Response

Use EventBridge to trigger automated responses:

```json
{
  "Rules": [
    {
      "Name": "ASH-Critical-Finding-Response",
      "EventPattern": {
        "source": ["aws.securityhub"],
        "detail-type": ["Security Hub Findings - Imported"],
        "detail": {
          "findings": {
            "ProductName": ["ASH"],
            "Severity": {
              "Label": ["CRITICAL", "HIGH"]
            }
          }
        }
      },
      "Targets": [
        {
          "Id": "1",
          "Arn": "arn:aws:sns:us-east-1:123456789012:security-alerts"
        }
      ]
    }
  ]
}
```

## Troubleshooting

### Common Issues

**Security Hub Not Enabled**
```bash
# Check if Security Hub is enabled
aws securityhub get-enabled-standards --region us-east-1

# Enable Security Hub if needed
aws securityhub enable-security-hub --region us-east-1
```

**Permission Denied**
```bash
# Check IAM permissions
aws sts get-caller-identity
aws securityhub describe-hub --region us-east-1
```

**Region Mismatch**
```bash
# Verify AWS region configuration
aws configure get region
echo $AWS_REGION
```

**Findings Not Appearing**
- Check Security Hub console filters
- Verify findings aren't suppressed
- Confirm account ID matches

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Run with debug output
ash /path/to/code --reporters aws-security-hub --log-level DEBUG
```

## Cost Considerations

Security Hub pricing includes:

- **Finding ingestion**: $0.0003 per finding per month
- **Compliance checks**: Additional costs for enabled standards
- **API calls**: Standard AWS API pricing applies

### Cost Optimization Tips

1. **Filter findings** by severity to reduce ingestion costs
2. **Use suppression rules** for false positives
3. **Monitor usage** with AWS Cost Explorer
4. **Archive resolved findings** to reduce storage costs

## Compliance Integration

### AWS Foundational Security Standard

ASH findings automatically map to relevant controls:

- **[IAM.1]** Password policies for IAM users
- **[S3.1]** S3 bucket public access
- **[EC2.1]** Security group rules

### Custom Standards

Create custom standards that include ASH findings:

```bash
aws securityhub create-custom-action \
  --name "Mark ASH Finding as Accepted Risk" \
  --description "Accept ASH finding as business risk" \
  --id "ash-accept-risk"
```

## Best Practices

1. **Enable Security Hub** in all regions where you scan code
2. **Set up cross-region aggregation** for centralized monitoring
3. **Create custom insights** for ASH-specific findings
4. **Use suppression rules** for known false positives
5. **Integrate with incident response** workflows
6. **Monitor costs** and optimize finding ingestion
7. **Regular review** of findings and their resolution status

## Integration Examples

### With AWS Config

Correlate ASH findings with AWS Config compliance:

```python
import boto3

def correlate_findings():
    securityhub = boto3.client('securityhub')
    config = boto3.client('config')

    # Get ASH findings
    findings = securityhub.get_findings(
        Filters={'ProductName': [{'Value': 'ASH', 'Comparison': 'EQUALS'}]}
    )

    # Correlate with Config rules
    for finding in findings['Findings']:
        # Implementation depends on your specific use case
        pass
```

### With AWS Systems Manager

Create Systems Manager documents for automated remediation:

```yaml
schemaVersion: "0.3"
description: "Remediate ASH Security Finding"
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  FindingId:
    type: String
    description: "Security Hub Finding ID"
mainSteps:
  - name: "RemediateFinding"
    action: "aws:executeScript"
    inputs:
      Runtime: "python3.8"
      Handler: "remediate_finding"
      Script: |
        def remediate_finding(events, context):
            # Implement remediation logic
            pass
```

## Related Documentation

- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [AWS Security Finding Format (ASFF)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
- [ASH Configuration Guide](../../configuration-guide.md)
- [Other AWS Reporters](index.md)
