# CloudWatch Logs Reporter

Streams ASH scan results to Amazon CloudWatch Logs for real-time monitoring and analysis.

> For detailed visual diagrams of the CloudWatch Logs Reporter architecture and workflow, see [CloudWatch Logs Reporter Diagrams](cloudwatch-logs-reporter-diagrams.md).

## Overview

The CloudWatch Logs Reporter publishes security scan results directly to Amazon CloudWatch Logs, enabling:

- **Real-time monitoring** of security scan results
- **Integration with CloudWatch alarms** for automated alerting
- **Centralized logging** across multiple scan environments
- **Long-term retention** with configurable log retention policies

## Configuration

### Basic Configuration

```yaml
reporters:
  cloudwatch-logs:
    enabled: true
    options:
      aws_region: "us-east-1"
      log_group_name: "/aws/ash/scan-results"
      log_stream_name: "ASHScanResults"
```

### Environment Variables

The reporter supports configuration via environment variables:

```bash
# AWS region (falls back to AWS_DEFAULT_REGION)
export AWS_REGION="us-east-1"

# CloudWatch log group name
export ASH_CLOUDWATCH_LOG_GROUP_NAME="/aws/ash/scan-results"
```

### Complete Configuration Example

```yaml
reporters:
  cloudwatch-logs:
    enabled: true
    options:
      aws_region: "us-east-1"
      log_group_name: "/aws/ash/security-scans"
      log_stream_name: "production-scans"
```

## Prerequisites

### AWS Permissions

The reporter requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/ash/*",
        "arn:aws:logs:*:*:log-group:/aws/ash/*:*"
      ]
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

### CloudWatch Log Group

The log group must exist before publishing logs:

```bash
# Create log group
aws logs create-log-group --log-group-name "/aws/ash/scan-results"

# Set retention policy (optional)
aws logs put-retention-policy \
  --log-group-name "/aws/ash/scan-results" \
  --retention-in-days 30
```

## Features

### Structured Logging

Results are published as structured JSON logs:

```json
{
  "timestamp": "2024-06-11T00:00:00Z",
  "scan_id": "ash-scan-20240611-000000",
  "source": "ASH",
  "level": "INFO",
  "message": "Security scan completed",
  "results": {
    "total_findings": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "scanners_executed": ["bandit", "semgrep", "checkov"],
    "scan_duration": 45.2
  }
}
```

### Automatic Log Stream Management

- **Auto-creation**: Log streams are created automatically if they don't exist
- **Timestamped entries**: Each log entry includes precise timestamps
- **Batch processing**: Multiple findings are efficiently batched for performance

### Integration with CloudWatch Features

- **CloudWatch Insights**: Query and analyze scan results using CloudWatch Logs Insights
- **Metric Filters**: Create custom metrics from log data
- **Alarms**: Set up alarms based on security findings
- **Dashboards**: Visualize security trends over time

## Usage Examples

### Basic Usage

```bash
# Run scan with CloudWatch Logs reporting
ash /path/to/code --reporters cloudwatch-logs
```

### With Custom Configuration

```bash
# Set log group via environment variable
export ASH_CLOUDWATCH_LOG_GROUP_NAME="/security/ash-scans"
ash /path/to/code --reporters cloudwatch-logs
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run ASH Security Scan
  env:
    AWS_REGION: us-east-1
    ASH_CLOUDWATCH_LOG_GROUP_NAME: "/ci-cd/security-scans"
  run: |
    ash . --reporters cloudwatch-logs,sarif
```

## CloudWatch Insights Queries

### Query Recent Scan Results

```sql
fields @timestamp, scan_id, results.total_findings, results.critical, results.high
| filter @message like /Security scan completed/
| sort @timestamp desc
| limit 20
```

### Find High-Severity Findings

```sql
fields @timestamp, scan_id, results.critical, results.high
| filter results.critical > 0 or results.high > 0
| sort @timestamp desc
```

### Analyze Scanner Performance

```sql
fields @timestamp, scan_id, results.scan_duration, results.scanners_executed
| stats avg(results.scan_duration) by bin(5m)
```

## Monitoring and Alerting

### CloudWatch Alarms

Create alarms for critical security findings:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name "ASH-Critical-Findings" \
  --alarm-description "Alert on critical security findings" \
  --metric-name "CriticalFindings" \
  --namespace "ASH/Security" \
  --statistic "Sum" \
  --period 300 \
  --threshold 1 \
  --comparison-operator "GreaterThanOrEqualToThreshold"
```

### Metric Filters

Extract metrics from log data:

```bash
aws logs put-metric-filter \
  --log-group-name "/aws/ash/scan-results" \
  --filter-name "CriticalFindings" \
  --filter-pattern '[timestamp, scan_id, source, level, message, results.critical > 0]' \
  --metric-transformations \
    metricName=CriticalFindings,metricNamespace=ASH/Security,metricValue=1
```

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Check IAM permissions
aws sts get-caller-identity
aws logs describe-log-groups --log-group-name-prefix "/aws/ash"
```

**Log Group Not Found**
```bash
# Create the log group
aws logs create-log-group --log-group-name "/aws/ash/scan-results"
```

**Region Mismatch**
```bash
# Verify AWS region configuration
aws configure get region
echo $AWS_REGION
```

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Run with debug output
ash /path/to/code --reporters cloudwatch-logs --log-level DEBUG
```

### Retry Configuration

Configure retry behavior for API calls:

```yaml
reporters:
  cloudwatch-logs:
    enabled: true
    options:
      aws_region: "us-east-1"
      log_group_name: "/aws/ash/scan-results"
      log_stream_name: "ASHScanResults"
      # Retry configuration
      max_retries: 5  # Increase max retries
      base_delay: 2.0  # Increase base delay
      max_delay: 120.0  # Increase max delay
``````

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
# Run with debug output
ash /path/to/code --reporters cloudwatch-logs --log-level DEBUG
```

## Cost Considerations

CloudWatch Logs pricing includes:

- **Ingestion**: $0.50 per GB ingested
- **Storage**: $0.03 per GB per month
- **Insights queries**: $0.005 per GB scanned

### Cost Optimization Tips

1. **Set retention policies** to automatically delete old logs
2. **Use log filtering** to reduce ingestion volume
3. **Compress large scan results** before logging
4. **Monitor usage** with CloudWatch billing alarms

## Integration Examples

### With AWS Lambda

```python
import boto3
import json

def lambda_handler(event, context):
    # Trigger ASH scan and log results
    # Implementation depends on your Lambda setup
    pass
```

### With Amazon EventBridge

Create rules to trigger actions based on scan results:

```json
{
  "Rules": [
    {
      "Name": "ASH-Critical-Findings",
      "EventPattern": {
        "source": ["aws.logs"],
        "detail": {
          "results": {
            "critical": [{"numeric": [">", 0]}]
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

## Best Practices

1. **Use descriptive log group names** that reflect your organization structure
2. **Set appropriate retention policies** to manage costs
3. **Create metric filters** for key security metrics
4. **Set up alarms** for critical and high-severity findings
5. **Use CloudWatch Insights** for regular security analysis
6. **Tag log groups** for better resource management
7. **Monitor costs** and optimize log retention as needed

## Related Documentation

- [AWS CloudWatch Logs Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [CloudWatch Logs Insights Query Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [ASH Configuration Guide](../../configuration-guide.md)
- [Other AWS Reporters](index.md)
