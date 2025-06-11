# S3 Reporter

Stores ASH security scan reports in Amazon S3 for centralized storage, archival, and integration with other AWS services.

## Overview

The S3 Reporter provides:

- **Centralized storage** of scan results across multiple environments
- **Long-term archival** with configurable lifecycle policies
- **Integration with AWS analytics** services like Athena and QuickSight
- **Secure access control** using S3 bucket policies and IAM
- **Cost-effective storage** with multiple storage classes

## Configuration

### Basic Configuration

```yaml
reporters:
  s3-reporter:
    enabled: true
    options:
      bucket_name: "my-security-reports"
      aws_region: "us-east-1"
```

### Advanced Configuration

```yaml
reporters:
  s3-reporter:
    enabled: true
    options:
      bucket_name: "company-security-scans"
      aws_region: "us-west-2"
      key_prefix: "ash-reports"
      include_timestamp: true
      storage_class: "STANDARD_IA"
      server_side_encryption: "AES256"
      metadata:
        project: "security-scanning"
        environment: "production"
        team: "security"
```

### Environment Variables

```bash
# S3 bucket name
export ASH_S3_BUCKET_NAME="my-security-reports"

# AWS region
export AWS_REGION="us-east-1"

# Optional: S3 key prefix
export ASH_S3_KEY_PREFIX="security-scans"
```

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
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-security-reports",
        "arn:aws:s3:::my-security-reports/*"
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

## Features

### Flexible File Organization

The reporter supports various file organization patterns:

```
s3://my-security-reports/
├── ash-reports/
│   ├── 2024/
│   │   ├── 06/
│   │   │   ├── 11/
│   │   │   │   ├── scan-20240611-120000.sarif.json
│   │   │   │   ├── scan-20240611-120000.html
│   │   │   │   └── scan-20240611-120000.csv
│   │   │   └── daily-summary-20240611.json
│   │   └── monthly-summary-202406.json
│   └── latest/
│       ├── latest.sarif.json
│       └── latest.html
```

### Multiple Format Support

Store reports in various formats simultaneously:

```yaml
options:
  formats:
    - "sarif"     # SARIF JSON format
    - "html"      # HTML report
    - "csv"       # CSV export
    - "json"      # Raw JSON data
    - "yaml"      # YAML format
```

### Metadata and Tagging

Add metadata and tags for better organization:

```yaml
options:
  metadata:
    project: "web-application"
    environment: "production"
    scan_type: "security"
    version: "1.2.3"
  tags:
    Team: "Security"
    Project: "WebApp"
    Environment: "Prod"
    CostCenter: "Engineering"
```

### Storage Class Optimization

Choose appropriate storage classes for cost optimization:

```yaml
options:
  storage_class: "STANDARD_IA"  # Options: STANDARD, STANDARD_IA, ONEZONE_IA, GLACIER, DEEP_ARCHIVE
```

## Usage Examples

### Basic Usage

```bash
# Store reports in S3
ash scan /path/to/code --reporters s3-reporter
```

### With Custom Configuration

```bash
# Set bucket via environment variable
export ASH_S3_BUCKET_NAME="security-reports-prod"
export ASH_S3_KEY_PREFIX="applications/web-app"
ash scan /path/to/code --reporters s3-reporter,sarif
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Security Scan
  env:
    AWS_REGION: us-east-1
    ASH_S3_BUCKET_NAME: "ci-security-reports"
    ASH_S3_KEY_PREFIX: "github-actions/${{ github.repository }}"
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: |
    ash scan . --reporters s3-reporter,sarif
    
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
        ASH_S3_KEY_PREFIX = "jobs/${env.JOB_NAME}/${env.BUILD_NUMBER}"
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'ash scan . --reporters s3-reporter,html'
            }
        }
        stage('Archive Results') {
            steps {
                script {
                    def reportUrl = "https://s3.console.aws.amazon.com/s3/buckets/${env.ASH_S3_BUCKET_NAME}/${env.ASH_S3_KEY_PREFIX}/"
                    currentBuild.description = "Security Report: ${reportUrl}"
                }
            }
        }
    }
}
```

## Integration with AWS Services

### Amazon Athena

Query scan results using SQL:

```sql
-- Create external table for SARIF reports
CREATE EXTERNAL TABLE security_scans (
  scan_id string,
  timestamp string,
  findings array<struct<
    rule_id: string,
    severity: string,
    message: string,
    file_path: string
  >>
)
STORED AS JSON
LOCATION 's3://my-security-reports/ash-reports/'
```

### Amazon QuickSight

Create dashboards from S3 data:

1. **Connect to S3**: Use Athena as data source
2. **Create datasets**: From security scan tables
3. **Build visualizations**: Trend analysis, severity distribution
4. **Share dashboards**: With security teams and management

### AWS Lambda

Process reports automatically:

```python
import json
import boto3

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    
    # Triggered by S3 event
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    # Download and process report
    response = s3.get_object(Bucket=bucket, Key=key)
    report_data = json.loads(response['Body'].read())
    
    # Process findings (e.g., send alerts for critical issues)
    critical_findings = [
        finding for finding in report_data.get('findings', [])
        if finding.get('severity') == 'CRITICAL'
    ]
    
    if critical_findings:
        # Send alert via SNS
        sns = boto3.client('sns')
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123456789012:security-alerts',
            Message=f'Critical security findings detected: {len(critical_findings)} issues',
            Subject='Security Alert: Critical Findings'
        )
    
    return {'statusCode': 200}
```

## Lifecycle Management

### S3 Lifecycle Policies

Automatically manage report retention:

```json
{
  "Rules": [
    {
      "ID": "ASH-Reports-Lifecycle",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "ash-reports/"
      },
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555  // 7 years retention
      }
    }
  ]
}
```

Apply lifecycle policy:

```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket my-security-reports \
  --lifecycle-configuration file://lifecycle-policy.json
```

### Automated Cleanup

Clean up old reports with Lambda:

```python
import boto3
from datetime import datetime, timedelta

def cleanup_old_reports(event, context):
    s3 = boto3.client('s3')
    bucket_name = 'my-security-reports'
    
    # Delete reports older than 90 days
    cutoff_date = datetime.now() - timedelta(days=90)
    
    paginator = s3.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=bucket_name, Prefix='ash-reports/')
    
    for page in pages:
        for obj in page.get('Contents', []):
            if obj['LastModified'].replace(tzinfo=None) < cutoff_date:
                s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
                print(f"Deleted: {obj['Key']}")
```

## Security Best Practices

### Bucket Security

1. **Block public access**:
   ```bash
   aws s3api put-public-access-block \
     --bucket my-security-reports \
     --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```

2. **Enable server-side encryption**:
   ```bash
   aws s3api put-bucket-encryption \
     --bucket my-security-reports \
     --server-side-encryption-configuration '{
       "Rules": [{
         "ApplyServerSideEncryptionByDefault": {
           "SSEAlgorithm": "AES256"
         }
       }]
     }'
   ```

3. **Enable access logging**:
   ```bash
   aws s3api put-bucket-logging \
     --bucket my-security-reports \
     --bucket-logging-status '{
       "LoggingEnabled": {
         "TargetBucket": "my-access-logs",
         "TargetPrefix": "security-reports-access/"
       }
     }'
   ```

### Access Control

Use IAM policies for fine-grained access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/SecurityTeam"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-security-reports",
        "arn:aws:s3:::my-security-reports/*"
      ]
    }
  ]
}
```

## Cost Optimization

### Storage Class Selection

| Storage Class | Use Case | Cost | Retrieval Time |
|---------------|----------|------|----------------|
| STANDARD | Frequently accessed reports | Highest | Immediate |
| STANDARD_IA | Monthly/quarterly reviews | Medium | Immediate |
| GLACIER | Long-term archival | Low | Minutes to hours |
| DEEP_ARCHIVE | Compliance archival | Lowest | 12+ hours |

### Cost Monitoring

Monitor S3 costs:

```bash
# Get storage metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/S3 \
  --metric-name BucketSizeBytes \
  --dimensions Name=BucketName,Value=my-security-reports Name=StorageType,Value=StandardStorage \
  --start-time 2024-06-01T00:00:00Z \
  --end-time 2024-06-11T00:00:00Z \
  --period 86400 \
  --statistics Average
```

## Troubleshooting

### Common Issues

**Access Denied**
```bash
# Check bucket permissions
aws s3api get-bucket-policy --bucket my-security-reports

# Verify IAM permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/ash-user \
  --action-names s3:PutObject \
  --resource-arns arn:aws:s3:::my-security-reports/test-object
```

**Bucket Not Found**
```bash
# List available buckets
aws s3 ls

# Check bucket region
aws s3api get-bucket-location --bucket my-security-reports
```

**Upload Failures**
```bash
# Test S3 connectivity
aws s3 cp test-file.txt s3://my-security-reports/test/

# Check CloudTrail for detailed error information
aws logs filter-log-events \
  --log-group-name CloudTrail/S3DataEvents \
  --start-time 1640995200000
```

### Debug Mode

Enable debug logging:

```bash
ash scan /path/to/code --reporters s3-reporter --log-level DEBUG
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
