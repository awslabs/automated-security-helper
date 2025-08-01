# AWS Plugins

ASH includes powerful AWS-specific plugins that extend security reporting capabilities with cloud-native services, enabling enterprise-scale security monitoring, AI-powered analysis, and seamless integration with AWS security services.

## Overview

AWS plugins provide:

- **Cloud-native integration** with AWS security and monitoring services
- **Scalable storage and processing** for large-scale security operations
- **AI-powered analysis** using Amazon Bedrock foundation models
- **Compliance reporting** through AWS Security Hub integration
- **Real-time monitoring** with CloudWatch Logs streaming

## Available Plugins

| Plugin                                                      | Purpose                      | Key Features                                                  | Use Cases                                             |
|-------------------------------------------------------------|------------------------------|---------------------------------------------------------------|-------------------------------------------------------|
| **[Security Hub Reporter](security-hub-reporter.md)**       | AWS Security Hub integration | ASFF format, batch processing, compliance mapping             | Centralized security monitoring, compliance reporting |
| **[Bedrock Summary Reporter](bedrock-summary-reporter.md)** | AI-powered summaries         | Executive summaries, technical analysis, multiple models      | Management reporting, risk assessment                 |
| **[CloudWatch Logs Reporter](cloudwatch-logs-reporter.md)** | Real-time logging            | Structured logging, metric filters, alarms                    | Real-time monitoring, automated alerting              |
| **[S3 Reporter](s3-reporter.md)**                           | Cloud storage for reports    | Multiple formats, lifecycle management, analytics integration | Long-term archival, data analytics                    |

## Quick Start

### Basic Setup

1. **Configure AWS credentials**:
   ```bash
   aws configure
   # or use IAM roles (recommended)
   ```

2. **Enable desired plugins**:
   ```yaml
   # ash-config.yml
   reporters:
     aws-security-hub:
       enabled: true
       options:
         aws_region: "us-east-1"

     s3-reporter:
       enabled: true
       options:
         bucket_name: "my-security-reports"
         aws_region: "us-east-1"
   ```

3. **Run scan with AWS reporters**:
   ```bash
   ash /path/to/code --reporters aws-security-hub,s3-reporter
   ```

### Enterprise Setup

For enterprise deployments, combine multiple AWS plugins:

```yaml
# Enterprise configuration
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-east-1"

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
      storage_class: "STANDARD_IA"
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
| Security Hub Reporter    | AWS Security Hub       | AWS Config, AWS Inspector      |
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
        "securityhub:GetFindings",
        "bedrock:InvokeModel",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

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
ash /path/to/code --reporters aws-security-hub
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
      run: |
        ash . --reporters aws-security-hub,bedrock-summary-reporter,s3-reporter

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
        stage('Security Scan') {
            steps {
                withAWS(role: 'arn:aws:iam::123456789012:role/Jenkins-ASH') {
                    sh '''
                        ash . \
                          --reporters aws-security-hub,s3-reporter,cloudwatch-logs \
                          --config jenkins-ash-config.yml
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
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']

        # Download and extract code
        s3 = boto3.client('s3')
        s3.download_file(bucket, key, '/tmp/code.zip')

        # Extract and scan
        subprocess.run(['unzip', '/tmp/code.zip', '-d', '/tmp/code'])

        # Run ASH with AWS reporters
        result = subprocess.run([
            'ash', 'scan', '/tmp/code',
            '--reporters', 'aws-security-hub,cloudwatch-logs',
            '--config', '/opt/ash-lambda-config.yml'
        ], capture_output=True, text=True)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan completed successfully',
                'findings_count': result.stdout.count('finding')
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
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
| Security Hub Reporter    | $0.0003 per finding     | $10-50                  |
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
# Enable debug logging for all AWS plugins
ash /path/to/code \
  --reporters aws-security-hub,bedrock-summary-reporter,cloudwatch-logs,s3-reporter \
  --log-level DEBUG
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
reporters:
  aws-security-hub:
    enabled: true
    options:
      aws_region: "us-east-1"

  s3-reporter:
    enabled: true
    options:
      bucket_name: "security-reports"
      formats: ["sarif", "html"]

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
