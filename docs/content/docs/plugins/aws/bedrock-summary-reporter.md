# Bedrock Summary Reporter

Generates AI-powered executive summaries and detailed security analysis using Amazon Bedrock's foundation models, providing human-readable insights from ASH scan results.

> For detailed visual diagrams of the Bedrock Summary Reporter architecture and workflow, see [Bedrock Summary Reporter Diagrams](bedrock-summary-reporter-diagrams.md).

> **Note**: This reporter has been updated to match the documentation. All features described in this document are now implemented.

## Overview

The Bedrock Summary Reporter leverages Amazon Bedrock to:

- **Generate executive summaries** for stakeholders and management
- **Provide detailed technical analysis** with remediation recommendations
- **Create risk assessments** based on finding severity and context
- **Support multiple foundation models** for different analysis styles
- **Customize output format** for various audiences

## Configuration

### Basic Configuration

```yaml
reporters:
  bedrock-summary-reporter:
    enabled: true
    options:
      model_id: "anthropic.claude-v2"
      aws_region: "us-east-1"
```

### Advanced Configuration

```yaml
reporters:
  bedrock-summary-reporter:
    enabled: true
    options:
      model_id: "anthropic.claude-instant-v1"
      aws_region: "us-west-2"
      max_tokens: 4000
      temperature: 0.1
      top_p: 0.9
      include_code_snippets: true
      summary_style: "executive"  # executive, technical, or detailed
      custom_prompt: "Focus on business impact and compliance risks"
      # Retry and fallback configuration
      max_retries: 5      # Default: 3
      base_delay: 2.0     # Default: 1.0 seconds
      max_delay: 120.0    # Default: 60.0 seconds
      enable_fallback_models: true
```

### Environment Variables

```bash
# AWS region
export AWS_REGION="us-east-1"

# Bedrock model ID
export ASH_BEDROCK_MODEL_ID="anthropic.claude-v2"

# Custom configuration
export ASH_BEDROCK_MAX_TOKENS="3000"
export ASH_BEDROCK_TEMPERATURE="0.2"
```

## Prerequisites

### Amazon Bedrock Setup

1. **Enable Bedrock** in your AWS account and region
2. **Request model access** for your chosen foundation models:
   ```bash
   # Check available models
   aws bedrock list-foundation-models --region us-east-1
   ```

3. **Grant model access** through the AWS Console:
   - Navigate to Amazon Bedrock → Model access
   - Request access to desired models (Claude, Titan, etc.)

### IAM Permissions

The reporter requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:ListFoundationModels",
        "bedrock:GetFoundationModel"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*",
        "arn:aws:bedrock:*::foundation-model/amazon.titan-*",
        "arn:aws:bedrock:*::foundation-model/ai21.j2-*",
        "arn:aws:bedrock:*::foundation-model/cohere.command-*"
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

## Supported Models

The Bedrock Summary Reporter works with any text-based foundation model available in Amazon Bedrock. Best results have been observed with Amazon Nova and Anthropic Claude models due to their strong reasoning capabilities and context handling.

### Model Selection Guidelines

```yaml
# Example configuration with Anthropic Claude model
model_id: "anthropic.claude-v2"
```

### Model Recommendations

| Use Case | Recommended Model Types | Considerations |
|----------|------------------------|----------------|
| Detailed Analysis | Claude, Nova | Best for comprehensive security analysis |
| Quick Summaries | Lighter models | Faster response, more cost-effective |
| CI/CD Integration | Optimized for speed | Choose models with lower latency |

### Checking Available Models

To see which models are available in your AWS account:

```bash
# List available foundation models
aws bedrock list-foundation-models --region us-east-1
```

> **Note**: Model availability may vary by region and account. Ensure you have requested access to your preferred models in the Amazon Bedrock console.

## Features

### Executive Summary Generation

Generates concise summaries for leadership:

```markdown
# Security Scan Executive Summary

## Overview
Your codebase scan identified **15 security findings** across 3 categories, with **2 critical issues** requiring immediate attention.

## Key Risks
- **Hardcoded credentials** in configuration files (CRITICAL)
- **SQL injection vulnerabilities** in user input handling (HIGH)
- **Insecure cryptographic practices** in data encryption (MEDIUM)

## Business Impact
- **Compliance risk**: Potential GDPR violations due to data exposure
- **Security risk**: Unauthorized access to customer data
- **Operational risk**: Potential service disruption

## Recommended Actions
1. Immediately rotate exposed credentials
2. Implement parameterized queries for database access
3. Update cryptographic libraries to current standards
```

### Technical Analysis

Provides detailed technical insights:

```markdown
# Technical Security Analysis

## Critical Findings Analysis

### 1. Hardcoded API Keys (2 instances)
**Location**: `src/config/database.py:15`, `src/utils/api_client.py:23`
**Risk**: Direct exposure of authentication credentials
**Remediation**:
- Move credentials to environment variables
- Implement AWS Secrets Manager integration
- Add credential scanning to CI/CD pipeline

### 2. SQL Injection Vulnerability
**Location**: `src/models/user.py:45-52`
**Risk**: Potential database compromise
**Code Pattern**: Direct string concatenation in SQL queries
**Remediation**:
- Replace with parameterized queries
- Implement input validation
- Add SQL injection testing
```

### Risk Assessment

Provides contextual risk analysis:

```markdown
# Risk Assessment

## Overall Risk Score: HIGH (7.5/10)

### Risk Breakdown
- **Critical Issues**: 2 (immediate action required)
- **High Severity**: 5 (address within 1 week)
- **Medium Severity**: 6 (address within 1 month)
- **Low Severity**: 2 (address in next sprint)

### Compliance Impact
- **SOC 2**: Critical findings may impact Type II compliance
- **PCI DSS**: Payment processing code requires immediate attention
- **GDPR**: Data handling practices need review
```

## Usage Examples

### Basic Usage

```bash
# Generate AI summary with default settings
ash /path/to/code --reporters bedrock-summary-reporter
```

### Custom Model and Style

```bash
# Use a lighter model for faster, cost-effective summaries
export ASH_BEDROCK_MODEL_ID="anthropic.claude-instant-v1"
ash /path/to/code --reporters bedrock-summary-reporter
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan with AI Summary
  env:
    AWS_REGION: us-east-1
    ASH_BEDROCK_MODEL_ID: "anthropic.claude-3-sonnet-20240229-v1:0"
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  run: |
    ash . --reporters sarif,bedrock-summary-reporter

- name: Post Summary to PR
  uses: actions/github-script@v6
  with:
    script: |
      const fs = require('fs');
      const summary = fs.readFileSync('output/bedrock-summary.md', 'utf8');
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: summary
      });
```

## Output Formats

### Markdown Report

The primary output is a comprehensive Markdown report:

```
output/
├── bedrock-summary.md          # Main summary report
├── bedrock-executive.md        # Executive summary only
└── bedrock-technical.md        # Technical details only
```

### Customizable Sections

Configure which sections to include:

```yaml
options:
  include_sections:
    - executive_summary
    - risk_assessment
    - technical_analysis
    - remediation_guide
    - compliance_impact
  exclude_sections:
    - code_snippets
    - detailed_findings
```

## Customization

### Custom Prompts

Tailor the AI analysis to your needs:

```yaml
options:
  custom_prompts:
    executive: |
      Create an executive summary focusing on:
      - Business impact and financial risk
      - Compliance implications
      - Strategic recommendations
      - Timeline for remediation

    technical: |
      Provide technical analysis including:
      - Root cause analysis
      - Specific remediation steps
      - Code examples where helpful
      - Testing recommendations
```

### Industry-Specific Analysis

Configure for specific industries:

```yaml
options:
  industry_context: "healthcare"  # healthcare, finance, retail, etc.
  compliance_frameworks: ["HIPAA", "SOC2", "GDPR"]
  custom_context: |
    This application processes patient health information
    and must comply with HIPAA requirements.
```

## Cost Optimization

### Model Selection

Choose models based on your needs:

| Model Type | Speed | Cost | Quality | Best For |
|------------|-------|------|---------|----------|
| Lighter Models | Fast | Low | Good | Quick summaries, CI/CD |
| Mid-tier Models | Medium | Medium | Excellent | Balanced analysis |
| Advanced Models | Slow | High | Superior | Detailed reports |

### Token Management

Optimize token usage:

```yaml
options:
  max_tokens: 2000        # Limit response length
  temperature: 0.1        # Reduce randomness for consistency
  summarize_findings: true # Pre-process findings to reduce input size
  batch_processing: true   # Process multiple scans together
```

### Usage Monitoring

Monitor Bedrock usage and costs:

```bash
# Check Bedrock usage
aws bedrock get-model-invocation-logging-configuration

# Monitor costs with CloudWatch
aws logs filter-log-events \
  --log-group-name "/aws/bedrock/modelinvocations" \
  --start-time 1640995200000
```

## Troubleshooting

### Common Issues

**Model Access Denied**
```bash
# Check model access status
aws bedrock list-foundation-models --region us-east-1

# Request access through AWS Console
# Bedrock → Model access → Request model access
```

**Token Limit Exceeded**
```yaml
# Reduce max_tokens or enable summarization
options:
  max_tokens: 1500
  summarize_findings: true
```

**High Costs**
```yaml
# Use more cost-effective model
options:
  model_id: "anthropic.claude-instant-v1"
  max_tokens: 1000
```

**API Errors**
```yaml
# Configure retry behavior
options:
  max_retries: 5      # Default: 3
  base_delay: 2.0     # Default: 1.0 seconds
  max_delay: 120.0    # Default: 60.0 seconds
  enable_fallback_models: true  # Enable fallback models
```

### Debug Mode

Enable debug logging:

```bash
ash /path/to/code --reporters bedrock-summary-reporter --log-level DEBUG
```

## Best Practices

1. **Choose appropriate models** based on use case and budget
2. **Set token limits** to control costs
3. **Use custom prompts** for industry-specific analysis
4. **Monitor usage** and costs regularly
5. **Cache results** for repeated analysis of the same codebase
6. **Combine with other reporters** for comprehensive reporting
7. **Review AI-generated content** for accuracy and relevance

## Integration Examples

### Slack Integration

Post summaries to Slack channels:

```python
import requests
import json

def post_to_slack(summary_file, webhook_url):
    with open(summary_file, 'r') as f:
        summary = f.read()

    payload = {
        "text": "Security Scan Summary",
        "attachments": [{
            "color": "warning",
            "text": summary[:1000] + "..." if len(summary) > 1000 else summary
        }]
    }

    requests.post(webhook_url, json=payload)
```

### Email Reports

Send executive summaries via email:

```python
import boto3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_summary(summary_file, recipients):
    ses = boto3.client('ses')

    with open(summary_file, 'r') as f:
        summary = f.read()

    msg = MIMEMultipart()
    msg['Subject'] = 'Security Scan Executive Summary'
    msg['From'] = 'security@company.com'
    msg['To'] = ', '.join(recipients)

    msg.attach(MIMEText(summary, 'plain'))

    ses.send_raw_email(
        Source=msg['From'],
        Destinations=recipients,
        RawMessage={'Data': msg.as_string()}
    )
```

## Related Documentation

- [Amazon Bedrock User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/)
- [Foundation Models in Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)
- [ASH Configuration Guide](../../configuration-guide.md)
- [Other AWS Reporters](index.md)
