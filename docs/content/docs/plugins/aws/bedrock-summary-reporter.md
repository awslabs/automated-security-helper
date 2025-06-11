# Bedrock Summary Reporter

Generates AI-powered executive summaries and detailed security analysis using Amazon Bedrock's foundation models, providing human-readable insights from ASH scan results.

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
      model_id: "anthropic.claude-3-sonnet-20240229-v1:0"
      aws_region: "us-east-1"
```

### Advanced Configuration

```yaml
reporters:
  bedrock-summary-reporter:
    enabled: true
    options:
      model_id: "anthropic.claude-3-haiku-20240307-v1:0"
      aws_region: "us-west-2"
      max_tokens: 4000
      temperature: 0.1
      top_p: 0.9
      include_code_snippets: true
      summary_style: "executive"  # executive, technical, or detailed
      custom_prompt: "Focus on business impact and compliance risks"
```

### Environment Variables

```bash
# AWS region
export AWS_REGION="us-east-1"

# Bedrock model ID
export ASH_BEDROCK_MODEL_ID="anthropic.claude-3-sonnet-20240229-v1:0"

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

### Anthropic Claude Models

```yaml
# Claude 3 Sonnet (balanced performance and cost)
model_id: "anthropic.claude-3-sonnet-20240229-v1:0"

# Claude 3 Haiku (fastest, most cost-effective)
model_id: "anthropic.claude-3-haiku-20240307-v1:0"

# Claude 3 Opus (highest capability)
model_id: "anthropic.claude-3-opus-20240229-v1:0"
```

### Amazon Titan Models

```yaml
# Titan Text G1 - Express
model_id: "amazon.titan-text-express-v1"

# Titan Text G1 - Lite
model_id: "amazon.titan-text-lite-v1"
```

### AI21 Labs Jurassic Models

```yaml
# Jurassic-2 Mid
model_id: "ai21.j2-mid-v1"

# Jurassic-2 Ultra
model_id: "ai21.j2-ultra-v1"
```

### Cohere Command Models

```yaml
# Command
model_id: "cohere.command-text-v14"

# Command Light
model_id: "cohere.command-light-text-v14"
```

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
ash scan /path/to/code --reporters bedrock-summary-reporter
```

### Custom Model and Style

```bash
# Use Claude Haiku for faster, cost-effective summaries
export ASH_BEDROCK_MODEL_ID="anthropic.claude-3-haiku-20240307-v1:0"
ash scan /path/to/code --reporters bedrock-summary-reporter
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
    ash scan . --reporters sarif,bedrock-summary-reporter
    
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

| Model | Speed | Cost | Quality | Best For |
|-------|-------|------|---------|----------|
| Claude Haiku | Fast | Low | Good | Quick summaries, CI/CD |
| Claude Sonnet | Medium | Medium | Excellent | Balanced analysis |
| Claude Opus | Slow | High | Superior | Detailed reports |

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
  model_id: "anthropic.claude-3-haiku-20240307-v1:0"
  max_tokens: 1000
```

### Debug Mode

Enable debug logging:

```bash
ash scan /path/to/code --reporters bedrock-summary-reporter --log-level DEBUG
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
