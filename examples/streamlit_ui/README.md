# ASH Streamlit UI

This is a Streamlit-based UI for the Automated Security Helper (ASH). It provides a graphical interface for running ASH scans, viewing results, and analyzing findings with Amazon Bedrock.

## Features

- Run ASH scans with configurable options
- View scan results and filter findings
- Analyze security findings with Amazon Bedrock AI
- Get AI-powered recommendations for fixing security issues

## Prerequisites

- Python 3.10 or later
- ASH v3 installed
- AWS credentials configured (for Amazon Bedrock integration)

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Make sure you have ASH installed:

```bash
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.0.0-beta
```

## Usage

Run the Streamlit app:

```bash
streamlit run ash_ui.py
```

### Running Scans

1. Navigate to the "Run Scan" tab
2. Configure your scan options
3. Click "Run ASH Scan"

### Viewing Results

1. Navigate to the "View Results" tab
2. Select a results file (default is `.ash/ash_output/ash_aggregated_results.json`)
3. Filter findings by severity or scanner
4. Click on a finding to view details

### AI Analysis

1. Navigate to the "AI Analysis" tab
2. Select your AWS region and Bedrock model
3. Click "Connect to Bedrock"
4. Select a finding from the "View Results" tab
5. Click "Analyze with Bedrock" to get AI-powered analysis and recommendations

## AWS Credentials

To use the Amazon Bedrock integration, you need to have AWS credentials configured with permissions to access Amazon Bedrock. You can configure credentials using:

- AWS CLI: `aws configure`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- AWS credentials file: `~/.aws/credentials`

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.