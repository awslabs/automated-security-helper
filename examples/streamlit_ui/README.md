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

Install the required dependencies:

```bash
# ASH
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.1.5

# Streamlit
pip install streamlit
```

## Usage

### Start the Streamlit app...

#### ...directly from GitHub...

```bash
streamlit run https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/examples/streamlit_ui/ash_ui.py
```

#### ...or clone and run from local

```bash
git clone https://github.com/awslabs/automated-security-helper.git --branch v3.1.5
streamlit run ./automated-security-helper/examples/streamlit_ui/ash_ui.py
```

### Running Scans

> Note: If you already have a scan completed and you'd like to interact with the results
> you can skip directly to the Results and Analysis tabs

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
2. Select your AWS profile and region
3. Click "Connect to Bedrock"
4. Load findings directly in the AI Analysis tab:
   - Enter the path to your results file
   - Click "Load Findings"
5. Filter findings:
   - By default, only unsuppressed findings are shown
   - Uncheck "Show unsuppressed findings only" to see all findings
6. Select a finding to analyze:
   - Use the dropdown to select a specific finding
   - Use Previous/Next buttons to navigate through findings
7. Select a model from the list
   - Available models and inference profiles are retrieved from Amazon Bedrock using the selected profile
8. Click "Analyze with Bedrock" to get AI-powered analysis and recommendations
   - The analysis includes security concerns, potential impacts, and recommended fixes

## AWS Credentials

To use the Amazon Bedrock integration, you need to have AWS credentials configured with permissions to access Amazon Bedrock. You can configure credentials using:

- AWS CLI: `aws configure`
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- AWS credentials file: `~/.aws/credentials`

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
