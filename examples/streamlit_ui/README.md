# ASH Streamlit UI Example

This example demonstrates how to use Streamlit to create a web-based user interface for the Automated Security Helper (ASH).

## Features

- Run ASH scans with a user-friendly interface
- Configure all ASH scan parameters through the UI
- View and filter scan results
- Display summary reports

## Requirements

- Python 3.8+
- Streamlit
- ASH v3.0.0-beta or later

## Installation

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Run the Streamlit application:

```bash
streamlit run ash_ui.py
```

2. Open your web browser and navigate to the URL displayed in the terminal (typically http://localhost:8501)

3. Use the interface to configure and run ASH scans

## Configuration

The UI provides access to all ASH scan configuration options, including:

- Source and output directories
- Scanner selection
- Execution options
- Output formats
- Logging options
- Container options

## Viewing Results

The "View Results" tab allows you to:

- Load and view scan results
- Filter findings by severity and scanner
- View detailed information about each finding
- Access summary reports

## Notes

- This UI is intended for local development and testing purposes
- For production use, consider implementing authentication and access controls