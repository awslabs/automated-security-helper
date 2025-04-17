# Local Development Setup Guide

This guide will help you set up your local development environment for the Automated Security Helper project.

## Prerequisites

- Python 3.10 or later
- Poetry (Python package manager)

## Setting up Poetry

1. Install Poetry on your system

[Official instructions](https://python-poetry.org/docs/#installing-with-the-official-installer)

Linux, macOS, Windows (WSL)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

```ps1
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | py -
```


1. Verify Poetry installation:
```bash
poetry --version
```

## Project Setup

1. Clone the repository:

```bash
git clone https://github.com/awslabs/automated-security-helper.git
cd automated-security-helper
```

2. Install project dependencies:

```bash
poetry install
```

This command will:
- Create a virtual environment
- Install all dependencies from pyproject.toml
- Set up the project in development mode

3. Activate the virtual environment:

```bash
eval $(poetry env activate)
```

## Testing

Run the test suite:
```bash
pytest
```

## Development Commands

- Format and lint code:
```bash
poetry run ruff .
```

- Run a specific script:
```bash
poetry run asharp
```

## Project Dependencies

The project uses the following key dependencies:
- Python
- bandit
- checkov
- pydantic

Development dependencies include:
- ruff
- pytest
- pytest-cov

## Troubleshooting

If you encounter any issues:

1. Verify your Python version matches the required version (3.10+):
```bash
python --version
```

2. Try cleaning and rebuilding the environment:
```bash
poetry env remove python
poetry install
```

3. Update Poetry and dependencies:
```bash
poetry self update
poetry update
```
