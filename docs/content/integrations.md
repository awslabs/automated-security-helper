# Integrations

## Execution

| Workflow | Guide | Output |
| --- | --- | --- |
| Local development | [Run ASH locally](getting-started/local.md) | A scan you can inspect in the terminal or an offline HTML report |
| Pull requests and CI | [Run ASH in CI](getting-started/ci.md) | A reproducible check, an actionable summary, and report artifacts |
| Before a commit | [Set up pre-commit](how-to/pre-commit.md) | A faster project check before committing |
| An AI coding assistant | [Connect an MCP client](getting-started/agents.md) | Scan, poll progress, and retrieve findings from your editor |
| Several projects | [Workspace scanning over MCP](how-to/scale-large-repos.md) | Per-project results with a combined workspace view |

## Connect an AI assistant

Use [stdio for a local MCP client](how-to/mcp-server.md), or
[Streamable HTTP](how-to/mcp-server.md) when your client needs an HTTP
transport. Follow the [editor and agent guidance](docs/genai-steering-guide.md)
to add ASH to an existing coding workflow.

The [MCP tool reference](reference/mcp-tools.md) explains each tool's inputs
and outputs. For a running scan, poll its status before fetching results; review
coverage as well as findings.

## Reporting destinations

| Destination | Guide | Output |
| --- | --- | --- |
| GitHub or another SARIF consumer | [Report formats](reference/output-files.md) | Code scanning annotations and portable finding data |
| AWS Security Hub | [Security Hub reporter](plugins/aws.md) | Centralized security findings |
| Amazon S3 | [S3 reporter](plugins/aws.md) | Stored scan artifacts |
| Amazon CloudWatch Logs | [CloudWatch Logs reporter](plugins/aws.md) | Scan logs in an existing operational workflow |
| Amazon Bedrock | [Bedrock summary reporter](plugins/aws.md) | Executive and technical summaries with traceable finding references |
| A custom destination | [Build a reporter plugin](plugins/write-a-reporter.md) | A delivery format that fits your environment |

Configure enabled reporters in your [ASH configuration](how-to/configure.md).
AWS reporters need the permissions and regional settings described in their
guides. A scan's exit status reflects its configured thresholds and execution
state; a report's filters change only the view.
