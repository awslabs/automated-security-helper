# Connect an AI agent to ASH

In this tutorial you connect a coding agent to ASH's MCP server and have the agent scan a
small project for you. The agent starts the scan, follows it to the end, reads the results,
explains a finding, drafts a suppression, and compares two scans.

Any agent or IDE that can start a local MCP server over stdio works: Claude Code, Kiro, Cursor,
GitHub Copilot in VS Code, Codex, Gemini CLI, and others. The agent starts `ash mcp` as a child
process on your machine, and every scan runs there, with the scanner tools installed there.

You need git and an agent that supports MCP tools.

## 1. Install ASH

Install ASH with one of the methods in [Install ASH](../how-to/install.md), then check that
`ash` is on your `PATH`:

```bash
ash --version
```

It prints the ASH version.

Then install the tools the scanners run:

<!-- doctest: illustrative reason="downloads scanner tools from the network" -->
```bash
ash dependencies install
```

You can skip this step. In an online scan with the sandbox off, ASH then installs the tools
it runs with uv itself, which needs uv on your `PATH`. Every other scanner whose tool is
missing, and that has files to scan, is reported as MISSING, and the scan ends with status
`incomplete`. [Manage scanner tools](../docs/advanced-usage.md) lists the tools ASH installs
with uv and explains where ASH looks for the others.

## 2. Create a project to scan

Make a project with two known problems, so you can check what the agent reports:

```bash
mkdir ash-agent-demo
cd ash-agent-demo
git init --quiet
cat > app.py <<'EOF'
import hashlib
import subprocess


def cache_key(text):
    return hashlib.md5(text.encode()).hexdigest()


def run(command):
    return subprocess.call(command, shell=True)
EOF
pwd
```

`pwd` prints the absolute path of the project. You give that path to the agent.

## 3. Connect the agent

Add this server to your agent's MCP configuration:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "ash",
      "args": ["mcp"]
    }
  }
}
```

Where the file lives depends on the agent. VS Code reads `.vscode/mcp.json` and uses the key
`servers` instead of `mcpServers`. [Install the ASH plugin for your
agent](../how-to/agent-plugins.md) shows the file each agent reads, and it also covers the
generated plugins, which add this server together with instructions for the agent.

In Claude Code you can add the server from the command line instead:

<!-- doctest: illustrative reason="needs Claude Code" -->
```bash
claude mcp add ash -- ash mcp
```

Restart the agent, or reload its MCP servers, so it starts `ash mcp`.

If the agent reports that it cannot start the server, it probably does not see the same `PATH`
as your shell, which is common for desktop apps. Put the absolute path of `ash` in `command`.
This prints it:

```bash
command -v ash
```

## 4. Check the connection

Ask the agent:

```text
Call the ASH check_installation tool and tell me what it returns.
```

The agent calls `check_installation`. You should see `"installed": true` and the ASH version.
If the agent says it has no ASH tools, the server did not start: check the configuration from
step 3.

`check_installation` also asks each built-in scanner whether its tool is installed.
`"ready": true` means every scanner that ASH enables by default can run, or will once the
first scan installs its tool; otherwise `missing_dependencies` names the ones that cannot. It
installs nothing. If you skipped step 1, the scanners whose tool ASH installs with uv are in
`installs_on_first_scan`: the first scan installs them, which needs network access.
Install any scanner listed in `missing_dependencies` (step 1).

## 5. Ask for a scan

Ask the agent, with the path that `pwd` printed in step 2:

```text
Use ASH to scan /absolute/path/to/ash-agent-demo and tell me what it finds.
```

Scanning a project takes from several seconds to a few minutes. The agent works through it
like this:

1. It calls `run_ash_scan` with `source_dir` set to the project. The tool returns at once
   with a `scan_id` and status `running`. The scan continues in the server.
2. It calls `get_scan_progress` with that `scan_id` every few seconds until `is_complete` is
   true. `status` is then one of the final values in the table below.
3. It reads the results.

| Final status | Meaning |
|--------------|---------|
| `completed` | Every selected scanner ran. |
| `incomplete` | The scan finished and its results are readable, but at least one selected scanner did not run or did not finish. `incomplete_scanners` names each one and the reason, such as `missing_dependencies`. The findings are real but do not cover what those scanners check. |
| `failed` | The scan crashed or left no readable results. `error_message` says why. |
| `cancelled` | Someone canceled the scan. |

`incomplete` is a final status. If your agent keeps polling after the scan reports it, tell
the agent that the scan is finished.

When the scan ends, the agent reports three findings, all from bandit:

| Rule | Severity | Line | Finding |
|------|----------|------|---------|
| B602 | HIGH | 10 | `subprocess` call with `shell=True` |
| B324 | HIGH | 6 | MD5 hash |
| B404 | LOW | 2 | `import subprocess` |

The two HIGH findings are actionable: they are at or above the default severity threshold,
MEDIUM. The LOW finding is reported but does not fail a scan.

If the status is `incomplete`, ask the agent which scanners were incomplete and why. Install
their tools (step 1) and ask for the scan again.

If the agent reports "Scan target is outside the permitted roots", the project is in a place
the server refuses by default: the filesystem root, or one of `/boot`, `/dev`, `/etc`, `/proc`,
`/root`, and `/sys` (Windows has its own list). This happens when you work as root, in a
container for example. Name the directory that holds your projects in `ASH_MCP_ALLOWED_ROOTS`,
in the server's environment, and restart the agent:

<!-- doctest: config kind=mcp-client -->
```json
{
  "mcpServers": {
    "ash": {
      "command": "ash",
      "args": ["mcp"],
      "env": {
        "ASH_MCP_ALLOWED_ROOTS": "/root/projects"
      }
    }
  }
}
```

Once the variable is set, the server scans, and reads results from, only the directories it
names and their subdirectories.

## 6. Read the results

ASH wrote its output into the project, in `.ash/ash_output`. The agent read it through
`get_scan_results`, and you can open the same files:

| File | What it holds |
|------|---------------|
| `.ash/ash_output/reports/ash.summary.md` | A readable summary: scanners, counts, and findings. |
| `.ash/ash_output/reports/ash.flat.json` | One record per finding, with its `id`, `rule_id`, `severity`, `file_path`, and line. |
| `.ash/ash_output/reports/ash.html` | The same findings as a web page. |
| `.ash/ash_output/ash_aggregated_results.json` | Everything ASH knows about the scan, including each scanner's status. |

[Read scan results](../how-to/read-results.md) describes every output file.

## 7. Explain a finding

Ask the agent:

```text
Explain the B602 finding.
```

The agent finds the finding's `id` in `ash.flat.json` (for this project,
`bandit-B602-e1cb79ce5694`) and calls `explain_finding` with it and the output directory. The
answer includes the scanner's description, "subprocess call with shell=True identified,
security issue.", the severity and why it is actionable ("above MEDIUM threshold"), and the
code at line 10.

## 8. Draft a suppression

The MD5 hash on line 6 builds a cache key and protects nothing, so in this project it is an
accepted risk. (Passing `usedforsecurity=False` to `hashlib.md5` would fix it in the code; a
suppression records the decision in the config instead.) Ask the agent:

```text
Draft an ASH suppression for the B324 finding with the reason
"MD5 builds a cache key; it does not protect anything". Do not edit any files.
```

The agent calls `suggest_suppression`, which writes nothing and returns an entry like this.
`suggest_suppression` takes the path of the results file,
`.ash/ash_output/ash_aggregated_results.json`, not the output directory that `explain_finding`
takes.

```text
client_supplied: false
expiration: '2027-01-08'
line_end: 6
line_start: 6
path: app.py
reason: MD5 builds a cache key; it does not protect anything
rule_id: B324
```

The expiration date defaults to 90 days from today. From that date on, the suppression no
longer applies and the finding comes back. ASH sets `client_supplied` itself, so leave it out
of your config. Add the entry to the project's config under `global_settings.suppressions`,
and put in the date the agent gave you. The project has no config yet, so create
`.ashrc.yaml`:

```bash
cat > .ashrc.yaml <<'EOF'
global_settings:
  suppressions:
    - rule_id: "B324"
      path: "app.py"
      line_start: 6
      line_end: 6
      reason: "MD5 builds a cache key; it does not protect anything"
      expiration: "2027-06-30"
EOF
```

Check that ASH accepts the file:

```bash
ash config validate
```

It checks the config a scan of the project would use, the way the scan loads it, and ends
with `Configuration is valid! A scan accepts it.` It may also warn that `project_name` is not
set, which a scan accepts. A wrong value, a missing required field such as `reason`, or a
misspelled key such as `expiry` for `expiration` makes it name the field and exit with code 3:

<!-- doctest: run expect-exit=3 -->
```bash
sed 's/expiration:/expiry:/' .ashrc.yaml > typo.yaml
ash config validate --config typo.yaml
```

Then delete the copy:

```bash
rm typo.yaml
```

[Suppress findings](../how-to/suppress-findings.md) covers the other fields a suppression can
use.

## 9. Fix a finding and compare the scans

The next scan replaces the results in `.ash/ash_output`, so keep a copy of this scan first. If
you set `ASH_MCP_ALLOWED_ROOTS`, keep the copy inside one of its directories, where the server
can read it:

<!-- doctest: illustrative reason="needs the results of the scan the agent ran" -->
```bash
cp .ash/ash_output/ash_aggregated_results.json ../scan1-results.json
```

Fix the B602 finding by removing `shell=True`:

```bash
cat > app.py <<'EOF'
import hashlib
import subprocess


def cache_key(text):
    return hashlib.md5(text.encode()).hexdigest()


def run(command):
    return subprocess.call(command)
EOF
```

Ask the agent, with the absolute path of the copy:

```text
Scan the project again, then use diff_scan_results to compare
/absolute/path/to/scan1-results.json with the new ash_aggregated_results.json.
```

`diff_scan_results` returns three lists:

| List | Contents for this project |
|------|---------------------------|
| `resolved` | B602, the finding you fixed. |
| `new` | B603, LOW: bandit still notes a `subprocess` call, now without a shell. |
| `severity_changed` | Empty. |

B324 is in none of the lists. It is still found, and the new results mark it suppressed with
your reason. The scan now has no actionable findings.

## Next steps

- [ASH GenAI integration guide](../docs/genai-steering-guide.md): instructions written for the
  agent itself. `ash get-genai-guide` writes the guide for your installed version of ASH to a
  file, without network access, so you can give it to your agent.
- [MCP tools reference](../reference/mcp-tools.md): every tool, its parameters, and its
  resources.
- [Run the MCP server](../how-to/mcp-server.md): limit which directories an agent can scan, or
  run the server over HTTP.
- [Scale to large repositories](../how-to/scale-large-repos.md): scan a VS Code workspace with
  the workspace tools.
