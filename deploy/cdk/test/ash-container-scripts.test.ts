/**
 * The container scripts are the part of this app that runs in production, so they
 * are tested against their source rather than through escaped buildspec JSON.
 *
 * These assertions encode facts about ASH and about the AWS services involved
 * that were verified by reading ASH's source and the AWS documentation. Each
 * failure below should send the reader back to a specific thing to re-check.
 */

import {
  ASH_MATERIALIZED_CONFIG_PATH,
  CODECOMMIT_GATE_HANDLER,
  MCP_ENTRYPOINT_SCRIPT,
} from '../lib/ash-container-scripts';

describe('MCP entrypoint script', () => {
  test('invokes the streamable-http transport with the AgentCore-mandated host and port', () => {
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('ash mcp --transport streamable-http');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('${ASH_MCP_HOST:-0.0.0.0}');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('${ASH_MCP_PORT:-8000}');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('${ASH_MCP_MOUNT_PATH:-/mcp}');
  });

  test('is the image ENTRYPOINT, because AgentCore cannot supply a command', () => {
    // ContainerConfiguration has only ContainerUri, so if this stops being a
    // shell entrypoint the command has nowhere else to come from.
    expect(MCP_ENTRYPOINT_SCRIPT.startsWith('#!/bin/sh')).toBe(true);
    expect(MCP_ENTRYPOINT_SCRIPT.trimEnd().endsWith('exec "$@"')).toBe(true);
  });

  test('states the stateless intent explicitly in both directions', () => {
    // ASH spells this as a paired flag, so the script names the direction it
    // wants rather than inheriting whatever ASH's default happens to be.
    //
    // Both spellings are now emitted only when `ash mcp --help` advertises them;
    // which branch runs, and what happens when neither is available, is covered
    // by the "MCP entrypoint capability probe" suite below. This test only pins
    // that the script still knows both spellings.
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('--stateless-http');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('--no-stateless-http');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('${ASH_MCP_STATELESS:-true}');
  });

  test('splits the allowed-host list so --allowed-host is repeated per host', () => {
    // The flag is repeatable. Passing a comma-joined string as one value would
    // produce a Host allowlist containing a single entry that matches nothing.
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('IFS=,');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('--allowed-host "$ash_host"');
  });

  test('uses python3 and boto3, not the AWS CLI', () => {
    // The ASH image installs no AWS CLI. It does depend on boto3, declared in
    // ASH's pyproject.toml dependencies. An `aws` invocation here would fail at
    // container start, after deployment reported success.
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('python3 -c');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('boto3.client(\'ssm\')');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('boto3.client(\'secretsmanager\')');
    expect(MCP_ENTRYPOINT_SCRIPT).not.toMatch(/(^|\s)aws\s+(ssm|secretsmanager)\s/m);
  });

  test('resolves the secret from an ARN rather than reading a value', () => {
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN');
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('get_secret_value');
  });

  test('refuses to start unauthenticated when auth was configured but unresolvable', () => {
    // Failing open here would serve an unauthenticated MCP endpoint to whoever
    // could reach it, while the deployment reported that auth was enabled.
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('exit 64');
  });

  test('applies the base config through ASH_CONFIG, not a per-directory file', () => {
    // ASH's get_default_config() reads ASH_CONFIG from the process environment, so
    // this applies to every scan the process runs — including MCP-initiated scans
    // of directories that have never seen this deployment's config.
    expect(MCP_ENTRYPOINT_SCRIPT).toContain('ASH_CONFIG');
    expect(ASH_MATERIALIZED_CONFIG_PATH).toBe('/tmp/ash-config/.ash.yaml');
  });
});

describe('CodeCommit gate handler', () => {
  test('reads repositoryNames as a list', () => {
    // The CodeCommit pull-request event carries `repositoryNames` as an array.
    // Treating it as a string would silently pass the first character as the
    // repository name.
    expect(CODECOMMIT_GATE_HANDLER).toContain('detail.get("repositoryNames") or []');
    expect(CODECOMMIT_GATE_HANDLER).toContain('repository_names[0]');
  });

  test('passes destinationCommit as beforeCommitId and sourceCommit as afterCommitId', () => {
    // PostCommentForPullRequest documents beforeCommitId as the destination
    // branch's commit and afterCommitId as the source branch tip. Reversing them
    // attaches the comment to the wrong diff.
    expect(CODECOMMIT_GATE_HANDLER).toContain(
      '_post(codecommit, pull_request_id, repository_name, destination_commit, source_commit, body)',
    );
    expect(CODECOMMIT_GATE_HANDLER).toContain('beforeCommitId=before_commit_id');
    expect(CODECOMMIT_GATE_HANDLER).toContain('afterCommitId=after_commit_id');
  });

  test('distinguishes findings from scanner failure', () => {
    // ASH exit 2 means a scan completed and found something; 1 and 3 mean it could
    // not do its job. Collapsing them would report a broken scanner as a clean
    // repository, which is the worst possible failure for a security gate.
    expect(CODECOMMIT_GATE_HANDLER).toContain('EXIT_ACTIONABLE_FINDINGS = 2');
    expect(CODECOMMIT_GATE_HANDLER).toContain('EXIT_SCANNER_ERROR = 1');
    expect(CODECOMMIT_GATE_HANDLER).toContain('EXIT_INVALID_CONFIG = 3');
    expect(CODECOMMIT_GATE_HANDLER).toContain('"errored"');
  });

  test('only APPROVEs a passing scan', () => {
    expect(CODECOMMIT_GATE_HANDLER).toContain(
      'state = "APPROVE" if verdict == "passed" else "REVOKE"',
    );
  });

  test('tolerates being the pull request author', () => {
    // CodeCommit refuses an approval from the author. The comment is still worth
    // posting, so only the vote is skipped.
    expect(CODECOMMIT_GATE_HANDLER).toContain('PullRequestCannotBeApprovedByAuthorException');
  });

  test('narrows the scan to the pull request diff against the destination commit', () => {
    expect(CODECOMMIT_GATE_HANDLER).toContain('"--changed-files-only", "--base-ref", destination_commit');
  });

  test('reads the markdown report ASH actually writes', () => {
    expect(CODECOMMIT_GATE_HANDLER).toContain('"reports" / "ash.summary.md"');
    expect(CODECOMMIT_GATE_HANDLER).toContain('--compact-report');
  });

  test('is valid Python', () => {
    // The handler is embedded as a string, so nothing else would catch a syntax
    // error before the first pull request arrived.
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const fs = require('fs') as typeof import('fs');
    const path = require('path') as typeof import('path');
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ash-gate-')), 'handler.py');
    fs.writeFileSync(file, CODECOMMIT_GATE_HANDLER);
    // py_compile parses without importing, so boto3 does not need to be present.
    execFileSync('python3', ['-m', 'py_compile', file], { stdio: 'pipe' });
  });
});

describe('MCP entrypoint script is valid shell', () => {
  test('parses under sh -n', () => {
    // Same reasoning as the Python check: a quoting mistake in a heredoc payload
    // would otherwise surface as a container that will not start.
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const fs = require('fs') as typeof import('fs');
    const path = require('path') as typeof import('path');
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ash-entry-')), 'entrypoint.sh');
    fs.writeFileSync(file, MCP_ENTRYPOINT_SCRIPT);
    execFileSync('sh', ['-n', file], { stdio: 'pipe' });
  });
});

/**
 * The capability probe is RUN here, not pattern-matched.
 *
 * Asserting that the script merely contains `--stateless-http` cannot tell a
 * working branch from a broken one — the string is present either way. These
 * tests execute the real entrypoint against a fake `ash` whose `mcp --help`
 * advertises either the modern option set or v3.7.0's, and then read back the
 * argv the entrypoint actually exec'd.
 */
describe('MCP entrypoint capability probe', () => {
  const os = require('os') as typeof import('os');
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');
  const { spawnSync } = require('child_process') as typeof import('child_process');

  /**
   * A stand-in for ASH. `mcp --help` lists the options of the era being
   * simulated; any other invocation is the real exec, and records its argv.
   */
  const FAKE_ASH = `#!/bin/sh
if [ "$1" = "mcp" ] && [ "$2" = "--help" ]; then
  echo "Usage: ash mcp [OPTIONS]"
  echo "  --transport TEXT"
  echo "  --host TEXT"
  echo "  --port INTEGER"
  echo "  --mount-path TEXT"
  echo "  --auth-header-name TEXT"
  echo "  --auth-header-value TEXT"
  if [ -n "\${FAKE_ASH_MODERN:-}" ]; then
    echo "  --stateless-http/--no-stateless-http"
    echo "  --allowed-host TEXT"
  fi
  exit 0
fi
if [ -n "\${FAKE_ASH_HELP_BROKEN:-}" ]; then
  exit 1
fi
: > "\${FAKE_ASH_ARGV}"
for fake_arg in "$@"; do
  echo "\${fake_arg}" >> "\${FAKE_ASH_ARGV}"
done
exit 0
`;

  /** Broken-install variant: `mcp --help` itself fails. */
  const FAKE_ASH_BROKEN_HELP = `#!/bin/sh
echo "ImportError: cannot import name 'mcp'" >&2
exit 1
`;

  function runEntrypoint(
    env: Record<string, string>,
    fakeAsh: string = FAKE_ASH,
  ): { status: number | null; stderr: string; argv: string[] } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-probe-'));
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const ash = path.join(bin, 'ash');
    fs.writeFileSync(ash, fakeAsh, { mode: 0o755 });
    const entrypoint = path.join(dir, 'entrypoint.sh');
    fs.writeFileSync(entrypoint, MCP_ENTRYPOINT_SCRIPT);
    const argvFile = path.join(dir, 'argv');

    const result = spawnSync('sh', [entrypoint], {
      encoding: 'utf-8',
      env: {
        PATH: `${bin}:${process.env.PATH}`,
        FAKE_ASH_ARGV: argvFile,
        ...env,
      },
    });

    const argv = fs.existsSync(argvFile)
      ? fs.readFileSync(argvFile, 'utf-8').split('\n').filter((line: string) => line !== '')
      : [];
    return { status: result.status, stderr: result.stderr ?? '', argv };
  }

  test('passes --stateless-http when the ASH in the image supports it', () => {
    const { status, argv } = runEntrypoint({ FAKE_ASH_MODERN: '1' });
    expect(status).toBe(0);
    expect(argv).toContain('--stateless-http');
    expect(argv).not.toContain('--no-stateless-http');
  });

  test('REFUSES to start stateless-by-default on an ASH without the option', () => {
    // The defect this whole probe exists for: AshVersion=v3.7.0 with the shipped
    // McpStatelessHttp default. Starting anyway would serve a stateful server
    // that 404s every platform-injected session id while looking healthy.
    const { status, stderr, argv } = runEntrypoint({});
    expect(status).toBe(65);
    expect(stderr).toContain('--stateless-http');
    expect(argv).toEqual([]);
  });

  test('runs without either stateless flag when stateful was asked for explicitly', () => {
    // An ASH with no stateless mode is already stateful, so this is the one
    // combination that is genuinely satisfiable on an older release.
    const { status, argv } = runEntrypoint({ ASH_MCP_STATELESS: 'false' });
    expect(status).toBe(0);
    expect(argv).not.toContain('--stateless-http');
    expect(argv).not.toContain('--no-stateless-http');
    expect(argv).toContain('mcp');
  });

  test('passes --no-stateless-http when stateful was asked for and the option exists', () => {
    const { status, argv } = runEntrypoint({
      FAKE_ASH_MODERN: '1',
      ASH_MCP_STATELESS: 'false',
    });
    expect(status).toBe(0);
    expect(argv).toContain('--no-stateless-http');
    expect(argv).not.toContain('--stateless-http');
  });

  test('repeats --allowed-host once per comma-separated host', () => {
    const { status, argv } = runEntrypoint({
      FAKE_ASH_MODERN: '1',
      ASH_MCP_ALLOWED_HOST: 'alb.example.com,other.example.com',
    });
    expect(status).toBe(0);
    expect(argv.filter((a: string) => a === '--allowed-host')).toHaveLength(2);
    expect(argv).toContain('alb.example.com');
    expect(argv).toContain('other.example.com');
  });

  test('warns but still starts when a Host allowlist cannot be enforced', () => {
    // Deliberately NOT a refusal: the Fargate stack substitutes the load
    // balancer DNS name whenever McpAllowedHost is empty, so refusing here would
    // leave no parameter value that lets that target deploy.
    const { status, stderr, argv } = runEntrypoint({
      ASH_MCP_STATELESS: 'false',
      ASH_MCP_ALLOWED_HOST: 'alb.example.com',
    });
    expect(status).toBe(0);
    expect(stderr).toContain('WARNING');
    expect(stderr).toContain('EVERY Host header will be accepted');
    expect(argv).not.toContain('--allowed-host');
  });

  test('distinguishes a broken ASH install from a missing option', () => {
    // Reading a failed `ash mcp --help` as "the flag is absent" would report the
    // wrong cause and, worse, would let the stateful path look satisfiable.
    const { status, stderr } = runEntrypoint({}, FAKE_ASH_BROKEN_HELP);
    expect(status).toBe(69);
    expect(stderr).toContain('cannot serve MCP at all');
  });
});
