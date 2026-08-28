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
    // ASH spells this as a paired flag. Passing neither would inherit ASH's
    // default, so a change to that default would silently change behaviour on
    // AgentCore, where stateful mode answers 404 to every request.
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
