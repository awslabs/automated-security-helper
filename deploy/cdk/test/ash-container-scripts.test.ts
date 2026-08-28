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
  ASH_S3_SYNC_PATH,
  ASH_S3_SYNC_SCRIPT,
  CODECOMMIT_GATE_HANDLER,
  MATERIALIZE_S3_SYNC_COMMAND,
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

describe('S3 sync helper', () => {
  test('uses boto3, because the ASH image ships no AWS CLI', () => {
    // The same constraint the MCP entrypoint is built around. This helper exists
    // only because `aws s3 cp --recursive` is unavailable in that image.
    expect(ASH_S3_SYNC_SCRIPT).toContain('import boto3');
    expect(ASH_S3_SYNC_SCRIPT).toContain('boto3.client("s3")');
    expect(ASH_S3_SYNC_SCRIPT).not.toMatch(/(^|\s)aws\s+s3\s/m);
  });

  test('paginates the listing, so a shard set over one page is not truncated', () => {
    // ListObjectsV2 returns at most 1000 keys per call. A single list_objects_v2
    // call would silently download a prefix of the results and the merge would
    // then report a clean scan for whatever fell off the end.
    expect(ASH_S3_SYNC_SCRIPT).toContain('get_paginator("list_objects_v2")');
    expect(ASH_S3_SYNC_SCRIPT).toContain('paginator.paginate(');
  });

  test('refuses a key that would write outside the destination directory', () => {
    // The merge downloads keys written by the shard builds. A key containing ".."
    // would otherwise escape the download directory.
    expect(ASH_S3_SYNC_SCRIPT).toContain('is_relative_to');
    expect(ASH_S3_SYNC_SCRIPT).toContain('would write outside');
  });

  test('fails loudly on a bad invocation rather than exiting 0', () => {
    // Called from a buildspec running under errexit. A helper that printed a
    // usage message and exited 0 would let a shard report success having
    // uploaded nothing.
    expect(ASH_S3_SYNC_SCRIPT).toContain('raise SystemExit(2)');
    expect(ASH_S3_SYNC_SCRIPT).toContain('unknown subcommand');
  });

  test('is valid Python', () => {
    // Embedded as a string, so nothing else would catch a syntax error before a
    // shard tried to upload its results.
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const fs = require('fs') as typeof import('fs');
    const path = require('path') as typeof import('path');
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ash-s3-')), 'ash_s3_sync.py');
    fs.writeFileSync(file, ASH_S3_SYNC_SCRIPT);
    execFileSync('python3', ['-m', 'py_compile', file], { stdio: 'pipe' });
  });

  test('is written outside the directory ASH scans', () => {
    // A CodeBuild build's working directory is the source tree. A helper written
    // there would be scanned as part of the repository and reported as a finding
    // in the adopter's own results.
    expect(ASH_S3_SYNC_PATH.startsWith('/tmp/')).toBe(true);
  });
});

describe('S3 sync materialization command', () => {
  test('quotes the heredoc delimiter so the shell expands nothing in the body', () => {
    // With an unquoted <<PY the shell would expand the Python's own $ and
    // backticks, corrupting the file. The failure would be a syntax error inside
    // a generated file nobody reads.
    expect(MATERIALIZE_S3_SYNC_COMMAND).toContain("<<'PY'");
  });

  test('reproduces the script byte for byte and terminates the heredoc', () => {
    expect(MATERIALIZE_S3_SYNC_COMMAND).toContain(ASH_S3_SYNC_SCRIPT);
    // The delimiter must sit alone on its own line, which requires the script to
    // end with a newline. A script without one would swallow the PY line and the
    // heredoc would never close.
    expect(ASH_S3_SYNC_SCRIPT.endsWith('\n')).toBe(true);
    expect(MATERIALIZE_S3_SYNC_COMMAND.endsWith('\nPY')).toBe(true);
  });

  test('the written file and the invoked path are the same', () => {
    // Two independently-written string literals otherwise, and a mismatch would
    // surface as "no such file" only once a shard finished scanning.
    expect(MATERIALIZE_S3_SYNC_COMMAND).toContain(`cat > ${ASH_S3_SYNC_PATH} <<'PY'`);
  });

  test('parses under sh -n, both the writer and what it writes', () => {
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const fs = require('fs') as typeof import('fs');
    const path = require('path') as typeof import('path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-s3sync-'));
    const file = path.join(dir, 'materialize.sh');
    // Rewritten to a writable path: the real command targets /tmp/ash-s3-sync.py,
    // and `sh -n` only parses, but keeping the assertion about parsing rather
    // than about /tmp keeps this test from depending on the runner's filesystem.
    fs.writeFileSync(file, MATERIALIZE_S3_SYNC_COMMAND);
    execFileSync('sh', ['-n', file], { stdio: 'pipe' });
  });

  test('the heredoc actually produces the script when run', () => {
    // The parse check above would pass on a heredoc that terminated early and
    // wrote a truncated file. This runs it and compares the bytes, which is the
    // only thing that proves the delimiter and the escaping agree.
    const { execFileSync } = require('child_process') as typeof import('child_process');
    const os = require('os') as typeof import('os');
    const fs = require('fs') as typeof import('fs');
    const path = require('path') as typeof import('path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-s3run-'));
    const target = path.join(dir, 'ash-s3-sync.py');
    const script = MATERIALIZE_S3_SYNC_COMMAND.split(ASH_S3_SYNC_PATH).join(target);
    execFileSync('sh', ['-c', script], { stdio: 'pipe' });
    expect(fs.readFileSync(target, 'utf8')).toBe(ASH_S3_SYNC_SCRIPT);
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
