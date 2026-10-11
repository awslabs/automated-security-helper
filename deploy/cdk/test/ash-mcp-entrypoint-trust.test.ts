/**
 * Every MCP target that binds 0.0.0.0 names its Host allowlist or says that something
 * in front of ASH checks Host, and only AgentCore says the platform issues sessions.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Both MCP targets run the same baked entrypoint (`MCP_ENTRYPOINT_SCRIPT`) on
 * `--host 0.0.0.0`. ASH's MCP hardening (the mcp cluster's interface notes, 1b and
 * 1c) makes two things explicit operator decisions instead of side effects of the
 * bind address:
 *
 * - Host checking. A non-loopback bind without `--allowed-host` refuses to start
 *   unless the operator passes `--trust-upstream-host-check`, which states that a
 *   proxy or platform in front of ASH checks Host and Origin. Fargate knows its
 *   Host (the load balancer's DNS name) and passes `--allowed-host`. AgentCore
 *   cannot know it (Host is on AgentCore's restricted-header list) and its platform
 *   restricts what reaches the container, so it passes the opt-out.
 * - Session identity. In stateless mode a client-supplied `Mcp-Session-Id` is not a
 *   credential, so session tools refuse unless the operator passes
 *   `--trust-upstream-session-id`, which states that a platform in front of ASH
 *   issues and authenticates that header. AgentCore does; a load balancer does not.
 *
 * The entrypoint used to pass neither, and when a Host allowlist was requested from
 * an ASH whose `ash mcp` lacked `--allowed-host` it warned and started anyway, so
 * the Fargate service accepted every Host header while its stack said otherwise.
 *
 * HOW THE ENTRYPOINT IS TOLD, AND WHY THESE NAMES
 * -----------------------------------------------
 * The stacks hand the entrypoint its choices as environment variables, the same names
 * the Terraform launcher reads (ash-image-pipeline/files/ash-mcp-serve):
 * `ASH_MCP_TRUST_UPSTREAM_HOST_CHECK` and `ASH_MCP_TRUST_UPSTREAM_SESSION_ID`, each
 * `true` or `false`. Unlike the Terraform launcher, whose defaults are AgentCore's,
 * the CDK entrypoint defaults both to `false`: every CDK stack sets them, so an unset
 * value means nobody decided, and a bind with no allowlist and no opt-out refuses.
 * The flags are passed only when this image's `ash mcp --help` lists them; an older
 * ASH that lacks them has no such check to opt out of.
 *
 * The environment each stack gives the container is read off the synthesized
 * template, not written out here, so these tests follow the stacks.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { ASH_PARAMETER_NAMES } from '../lib/ash-config';
import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { MCP_ENTRYPOINT_SCRIPT } from '../lib/ash-container-scripts';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { CfnResolver, CfnTemplate, onlyResource, stringEnvironment, synth } from './support/cfn';

const AGENTCORE = synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'));
const FARGATE = synth((app) => new AshFargateStack(app, 'AshFargate'));

/** What CloudFormation would return for the load balancer's DNS name: mixed case. */
const ALB_DNS_NAME = 'internal-AshFargate-LoadBalancer-123.us-east-1.ELB.amazonaws.com';

/**
 * Three eras of `ash mcp --help`:
 * - release: v3.7.0, no --stateless-http and no --allowed-host;
 * - allowed-host: has --stateless-http and --allowed-host, but no trust flags;
 * - hardened: also has --trust-upstream-host-check and --trust-upstream-session-id.
 */
type AshEra = 'release' | 'allowed-host' | 'hardened';

const FAKE_ASH = `#!/bin/sh
if [ "$1" = "mcp" ] && [ "$2" = "--help" ]; then
  echo "Usage: ash mcp [OPTIONS]"
  echo "  --transport TEXT"
  echo "  --host TEXT"
  echo "  --port INTEGER"
  echo "  --mount-path TEXT"
  echo "  --auth-header-name TEXT"
  echo "  --auth-header-value TEXT"
  if [ "\${FAKE_ASH_ERA}" != "release" ]; then
    echo "  --stateless-http/--no-stateless-http"
    echo "  --allowed-host TEXT"
  fi
  if [ "\${FAKE_ASH_ERA}" = "hardened" ]; then
    echo "  --trust-upstream-host-check"
    echo "  --trust-upstream-session-id"
    echo "  --session-workspace-ttl INTEGER"
  fi
  exit 0
fi
: > "\${FAKE_ASH_ARGV}"
for fake_arg in "$@"; do
  echo "\${fake_arg}" >> "\${FAKE_ASH_ARGV}"
done
exit 0
`;

interface EntrypointRun {
  readonly status: number | null;
  readonly stderr: string;
  readonly argv: string[];
}

function runEntrypoint(env: Record<string, string>, era: AshEra): EntrypointRun {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-mcp-trust-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'ash'), FAKE_ASH, { mode: 0o755 });
    const entrypoint = path.join(dir, 'entrypoint.sh');
    fs.writeFileSync(entrypoint, MCP_ENTRYPOINT_SCRIPT);
    const argvFile = path.join(dir, 'argv');
    const result = spawnSync('sh', [entrypoint], {
      encoding: 'utf-8',
      env: {
        PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`,
        FAKE_ASH_ARGV: argvFile,
        FAKE_ASH_ERA: era,
        ...env,
      },
    });
    const argv = fs.existsSync(argvFile)
      ? fs.readFileSync(argvFile, 'utf-8').split('\n').filter((line) => line !== '')
      : [];
    return { status: result.status, stderr: result.stderr ?? '', argv };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The container environment at a launch with these parameters. The auth secret ARN
 * and the base-config parameter name resolve to empty at the defaults, which is what
 * keeps the entrypoint from calling AWS here.
 */
function agentCoreEnvironment(parameters: Record<string, string> = {}): Record<string, string> {
  const resolver = new CfnResolver(AGENTCORE, { parameters });
  const [, runtime] = onlyResource(AGENTCORE, 'AWS::BedrockAgentCore::Runtime');
  return stringEnvironment(resolver.resolve(runtime.Properties?.EnvironmentVariables));
}

function fargateEnvironment(parameters: Record<string, string> = {}): Record<string, string> {
  const [loadBalancer] = onlyResource(FARGATE, 'AWS::ElasticLoadBalancingV2::LoadBalancer');
  const resolver = new CfnResolver(FARGATE, {
    parameters,
    attributes: { [`${loadBalancer}.DNSName`]: ALB_DNS_NAME },
  });
  const [, taskDefinition] = onlyResource(FARGATE, 'AWS::ECS::TaskDefinition');
  const container = resolver.resolve(taskDefinition.Properties?.ContainerDefinitions)[0];
  const env: Record<string, string> = {};
  for (const entry of container.Environment as Array<{ Name: string; Value: unknown }>) {
    env[entry.Name] = String(entry.Value ?? '');
  }
  return env;
}

function valuesAfter(argv: string[], flag: string): string[] {
  return argv.filter((_arg, i) => argv[i - 1] === flag);
}

describe('AgentCore: the platform checks Host and issues the session header', () => {
  test('on a hardened ASH, the shipped defaults pass both trust flags and no allowlist', () => {
    const run = runEntrypoint(agentCoreEnvironment(), 'hardened');

    expect(run.status).toBe(0);
    expect(run.argv).toEqual(expect.arrayContaining(['mcp', '--stateless-http']));
    expect({
      sessionTrust: run.argv.includes('--trust-upstream-session-id'),
      hostTrust: run.argv.includes('--trust-upstream-host-check'),
      allowedHost: run.argv.includes('--allowed-host'),
    }).toEqual({ sessionTrust: true, hostTrust: true, allowedHost: false });
  });

  test('control: a stateful AgentCore server never trusts a session header it did not issue', () => {
    const run = runEntrypoint(
      agentCoreEnvironment({ [ASH_PARAMETER_NAMES.mcpStatelessHttp]: 'false' }),
      'hardened',
    );

    expect(run.argv).toContain('--no-stateless-http');
    expect(run.argv).not.toContain('--trust-upstream-session-id');
  });

  test('control: a named Host allowlist replaces the opt-out rather than joining it', () => {
    // ASH refuses --trust-upstream-host-check together with --allowed-host.
    const run = runEntrypoint(
      agentCoreEnvironment({ [ASH_PARAMETER_NAMES.mcpAllowedHost]: 'mcp.example.com' }),
      'hardened',
    );

    expect(valuesAfter(run.argv, '--allowed-host')).toEqual(['mcp.example.com']);
    expect(run.argv).not.toContain('--trust-upstream-host-check');
  });

  test('control: the shipped defaults still start on a release ASH (the D6 fallback)', () => {
    // A release ASH has neither trust flag and no Host check to opt out of, so the
    // opt-out has nothing to pass. This is the one-click default today.
    const run = runEntrypoint(agentCoreEnvironment(), 'release');

    expect(run.status).toBe(0);
    expect(run.argv).toContain('mcp');
    expect(run.argv).not.toContain('--trust-upstream-host-check');
    expect(run.argv).not.toContain('--trust-upstream-session-id');
  });
});

describe('Fargate: the load balancer name is the allowlist, and nothing is trusted upstream', () => {
  test('control: on a hardened ASH, the allowlist is the lower-cased load balancer name and no trust flag is passed', () => {
    const run = runEntrypoint(fargateEnvironment(), 'hardened');

    expect(valuesAfter(run.argv, '--allowed-host')).toEqual([ALB_DNS_NAME.toLowerCase()]);
    expect(run.argv).not.toContain('--trust-upstream-host-check');
    expect(run.argv).not.toContain('--trust-upstream-session-id');
  });

  test('an ASH that cannot enforce the allowlist refuses to start instead of accepting every Host', () => {
    // Stateful, so the stateless refusal (exit 65) is not what stops it.
    const run = runEntrypoint(
      fargateEnvironment({ [ASH_PARAMETER_NAMES.mcpStatelessHttp]: 'false' }),
      'release',
    );

    expect({ started: run.argv.length > 0, status: run.status === 0 ? 0 : 'non-zero' }).toEqual({
      started: false,
      status: 'non-zero',
    });
    expect(run.stderr).toContain('--allowed-host');
  });
});

describe('the entrypoint itself', () => {
  test('with neither an allowlist nor an explicit opt-out, it refuses to bind 0.0.0.0', () => {
    for (const era of ['hardened', 'allowed-host'] as const) {
      const run = runEntrypoint({}, era);
      expect({ era, started: run.argv.length > 0, status: run.status === 0 ? 0 : 'non-zero' }).toEqual({
        era,
        started: false,
        status: 'non-zero',
      });
    }
  });

  test.each<[string, CfnTemplate, () => Record<string, string>]>([
    ['AshAgentCore', AGENTCORE, () => agentCoreEnvironment()],
    ['AshFargate', FARGATE, () => fargateEnvironment()],
  ])('%s tells ASH which transport it serves', (_name, _template, environment) => {
    // The entrypoint starts streamable-http; ASH_MCP_TRANSPORT makes every caller
    // remote even for code paths that read the transport from the environment,
    // which is what the Terraform modules set too.
    expect(environment().ASH_MCP_TRANSPORT).toBe('streamable-http');
  });
});
