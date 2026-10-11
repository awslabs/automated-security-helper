/**
 * The image-build bootstrap does not expose CloudFormation's response URL.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The bootstrap custom resource answers CloudFormation from inside the image build
 * (see ash-image-build.ts), so the build has to learn the pre-signed response URL
 * CloudFormation handed the starter Lambda. The starter passed it to StartBuild as
 * a PLAINTEXT environment-variable override. A PLAINTEXT override is stored with the
 * build and returned by `codebuild:BatchGetBuilds` and the console to anyone who can
 * read builds in the account, and whoever holds the URL can answer CloudFormation
 * for this resource: report SUCCESS before the image exists, or FAILED to roll the
 * stack back.
 *
 * The property asserted: the URL appears nowhere in the StartBuild request and
 * nowhere in the starter's output, and the build can still answer CloudFormation.
 * CodeBuild resolves three variable types itself (PLAINTEXT, PARAMETER_STORE and
 * SECRETS_MANAGER), so the harness resolves the two stored types from what the
 * starter wrote and then runs the build's real post_build signal command against a
 * local HTTP server standing in for the response URL.
 *
 * The starter is run for real: its inline code is read out of the synthesized
 * template, executed with a recording stand-in for boto3, and `urlopen` is
 * intercepted, so no request leaves the process.
 */

import { spawn, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { CfnResolver, CfnTemplate, synth } from './support/cfn';
import { python3 } from './support/gate-harness';

const STACKS: Array<[string, CfnTemplate]> = [
  ['AshAgentCore', synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'))],
  ['AshFargate', synth((app) => new AshFargateStack(app, 'AshFargate'))],
  ['AshCodeCommitGate', synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'))],
];

/** A response URL shaped like CloudFormation's: pre-signed, with a signature to leak. */
const SIGNATURE = 'response-url-signature-must-not-leak';
function responseUrl(base = 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com'): string {
  return (
    `${base}/arn%3Aaws%3Acloudformation%3Aus-east-1%3A000000000000%3Astack/AshTestStack/test` +
    `%7CBootstrapBuild%7Crequest-1?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=${SIGNATURE}`
  );
}

interface StarterRun {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly calls: Array<{ service: string; method: string; kwargs: Record<string, any> }>;
  readonly responses: Array<{ url: string; method: string; body: Record<string, unknown> }>;
}

const FAKE_BOTO3 = (logFile: string) => `import json
_LOG = ${JSON.stringify(logFile)}


class _Answer(dict):
    def __missing__(self, key):
        return "fake-" + str(key)


class _Client:
    def __init__(self, service):
        self._service = service

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(*args, **kwargs):
            with open(_LOG, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"service": self._service, "method": name, "kwargs": kwargs}, default=str) + "\\n")
            return _Answer()

        return call


def client(service, *args, **kwargs):
    return _Client(service)
`;

const DRIVER = (responsesFile: string) => `import importlib.util, json, sys, urllib.request
_RESPONSES = ${JSON.stringify(responsesFile)}


def _fake_urlopen(request, *args, **kwargs):
    body = request.data.decode() if getattr(request, "data", None) else "{}"
    with open(_RESPONSES, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"url": request.full_url, "method": request.get_method(), "body": json.loads(body)}) + "\\n")

    class _Response:
        status = 200

        def read(self):
            return b""

    return _Response()


urllib.request.urlopen = _fake_urlopen
spec = importlib.util.spec_from_file_location("index", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.handler(json.loads(sys.argv[2]), None)
`;

function readLines<T>(file: string): T[] {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf-8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as T);
}

/** The starter Lambda: the inline-code function behind Custom::AshImageBootstrap. */
function starter(template: CfnTemplate): { code: string; env: Record<string, string> } {
  const resolver = new CfnResolver(template);
  const bootstrap = Object.values(template.Resources).find((r) => r.Type === 'Custom::AshImageBootstrap');
  if (!bootstrap) throw new Error('no Custom::AshImageBootstrap in this template');
  const token = bootstrap.Properties?.ServiceToken as { 'Fn::GetAtt': [string, string] };
  const fn = template.Resources[token['Fn::GetAtt'][0]];
  const code = fn.Properties?.Code?.ZipFile;
  if (typeof code !== 'string' || !code.includes('def handler(')) {
    throw new Error('the bootstrap starter has no inline handler');
  }
  const env = resolver.resolve(fn.Properties?.Environment?.Variables ?? {}) as Record<string, string>;
  return { code, env };
}

function runStarter(template: CfnTemplate, requestType: string, url = responseUrl()): StarterRun {
  const { code, env } = starter(template);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-bootstrap-'));
  try {
    fs.mkdirSync(path.join(dir, 'py', 'boto3'), { recursive: true });
    const callsFile = path.join(dir, 'calls.jsonl');
    const responsesFile = path.join(dir, 'responses.jsonl');
    fs.writeFileSync(path.join(dir, 'py', 'boto3', '__init__.py'), FAKE_BOTO3(callsFile));
    fs.writeFileSync(path.join(dir, 'index.py'), code);
    fs.writeFileSync(path.join(dir, 'driver.py'), DRIVER(responsesFile));
    const event = {
      RequestType: requestType,
      ResponseURL: url,
      StackId: 'arn:aws:cloudformation:us-east-1:000000000000:stack/AshTestStack/test',
      RequestId: 'request-1',
      LogicalResourceId: 'ImageBootstrapBuild',
      ResourceType: 'Custom::AshImageBootstrap',
      ResourceProperties: {},
    };
    const result = spawnSync(python3(), [path.join(dir, 'driver.py'), path.join(dir, 'index.py'), JSON.stringify(event)], {
      encoding: 'utf-8',
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        PYTHONPATH: path.join(dir, 'py'),
        PYTHONDONTWRITEBYTECODE: '1',
        AWS_REGION: 'us-east-1',
        AWS_EC2_METADATA_DISABLED: 'true',
        AWS_ENDPOINT_URL: 'http://127.0.0.1:9',
        ...env,
      },
    });
    return {
      status: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      calls: readLines(callsFile),
      responses: readLines(responsesFile),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The post_build signal command of the image build project, as the template ships it. */
function signalCommand(template: CfnTemplate): string {
  const resolver = new CfnResolver(template);
  const projects = Object.values(template.Resources).filter((r) => r.Type === 'AWS::CodeBuild::Project');
  for (const project of projects) {
    const spec = JSON.parse(String(resolver.resolve(project.Properties?.Source?.BuildSpec)));
    const commands: string[] = spec.phases?.post_build?.commands ?? [];
    const signal = commands.find((command) => command.includes('CFN_RESPONSE_URL'));
    if (signal) return signal;
  }
  throw new Error('no build project answers CloudFormation');
}

/**
 * The environment CodeBuild would give the build for these overrides: PLAINTEXT as
 * given, PARAMETER_STORE and SECRETS_MANAGER resolved from what the starter stored.
 */
function buildEnvironment(run: StarterRun): Record<string, string> {
  const startBuild = run.calls.find((c) => c.service === 'codebuild' && c.method === 'start_build');
  if (!startBuild) throw new Error('the starter never called StartBuild');
  const parameters = new Map<string, string>();
  const secrets = new Map<string, string>();
  for (const call of run.calls) {
    if (call.service === 'ssm' && call.method === 'put_parameter') {
      parameters.set(String(call.kwargs.Name), String(call.kwargs.Value));
    }
    if (call.service === 'secretsmanager' && ['create_secret', 'put_secret_value'].includes(call.method)) {
      const id = String(call.kwargs.Name ?? call.kwargs.SecretId);
      secrets.set(id, String(call.kwargs.SecretString));
      secrets.set('fake-ARN', String(call.kwargs.SecretString));
    }
  }
  const env: Record<string, string> = {};
  for (const variable of (startBuild.kwargs.environmentVariablesOverride ?? []) as any[]) {
    const type = String(variable.type ?? 'PLAINTEXT');
    const value = String(variable.value);
    if (type === 'PLAINTEXT') env[variable.name] = value;
    else if (type === 'PARAMETER_STORE') env[variable.name] = parameters.get(value) ?? '';
    else if (type === 'SECRETS_MANAGER') env[variable.name] = secrets.get(value.split(':')[0]) ?? '';
    else throw new Error(`CodeBuild has no environment variable type ${type}`);
  }
  return env;
}

describe.each(STACKS)('%s bootstrap starter', (_name, template) => {
  test('control: a Create starts the image build project, and only that', () => {
    const { env } = starter(template);
    const run = runStarter(template, 'Create');

    expect(run.status).toBe(0);
    const builds = run.calls.filter((c) => c.service === 'codebuild' && c.method === 'start_build');
    expect(builds.map((c) => c.kwargs.projectName)).toEqual([env.PROJECT_NAME]);
  });

  test('control: a Delete answers CloudFormation SUCCESS at the response URL', () => {
    const run = runStarter(template, 'Delete');

    expect(run.responses.map((r) => [r.method, r.url, r.body.Status])).toEqual([['PUT', responseUrl(), 'SUCCESS']]);
  });

  test('the response URL appears nowhere in the StartBuild request', () => {
    const run = runStarter(template, 'Create');
    const startBuild = run.calls.find((c) => c.service === 'codebuild' && c.method === 'start_build');

    expect(startBuild).toBeDefined();
    expect(JSON.stringify(startBuild?.kwargs)).not.toContain(SIGNATURE);
  });

  test('guard: the starter does not print the response URL', () => {
    const run = runStarter(template, 'Create');

    expect(run.stdout + run.stderr).not.toContain(SIGNATURE);
  });

  test('the build can still answer CloudFormation with what the starter gave it', async () => {
    const received: Array<{ method: string; body: string }> = [];
    const server = http.createServer((request, response) => {
      let body = '';
      request.on('data', (chunk) => (body += chunk));
      request.on('end', () => {
        received.push({ method: String(request.method), body });
        response.writeHead(200);
        response.end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    try {
      const port = (server.address() as { port: number }).port;
      const url = responseUrl(`http://127.0.0.1:${port}`);
      const run = runStarter(template, 'Create', url);
      const env = buildEnvironment(run);

      const status = await new Promise<number | null>((resolve) => {
        const child = spawn('sh', ['-c', signalCommand(template)], {
          env: {
            PATH: process.env.PATH ?? '/usr/bin:/bin',
            CODEBUILD_BUILD_SUCCEEDING: '1',
            CODEBUILD_BUILD_ID: 'ash-image:build-1',
            ...env,
          },
          stdio: 'ignore',
        });
        child.on('exit', (code) => resolve(code));
      });

      expect(status).toBe(0);
      expect(received.map((r) => [r.method, JSON.parse(r.body).Status])).toEqual([['PUT', 'SUCCESS']]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
