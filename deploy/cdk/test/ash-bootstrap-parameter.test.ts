/**
 * The parameter the bootstrap hands CloudFormation's response URL through.
 *
 * ash-bootstrap-response-url.test.ts proves the URL leaves the StartBuild request and
 * that the build can still answer. This pins the properties that make the handover
 * worth doing, read off the synthesized template and the starter's own code:
 *
 * - the value is a SecureString under this stack's key, so reading it takes
 *   `kms:Decrypt` on that key and not just `ssm:GetParameter`;
 * - a Delete removes it, so a torn-down stack leaves no parameter behind;
 * - the starter may write only that parameter and the build may read only it;
 * - the build's read grant exists before the bootstrap starts the build, which reads
 *   the parameter as it starts.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import {
  actionMatches,
  CfnResolver,
  CfnTemplate,
  roleOf,
  statementsForRole,
  synth,
} from './support/cfn';
import { python3, readLines } from './support/gate-harness';

const STACKS: Array<[string, CfnTemplate]> = [
  ['AshAgentCore', synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'))],
  ['AshFargate', synth((app) => new AshFargateStack(app, 'AshFargate'))],
  ['AshCodeCommitGate', synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'))],
];

const PROJECT_NAME = 'ash-image-build-project';
const KEY_ARN = 'arn:aws:kms:us-east-1:000000000000:key/stack-key';

interface Call {
  service: string;
  method: string;
  kwargs: Record<string, any>;
}

const FAKE_BOTO3 = (log: string) => `import json
class _C:
    def __init__(self, service):
        self._service = service
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        def call(*args, **kwargs):
            with open(${JSON.stringify(log)}, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"service": self._service, "method": name, "kwargs": kwargs}) + "\\n")
            return {}
        return call
def client(service, *args, **kwargs):
    return _C(service)
`;

const DRIVER = `import importlib.util, json, sys, urllib.request
urllib.request.urlopen = lambda *args, **kwargs: None
spec = importlib.util.spec_from_file_location("index", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.handler(json.loads(sys.argv[2]), None)
`;

function starterOf(template: CfnTemplate): { logicalId: string; code: string; role: string } {
  const bootstrap = Object.values(template.Resources).find((r) => r.Type === 'Custom::AshImageBootstrap');
  const token = bootstrap?.Properties?.ServiceToken as { 'Fn::GetAtt': [string, string] };
  const logicalId = token['Fn::GetAtt'][0];
  const fn = template.Resources[logicalId];
  return { logicalId, code: fn.Properties?.Code?.ZipFile as string, role: roleOf(fn.Properties?.Role) };
}

function runStarter(template: CfnTemplate, requestType: string): Call[] {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-bootstrap-parameter-'));
  try {
    fs.mkdirSync(path.join(dir, 'py', 'boto3'), { recursive: true });
    const log = path.join(dir, 'calls.jsonl');
    fs.writeFileSync(path.join(dir, 'py', 'boto3', '__init__.py'), FAKE_BOTO3(log));
    fs.writeFileSync(path.join(dir, 'index.py'), starterOf(template).code);
    fs.writeFileSync(path.join(dir, 'driver.py'), DRIVER);
    const event = {
      RequestType: requestType,
      ResponseURL: 'https://example.invalid/response',
      StackId: 'stack-1',
      RequestId: 'request-1',
      LogicalResourceId: 'ImageBootstrapBuild',
    };
    spawnSync(python3(), [path.join(dir, 'driver.py'), path.join(dir, 'index.py'), JSON.stringify(event)], {
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        PYTHONPATH: path.join(dir, 'py'),
        PYTHONDONTWRITEBYTECODE: '1',
        PROJECT_NAME,
        KEY_ARN,
      },
    });
    return readLines<Call>(log);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** The ARN the template grants on, with the project's name in place of its Ref. */
function parameterArns(template: CfnTemplate, role: string): string[] {
  const projects = Object.keys(template.Resources).filter(
    (id) => template.Resources[id].Type === 'AWS::CodeBuild::Project',
  );
  const resolver = new CfnResolver(template, {
    resourceRefs: Object.fromEntries(projects.map((id) => [id, PROJECT_NAME])),
  });
  return statementsForRole(template, role, resolver)
    .filter((s) => s.effect === 'Allow' && s.actions.some((a) => a.toLowerCase().startsWith('ssm:')))
    .flatMap((s) => s.resources);
}

describe.each(STACKS)('%s', (_name, template) => {
  test('the URL is stored as a SecureString under the stack key, overwriting the last one', () => {
    const put = runStarter(template, 'Create').find((c) => c.method === 'put_parameter');
    expect(put?.kwargs).toEqual(
      expect.objectContaining({
        Name: `/ash-bootstrap/${PROJECT_NAME}`,
        Type: 'SecureString',
        KeyId: KEY_ARN,
        Overwrite: true,
      }),
    );
  });

  test('the build is told the parameter it was written to', () => {
    const calls = runStarter(template, 'Create');
    const put = calls.find((c) => c.method === 'put_parameter');
    const start = calls.find((c) => c.method === 'start_build');
    const override = (start?.kwargs.environmentVariablesOverride as any[]).find(
      (v) => v.name === 'CFN_RESPONSE_URL',
    );
    expect(override).toEqual({ name: 'CFN_RESPONSE_URL', value: put?.kwargs.Name, type: 'PARAMETER_STORE' });
  });

  test('a Delete removes the parameter', () => {
    const calls = runStarter(template, 'Delete');
    expect(calls.filter((c) => c.method === 'delete_parameter').map((c) => c.kwargs.Name)).toEqual([
      `/ash-bootstrap/${PROJECT_NAME}`,
    ]);
    expect(calls.some((c) => c.method === 'start_build')).toBe(false);
  });

  test('the starter may write only that parameter, with the stack key', () => {
    const { role } = starterOf(template);
    const expected = `arn:aws:ssm:us-east-1:000000000000:parameter/ash-bootstrap/${PROJECT_NAME}`;
    expect(parameterArns(template, role)).toEqual([expected]);
    const resolver = new CfnResolver(template);
    const kms = statementsForRole(template, role, resolver).filter((s) =>
      s.actions.some((a) => actionMatches(a, 'kms:Encrypt')),
    );
    expect(kms.map((s) => s.resources)).toEqual([[resolver.resolve({ 'Fn::GetAtt': ['EncryptionKey1B843E66', 'Arn'] })]]);
  });

  test('the image build may read only that parameter, and its grant precedes the bootstrap', () => {
    const [, project] = Object.entries(template.Resources).find(
      ([, r]) => r.Type === 'AWS::CodeBuild::Project' && JSON.stringify(r.Properties?.Source?.BuildSpec).includes('CFN_RESPONSE_URL'),
    ) as [string, any];
    const role = roleOf(project.Properties?.ServiceRole);
    expect(parameterArns(template, role)).toEqual([
      `arn:aws:ssm:us-east-1:000000000000:parameter/ash-bootstrap/${PROJECT_NAME}`,
    ]);

    const readPolicy = Object.entries(template.Resources).find(
      ([id, r]) => r.Type === 'AWS::IAM::Policy' && id.startsWith('ImageBootstrapSsmAccess'),
    );
    expect(readPolicy).toBeDefined();
    const bootstrap = Object.values(template.Resources).find((r) => r.Type === 'Custom::AshImageBootstrap');
    expect(([] as string[]).concat(bootstrap?.DependsOn ?? [])).toContain(readPolicy?.[0]);
  });
});
