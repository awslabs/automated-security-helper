/**
 * Where the cfn-guard suppressions are allowed to be, pinned against the committed
 * templates.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * cfn-guard (AWS Guard Rules Registry, wa-Security-Pillar) skips any resource whose
 * `Metadata.guard.SuppressedRules` names the rule. That makes a suppression easy to
 * spread: copy the helper call onto one more resource and that resource stops being
 * checked, with nothing else changing. The suppressions here were approved one
 * resource at a time, so this asserts the exact set -- template, logical id, type and
 * rules -- and nothing else. A suppression added anywhere, removed from anywhere, or
 * widened to a second rule fails here and needs the same review the originals got.
 *
 * Read from `templates/` rather than synthesized in-process, because the committed
 * template is what cfn-guard scans and what an adopter launches. The drift gate
 * (`scripts/synth-templates.sh --check`) keeps the two in step.
 *
 * Logical ids are pinned on purpose. They are CDK's stable hash of the construct path,
 * so a rename that moves one is also a change in what is suppressed, and should be
 * looked at.
 */

import * as fs from 'fs';
import * as path from 'path';

const TEMPLATE_DIR = path.join(__dirname, '..', 'templates');

interface GuardEntry {
  template: string;
  logicalId: string;
  type: string;
  rules: string[];
}

function guardEntries(templates: Record<string, any>): GuardEntry[] {
  const out: GuardEntry[] = [];
  for (const [template, body] of Object.entries(templates)) {
    for (const [logicalId, resource] of Object.entries<any>(body.Resources ?? {})) {
      const guard = resource?.Metadata?.guard;
      if (guard === undefined) continue;
      out.push({ template, logicalId, type: resource.Type, rules: guard.SuppressedRules });
    }
  }
  return out.sort((a, b) =>
    `${a.template}/${a.logicalId}`.localeCompare(`${b.template}/${b.logicalId}`),
  );
}

const COMMITTED: Record<string, any> = Object.fromEntries(
  fs
    .readdirSync(TEMPLATE_DIR)
    .filter((f) => f.endsWith('.template.json'))
    .map((f) => [
      f.replace('.template.json', ''),
      JSON.parse(fs.readFileSync(path.join(TEMPLATE_DIR, f), 'utf8')),
    ]),
);

const TLS = 'S3_BUCKET_SSL_REQUESTS_ONLY';
const VPC = 'LAMBDA_INSIDE_VPC';
const IGW = 'NO_UNRESTRICTED_ROUTE_TO_IGW';

/**
 * The approved set. 13 resources carrying the 25 findings cfn-guard reported: one
 * bucket-policy result per policy statement (15 on 7 policies), two per Lambda function
 * (8 on 4), one per route (2 on 2).
 */
const APPROVED: GuardEntry[] = [
  { template: 'AshAgentCore', logicalId: 'ImageBootstrapStarter2B9D5AC0', type: 'AWS::Lambda::Function', rules: [VPC] },
  { template: 'AshCodeCommitGate', logicalId: 'ImageBootstrapStarter2B9D5AC0', type: 'AWS::Lambda::Function', rules: [VPC] },
  { template: 'AshCodeCommitGate', logicalId: 'ScanFunction322CD7EE', type: 'AWS::Lambda::Function', rules: [VPC] },
  { template: 'AshDistributedPipeline', logicalId: 'AccessLogsArchivePolicyBC5B3007', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshDistributedPipeline', logicalId: 'AccessLogsPolicyABDC4D2D', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshDistributedPipeline', logicalId: 'ArtifactsPolicy6E9058CC', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshDistributedPipeline', logicalId: 'ResultsPolicy9F4743DA', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshDistributedPipeline', logicalId: 'SourcePolicyE5AB5F73', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshFargate', logicalId: 'AccessLogsArchivePolicyBC5B3007', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshFargate', logicalId: 'AccessLogsPolicyABDC4D2D', type: 'AWS::S3::BucketPolicy', rules: [TLS] },
  { template: 'AshFargate', logicalId: 'ImageBootstrapStarter2B9D5AC0', type: 'AWS::Lambda::Function', rules: [VPC] },
  { template: 'AshFargate', logicalId: 'VpcPublicSubnet1DefaultRoute3DA9E72A', type: 'AWS::EC2::Route', rules: [IGW] },
  { template: 'AshFargate', logicalId: 'VpcPublicSubnet2DefaultRoute97F91067', type: 'AWS::EC2::Route', rules: [IGW] },
];

describe('cfn-guard suppressions sit only on the approved resources', () => {
  test('all five templates were read', () => {
    expect(Object.keys(COMMITTED).sort()).toEqual([
      'AshAgentCore',
      'AshCodeCommitGate',
      'AshDistributedPipeline',
      'AshFargate',
      'AshImagePipeline',
    ]);
  });

  test('the suppressed resources are exactly the approved set', () => {
    expect(guardEntries(COMMITTED)).toEqual(
      [...APPROVED].sort((a, b) =>
        `${a.template}/${a.logicalId}`.localeCompare(`${b.template}/${b.logicalId}`),
      ),
    );
  });

  test.each(APPROVED.map((e) => [`${e.template}/${e.logicalId}`, e] as const))(
    '%s records a reason beside each rule it suppresses',
    (_name, entry) => {
      const guard = COMMITTED[entry.template].Resources[entry.logicalId].Metadata.guard;
      expect(Object.keys(guard).sort()).toEqual(['SuppressedRuleReasons', 'SuppressedRules']);
      expect(Object.keys(guard.SuppressedRuleReasons).sort()).toEqual([...entry.rules].sort());
      for (const rule of entry.rules) {
        expect(guard.SuppressedRuleReasons[rule].length).toBeGreaterThan(40);
      }
    },
  );

  test('every suppressed bucket policy still enforces TLS on its bucket and objects', () => {
    // The reason the S3 suppression is honest. If enforceSSL were dropped, the
    // suppression would hide a real gap; this fails instead.
    for (const entry of APPROVED.filter((e) => e.rules.includes(TLS))) {
      const statements = COMMITTED[entry.template].Resources[entry.logicalId].Properties
        .PolicyDocument.Statement;
      const deny = statements.find(
        (s: any) =>
          s.Effect === 'Deny' &&
          s.Action === 's3:*' &&
          s.Condition?.Bool?.['aws:SecureTransport'] === 'false',
      );
      expect({ policy: `${entry.template}/${entry.logicalId}`, hasDeny: deny !== undefined }).toEqual(
        { policy: `${entry.template}/${entry.logicalId}`, hasDeny: true },
      );
      expect(deny.Resource).toHaveLength(2);
    }
  });

  test('a suppression on any other resource is caught', () => {
    // Positive control: the collector has to see a suppression placed somewhere new,
    // or the exact-set assertion above would pass over a blind spot.
    const tampered = structuredClone(COMMITTED);
    const victim = Object.keys(tampered.AshImagePipeline.Resources)[0];
    tampered.AshImagePipeline.Resources[victim].Metadata = {
      guard: { SuppressedRules: [VPC], SuppressedRuleReasons: { [VPC]: 'x'.repeat(50) } },
    };
    expect(guardEntries(tampered)).toHaveLength(APPROVED.length + 1);
    expect(guardEntries(tampered)).not.toEqual(guardEntries(COMMITTED));
  });

  test('a second rule on an approved resource is caught', () => {
    const tampered = structuredClone(COMMITTED);
    tampered.AshFargate.Resources.VpcPublicSubnet1DefaultRoute3DA9E72A.Metadata.guard.SuppressedRules.push(
      'INCOMING_SSH_DISABLED',
    );
    expect(guardEntries(tampered)).not.toEqual(guardEntries(COMMITTED));
  });
});
