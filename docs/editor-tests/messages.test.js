// The editor's sentences, and the places it departs from the schema's verdict.
//
// The schema's verdict is the base. A table of departures (messages.js) adjusts it where ASH
// itself reads a file differently from its schema, and the shared corpus
// (fixtures/validator-corpus.json) carries the editor's expected verdict for every case that
// meets one of those rows. These tests run the corpus through the validator and the
// judgment, require the corpus's verdict and findings, and check the wording that users read:
// ASH's own strings where ASH has one, the consequence of each finding, and the suggestion
// for a misspelled key.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  DEPARTURES,
  REFUSES,
  describeFailure,
  didYouMean,
  judge,
  validationOffMessage,
} from '../content/assets/javascripts/config-editor/messages.js';
import * as messagesModule from '../content/assets/javascripts/config-editor/messages.js';
import {
  UnsupportedKeyword,
  compilePatterns,
  validateField,
} from '../content/assets/javascripts/config-editor/validate.js';

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const block = fixture('editor-data.json');
const corpus = fixture('validator-corpus.json');
const patterns = compilePatterns(block.patterns);

const judgeField = (path, instance, options) =>
  judge(block, path, instance, validateField(block, path, instance, patterns), options);

const projected = (result) => result.findings.map(({ row, severity }) => ({ row, severity }));

for (const item of corpus.cases) {
  test(`editor verdict: ${item.id}`, () => {
    const result = judgeField(item.path, item.instance);
    if (item.editor) {
      assert.equal(result.valid, item.editor.valid);
      assert.deepEqual(projected(result), item.editor.findings);
    } else {
      // Where the schema is the whole story, each failure is one error with no row.
      assert.equal(result.valid, item.valid);
      assert.ok(result.findings.every((found) => found.row === null && found.severity === 'error'));
      assert.equal(result.findings.length > 0, !item.valid);
    }
    for (const found of result.findings) {
      assert.ok(typeof found.message === 'string' && found.message.length > 0);
      assert.equal(typeof found.pointer, 'string');
    }
  });
}

test('the table lists each row once, with a reason, and names the rows the corpus meets', () => {
  const rows = DEPARTURES.map((departure) => departure.row);
  assert.equal(new Set(rows).size, rows.length);
  for (const departure of DEPARTURES) {
    assert.ok(departure.reason.length > 20, departure.row);
    assert.ok(['valid', 'invalid'].includes(departure.schema), departure.row);
    assert.ok(['error', 'warning', 'note'].includes(departure.editor), departure.row);
  }
  const met = corpus.cases.flatMap((item) => (item.editor ? item.editor.findings : []));
  assert.deepEqual([...new Set(met.map((found) => found.row))].sort(), [...rows].sort());
});

test('every row of the table still differs from the schema, and the corpus says in which way', () => {
  const directions = new Set();
  for (const item of corpus.cases) {
    if (!item.editor) {
      continue;
    }
    for (const found of item.editor.findings) {
      const departure = DEPARTURES.find((row) => row.row === found.row);
      assert.equal(departure.schema, item.valid ? 'valid' : 'invalid', item.id);
      assert.equal(departure.editor, found.severity, item.id);
    }
    // A finding that is not a plain failure makes the editor's answer differ from the schema's.
    assert.ok(item.editor.findings.length > 0, item.id);
    if (item.valid && !item.editor.valid) {
      directions.add('stricter');
    }
    if (!item.valid && item.editor.valid) {
      directions.add('looser');
    }
  }
  assert.deepEqual([...directions].sort(), ['looser', 'stricter']);
});

test('a document with an internal field uses the string ASH uses', () => {
  const result = judgeField('', { build: {} });
  const want = block.constants.invalidTopLevelFieldWarning.replace('{field}', 'build');
  assert.equal(result.findings[0].message, want);
});

test('an unknown top-level key says what a scan does and suggests the closest key', () => {
  const result = judgeField('', { projct_name: 'x' });
  const [found] = result.findings;
  assert.equal(found.row, 'unknown-top-level-key');
  assert.match(found.message, /Unknown key 'projct_name'/);
  assert.match(found.message, /did you mean 'project_name'\?/);
  assert.match(found.message, /A scan ignores this key\./);
});

test('an unknown key in a suppression suggests the key and says the entry applies to nothing', () => {
  const instance = { suppressions: [{ path: 'a', reason: 'b', ruleId: 'x' }] };
  const result = judgeField('global_settings', instance);
  const [found] = result.findings;
  assert.equal(found.row, 'unknown-key-in-list-entry');
  assert.equal(found.severity, 'warning');
  assert.equal(found.pointer, '/suppressions/0');
  assert.match(found.message, /Unknown key 'ruleId' \(did you mean 'rule_id'\?\) in a suppression\./);
  assert.match(found.message, /A scan ignores this entry\./);
});

test('the same key is an error when the file asks to fail on unknown keys', () => {
  const instance = { suppressions: [{ path: 'a', reason: 'b', ruleId: 'x' }] };
  const result = judgeField('global_settings', instance, { failOnUnknownKeys: true });
  assert.equal(result.valid, false);
  assert.deepEqual(projected(result), [{ row: 'unknown-key-in-list-entry', severity: 'error' }]);
  assert.ok(result.findings[0].message.includes(REFUSES));
});

test('a deprecated key says what it was renamed to', () => {
  const instance = [{ path: 'a', reason: 'b', rule_id: 'x', expiration: '2030-01-01' }];
  const result = judgeField('global_settings.suppressions', instance);
  assert.match(result.findings[0].message, /'expiration' is the old name of 'expires'/);
});

test('two spellings of one plugin use the words ASH uses, and a scan refuses the file', () => {
  const result = judgeField('scanners', { BANDIT: {}, 'ban-dit': {} });
  const [found] = result.findings;
  assert.equal(found.row, 'ambiguous-plugin-spellings');
  assert.ok(
    found.message.startsWith(
      'scanners.BANDIT and scanners.ban-dit are two spellings of the bandit section: ambiguous, keep one',
    ),
  );
  assert.ok(found.message.includes(REFUSES));
});

test('a plugin section spelled another way is a note that names the declared spelling', () => {
  const result = judgeField('scanners', { BanditScanner: { enabled: false } });
  const [found] = result.findings;
  assert.equal(found.severity, 'note');
  assert.match(found.message, /'BanditScanner'/);
  assert.match(found.message, /'bandit'/);
});

test('the spelling rows apply to the sections of a whole document too', () => {
  const result = judgeField('', { scanners: { Bandit: {} }, converters: { Archive: {} } });
  assert.deepEqual(projected(result), [
    { row: 'plugin-section-spelling', severity: 'note' },
    { row: 'plugin-section-spelling', severity: 'note' },
  ]);
});

test('a reference where a scan refuses it names the reference, the field and the consequence', () => {
  const result = judgeField('scanners.bandit.options.scan_timeout', '${ASH_SCAN_TIMEOUT:60}');
  const [found] = result.findings;
  assert.equal(found.row, 'reference-in-typed-field');
  assert.match(found.message, /\$\{ASH_SCAN_TIMEOUT:60\}/);
  assert.match(found.message, /integer/);
  assert.ok(found.message.includes(REFUSES));
});

test('a reference where a scan accepts it is not a finding', () => {
  assert.deepEqual(judgeField('project_name', '${PROJECT}').findings, []);
  assert.deepEqual(judgeField('global_settings.severity_threshold', '${LEVEL}').findings, []);
});

test('a comma-separated string of formats says to write a list', () => {
  const result = judgeField('output_formats', 'sarif, html');
  assert.match(result.findings[0].message, /Write as a list/);
  const bad = judgeField('output_formats', 'sarif, nonsense');
  assert.equal(bad.valid, false);
  assert.equal(bad.findings[0].row, null);
});

test('failures that no row covers are errors with a sentence that carries the facts', () => {
  const type = describeFailure({ pointer: '', keyword: 'type', detail: { expected: ['boolean'] } }, 'yes');
  assert.match(type, /Expected a boolean, found a string\./);
  assert.ok(type.includes(REFUSES));

  const list = describeFailure({ pointer: '', keyword: 'type', detail: { expected: ['array', 'null'] } }, {});
  assert.match(list, /Expected a list or null, found a mapping\./);

  const enumeration = describeFailure(
    { pointer: '', keyword: 'enum', detail: { allowed: ['low', 'medium', 'high'] } },
    'hgih',
  );
  assert.match(enumeration, /allowed values: low, medium, high/);
  assert.match(enumeration, /did you mean 'high'\?/);

  const missing = describeFailure({ pointer: '', keyword: 'required', detail: { missing: ['a', 'b'] } }, {});
  assert.match(missing, /Missing required keys 'a', 'b'\./);

  const extra = describeFailure({ pointer: '', keyword: 'additionalProperties', detail: { extras: ['z'] } }, {});
  assert.match(extra, /Unknown key 'z'\./);

  const small = describeFailure({ pointer: '', keyword: 'minimum', detail: { limit: 1 } }, 0);
  assert.match(small, /at least 1/);
  const open = describeFailure({ pointer: '', keyword: 'exclusiveMinimum', detail: { limit: 0 } }, 0);
  assert.match(open, /more than 0/);

  for (const keyword of ['pattern', 'anyOf', 'false', 'items', 'const', 'maxLength', 'minItems']) {
    const sentence = describeFailure({ pointer: '/a', keyword, detail: { limit: 2, expected: 1 } }, 5);
    assert.ok(sentence.length > 10 && sentence.includes(REFUSES), keyword);
  }
});

test('did-you-mean offers the closest key and nothing when nothing is close', () => {
  const keys = ['rule_id', 'path', 'reason', 'expires'];
  assert.equal(didYouMean('ruleId', keys), 'rule_id');
  assert.equal(didYouMean('RULE_ID', keys), 'rule_id');
  assert.equal(didYouMean('expirs', keys), 'expires');
  assert.equal(didYouMean('zzzzzz', keys), null);
  assert.equal(didYouMean('path', keys), null);
  assert.equal(didYouMean('x', ['y']), null);
  assert.equal(didYouMean('ab', ['ac', 'aa']), 'aa');
  assert.equal(didYouMean('anything', []), null);
});

test('a keyword the validator cannot judge turns validation off with a message that says so', () => {
  const message = validationOffMessage(new UnsupportedKeyword('oneOf'));
  assert.match(message, /Validation is off/);
  assert.match(message, /oneOf/);
  assert.match(message, /ash config validate/);
});

test('a key named like a member of Object is an unknown key, and no entry is called its old name', () => {
  for (const key of ['constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
    const entry = { path: 'a', reason: 'b', [key]: 1 };
    const [found] = judgeField('global_settings', { suppressions: [entry] }).findings;
    assert.equal(found.message, `Unknown key '${key}' in a suppression. A scan ignores this entry.`);
  }
  // JSON.parse makes __proto__ an ordinary own key.
  const parsed = JSON.parse('{"suppressions":[{"path":"a","reason":"b","__proto__":1}]}');
  const [found] = judgeField('global_settings', parsed).findings;
  assert.equal(found.message, "Unknown key '__proto__' in a suppression. A scan ignores this entry.");
});

test('a build section with contents says the editor does not check them', () => {
  const warning = block.constants.invalidTopLevelFieldWarning.replace('{field}', 'build');
  const [found] = judgeField('', { build: { anything: true } }).findings;
  assert.equal(found.row, 'internal-top-level-field');
  assert.equal(found.message, `${warning} This editor does not check what is inside it.`);
  assert.equal(judgeField('', { build: {} }).findings[0].message, warning);
});

// The fixture's schema leaves out some entry models of ASH's published schema. This block
// puts them in where ASH puts them: a scope inside a suppression, and a list of ignore-path
// entries beside the suppressions.
function blockWithEntryModels() {
  const extended = structuredClone(block);
  const defs = extended.validationSchema.$defs;
  const text = { anyOf: [{ type: 'string' }, { type: 'null' }] };
  defs.SuppressionScope = {
    additionalProperties: false,
    properties: { resource_id: text, resource_type: text },
    type: 'object',
  };
  defs.IgnorePathWithReason = {
    additionalProperties: false,
    properties: { path: { minLength: 1, type: 'string' }, reason: { minLength: 1, type: 'string' } },
    required: ['path', 'reason'],
    type: 'object',
  };
  defs.AshSuppression.properties.scope = {
    anyOf: [{ $ref: '#/$defs/SuppressionScope' }, { type: 'null' }],
  };
  defs.GlobalSettings.properties.ignore_paths = {
    items: { $ref: '#/$defs/IgnorePathWithReason' },
    type: 'array',
  };
  return extended;
}

const withModels = blockWithEntryModels();

const judgeWithModels = (path, instance, options) =>
  judge(withModels, path, instance, validateField(withModels, path, instance, patterns), options);

const shown = (result) => result.findings.map(({ row, severity, pointer }) => ({ row, severity, pointer }));

const typoInScope = {
  global_settings: { suppressions: [{ path: 'a', reason: 'b', scope: { resorce_id: 'x' } }] },
};

test('an unknown key in a suppression scope warns, and the scope is named by what it is', () => {
  const result = judgeWithModels('', typoInScope);
  assert.equal(result.valid, true);
  assert.deepEqual(shown(result), [
    {
      row: 'unknown-key-in-list-entry',
      severity: 'warning',
      pointer: '/global_settings/suppressions/0/scope',
    },
  ]);
  assert.equal(
    result.findings[0].message,
    "Unknown key 'resorce_id' (did you mean 'resource_id'?) in a suppression scope. The suppression it belongs to matches nothing.",
  );
});

test('the same key in a scope is an error when the file asks to fail on unknown keys', () => {
  const result = judgeWithModels('', typoInScope, { failOnUnknownKeys: true });
  assert.equal(result.valid, false);
  assert.deepEqual(shown(result), [
    {
      row: 'unknown-key-in-list-entry',
      severity: 'error',
      pointer: '/global_settings/suppressions/0/scope',
    },
  ]);
  assert.ok(result.findings[0].message.endsWith(REFUSES));
});

test('an unknown key in an ignore-path entry warns wherever the list is judged from', () => {
  const entry = { path: 'a', reason: 'b', resaon: 'c' };
  const list = { global_settings: { ignore_paths: [entry] } };
  for (const [path, instance, pointer] of [
    ['', list, '/global_settings/ignore_paths/0'],
    ['global_settings', list.global_settings, '/ignore_paths/0'],
  ]) {
    const result = judgeWithModels(path, instance);
    const found = result.findings.find((item) => item.row === 'unknown-key-in-list-entry');
    assert.equal(found.severity, 'warning', path);
    assert.equal(found.pointer, pointer, path);
    assert.equal(
      found.message,
      "Unknown key 'resaon' (did you mean 'reason'?) in an ignore-path entry. A scan ignores this entry.",
    );
  }
});

test('a scope with an unknown key and a wrong value is refused, not downgraded', () => {
  const scope = { resorce_id: 'x', resource_id: 5 };
  const instance = { global_settings: { suppressions: [{ path: 'a', reason: 'b', scope }] } };
  const result = judgeWithModels('', instance);
  assert.equal(result.valid, false);
  assert.deepEqual(shown(result), [
    { row: null, severity: 'error', pointer: '/global_settings/suppressions/0/scope' },
  ]);
});

test('the table of entry models names each model, how its entry is called and what a scan does', () => {
  const models = messagesModule.ENTRY_MODELS;
  assert.deepEqual(Object.keys(models).sort(), [
    'AshExclusion',
    'AshSuppression',
    'IgnorePathWithReason',
    'SuppressionScope',
  ]);
  for (const [name, model] of Object.entries(models)) {
    assert.match(model.noun, /^an? [a-z -]+$/, name);
    assert.ok(model.ignored.endsWith('.'), name);
  }
  assert.equal(Object.isFrozen(models), true);
});
