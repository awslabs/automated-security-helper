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
    const result = judgeField(item.path, item.instance, item.options);
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

// The schema's pattern for a reference lets a carriage return through a default, and the
// loader's recognizer stops at one. So this text is a reference to the schema and an ordinary
// string to ASH, and a boolean or a number takes no string: ASH refuses the file either way.
const WITH_CARRIAGE_RETURN = '${CI_STRICT:a\rb}';

test('text the schema reads as a reference and ASH does not is refused where a reference is', () => {
  const field = judgeField('fail_on_findings', WITH_CARRIAGE_RETURN);
  assert.equal(field.valid, false);
  assert.deepEqual(projected(field), [{ row: 'reference-in-typed-field', severity: 'error' }]);
  assert.equal(field.findings[0].pointer, '');

  const document = judgeField('', { fail_on_findings: WITH_CARRIAGE_RETURN });
  assert.equal(document.valid, false);
  assert.deepEqual(projected(document), [{ row: 'reference-in-typed-field', severity: 'error' }]);
  assert.equal(document.findings[0].pointer, '/fail_on_findings');

  const timeout = judgeField('scanners.bandit.options.scan_timeout', '${ASH_SCAN_TIMEOUT:6\r0}');
  assert.equal(timeout.valid, false);
  assert.deepEqual(projected(timeout), [{ row: 'reference-in-typed-field', severity: 'error' }]);

  // A string the schema refuses stays the schema's failure, and a field that takes a string
  // or one of a set of names takes this text, as it takes any reference.
  assert.deepEqual(projected(judgeField('fail_on_findings', 'yes')), [{ row: null, severity: 'error' }]);
  assert.deepEqual(judgeField('project_name', WITH_CARRIAGE_RETURN).findings, []);
  assert.deepEqual(judgeField('global_settings.severity_threshold', WITH_CARRIAGE_RETURN).findings, []);
});

test('the sentence for a value at a field that takes no reference is true for a reference and for any other string', () => {
  const sentence = (value, kind) =>
    `The value ${value} is not accepted in this ${kind} field: a reference is refused here, and so is any other string. ${REFUSES}`;
  for (const text of ['${CI_STRICT}', '!ENV ${CI_STRICT}', WITH_CARRIAGE_RETURN]) {
    const result = judgeField('fail_on_findings', text);
    assert.equal(result.findings.length, 1, JSON.stringify(text));
    assert.equal(result.findings[0].message, sentence(text, 'boolean'));
  }
  const timeout = judgeField('scanners.bandit.options.scan_timeout', '${ASH_SCAN_TIMEOUT:60}');
  assert.equal(timeout.findings[0].message, sentence('${ASH_SCAN_TIMEOUT:60}', 'integer'));
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

test('a reference in a typed field is judged wherever the value sits, a whole document included', () => {
  const document = judgeField('', { fail_on_findings: '${CI_STRICT}' });
  assert.equal(document.valid, false);
  assert.deepEqual(projected(document), [{ row: 'reference-in-typed-field', severity: 'error' }]);
  assert.equal(document.findings[0].pointer, '/fail_on_findings');
  assert.match(document.findings[0].message, /\$\{CI_STRICT\} is not accepted in this boolean field/);

  const options = judgeField('scanners.zizmor.options', { online_audits: '${ASH_ONLINE}' });
  assert.deepEqual(projected(options), [{ row: 'reference-in-typed-field', severity: 'error' }]);
  assert.equal(options.findings[0].pointer, '/online_audits');

  const nested = { scanners: { zizmor: { options: { online_audits: '${ASH_ONLINE}' } } } };
  assert.equal(judgeField('', nested).findings[0].pointer, '/scanners/zizmor/options/online_audits');

  // A string field and an enum field take a reference, so nothing is said of them.
  const accepted = { project_name: '${PROJECT}', global_settings: { severity_threshold: '${LEVEL}' } };
  assert.deepEqual(judgeField('', accepted).findings, []);
});

test('keys that come from the file never read the data block through its prototype', () => {
  const instance = { constructor: '${A}', toString: 1, scanners: { constructor: {} } };
  const result = judgeField('', instance);
  assert.equal(result.valid, true);
  assert.deepEqual(
    result.findings.map((found) => [found.row, found.pointer]),
    [
      ['unknown-top-level-key', '/constructor'],
      ['unknown-top-level-key', '/toString'],
    ],
  );
});

test('ASH reads a string of output formats as the names between its commas', () => {
  const read = messagesModule.readOutputFormats;
  assert.deepEqual(read('sarif,html'), ['sarif', 'html']);
  assert.deepEqual(read('sarif,html,'), ['sarif', 'html']);
  assert.deepEqual(read('sarif,,html'), ['sarif', 'html']);
  assert.deepEqual(read(''), []);
  assert.deepEqual(read(' sarif'), ['sarif']);
  assert.deepEqual(read('  ,  '), []);
});

test('the strings of the output format vectors read as ASH reads them', () => {
  const read = messagesModule.readOutputFormats;
  const allowed = block.fields.output_formats.enum;
  const vectors = fixture('output-format-vectors.json');
  for (const group of vectors.groups) {
    for (const code of group.codePoints) {
      const text = group.template.replaceAll('{c}', String.fromCodePoint(code));
      const pieces = read(text);
      const label = `${group.id} ${code.toString(16)}`;
      if (group.formats === null) {
        assert.ok(pieces.some((piece) => !allowed.includes(piece)), label);
      } else {
        assert.deepEqual(pieces, group.formats, label);
      }
    }
  }
});

test('a string of output formats that ASH reads as a list is a warning, however it is written', () => {
  for (const text of ['sarif,html,', 'sarif,,html', '', ' sarif', 'sarif , html']) {
    const result = judgeField('output_formats', text);
    assert.equal(result.valid, true, JSON.stringify(text));
    assert.deepEqual(projected(result), [{ row: 'comma-separated-output-formats', severity: 'warning' }]);
    assert.match(result.findings[0].message, /Write as a list: output_formats: \[/);
  }
  const document = judgeField('', { output_formats: 'sarif,html' });
  assert.equal(document.valid, true);
  assert.equal(document.findings[0].pointer, '/output_formats');
  assert.match(document.findings[0].message, /Write as a list: output_formats: \[sarif, html\]/);
  // A piece that is not a format is still refused, whatever the commas.
  assert.equal(judgeField('output_formats', 'sarif,pdf').valid, false);
  assert.equal(judgeField('output_formats', `${String.fromCodePoint(0xfeff)}sarif`).valid, false);
});

test('an unquoted date where a string belongs is an error that says to quote it', () => {
  const entry = { path: 'a', reason: 'b', expires: '2030-01-01' };
  const document = { global_settings: { suppressions: [entry] } };
  const pointer = '/global_settings/suppressions/0/expires';
  const result = judgeField('', document, { unquotedDates: [pointer] });
  assert.equal(result.valid, false);
  assert.deepEqual(projected(result), [{ row: 'unquoted-date', severity: 'error' }]);
  assert.equal(result.findings[0].pointer, pointer);
  assert.equal(
    result.findings[0].message,
    `expires must be quoted: an unquoted 2030-01-01 is read as a date, not text, so put it in quotes. ${REFUSES}`,
  );
  // The same value written in quotes is fine, and so is a date the options do not name.
  assert.equal(judgeField('', document).valid, true);
  assert.equal(judgeField('', document, { unquotedDates: [] }).valid, true);
});

test('an unquoted date is left alone where ASH does not read the field as a string', () => {
  // A boolean field refuses the text on its own, and the date row adds nothing to it.
  const typed = judgeField('', { fail_on_findings: '2030-01-01' }, { unquotedDates: ['/fail_on_findings'] });
  assert.deepEqual(projected(typed), [{ row: null, severity: 'error' }]);
  // A key ASH does not know is ignored, so a date in it does no harm.
  const unknown = judgeField('', { mystery: '2030-01-01' }, { unquotedDates: ['/mystery'] });
  assert.deepEqual(projected(unknown), [{ row: 'unknown-top-level-key', severity: 'warning' }]);
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

// ASH folds the spellings of each plugin section onto the declared one before it reads a
// file, so what is inside a section spelled another way is read, and refused, as the declared
// section's contents are. The schema admits any contents at a key it does not declare.

test('what is inside a section spelled another way is judged as the declared section, where the file wrote it', () => {
  const instance = {
    scanners: { Bandit: { enabled: 'yes' } },
    converters: { Archive: { enabled: 'no' } },
  };
  const result = judgeField('', instance);
  assert.equal(result.valid, false);
  const inside = result.findings.filter((item) => item.row === 'variant-section-contents');
  assert.deepEqual(inside.map((item) => [item.severity, item.pointer, item.keyword]).sort(), [
    ['error', '/converters/Archive/enabled', 'type'],
    ['error', '/scanners/Bandit/enabled', 'type'],
  ]);
  // Each respelled section is still noted.
  assert.equal(result.findings.filter((item) => item.row === 'plugin-section-spelling').length, 2);
});

test("the sentence for a failure inside a respelled section is the declared spelling's", () => {
  const declared = judgeField('', { scanners: { bandit: { enabled: 'yes' } } }).findings[0];
  const variant = judgeField('', { scanners: { Bandit: { enabled: 'yes' } } }).findings[0];
  assert.equal(declared.row, null);
  assert.equal(declared.pointer, '/scanners/bandit/enabled');
  assert.equal(variant.row, 'variant-section-contents');
  assert.equal(variant.pointer, '/scanners/Bandit/enabled');
  assert.equal(variant.message, declared.message);
  assert.match(variant.message, /Expected a boolean, found a string\./);
});

test('a value of a respelled section that the declared spelling overrides is not judged', () => {
  const overridden = judgeField('scanners', { Bandit: { enabled: 'yes' }, bandit: { enabled: true } });
  assert.equal(overridden.valid, true);
  assert.deepEqual(projected(overridden), [{ row: 'plugin-section-spelling', severity: 'note' }]);
  const leaf = {
    Bandit: { options: { scan_timeout: 'x' } },
    bandit: { options: { scan_timeout: 30 } },
  };
  assert.equal(judgeField('scanners', leaf).valid, true);
});

test('a failing value is reported where the file wrote it, whichever spelling it came from', () => {
  const instance = {
    Bandit: { options: { scan_timeout: 'x' } },
    bandit: { options: { confidence_level: 'nonsense' } },
  };
  const result = judgeField('scanners', instance);
  const failures = Object.fromEntries(
    result.findings.filter((item) => item.keyword).map((item) => [item.pointer, item.row]),
  );
  // The declared spelling's own failure is one the schema shows for the file as written, so
  // it is a plain failure; the variant's is the one the fold finds.
  assert.deepEqual(failures, {
    '/Bandit/options/scan_timeout': 'variant-section-contents',
    '/bandit/options/confidence_level': null,
  });
  assert.equal(result.valid, false);
});

test('the rows that look at a value apply inside a section spelled another way', () => {
  const reference = judgeField('', {
    scanners: { Bandit: { options: { scan_timeout: '${ASH_SCAN_TIMEOUT}' } } },
  });
  const found = reference.findings.find((item) => item.row === 'reference-in-typed-field');
  assert.equal(found.pointer, '/scanners/Bandit/options/scan_timeout');
  assert.equal(reference.valid, false);
});

// The fixture holds no string field and no list of entries inside a plugin section. These
// blocks put them in, where ASH has them.
function blockWithStringField() {
  const extended = structuredClone(block);
  extended.validationSchema.$defs.BanditScannerConfig.properties.config_file = { type: 'string' };
  extended.fields['scanners.bandit.config_file'] = {
    ...structuredClone(block.fields['scanners.bandit.enabled']),
    key: 'config_file',
    kind: 'string',
    path: 'scanners.bandit.config_file',
    schemaPointer: '#/$defs/BanditScannerConfig/properties/config_file',
  };
  return extended;
}

test('an unquoted date inside a respelled section is reported where the file wrote it', () => {
  const extended = blockWithStringField();
  const instance = { Bandit: { config_file: '2030-01-01' } };
  const failures = validateField(extended, 'scanners', instance, patterns);
  const result = judge(extended, 'scanners', instance, failures, {
    unquotedDates: ['/Bandit/config_file'],
  });
  const found = result.findings.find((item) => item.row === 'unquoted-date');
  assert.equal(found.pointer, '/Bandit/config_file');
  assert.equal(result.valid, false);
});

test('an unknown key in an entry inside a respelled section warns where the file wrote it', () => {
  const extended = blockWithEntryModels();
  extended.validationSchema.$defs.BanditScannerConfigOptions.properties.excluded_paths = {
    items: { $ref: '#/$defs/IgnorePathWithReason' },
    type: 'array',
  };
  const entry = { path: 'a', reason: 'b', resaon: 'c' };
  const instance = { Bandit: { options: { excluded_paths: [entry] } } };
  const failures = validateField(extended, 'scanners', instance, patterns);
  const result = judge(extended, 'scanners', instance, failures);
  const found = result.findings.find((item) => item.row === 'unknown-key-in-list-entry');
  assert.equal(found.severity, 'warning');
  assert.equal(found.pointer, '/Bandit/options/excluded_paths/0');
  assert.equal(result.valid, true);
});

test('two spellings of one plugin are not folded, so the clash is the only thing said', () => {
  const result = judgeField('scanners', { BANDIT: { enabled: 'yes' }, 'ban-dit': {} });
  assert.deepEqual(projected(result), [{ row: 'ambiguous-plugin-spellings', severity: 'error' }]);
});

test('a key named __proto__ beside a respelled section is data, and pollutes nothing', () => {
  const instance = JSON.parse('{"__proto__": {"polluted": true}, "Bandit": {"enabled": "yes"}}');
  const result = judgeField('scanners', instance);
  assert.equal({}.polluted, undefined);
  assert.deepEqual(result.findings.map((item) => item.pointer).sort(), ['/Bandit', '/Bandit/enabled']);
});
