// The editor's YAML modules against the shared corpus in fixtures/yaml-oracle-*.json.
//
// A reading case is a YAML text with either the value ASH's own loader gives it or
// the refusal the reader must make. A planted edit is a text, an edit, and the exact
// text after. A Python test (tests/unit/docs/test_config_editor_yaml_oracle.py)
// checks the same files against ASH's loader; this file checks that the reader, the
// writer and the re-read gate give the same values and texts.
//
// Values are compared in the corpus's JSON projection: integers beyond 2**53, floats,
// dates and timestamps, mappings whose keys are not plain strings, and text with
// control characters are written as small tagged objects.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { applyEdit } from '../content/assets/javascripts/config-editor/state.js';
import { mappingPairs, readYaml } from '../content/assets/javascripts/config-editor/yaml-read.js';
import { Float, Reference, Timestamp, TypedMap, makeMap } from '../content/assets/javascripts/config-editor/yaml-scalars.js';
import { emitBlock } from '../content/assets/javascripts/config-editor/yaml-write.js';

const FIXTURES = fileURLToPath(new URL('./fixtures/', import.meta.url));
const REPOSITORY_CONFIG = fileURLToPath(new URL('../../.ash.yaml', import.meta.url));
const INPUT_TOKENS = [
  ['<BSu>', '\\' + 'u'],
  ['<BSU>', '\\U'],
  ['<SOH>', String.fromCharCode(1)],
];
const REFUSAL_CODES = new Set([
  'alias',
  'anchor',
  'character',
  'complex-key',
  'constructor',
  'directive',
  'merge',
  'second-document',
  'syntax',
  'tab',
  'tag',
  'too-large',
]);

function readCorpus(kind) {
  const found = [];
  const names = readdirSync(FIXTURES)
    .filter((name) => /^yaml-oracle-.*\.json$/.test(name))
    .sort();
  for (const name of names) {
    const data = JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8'));
    assert.equal(data.format, 'yaml-oracle/1', name);
    found.push(...(data[kind] ?? []));
  }
  return found;
}

const READING_CASES = readCorpus('cases');
const EDIT_CASES = readCorpus('edits');

function blockText(block) {
  let text = 'text' in block ? block.text : `${block.lines.join('\n')}\n`;
  for (const [token, replacement] of INPUT_TOKENS) {
    text = text.split(token).join(replacement);
  }
  return text;
}

function caseText(testCase) {
  if ('fill' in testCase) {
    const { prefix, char, count } = testCase.fill;
    return prefix + char.repeat(count);
  }
  return blockText(testCase);
}

// The projection of what the reader built, from the nodes, because a number's type
// (an int or a float) is not in the value.

function define(object, key, value) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });
}

function unsafeCode(code) {
  return (
    (code < 0x20 && ![0x09, 0x0a, 0x0d].includes(code)) ||
    (code >= 0x7f && code <= 0xa0) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0xfeff ||
    (code >= 0xd800 && code <= 0xdfff)
  );
}

function projectText(text) {
  const codes = [...text].map((character) => character.codePointAt(0));
  return codes.some(unsafeCode) ? { $codes: codes } : text;
}

function scalarText(node) {
  if (node.type === 'env') {
    return node.ref.explicit ? `!ENV ${node.ref.text}` : node.ref.text;
  }
  return node.type === 'str' || node.type === 'value' ? node.value : null;
}

function projectScalar(node) {
  switch (node.type) {
    case 'null':
      return null;
    case 'bool':
      return node.value;
    case 'int':
      return node.exact ? node.value : { $int: node.digits };
    case 'float':
      return { $float: node.value };
    case 'timestamp':
      return node.value.kind === 'date' ? { $date: node.value.iso } : { $datetime: node.value.iso };
    default:
      return projectText(scalarText(node));
  }
}

function keyIdentity(key) {
  // Python's True == 1 == 1.0, and a date is not a string.
  if (key.type === 'bool') {
    return `n:${key.value ? 1 : 0}`;
  }
  if (key.type === 'int' || key.type === 'float') {
    return `n:${key.value}`;
  }
  if (key.type === 'timestamp') {
    return `t:${key.value.iso}`;
  }
  return key.type === 'null' ? 'null' : `s:${scalarText(key)}`;
}

function projectMapping(node) {
  const fail = (code, message) => {
    throw new Error(`${code}: ${message}`);
  };
  const first = new Map();
  const pairs = [];
  for (const [key, value] of mappingPairs(node, fail)) {
    const id = keyIdentity(key);
    if (first.has(id)) {
      pairs[first.get(id)][1] = value;
    } else {
      first.set(id, pairs.length);
      pairs.push([key, value]);
    }
  }
  const plain = pairs.every(([key]) => {
    const text = scalarText(key);
    return typeof text === 'string' && !text.startsWith('$');
  });
  if (plain) {
    const object = {};
    for (const [key, value] of pairs) {
      define(object, scalarText(key), projectNode(value));
    }
    return object;
  }
  return { $map: pairs.map(([key, value]) => [projectScalar(key), projectNode(value)]) };
}

function projectNode(node) {
  if (node.kind === 'scalar') {
    return projectScalar(node);
  }
  return node.kind === 'seq' ? node.items.map(projectNode) : projectMapping(node);
}

function projectDoc(doc) {
  return doc.root === null ? null : projectNode(doc.root);
}

function floatFrom(value) {
  if (typeof value === 'number') {
    return value;
  }
  return { inf: Infinity, '-inf': -Infinity, nan: NaN }[value] ?? Number(value);
}

function isMapping(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function same(expected, actual) {
  if (isMapping(expected) && isMapping(actual)) {
    const left = Object.keys(expected);
    const right = Object.keys(actual);
    if (left.length === 1 && left[0] === '$float' && right.length === 1 && right[0] === '$float') {
      return Object.is(floatFrom(expected.$float), floatFrom(actual.$float));
    }
    return left.length === right.length && left.every((key) => right.includes(key) && same(expected[key], actual[key]));
  }
  if (Array.isArray(expected) && Array.isArray(actual)) {
    return expected.length === actual.length && expected.every((item, index) => same(item, actual[index]));
  }
  return typeof expected === typeof actual && expected === actual;
}

function short(value) {
  const text = JSON.stringify(value, (_key, item) => {
    if (typeof item === 'bigint') {
      return item.toString();
    }
    return typeof item === 'number' && !Number.isFinite(item) ? String(item) : item;
  });
  return (text ?? 'undefined').slice(0, 160);
}

function difference(expected, actual, where = 'value') {
  if (same(expected, actual)) {
    return null;
  }
  if (isMapping(expected) && isMapping(actual) && !('$float' in expected)) {
    for (const key of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort()) {
      if (!(key in expected)) {
        return `${where}.${key}: not expected, the reader gave ${short(actual[key])}`;
      }
      if (!(key in actual)) {
        return `${where}.${key}: missing, expected ${short(expected[key])}`;
      }
      const found = difference(expected[key], actual[key], `${where}.${key}`);
      if (found) {
        return found;
      }
    }
  }
  if (Array.isArray(expected) && Array.isArray(actual) && expected.length === actual.length) {
    for (let index = 0; index < expected.length; index += 1) {
      const found = difference(expected[index], actual[index], `${where}[${index}]`);
      if (found) {
        return found;
      }
    }
  }
  return `${where}: expected ${short(expected)}, the reader gave ${short(actual)}`;
}

// Reading.

function refusalOf(doc) {
  return doc.ok ? 'no refusal' : `${doc.refusal.code} at ${doc.refusal.line}:${doc.refusal.column} (${doc.refusal.message})`;
}

for (const testCase of READING_CASES) {
  test(`reads ${testCase.id} as the corpus says`, () => {
    const doc = readYaml(caseText(testCase));
    if (!('refuse' in testCase)) {
      assert.ok(doc.ok, `the reader refuses a text ASH reads: ${refusalOf(doc)}`);
      const found = difference(testCase.value, projectDoc(doc));
      assert.equal(found, null, found ?? '');
      return;
    }
    const { refuse } = testCase;
    assert.ok(REFUSAL_CODES.has(refuse.code), refuse.code);
    assert.equal(doc.ok, false, 'the reader reads a text the case says it refuses');
    assert.deepEqual(
      { code: doc.refusal.code, line: doc.refusal.line, column: doc.refusal.column },
      { code: refuse.code, line: refuse.line, column: refuse.column },
      refusalOf(doc),
    );
  });
}

// The value tree the page reads (doc.value): a number is a plain number, so a float
// matches any number, and a mapping with a key that is not a plain string is a typed
// map. With `typed` the tree is doc.typed instead, where a float is a Float and an
// integer is never one.

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !(value instanceof Reference) &&
    !(value instanceof Timestamp) &&
    !(value instanceof Float) &&
    !(value instanceof TypedMap)
  );
}

function referenceText(reference) {
  return reference.explicit ? `!ENV ${reference.text}` : reference.text;
}

function describe(value) {
  if (value instanceof Reference) {
    return `the reference ${referenceText(value)}`;
  }
  if (value instanceof Timestamp) {
    return `the ${value.kind} ${value.iso}`;
  }
  if (value instanceof TypedMap) {
    return `a map with typed keys and ${value.pairs.length} pairs`;
  }
  if (value instanceof Float) {
    return `the float ${value.value}`;
  }
  return short(value);
}

function pairsDifference(pairs, actual, typed, where) {
  if (actual instanceof TypedMap) {
    if (actual.pairs.length !== pairs.length) {
      return `${where}: expected ${pairs.length} pairs, the reader gave ${actual.pairs.length}`;
    }
    for (let index = 0; index < pairs.length; index += 1) {
      const found =
        treeDifference(pairs[index][0], actual.pairs[index][0], typed, `${where}.key[${index}]`) ??
        treeDifference(pairs[index][1], actual.pairs[index][1], typed, `${where}[${short(pairs[index][0])}]`);
      if (found) {
        return found;
      }
    }
    return null;
  }
  // Keys that are all strings make a plain object, even where a dollar sign starts one.
  if (pairs.every(([key]) => typeof key === 'string') && isPlainObject(actual)) {
    if (Object.keys(actual).length !== pairs.length) {
      return `${where}: expected ${pairs.length} keys, the reader gave ${Object.keys(actual).length}`;
    }
    for (const [key, value] of pairs) {
      if (!Object.hasOwn(actual, key)) {
        return `${where}.${key}: missing`;
      }
      const found = treeDifference(value, actual[key], typed, `${where}.${key}`);
      if (found) {
        return found;
      }
    }
    return null;
  }
  return `${where}: expected a map of ${pairs.length} pairs, the reader gave ${describe(actual)}`;
}

function treeDifference(expected, actual, typed, where = 'value') {
  const wrong = () => `${where}: expected ${short(expected)}, the reader gave ${describe(actual)}`;
  if (expected === null || typeof expected === 'boolean') {
    return actual === expected ? null : wrong();
  }
  if (typeof expected === 'number') {
    return typeof actual === 'number' && Object.is(actual, expected) ? null : wrong();
  }
  if (typeof expected === 'string') {
    const text = actual instanceof Reference ? referenceText(actual) : actual;
    return text === expected ? null : wrong();
  }
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) {
      return wrong();
    }
    for (let index = 0; index < expected.length; index += 1) {
      const found = treeDifference(expected[index], actual[index], typed, `${where}[${index}]`);
      if (found) {
        return found;
      }
    }
    return null;
  }
  if ('$float' in expected) {
    const number = typed ? (actual instanceof Float ? actual.value : undefined) : actual;
    return typeof number === 'number' && Object.is(number, floatFrom(expected.$float)) ? null : wrong();
  }
  if ('$int' in expected) {
    return typeof actual === 'bigint' && actual.toString() === expected.$int ? null : wrong();
  }
  if ('$date' in expected || '$datetime' in expected) {
    const kind = '$date' in expected ? 'date' : 'datetime';
    const iso = expected.$date ?? expected.$datetime;
    return actual instanceof Timestamp && actual.kind === kind && actual.iso === iso ? null : wrong();
  }
  if ('$codes' in expected) {
    const codes = typeof actual === 'string' ? [...actual].map((character) => character.codePointAt(0)) : null;
    const same = codes !== null && codes.length === expected.$codes.length && codes.every((code, index) => code === expected.$codes[index]);
    return same ? null : wrong();
  }
  if ('$map' in expected) {
    return pairsDifference(expected.$map, actual, typed, where);
  }
  const names = Object.keys(expected);
  if (!isPlainObject(actual) || Object.keys(actual).length !== names.length) {
    return wrong();
  }
  for (const name of names) {
    if (!Object.hasOwn(actual, name)) {
      return `${where}.${name}: missing`;
    }
    const found = treeDifference(expected[name], actual[name], typed, `${where}.${name}`);
    if (found) {
      return found;
    }
  }
  return null;
}

for (const testCase of READING_CASES) {
  if ('refuse' in testCase) {
    continue;
  }
  test(`the value tree for ${testCase.id} says what the corpus says`, () => {
    const doc = readYaml(caseText(testCase));
    assert.ok(doc.ok, refusalOf(doc));
    const found = treeDifference(testCase.value, doc.value, false);
    assert.equal(found, null, found ?? '');
  });
}

for (const testCase of READING_CASES) {
  if ('refuse' in testCase) {
    continue;
  }
  test(`the typed tree for ${testCase.id} says what the corpus says, floats and integers apart`, () => {
    const doc = readYaml(caseText(testCase));
    assert.ok(doc.ok, refusalOf(doc));
    const found = treeDifference(testCase.value, doc.typed, true);
    assert.equal(found, null, found ?? '');
  });
}

// The block emitter: what it writes for each value the corpus holds reads back as the
// same, type for type: an integer stays an integer, a float a float, a key keeps its type.

for (const testCase of READING_CASES) {
  if ('refuse' in testCase) {
    continue;
  }
  test(`the block emitter writes ${testCase.id} so that it reads back the same`, () => {
    const doc = readYaml(caseText(testCase));
    assert.ok(doc.ok, refusalOf(doc));
    for (const [unit, seq] of [[2, 'indented'], [4, 'indentless']]) {
      const text = `${emitBlock(doc.typed, { unit, seq })}\n`;
      const back = readYaml(text);
      assert.ok(back.ok, `the written text is refused: ${refusalOf(back)}\n${text.slice(0, 300)}`);
      const found = difference(projectDoc(doc), projectDoc(back));
      assert.equal(found, null, `the written text reads differently: ${found}\n${text.slice(0, 300)}`);
    }
  });
}

// Editing.

function editValue(raw) {
  if (raw !== null && typeof raw === 'object' && '$ref' in raw) {
    return new Reference(raw.$ref, Boolean(raw.explicit));
  }
  if (raw !== null && typeof raw === 'object' && '$float' in raw) {
    return new Float(floatFrom(raw.$float));
  }
  if (raw !== null && typeof raw === 'object' && '$map' in raw) {
    return makeMap(raw.$map.map(([key, item]) => [editValue(key), editValue(item)]));
  }
  if (Array.isArray(raw)) {
    return raw.map(editValue);
  }
  if (raw !== null && typeof raw === 'object') {
    const object = {};
    for (const [key, item] of Object.entries(raw)) {
      define(object, key, editValue(item));
    }
    return object;
  }
  return raw;
}

for (const testCase of EDIT_CASES) {
  test(`edits ${testCase.id} as the corpus says, with no gate trip`, () => {
    const before = blockText(testCase.before);
    const edit = { ...testCase.edit };
    if ('value' in edit) {
      edit.value = editValue(edit.value);
    }
    const result = applyEdit(before, edit);
    if (testCase.how === 'refused') {
      assert.equal(result.ok, false);
      assert.equal(result.how, 'refused');
      assert.equal(result.reason, testCase.reason);
      return;
    }
    assert.ok(result.ok, result.message);
    // A patch that failed the gate would show here as a re-emitted entry.
    assert.equal(result.how, testCase.how);
    assert.equal(result.text, testCase.how === 'none' ? before : blockText(testCase.after));
    if ('droppedComments' in testCase) {
      assert.equal(result.droppedComments, testCase.droppedComments);
    }
  });
}

test('the corpus has its cases, each with its own id', () => {
  const ids = [...READING_CASES, ...EDIT_CASES].map((testCase) => testCase.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(READING_CASES.length >= 100);
  assert.ok(EDIT_CASES.length >= 50);
});

// The comparison itself can tell a wrong value from a right one.

test('the comparison tells a boolean from the word, the number and the other boolean', () => {
  const projected = projectDoc(readYaml('a: yes\n'));
  assert.ok(same({ a: true }, projected));
  assert.ok(!same({ a: 'yes' }, projected));
  assert.ok(!same({ a: 1 }, projected));
  assert.ok(!same({ a: false }, projected));
});

test('a planted wrong value is reported where it is', () => {
  const testCase = READING_CASES.find((item) => item.id === 'bool-words');
  const wrong = { ...testCase.value, g: false };
  const found = difference(wrong, projectDoc(readYaml(caseText(testCase))));
  assert.match(found, /^value\.g:/);
});

test('float zeros are told apart and not-a-number equals itself', () => {
  assert.ok(!same({ $float: '0.0' }, { $float: '-0.0' }));
  assert.ok(same({ $float: 'nan' }, { $float: NaN }));
  assert.ok(same({ $float: '1500.0' }, { $float: '1.5e3' }));
});

// The repository's own configuration file: the whole of it, as it is now.

function lines(text) {
  return text.split('\n');
}

function firstPath(node, wanted, trail = []) {
  if (wanted(node)) {
    return trail;
  }
  if (node.kind === 'map' && node.style === 'block') {
    for (const entry of node.entries) {
      const found = firstPath(entry.value, wanted, [...trail, entry.key.text]);
      if (found !== null) {
        return found;
      }
    }
  }
  return null;
}

function valueAt(value, steps) {
  return steps.reduce((current, step) => current[step], value);
}

test('the repository configuration file reads, and the nodes lie inside the text', () => {
  const text = readFileSync(REPOSITORY_CONFIG, 'utf8');
  const doc = readYaml(text);
  assert.ok(doc.ok, refusalOf(doc));
  assert.equal(doc.root.kind, 'map');
  assert.equal(doc.lineStarts.length, lines(text).length);
  const check = (node, parent) => {
    assert.ok(node.start >= parent.start && node.end <= parent.end, `a node lies outside its parent at ${node.start}`);
    const children = node.kind === 'map' ? node.entries.flatMap((entry) => [entry.key, entry.value]) : node.kind === 'seq' ? node.items : [];
    for (const child of children) {
      check(child, node);
    }
  };
  check(doc.root, { start: 0, end: text.length });
});

test('an edit to the repository configuration file changes only the lines it names', () => {
  const text = readFileSync(REPOSITORY_CONFIG, 'utf8');
  const doc = readYaml(text);
  assert.ok(doc.ok, refusalOf(doc));
  const before = lines(text);

  const scalar = firstPath(doc.root, (node) => node.kind === 'scalar' && node.type === 'str' && node.style === 'plain');
  assert.ok(scalar !== null && scalar.length > 0, 'the file has a plain string value');
  const old = valueAt(doc.value, scalar);

  const unchanged = applyEdit(text, { op: 'set', path: scalar, value: old });
  assert.equal(unchanged.how, 'none');
  assert.equal(unchanged.text, text);

  const changed = applyEdit(text, { op: 'set', path: scalar, value: 'zz edited value' });
  assert.equal(changed.how, 'patch');
  const after = lines(changed.text);
  assert.equal(after.length, before.length);
  assert.equal(after.filter((line, index) => line !== before[index]).length, 1);

  const added = applyEdit(text, { op: 'set', path: [...scalar.slice(0, -1), 'zz_new_key'], value: 'zz' });
  assert.equal(added.ok, true, added.message);
  assert.equal(added.how, 'patch');
  assert.equal(lines(added.text).length, before.length + 1);

  const deleted = applyEdit(text, { op: 'delete', path: scalar });
  assert.equal(deleted.how, 'patch');
  assert.equal(lines(deleted.text).length, before.length - 1);
});

function lineIndexOf(doc, offset) {
  let index = 0;
  while (index + 1 < doc.lineStarts.length && doc.lineStarts[index + 1] <= offset) {
    index += 1;
  }
  return index;
}

test('deleting the first key of a suppression in the repository configuration file changes only that suppression', () => {
  const text = readFileSync(REPOSITORY_CONFIG, 'utf8');
  const doc = readYaml(text);
  assert.ok(doc.ok, refusalOf(doc));
  const path = ['global_settings', 'suppressions', 0, 'rule_id'];
  const item = valueAt(doc.value, path.slice(0, -1));
  assert.ok(Object.hasOwn(item, 'rule_id'), 'the file starts its first suppression with a rule_id');
  const settings = doc.root.entries.find((entry) => entry.key.text === 'global_settings').value;
  const suppressions = settings.entries.find((entry) => entry.key.text === 'suppressions').value;
  const first = suppressions.items[0];
  const keyColumn = first.entries[0].key.column;
  const line = lineIndexOf(doc, first.dash);
  const before = lines(text);
  assert.ok(before[line].slice(0, keyColumn).trim() === '-', 'the key shares its line with the dash');

  const result = applyEdit(text, { op: 'delete', path });
  assert.equal(result.ok, true, result.message);
  assert.equal(result.how, 'patch');
  assert.equal(result.droppedComments, 0);
  // The next key moves up to the dash line; every other line, comments included, stays.
  const expected = [
    ...before.slice(0, line),
    before[line].slice(0, keyColumn) + before[line + 1].slice(keyColumn),
    ...before.slice(line + 2),
  ];
  const after = lines(result.text);
  assert.equal(after.length, expected.length, `the file has ${after.length} lines, expected ${expected.length}`);
  const at = after.findIndex((item, index) => item !== expected[index]);
  assert.equal(at, -1, `line ${at + 1} differs`);
});

test('an item appended to a list in the repository configuration file is one new line', () => {
  const text = readFileSync(REPOSITORY_CONFIG, 'utf8');
  const doc = readYaml(text);
  assert.ok(doc.ok, refusalOf(doc));
  const list = firstPath(doc.root, (node) => node.kind === 'seq' && node.style === 'block');
  assert.ok(list !== null && list.length > 0, 'the file has a block list');
  const result = applyEdit(text, { op: 'append', path: list, value: 'zz-appended' });
  assert.equal(result.how, 'patch');
  const before = lines(text);
  const after = lines(result.text);
  assert.equal(after.length, before.length + 1);
  const at = after.findIndex((line, index) => line !== before[index]);
  assert.equal(after[at].trim(), '- zz-appended');
  assert.deepEqual([...after.slice(0, at), ...after.slice(at + 1)], before);
});
