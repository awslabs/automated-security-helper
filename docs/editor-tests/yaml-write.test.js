// Tests for the configuration editor's YAML writer: how values become text, and
// the text changes it proposes for an edit.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readYaml } from '../content/assets/javascripts/config-editor/yaml-read.js';
import {
  Float,
  Reference,
  Timestamp,
  TypedMap,
  makeMap,
  resolvePlain,
} from '../content/assets/javascripts/config-editor/yaml-scalars.js';
import {
  applyToValue,
  editBound,
  emitBlock,
  formatFloat,
  formatNumber,
  formatPath,
  formatScalar,
  formatString,
  newDocumentText,
  planPatch,
  planReemit,
  sameValue,
} from '../content/assets/javascripts/config-editor/yaml-write.js';

function patch(text, edit) {
  return planPatch(readYaml(text), edit);
}

function reemit(text, edit) {
  return planReemit(readYaml(text), edit);
}

// A number past 2**53 is spelled so that what it means is plain: a double as an exponent
// or a power, an integer as a BigInt. An integer literal there would already have lost
// digits before a test ran, so no case rests on one.
test('a number is written so that ASH reads the same number back', () => {
  const cases = [
    [2, '2'],
    [-7, '-7'],
    [1.5, '1.5'],
    [0.1, '0.1'],
    [1e-7, '1.0e-7'],
    [1.5e300, '1.5e+300'],
    [1e21, '1.0e+21'],
    [1e20, '1.0e+20'],
    [9007199254740991, '9007199254740991'],
    [2 ** 53, '9.007199254740992e+15'],
    [NaN, '.nan'],
    [Infinity, '.inf'],
    [-Infinity, '-.inf'],
    [-0, '-0.0'],
    [12345678901234567890123n, '12345678901234567890123'],
    [9007199254740992n, '9007199254740992'],
    [9007199254740993n, '9007199254740993'],
    [-9007199254740993n, '-9007199254740993'],
  ];
  for (const [number, text] of cases) {
    assert.equal(formatNumber(number), text);
  }
  for (const number of [1.5, 1e-7, 1.5e300, 0.1, 123456.789, -3, 1e21]) {
    assert.equal(Number(resolvePlain(formatNumber(number)).value), number, String(number));
  }
  // An integer past 2**53 comes back as the same integer, digit for digit.
  for (const big of [9007199254740992n, 9007199254740993n, -9007199254740993n, 12345678901234567890123n]) {
    const read = resolvePlain(formatNumber(big));
    assert.equal(read.type, 'int', String(big));
    assert.equal(read.value, big, String(big));
    assert.equal(read.digits, big.toString(), String(big));
  }
});

test('a float is written with a dot, so that ASH reads a float and never an integer', () => {
  const cases = [
    [1, '1.0'],
    [2500, '2500.0'],
    [1.5, '1.5'],
    [-3, '-3.0'],
    [0, '0.0'],
    [-0, '-0.0'],
    [1e-7, '1.0e-7'],
    [1.5e300, '1.5e+300'],
    [1e21, '1.0e+21'],
    [1.2345678901234568e20, '123456789012345680000.0'],
    [2 ** 53, '9007199254740992.0'],
    [NaN, '.nan'],
    [Infinity, '.inf'],
    [-Infinity, '-.inf'],
  ];
  for (const [number, text] of cases) {
    assert.equal(formatFloat(number), text);
    assert.equal(formatScalar(new Float(number)), text);
    const read = resolvePlain(text);
    assert.equal(read.type, 'float', text);
    assert.ok(Object.is(read.value, number), text);
  }
});

test('an integer beyond 2**53 is written with every digit, as the integer it is', () => {
  assert.equal(formatScalar(9007199254740993n), '9007199254740993');
  assert.equal(formatScalar(-123456789012345678901234567890n), '-123456789012345678901234567890');
  assert.equal(
    emitBlock({
      limit: 9007199254740993n,
      floor: -9007199254740993n,
      safe: 9007199254740991,
      list: [9007199254740992n],
    }),
    'limit: 9007199254740993\nfloor: -9007199254740993\nsafe: 9007199254740991\nlist:\n  - 9007199254740992',
  );
});

test('a string is written plain only where both readings agree, and keeps its quotes if it can', () => {
  assert.equal(formatString('hello'), 'hello');
  assert.equal(formatString('yes'), '"yes"');
  assert.equal(formatString(''), '""');
  assert.equal(formatString('0755'), '"0755"');
  assert.equal(formatString('k: v'), '"k: v"');
  assert.equal(formatString('it\'s', 'single'), "'it''s'");
  assert.equal(formatString('x', 'double'), '"x"');
  assert.equal(formatString('a,b', null, true), '"a,b"');
  assert.equal(formatString('one\ntwo', 'single'), '"one\\ntwo"');
});

test('every kind of scalar has a written form', () => {
  assert.equal(formatScalar(null), 'null');
  assert.equal(formatScalar(true), 'true');
  assert.equal(formatScalar(5), '5');
  assert.equal(formatScalar(new Float(2)), '2.0');
  assert.equal(formatScalar(new Reference('${HOME}', false)), '${HOME}');
  assert.equal(formatScalar(new Reference('${HOME:x}', true)), '!ENV ${HOME:x}');
  assert.equal(formatScalar(new Reference('${HOME}', false), { inFlow: true }), '!ENV "${HOME}"');
  assert.equal(formatScalar(new Reference('abc', false)), '!ENV abc');
  assert.equal(formatScalar(new Timestamp('date', '2026-12-31')), '2026-12-31');
  assert.throws(() => formatScalar({}), TypeError);
});

test('block text keeps the indentation unit, the list style and the line ending it is given', () => {
  assert.equal(
    emitBlock({ a: 1, b: { c: 'x', d: [1, 2] } }),
    'a: 1\nb:\n  c: x\n  d:\n    - 1\n    - 2',
  );
  assert.equal(emitBlock({ list: ['a'] }, { seq: 'indentless' }), 'list:\n- a');
  assert.equal(emitBlock({ a: { b: 1 } }, { unit: 4 }), 'a:\n    b: 1');
  assert.equal(emitBlock({ a: 1 }, { indent: 4 }), '    a: 1');
  assert.equal(emitBlock({ a: 1, b: 2 }, { newline: '\r\n' }), 'a: 1\r\nb: 2');
  assert.equal(
    emitBlock([{ name: 'a', n: 1 }, { name: 'b' }]),
    '- name: a\n  n: 1\n- name: b',
  );
  assert.equal(emitBlock([[1, 2], [3]]), '- - 1\n  - 2\n- - 3');
  assert.equal(emitBlock({ yes: 1, 'a b': [], c: {} }), '"yes": 1\na b: []\nc: {}');
  assert.equal(emitBlock('x'), 'x');
  assert.equal(emitBlock([]), '[]');
});

test('what the emitter writes reads back as the same value, type for type', () => {
  const value = {
    name: 'x y',
    flag: false,
    nothing: null,
    quoted: ['yes', '0755', '', 'k: v', 'a #b'],
    nested: { n: 3, f: 1.5, ref: new Reference('${HOME:x}', true), list: [{ a: 1, b: [2] }, {}] },
    'odd key': 'v',
    floats: [new Float(1), new Float(2500), 1.5, new Float(-0), new Float(Infinity)],
    keys: makeMap([
      [1, 'int'],
      ['1', 'text'],
      [null, 'null'],
      [new Float(1.5), 'float'],
      [new Timestamp('date', '2026-12-31'), 'date'],
      [new Reference('${KEY}', false), 'reference'],
      ['${KEY}', 'quoted reference'],
    ]),
    flags: makeMap([
      [true, 'a'],
      [false, 'b'],
    ]),
  };
  assert.ok(value.keys instanceof TypedMap);
  const doc = readYaml(`${emitBlock(value)}\n`);
  assert.ok(doc.ok, doc.refusal && doc.refusal.message);
  assert.equal(sameValue(value, doc.typed), true);
  assert.equal(
    emitBlock(value.keys),
    '1: int\n"1": text\nnull: "null"\n1.5: float\n2026-12-31: date\n${KEY}: reference\n"${KEY}": quoted reference',
  );
  assert.equal(emitBlock(value.flags), 'true: a\nfalse: b');
  // An integer where a float was is a different value, and so is text where a key was.
  assert.equal(sameValue(value, { ...value, floats: [1, 2500, 1.5, -0, Infinity] }), false);
  assert.equal(sameValue(value.keys, makeMap([[1, 'int'], ['1', 'text']])), false);
});

test('a new file is the schema comment, the project name, and nothing else', () => {
  assert.equal(
    newDocumentText({ modeline: '# yaml-language-server: $schema=x', projectName: 'demo' }),
    '# yaml-language-server: $schema=x\nproject_name: demo\n',
  );
  assert.equal(newDocumentText({ projectName: 'yes' }), 'project_name: "yes"\n');
  assert.equal(newDocumentText({ modeline: 'm' }), '# m\n');
  assert.equal(newDocumentText({}), '');
  assert.equal(
    newDocumentText({ modeline: '# m', projectName: 'p', newline: '\r\n' }),
    '# m\r\nproject_name: p\r\n',
  );
});

test('an edit applied to a value tree creates, replaces, deletes and appends', () => {
  assert.deepStrictEqual(applyToValue({ a: 1 }, { op: 'set', path: ['b', 'c'], value: 2 }), {
    a: 1,
    b: { c: 2 },
  });
  assert.deepStrictEqual(applyToValue(null, { op: 'set', path: ['a'], value: 1 }), { a: 1 });
  assert.deepStrictEqual(applyToValue({ a: 1 }, { op: 'delete', path: ['x', 'y'] }), { a: 1 });
  assert.deepStrictEqual(applyToValue({ a: [1, 2, 3] }, { op: 'delete', path: ['a', 1] }), {
    a: [1, 3],
  });
  assert.deepStrictEqual(applyToValue({ a: 'x' }, { op: 'append', path: ['a'], value: 1 }), {
    a: [1],
  });
  assert.deepStrictEqual(applyToValue({ l: [1] }, { op: 'append', path: ['l'], value: 2 }), {
    l: [1, 2],
  });
  const before = { a: { b: 1 } };
  applyToValue(before, { op: 'set', path: ['a', 'b'], value: 2 });
  assert.deepStrictEqual(before, { a: { b: 1 } });
});

test('an edit reaches into a mapping with typed keys by its string keys only', () => {
  const typed = { m: makeMap([[1, 'a'], ['1', 'b'], ['l', 'x']]) };
  const set = applyToValue(typed, { op: 'set', path: ['m', '1'], value: 'c' });
  assert.deepStrictEqual(set.m.pairs, [[1, 'a'], ['1', 'c'], ['l', 'x']]);
  const added = applyToValue(typed, { op: 'set', path: ['m', 'z', 'y'], value: 2 });
  assert.deepStrictEqual(added.m.pairs, [[1, 'a'], ['1', 'b'], ['l', 'x'], ['z', { y: 2 }]]);
  const removed = applyToValue(typed, { op: 'delete', path: ['m', 'l'] });
  assert.deepStrictEqual(removed.m.pairs, [[1, 'a'], ['1', 'b']]);
  const appended = applyToValue({ m: makeMap([[1, 'a'], ['l', ['x']]]) }, { op: 'append', path: ['m', 'l'], value: 'y' });
  assert.deepStrictEqual(appended.m.pairs, [[1, 'a'], ['l', ['x', 'y']]]);
  assert.deepStrictEqual(typed.m.pairs, [[1, 'a'], ['1', 'b'], ['l', 'x']]);
  // A path cannot name a key that is not a string, so such a key is never removed by one.
  const kept = applyToValue({ m: makeMap([[null, 1], ['b', 2]]) }, { op: 'delete', path: ['m', 'b'] });
  assert.deepStrictEqual(kept.m.pairs, [[null, 1]]);
  assert.deepStrictEqual(applyToValue(typed, { op: 'delete', path: ['m', 'nothing'] }), typed);
});

test('two value trees are the same when types and reference texts agree', () => {
  assert.equal(sameValue({ a: 1, b: [1, 2] }, { b: [1, 2], a: 1 }), true);
  assert.equal(sameValue(new Reference('${A}', true), new Reference('${A}', false)), true);
  assert.equal(sameValue(new Reference('${A}', false), '${A}'), false);
  assert.equal(sameValue(new Reference('${A}', false), new Reference('${B}', false)), false);
  assert.equal(sameValue(NaN, NaN), true);
  assert.equal(sameValue(0, -0), false);
  assert.equal(sameValue(1, '1'), false);
  assert.equal(sameValue(true, 'yes'), false);
  assert.equal(sameValue(10n, 10n), true);
  assert.equal(
    sameValue(new Timestamp('date', '2026-12-31'), new Timestamp('date', '2026-12-31')),
    true,
  );
  assert.equal(sameValue(new Timestamp('date', '2026-12-31'), '2026-12-31'), false);
  assert.equal(sameValue({ a: 1 }, { a: 1, b: 2 }), false);
  assert.equal(sameValue([1], [1, 2]), false);
});

test('two value trees are told apart by the type of every number and every key', () => {
  // An integer is not a float, whatever the value; a JavaScript number is one or the
  // other as it is written, and a BigInt is an integer.
  assert.equal(sameValue(1, new Float(1)), false);
  assert.equal(sameValue(new Float(1.5), 1.5), true);
  assert.equal(sameValue(new Float(NaN), NaN), true);
  assert.equal(sameValue(new Float(0), new Float(-0)), false);
  assert.equal(sameValue(5, 5n), true);
  assert.equal(sameValue(2 ** 53, new Float(2 ** 53)), true);
  assert.equal(sameValue({ a: [1.5, 2] }, { a: [new Float(1.5), 2] }), true);
  assert.equal(sameValue({ a: [new Float(2)] }, { a: [2] }), false);
  // The key 1, the key "1", true, null and the text null are different keys.
  const keys = [[1, 'x'], ['1', 'x'], [null, 'x'], ['null', 'x'], [new Float(1.5), 'x'], [true, 'x']];
  for (const left of keys) {
    for (const right of keys) {
      const same = left === right;
      assert.equal(sameValue(makeMap([left]), makeMap([right])), same, `${String(left[0])} against ${String(right[0])}`);
    }
  }
  // Python makes `yes` and `true` one key, and a mapping's key order does not matter.
  assert.equal(sameValue(makeMap([[true, 'x']]), makeMap([[true, 'x']])), true);
  assert.equal(sameValue(makeMap([[1, 'a'], [null, 'b']]), makeMap([[null, 'b'], [1, 'a']])), true);
  assert.equal(sameValue(makeMap([[1, 'a']]), { 1: 'a' }), false);
  assert.equal(sameValue(makeMap([[1, 'a']]), makeMap([[1, 'b']])), false);
  assert.equal(sameValue(makeMap([[new Reference('${K}', false), 'a']]), makeMap([['${K}', 'a']])), false);
  assert.equal(
    sameValue(makeMap([[new Reference('${K}', false), 'a']]), makeMap([[new Reference('${K}', true), 'a']])),
    true,
  );
});

test('two integers a double cannot tell apart are two values', () => {
  assert.equal(sameValue(9007199254740993n, 9007199254740992n), false);
  assert.equal(sameValue(9007199254740993n, 9007199254740993n), true);
  assert.equal(sameValue(-9007199254740993n, 9007199254740993n), false);
  assert.equal(sameValue([9007199254740993n], [9007199254740992n]), false);
  assert.equal(sameValue({ a: 9007199254740993n }, { a: 9007199254740992n }), false);
  // An integer is never the float of its value, and a number that large is a float.
  assert.equal(sameValue(9007199254740992n, 2 ** 53), false);
  assert.equal(sameValue(9007199254740992n, new Float(2 ** 53)), false);
  // The largest integer a number holds exactly is one value as a number and as a BigInt.
  assert.equal(sameValue(9007199254740991n, 9007199254740991), true);
  // As keys: two integer keys that differ by one are two keys, and the float key of an
  // integer key's value is that key, as in Python, written last and so kept as a float.
  assert.equal(sameValue(makeMap([[9007199254740993n, 'a']]), makeMap([[9007199254740992n, 'a']])), false);
  const merged = makeMap([[9007199254740992n, 'a'], [new Float(2 ** 53), 'b']]);
  assert.deepStrictEqual(merged.pairs, [[new Float(2 ** 53), 'b']]);
  assert.equal(sameValue(merged, makeMap([[new Float(2 ** 53), 'b']])), true);
  // A key's type is part of what it is, so the integer key is not the float key.
  assert.equal(sameValue(merged, makeMap([[9007199254740992n, 'b']])), false);
});

test('a path is written the way people write it', () => {
  assert.equal(formatPath(['scanners', 'bandit', 'options']), 'scanners.bandit.options');
  assert.equal(formatPath(['items', 0, 'name']), 'items[0].name');
});

test('a patch changes only the scalar it names and leaves the comment after it', () => {
  assert.deepEqual(patch('a: one # why\nb: two\n', { op: 'set', path: ['a'], value: 'x' }), {
    ok: true,
    how: 'patch',
    text: 'a: x # why\nb: two\n',
    droppedComments: 0,
  });
});

test('an edit elsewhere leaves an integer beyond 2**53 as it was, and an edit of its own writes every digit', () => {
  const text = 'limit: 9007199254740993 # cap\nother: 1\n';
  assert.deepEqual(patch(text, { op: 'set', path: ['other'], value: 2 }), {
    ok: true,
    how: 'patch',
    text: 'limit: 9007199254740993 # cap\nother: 2\n',
    droppedComments: 0,
  });
  assert.equal(
    patch(text, { op: 'set', path: ['limit'], value: 9007199254740995n }).text,
    'limit: 9007199254740995 # cap\nother: 1\n',
  );
  assert.equal(patch(text, { op: 'set', path: ['limit'], value: 9007199254740993n }).how, 'none');
  // The next integer down is another value, so it is a change.
  assert.equal(
    patch(text, { op: 'set', path: ['limit'], value: 9007199254740992n }).text,
    'limit: 9007199254740992 # cap\nother: 1\n',
  );
  // Integers in a list are kept, and one is added with every digit.
  assert.equal(
    patch('l:\n  - 9007199254740993\n  - 9007199254740992\n', { op: 'set', path: ['l', 2], value: 9007199254740994n }).text,
    'l:\n  - 9007199254740993\n  - 9007199254740992\n  - 9007199254740994\n',
  );
});

test('writing an entry again keeps every digit of an integer beyond 2**53', () => {
  const result = reemit('opts: {limit: 9007199254740993, list: [a]}\n', {
    op: 'append',
    path: ['opts', 'list'],
    value: 'b',
  });
  assert.equal(result.ok, true);
  assert.equal(result.text, 'opts:\n  limit: 9007199254740993\n  list:\n    - a\n    - b\n');
});

test('a whole number beyond 2**53 given as a plain number is refused, because its digits are already gone', () => {
  const text = 'a: 1\nlist: [x]\n';
  const lossy = [
    2 ** 53,
    2 ** 53 + 2,
    -(2 ** 60),
    1e21,
    [1, 2 ** 54],
    { deep: { value: 1e30 } },
    makeMap([['k', 2 ** 60]]),
    makeMap([[2 ** 60, 'key']]),
  ];
  for (const value of lossy) {
    for (const edit of [
      { op: 'set', path: ['a'], value },
      { op: 'append', path: ['list'], value },
    ]) {
      for (const result of [patch(text, edit), reemit(text, edit)]) {
        assert.equal(result.ok, false);
        assert.equal(result.final, true);
        assert.equal(result.reason, 'number');
        assert.match(result.message, /9007199254740991/);
      }
    }
  }
  // The message names the number, so the page can say which field it came from.
  assert.match(patch(text, { op: 'set', path: ['a'], value: 1e21 }).message, /1e\+21/);
  // A delete carries no value, so a lossy number in it means nothing.
  assert.equal(patch(text, { op: 'delete', path: ['a'], value: 1e21 }).ok, true);
});

test('a BigInt, a Float, a fraction and a number a number holds exactly are written as they are given', () => {
  const text = 'a: 1\n';
  const values = [
    [9007199254740993n, '9007199254740993'],
    [new Float(2 ** 53), '9007199254740992.0'],
    [new Float(1e21), '1.0e+21'],
    [9007199254740991, '9007199254740991'],
    [1.5, '1.5'],
    [-0, '-0.0'],
    [Infinity, '.inf'],
    [NaN, '.nan'],
  ];
  for (const [value, written] of values) {
    const result = patch(text, { op: 'set', path: ['a'], value });
    assert.equal(result.ok, true, String(value));
    assert.equal(result.text, `a: ${written}\n`, String(value));
  }
});

test('an edit that changes nothing says so', () => {
  assert.deepEqual(patch('a: 1\n', { op: 'set', path: ['a'], value: 1 }), {
    ok: true,
    how: 'none',
    text: 'a: 1\n',
    droppedComments: 0,
  });
});

test('deleting an entry counts the comments that were on its lines', () => {
  assert.deepEqual(patch('a: 1\nb: 2 # inline\nc: 3\n', { op: 'delete', path: ['b'] }), {
    ok: true,
    how: 'patch',
    text: 'a: 1\nc: 3\n',
    droppedComments: 1,
  });
});

test('a list item is added at the end of the list, and replaced in place', () => {
  assert.equal(
    patch('items:\n  - a\n', { op: 'set', path: ['items', 1], value: 'b' }).text,
    'items:\n  - a\n  - b\n',
  );
  assert.equal(
    patch('l:\n  - a\n  - b\n', { op: 'set', path: ['l', 0], value: { k: 1 } }).text,
    'l:\n  - k: 1\n  - b\n',
  );
  const far = patch('items:\n  - a\n', { op: 'set', path: ['items', 5], value: 'b' });
  assert.equal(far.ok, false);
  assert.equal(far.final, true);
  assert.equal(far.reason, 'path');
});

test('an edit the editor will not make is refused with a reason', () => {
  const cases = [
    ['a repeated key', 'a: 1\na: 2\n', { op: 'set', path: ['a'], value: 3 }, 'duplicate-key'],
    ['a merge key', 'd:\n  <<: {x: 2}\n  y: 1\n', { op: 'set', path: ['d', 'y'], value: 2 }, 'merge-key'],
    ['an alias', 'a: &x 1\nb: *x\n', { op: 'set', path: ['a'], value: 2 }, 'unreadable'],
    ['no path', 'a: 1\n', { op: 'set', path: [], value: 1 }, 'path'],
    ['a negative position', 'a: [1]\n', { op: 'delete', path: ['a', -1] }, 'path'],
  ];
  for (const [name, text, edit, reason] of cases) {
    const result = patch(text, edit);
    assert.equal(result.ok, false, name);
    assert.equal(result.final, true, name);
    assert.equal(result.reason, reason, name);
    assert.equal(typeof result.message, 'string', name);
  }
});

test('a shape a line patch does not handle is passed on, not refused', () => {
  const cases = [
    ['a list in flow style', 'list: [a]\n', { op: 'append', path: ['list'], value: 'b' }],
    ['a new key in a flow mapping', 'a: {x: 1}\n', { op: 'set', path: ['a', 'y'], value: 2 }],
    ['a deletion in a flow list', 'list: [a, b]\n', { op: 'delete', path: ['list', 0] }],
  ];
  for (const [name, text, edit] of cases) {
    assert.deepEqual(patch(text, edit), { ok: false, final: false, reason: 'unsupported' }, name);
  }
});

test('the first key of a compact list item is taken out where it is, and the next key moves up', () => {
  const cases = [
    [
      'a mapping item',
      'l:\n  - a: 1\n    b: 2\n  - c: 3\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - b: 2\n  - c: 3\n',
      0,
    ],
    [
      'the comment on its own line goes with it, and the comment line above the next key stays',
      'l:\n  - a: 1 # one\n    # about b\n    b: 2\n  - c: 3\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - # about b\n    b: 2\n  - c: 3\n',
      1,
    ],
    [
      'a blank line, then two comment lines, between the keys',
      'l:\n  - a: 1\n\n    # first\n    # second\n    b: 2\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - # first\n    # second\n    b: 2\n',
      0,
    ],
    [
      'a comment line above the next item of a list in a list',
      'l:\n  - - 1 # one\n    # about two\n    - 2\n  - 3\n',
      { op: 'delete', path: ['l', 0, 0] },
      'l:\n  - # about two\n    - 2\n  - 3\n',
      1,
    ],
    [
      'line breaks of two characters',
      'l:\r\n  - a: 1 # one\r\n    # about b\r\n    b: 2\r\n  - c: 3\r\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\r\n  - # about b\r\n    b: 2\r\n  - c: 3\r\n',
      1,
    ],
    [
      'a list in a list',
      'l:\n  - - 1\n    - 2\n  - 3\n',
      { op: 'delete', path: ['l', 0, 0] },
      'l:\n  - - 2\n  - 3\n',
      0,
    ],
    [
      'comment lines before the item and before the next item stay',
      'g:\n  s:\n    # group A\n    - r: rule-a\n      p: a.py\n    # group B\n    - r: rule-b\n      p: b.py\n',
      { op: 'delete', path: ['g', 's', 1, 'r'] },
      'g:\n  s:\n    # group A\n    - r: rule-a\n      p: a.py\n    # group B\n    - p: b.py\n',
      0,
    ],
  ];
  for (const [name, text, edit, after, dropped] of cases) {
    const result = patch(text, edit);
    assert.equal(result.how, 'patch', name);
    assert.equal(result.text, after, name);
    assert.equal(result.droppedComments, dropped, name);
  }
});

test('the only child of a parent leaves an empty collection after the parent key, and the comments around it stay', () => {
  const cases = [
    [
      'a comment on the parent key',
      'scanners:\n  bandit: # keep bandit strict\n    enabled: false\n',
      { op: 'delete', path: ['scanners', 'bandit', 'enabled'] },
      'scanners:\n  bandit: {} # keep bandit strict\n',
      0,
    ],
    [
      'a comment line above the child',
      'scanners:\n  bandit:\n    # about enabled\n    enabled: false\nother: 1\n',
      { op: 'delete', path: ['scanners', 'bandit', 'enabled'] },
      'scanners:\n  bandit: {}\n    # about enabled\nother: 1\n',
      0,
    ],
    [
      'the last item of a list whose key has a comment',
      'suppressions: # reviewed quarterly\n  - id: a\n    path: a.py\nother: 1\n',
      { op: 'delete', path: ['suppressions', 0] },
      'suppressions: [] # reviewed quarterly\nother: 1\n',
      0,
    ],
    [
      'a comment after the dash of the item',
      'l:\n  - # about a\n    a: 1\n  - c: 3\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - {} # about a\n  - c: 3\n',
      0,
    ],
    [
      'the only key of an item that shares its line with the dash',
      'l:\n  - a: 1 # one\n  - c: 3\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - {} # one\n  - c: 3\n',
      0,
    ],
    [
      'a comment of the child itself goes with it',
      'a:\n  b: 1 # note\nz: 2\n',
      { op: 'delete', path: ['a', 'b'] },
      'a: {}\nz: 2\n',
      1,
    ],
    ['the only key of the file', '# header\na: 1\n', { op: 'delete', path: ['a'] }, '# header\n{}\n', 0],
    [
      'a last line with no break after it',
      'a: # note\n  b: 1',
      { op: 'delete', path: ['a', 'b'] },
      'a: {} # note',
      0,
    ],
    [
      'line breaks of two characters',
      'a: # note\r\n  b: 1\r\nz: 2\r\n',
      { op: 'delete', path: ['a', 'b'] },
      'a: {} # note\r\nz: 2\r\n',
      0,
    ],
  ];
  for (const [name, text, edit, after, dropped] of cases) {
    const result = patch(text, edit);
    assert.equal(result.how, 'patch', name);
    assert.equal(result.text, after, name);
    assert.equal(result.droppedComments, dropped, name);
    assert.equal(readYaml(result.text).ok, true, name);
  }
});

test('a plain string with a question mark is quoted inside a flow list, where PyYAML ends a plain scalar at it', () => {
  const result = patch('paths: [a, b] # note\n', { op: 'set', path: ['paths', 1], value: 'src/a?.py' });
  assert.equal(result.how, 'patch');
  assert.equal(result.text, 'paths: [a, "src/a?.py"] # note\n');
  assert.equal(readYaml(result.text).ok, true);
});

test('a block-only path is written again as the list item that holds the edit, never as the list', () => {
  const text = 'g:\n  items:\n    # first\n    - a: 1\n      b: 2\n    # second\n    - a: 3\n      b: 4\n';
  const result = reemit(text, { op: 'delete', path: ['g', 'items', 1, 'a'] });
  assert.equal(result.ok, true);
  assert.equal(result.label, 'g.items[1]');
  assert.equal(
    result.text,
    'g:\n  items:\n    # first\n    - a: 1\n      b: 2\n    # second\n    - b: 4\n',
  );
  assert.equal(result.droppedComments, 0);
});

test('writing an entry again names it and counts the comments it held', () => {
  const text = 'scanners:\n  checkov:\n    # note\n    a: [1, 2] # inline\n    b: 2\nother: 1\n';
  const result = reemit(text, { op: 'append', path: ['scanners', 'checkov', 'a'], value: 3 });
  assert.deepEqual(result, {
    ok: true,
    how: 'reemit',
    text: 'scanners:\n  checkov:\n    # note\n    a:\n      - 1\n      - 2\n      - 3\n    b: 2\nother: 1\n',
    droppedComments: 1,
    label: 'scanners.checkov.a',
  });
});

test('a block-only path is written again as the entry the edit changes, or the one that holds a deleted entry', () => {
  const text = 'scanners:\n  checkov:\n    # note\n    a: 1\n    b: 2\nother: 1\n';
  const set = reemit(text, { op: 'set', path: ['scanners', 'checkov', 'a'], value: 5 });
  assert.equal(set.label, 'scanners.checkov.a');
  assert.equal(set.text, 'scanners:\n  checkov:\n    # note\n    a: 5\n    b: 2\nother: 1\n');
  assert.equal(set.droppedComments, 0);
  const created = reemit(text, { op: 'set', path: ['scanners', 'checkov', 'c'], value: 3 });
  assert.equal(created.label, 'scanners.checkov');
  assert.equal(created.text, 'scanners:\n  checkov:\n    a: 1\n    b: 2\n    c: 3\nother: 1\n');
  assert.equal(created.droppedComments, 1);
  const deleted = reemit(text, { op: 'delete', path: ['scanners', 'checkov', 'a'] });
  assert.equal(deleted.label, 'scanners.checkov');
  assert.equal(deleted.text, 'scanners:\n  checkov:\n    b: 2\nother: 1\n');
  const top = reemit(text, { op: 'delete', path: ['other'] });
  assert.equal(top.ok, false);
  assert.equal(top.final, false);
});

test('an edit may reach the lines of the smallest block that holds it, and no further', () => {
  const text = 'a:\n  - x: 1\n    y: 2\n  # next\n  - x: 3\n    y: 4\nb: [1]\n';
  const lines = text.split('\n');
  const start = (line) => lines.slice(0, line).join('\n').length + (line > 0 ? 1 : 0);
  const bound = (edit) => editBound(readYaml(text), edit);
  // A key of an item: its own lines, with the line breaks before and after.
  assert.deepEqual(bound({ op: 'set', path: ['a', 1, 'y'], value: 5 }), [start(5) - 1, start(6)]);
  // The first key of an item is deleted from the item, which holds the dash line too.
  assert.deepEqual(bound({ op: 'delete', path: ['a', 1, 'x'] }), [start(4) - 1, start(6)]);
  // A whole item is deleted from the list's entry.
  assert.deepEqual(bound({ op: 'delete', path: ['a', 1] }), [start(0), start(6)]);
  // Inside a flow collection the block is the entry that holds it.
  assert.deepEqual(bound({ op: 'append', path: ['b'], value: 2 }), [start(6) - 1, start(7)]);
  // A new top-level key may go anywhere at the end of the file, so there is no bound.
  assert.equal(bound({ op: 'set', path: ['c'], value: 1 }), null);
  assert.equal(editBound(readYaml('{a: 1}\n'), { op: 'set', path: ['b'], value: 1 }), null);
  assert.equal(editBound(readYaml('a: [\n'), { op: 'set', path: ['a'], value: 1 }), null);
});

test('a flow document is written again as a whole', () => {
  const result = reemit('{a: 1}\n', { op: 'set', path: ['b'], value: 2 });
  assert.equal(result.ok, true);
  assert.equal(result.text, 'a: 1\nb: 2\n');
  assert.equal(result.label, 'the top level');
});

test('an entry that holds a repeated key is not written again', () => {
  const result = reemit('s:\n  a: 1\n  a: 2\n', { op: 'set', path: ['s'], value: 1 });
  assert.equal(result.ok, false);
  assert.equal(result.final, true);
  assert.equal(result.reason, 'duplicate-key');
});
