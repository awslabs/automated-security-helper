// Tests for the configuration editor's YAML writer: how values become text, and
// the text changes it proposes for an edit.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readYaml } from '../content/assets/javascripts/config-editor/yaml-read.js';
import { Reference, Timestamp, resolvePlain } from '../content/assets/javascripts/config-editor/yaml-scalars.js';
import {
  applyToValue,
  emitBlock,
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
  ];
  for (const [number, text] of cases) {
    assert.equal(formatNumber(number), text);
  }
  for (const number of [1.5, 1e-7, 1.5e300, 0.1, 123456.789, -3, 1e21]) {
    assert.equal(Number(resolvePlain(formatNumber(number)).value), number, String(number));
  }
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

test('what the emitter writes reads back as the same value', () => {
  const value = {
    name: 'x y',
    flag: false,
    nothing: null,
    quoted: ['yes', '0755', '', 'k: v', 'a #b'],
    nested: { n: 3, f: 1.5, ref: new Reference('${HOME:x}', true), list: [{ a: 1, b: [2] }, {}] },
    'odd key': 'v',
  };
  const doc = readYaml(`${emitBlock(value)}\n`);
  assert.ok(doc.ok, doc.refusal && doc.refusal.message);
  assert.equal(sameValue(value, doc.value), true);
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
      'comments between the two keys go with it',
      'l:\n  - a: 1 # one\n    # about b\n    b: 2\n  - c: 3\n',
      { op: 'delete', path: ['l', 0, 'a'] },
      'l:\n  - b: 2\n  - c: 3\n',
      2,
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
      'g:\n  s:\n    # group A\n    - r: X1\n      p: a.py\n    # group B\n    - r: X2\n      p: b.py\n',
      { op: 'delete', path: ['g', 's', 1, 'r'] },
      'g:\n  s:\n    # group A\n    - r: X1\n      p: a.py\n    # group B\n    - p: b.py\n',
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
  const text = 'scanners:\n  checkov:\n    # note\n    a: 1\n    b: 2\nother: 1\n';
  const result = reemit(text, { op: 'set', path: ['scanners', 'checkov', 'a'], value: 5 });
  assert.deepEqual(result, {
    ok: true,
    how: 'reemit',
    text: 'scanners:\n  checkov:\n    a: 5\n    b: 2\nother: 1\n',
    droppedComments: 1,
    label: 'scanners.checkov',
  });
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
