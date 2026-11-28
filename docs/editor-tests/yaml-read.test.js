// Tests for the configuration editor's YAML reader: the values it builds, the
// positions and styles it keeps for the patcher, and the inputs it refuses.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_BYTES, mappingPairs, readYaml } from '../content/assets/javascripts/config-editor/yaml-read.js';
import { Float, Reference, Timestamp, TypedMap } from '../content/assets/javascripts/config-editor/yaml-scalars.js';

function read(text) {
  const doc = readYaml(text);
  assert.ok(doc.ok, `the reader refused: ${doc.refusal && doc.refusal.message}`);
  return doc;
}

function refusal(text) {
  const doc = readYaml(text);
  assert.equal(doc.ok, false, 'the reader read a text it should refuse');
  const { code, line, column } = doc.refusal;
  return { code, line, column };
}

test('a block document gives its offsets, lines, styles and indentation', () => {
  const text = "a: 1\nb:\n  - x\n  - y # why\nc: 'q'\n";
  const doc = read(text);
  assert.equal(doc.root.kind, 'map');
  assert.equal(doc.root.style, 'block');
  assert.equal(doc.root.indent, 0);
  const [a, b, c] = doc.root.entries;
  assert.equal(a.key.text, 'a');
  assert.equal(a.colon, 1);
  assert.equal(a.value.type, 'int');
  assert.equal(a.value.value, 1);
  assert.deepEqual([a.start, a.end], [0, 4]);
  assert.equal(b.value.kind, 'seq');
  assert.equal(b.value.indent, 2);
  assert.equal(b.value.items.length, 2);
  assert.deepEqual(
    b.value.items.map((item) => [item.text, item.dash, item.dashEnd, item.dashColumn]),
    [
      ['x', 10, 11, 2],
      ['y', 16, 17, 2],
    ],
  );
  assert.equal(b.end, 19);
  assert.equal(c.value.style, 'single');
  assert.equal(text.slice(c.value.start, c.value.end), "'q'");
  assert.equal(c.value.text, 'q');
  assert.deepEqual(doc.lineStarts, [0, 5, 8, 14, 26, 33]);
  assert.equal(doc.newline, '\n');
  assert.deepEqual(doc.style, { indent: 2, seq: 'indented' });
});

test('every comment is recorded with its range, the modeline and block scalar headers included', () => {
  const text = '# yaml-language-server: $schema=x\na: 1 # one\nb: |  # block\n  t\n';
  const doc = read(text);
  assert.deepEqual(
    doc.comments.map((comment) => text.slice(comment.start, comment.end)),
    ['# yaml-language-server: $schema=x', '# one', '# block'],
  );
  assert.deepEqual(
    doc.comments.map((comment) => comment.line),
    [0, 1, 2],
  );
});

test('plain scalars are typed as ASH reads them and references stay tokens', () => {
  const doc = read(
    'n: 3\nf: 1.5\nb: yes\nz: ~\ns: text\nd: 2026-12-31\nr: ${HOME:x}\nq: !ENV ${A}\n',
  );
  const { value } = doc;
  assert.equal(value.n, 3);
  assert.equal(value.f, 1.5);
  assert.equal(value.b, true);
  assert.equal(value.z, null);
  assert.equal(value.s, 'text');
  assert.ok(value.d instanceof Timestamp);
  assert.equal(value.d.iso, '2026-12-31');
  assert.ok(value.r instanceof Reference);
  assert.equal(value.r.text, '${HOME:x}');
  assert.equal(value.r.explicit, false);
  assert.ok(value.q instanceof Reference);
  assert.equal(value.q.text, '${A}');
  assert.equal(value.q.explicit, true);
});

test('flow collections are read, and keep their style', () => {
  const doc = read('a: [1, two, {k: v}]\nb: {x: 1, y: [2, 3]}\n');
  assert.deepStrictEqual(doc.value, { a: [1, 'two', { k: 'v' }], b: { x: 1, y: [2, 3] } });
  const [a, b] = doc.root.entries;
  assert.equal(a.value.style, 'flow');
  assert.equal(a.value.items.length, 3);
  assert.equal(b.value.style, 'flow');
  assert.equal(doc.text.slice(b.value.start, b.value.end), '{x: 1, y: [2, 3]}');
});

test('block scalars end at their last content line', () => {
  const text = 'a: |\n  one\n  two\nb: >-\n  x\n  y\nc: |+\n  z\n\nd: 1\n';
  const doc = read(text);
  assert.deepStrictEqual(doc.value, { a: 'one\ntwo\n', b: 'x y', c: 'z\n\n', d: 1 });
  const [a, b, c] = doc.root.entries;
  assert.equal(text.slice(a.value.start, a.value.end), '|\n  one\n  two');
  assert.equal(text.slice(b.value.start, b.value.end), '>-\n  x\n  y');
  assert.equal(text.slice(c.value.start, c.value.end), '|+\n  z');
  assert.equal(a.value.style, 'literal');
  assert.equal(b.value.style, 'folded');
});

test('quoted and multi-line scalars are folded and unescaped as PyYAML does', () => {
  const doc = read('a: "t\\tab \\x41"\nb: \'it\'\'s\'\nc: one\n  two\n\n  three\n');
  assert.deepStrictEqual(doc.value, { a: 't\tab A', b: "it's", c: 'one two\nthree' });
});

test('an anchor nothing uses is kept on the node, and an empty tagged value is read', () => {
  const doc = read('a: &x 1\nb: 2\nc: !!str\nd: !ENV\n');
  assert.equal(doc.root.entries[0].value.anchor, 'x');
  assert.equal(doc.text.slice(doc.root.entries[0].value.start, doc.root.entries[0].value.end), '&x 1');
  assert.equal(doc.value.a, 1);
  assert.equal(doc.value.c, '');
  assert.ok(doc.value.d instanceof Reference);
  assert.equal(doc.value.d.text, '');
  assert.equal(doc.value.d.explicit, true);
});

test('the indentation unit, the list style and the line ending are detected', () => {
  assert.equal(read('a:\n    b: 1\n').style.indent, 4);
  const indentless = read('list:\n- a\n- b\n');
  assert.equal(indentless.style.seq, 'indentless');
  const list = indentless.root.entries[0].value;
  assert.equal(list.indent, 0);
  assert.equal(list.indentless, true);
  assert.equal(list.items[0].dashColumn, 0);
  const crlf = read('a: 1\r\nb: 2\r\n');
  assert.equal(crlf.newline, '\r\n');
  assert.deepStrictEqual(crlf.value, { a: 1, b: 2 });
  assert.deepEqual(crlf.lineStarts, [0, 6, 12]);
  assert.equal(crlf.root.entries[0].end, 4);
});

test('a repeated key keeps the last value, warns, and locks both entries', () => {
  const doc = read('a: 1\nb: 2\na: 3\n');
  assert.deepStrictEqual(doc.value, { a: 3, b: 2 });
  assert.equal(doc.warnings.length, 1);
  assert.equal(doc.warnings[0].code, 'duplicate-key');
  assert.equal(doc.warnings[0].line, 3);
  assert.equal(doc.warnings[0].firstLine, 1);
  const [first, second, third] = doc.root.entries;
  assert.equal(first.locked, 'duplicate-key');
  assert.equal(third.locked, 'duplicate-key');
  assert.equal(second.locked, undefined);
});

test('a merge key puts its pairs first, and locks the mapping that holds it', () => {
  const doc = read('d:\n  <<: {x: 9}\n  z: 3\n');
  assert.deepStrictEqual(doc.value, { d: { x: 9, z: 3 } });
  assert.equal(doc.root.entries[0].value.locked, 'merge-key');
  assert.equal(doc.warnings.length, 1);
  assert.equal(doc.warnings[0].code, 'merge-key');
  assert.match(doc.warnings[0].message, /the keys x come from a merge key/);
  assert.equal(doc.warnings[0].line, 2);
  const list = read('d:\n  <<: [{x: 1}, {x: 2, y: 3}]\n');
  assert.deepStrictEqual(list.value, { d: { x: 1, y: 3 } });
  const pairs = mappingPairs(doc.root.entries[0].value, () => {
    throw new Error('no failure expected');
  });
  assert.deepEqual(
    pairs.map(([key]) => key.text),
    ['x', 'z'],
  );
});

test('an equals sign is a key as text, and a refusal as a value', () => {
  assert.deepStrictEqual(read('=: 1\n').value, { '=': 1 });
  assert.deepEqual(refusal('a: =\n'), { code: 'constructor', line: 1, column: 4 });
});

test('a key called __proto__ is data and changes nothing else', () => {
  const doc = read('__proto__: 1\nb: 2\n');
  assert.equal(Object.keys(doc.value).length, 2);
  assert.equal(Object.getPrototypeOf(doc.value), Object.prototype);
  assert.equal(doc.value.polluted, undefined);
});

test('the value tree names a key by what it resolves to, not by how it is written', () => {
  const quoted = read('"1": a\n1: b\n');
  assert.ok(quoted.value instanceof TypedMap);
  assert.deepStrictEqual(quoted.value.pairs, [['1', 'a'], [1, 'b']]);
  assert.deepStrictEqual(quoted.typed.pairs, [['1', 'a'], [1, 'b']]);
  assert.equal(quoted.warnings.length, 0);

  const words = read('yes: a\ntrue: b\nOn: c\n');
  assert.deepStrictEqual(words.value.pairs, [[true, 'c']]);
  assert.equal(words.warnings.filter((warning) => warning.code === 'duplicate-key').length, 2);
  // The key written again is its last writing, so the entry moves after x and is true.
  assert.deepStrictEqual(read('1: a\nx: b\ntrue: c\n').value.pairs, [['x', 'b'], [true, 'c']]);

  const mixed = read('m: {null: a, on: b, 7: c, 1.5: d, x: e}\n');
  assert.deepStrictEqual(mixed.value.m.pairs, [[null, 'a'], [true, 'b'], [7, 'c'], [1.5, 'd'], ['x', 'e']]);
  assert.deepStrictEqual(mixed.typed.m.pairs[3], [new Float(1.5), 'd']);

  const date = read('2026-12-31: a\n');
  assert.ok(date.value instanceof TypedMap);
  assert.ok(date.value.pairs[0][0] instanceof Timestamp);
  assert.equal(date.value.pairs[0][0].iso, '2026-12-31');

  const reference = read('${KEY}: a\n"${KEY}": b\n');
  assert.equal(reference.value.pairs.length, 2);
  assert.ok(reference.value.pairs[0][0] instanceof Reference);
  assert.equal(reference.value.pairs[1][0], '${KEY}');
  assert.equal(reference.warnings.length, 0);

  // A mapping whose keys are all strings stays a plain object, with a text key such as
  // a dollar sign or an equals sign among them.
  assert.deepStrictEqual(read('$a: 1\n"2": 2\n=: 3\n').value, { $a: 1, 2: 2, '=': 3 });
});

test('the typed tree keeps a float apart from an integer, and the value tree reads both as numbers', () => {
  const doc = read('a: 1.0\nb: 1\nc: [2.5, 3]\nd: !!float 7\ne: .inf\nf: 12345678901234567890123\n');
  assert.ok(doc.typed.a instanceof Float);
  assert.equal(doc.typed.a.value, 1);
  assert.equal(doc.typed.b, 1);
  assert.ok(doc.typed.c[0] instanceof Float);
  assert.equal(doc.typed.c[1], 3);
  assert.ok(doc.typed.d instanceof Float);
  assert.ok(doc.typed.e instanceof Float);
  assert.equal(doc.typed.f, 12345678901234567890123n);
  assert.deepStrictEqual(doc.value, {
    a: 1,
    b: 1,
    c: [2.5, 3],
    d: 7,
    e: Infinity,
    f: 12345678901234567890123n,
  });
  const keyed = read('1.5: a\n2: b\n');
  assert.deepStrictEqual(keyed.typed.pairs, [[new Float(1.5), 'a'], [2, 'b']]);
  assert.deepStrictEqual(keyed.value.pairs, [[1.5, 'a'], [2, 'b']]);
});

test('an integer beyond 2**53 is read with every digit, and the integers either side of it stay apart', () => {
  const doc = read(
    [
      'a: 9007199254740991',
      'b: 9007199254740992',
      'c: 9007199254740993',
      'd: -9007199254740993',
      'e: 9_007_199_254_740_993',
      'f: 0x20000000000001',
      'g: !!int 9007199254740993',
      'h: 9007199254740992.0',
      '',
    ].join('\n'),
  );
  // 9007199254740991 is the largest integer a number holds exactly; every integer past
  // it is a BigInt, in whatever way the file spells it.
  assert.equal(doc.typed.a, 9007199254740991);
  assert.equal(doc.typed.b, 9007199254740992n);
  assert.equal(doc.typed.c, 9007199254740993n);
  assert.equal(doc.typed.d, -9007199254740993n);
  assert.equal(doc.typed.e, 9007199254740993n);
  assert.equal(doc.typed.f, 9007199254740993n);
  assert.equal(doc.typed.g, 9007199254740993n);
  assert.notEqual(doc.typed.b, doc.typed.c);
  // The float of the same value as b is a float, not that integer.
  assert.ok(doc.typed.h instanceof Float);
  assert.equal(doc.typed.h.value, 2 ** 53);
  // What the page reads holds the same integers, never a rounded number.
  for (const name of ['b', 'c', 'd', 'e', 'f', 'g']) {
    assert.equal(typeof doc.value[name], 'bigint', name);
    assert.equal(doc.value[name], doc.typed[name], name);
  }
});

test('keys beyond 2**53 are two keys, and the integer key and the float key of one value are one key', () => {
  const doc = read('9007199254740993: a\n9007199254740992: b\n9007199254740992.0: c\n');
  assert.ok(doc.typed instanceof TypedMap);
  // An integer and a float of one value are one key, and ASH's loader keeps the last
  // writing of a key whole: its spelling (the float) and its value.
  assert.deepStrictEqual(doc.typed.pairs, [
    [9007199254740993n, 'a'],
    [new Float(2 ** 53), 'c'],
  ]);
  const placed = read('1: a\nx: b\n1.0: c\n');
  assert.deepStrictEqual(placed.typed.pairs, [
    ['x', 'b'],
    [new Float(1), 'c'],
  ]);
});

test('the empty and comment-only documents have no root', () => {
  for (const text of ['', '# only a comment\n', '\n\n  \n', '---\n']) {
    const doc = read(text);
    assert.equal(doc.root, null, JSON.stringify(text));
    assert.equal(doc.typed, null, JSON.stringify(text));
    assert.equal(doc.value, null, JSON.stringify(text));
  }
});

test('an alias is refused where it is written, in ASH words', () => {
  const doc = readYaml('a: &x 1\nb: *x\n');
  assert.equal(doc.ok, false);
  assert.deepEqual(
    { code: doc.refusal.code, line: doc.refusal.line, column: doc.refusal.column },
    { code: 'alias', line: 2, column: 4 },
  );
  assert.match(doc.refusal.message, /ASH configuration does not accept YAML aliases/);
});

test('an anchor written twice is refused at its second writing, as PyYAML refuses it', () => {
  const cases = [
    ['two scalars', 'a: &x 1\nb: &x 2\n', { code: 'anchor', line: 2, column: 4 }],
    ['two collections', 'a: &x {k: 1}\nb: &x [1]\n', { code: 'anchor', line: 2, column: 4 }],
    ['a scalar and a list item', 'a: &x 1\nl:\n  - &x 2\n', { code: 'anchor', line: 3, column: 5 }],
    ['an anchor after a tag', 'a: &x 1\nb: !!str &x two\n', { code: 'anchor', line: 2, column: 4 }],
    ['a tag before an anchor', 'a: !!str &x one\nb: &x 2\n', { code: 'anchor', line: 2, column: 4 }],
  ];
  for (const [name, text, expected] of cases) {
    assert.deepEqual(refusal(text), expected, name);
  }
  assert.match(readYaml('a: &x 1\nb: &x 2\n').refusal.message, /found duplicate anchor 'x'/);
  // Different names, and the same name in a text that is not a second writing, read as before.
  assert.ok(readYaml('a: &x 1\nb: &y 2\n').ok);
  assert.ok(readYaml('a: "&x"\nb: &x 2\n').ok);
});

test('the inputs the editor will not read are refused with a code, a line and a column', () => {
  const cases = [
    ['a second document', 'a: 1\n---\nb: 2\n', { code: 'second-document', line: 2, column: 1 }],
    ['an unknown tag', 'a: !custom x\n', { code: 'tag', line: 1, column: 4 }],
    ['a complex key', '? a\n: b\n', { code: 'complex-key', line: 1, column: 1 }],
    ['a directive', '%YAML 1.2\n---\na: 1\n', { code: 'directive', line: 1, column: 1 }],
    ['a tab for indentation', 'a:\n\tb: 1\n', { code: 'tab', line: 2, column: 1 }],
    ['a control character', `a: 1\n${String.fromCharCode(0)}`, { code: 'character', line: 2, column: 1 }],
    ['a merge of a scalar', 'a:\n  <<: 5\n', { code: 'merge', line: 2, column: 7 }],
    ['an unclosed flow sequence', 'a: [1, 2\n', { code: 'syntax', line: 2, column: 1 }],
  ];
  for (const [name, text, expected] of cases) {
    assert.deepEqual(refusal(text), expected, name);
  }
});

test('a text over 2 MiB is refused before it is read', () => {
  const big = `a: ${'x'.repeat(MAX_BYTES)}`;
  assert.deepEqual(refusal(big), { code: 'too-large', line: 1, column: 1 });
  assert.ok(readYaml(`a: ${'x'.repeat(1000)}`).ok);
});

test('a column counts characters, not UTF-16 units', () => {
  const emoji = String.fromCodePoint(0x1f600);
  assert.deepEqual(refusal(`[${emoji}, *x]`), { code: 'alias', line: 1, column: 5 });
});

test('a refusal leaves no nodes behind', () => {
  const doc = readYaml('a: &x 1\nb: *x\n');
  assert.equal(doc.root, null);
  assert.equal(doc.typed, undefined);
  assert.equal(doc.value, undefined);
});
