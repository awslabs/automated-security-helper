// Tests for how a plain YAML scalar is read and written: PyYAML's YAML 1.1
// resolution rules, ASH's environment reference, and the rule for writing a string
// so that both a YAML 1.1 and a YAML 1.2 reader get the same text back.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  Reference,
  ScalarError,
  Timestamp,
  constructTagged,
  matchReference,
  plainSafe,
  plainSyntaxOk,
  quoteDouble,
  quoteSingle,
  readingsDiffer,
  resolvePlain,
  utf8Length,
  yaml12Type,
} from '../content/assets/javascripts/config-editor/yaml-scalars.js';

const RESOLUTION = [
  // Booleans: the 1.1 words, in the three letter cases PyYAML lists.
  ['yes', 'bool', true],
  ['No', 'bool', false],
  ['ON', 'bool', true],
  ['off', 'bool', false],
  ['true', 'bool', true],
  ['False', 'bool', false],
  ['y', 'str', 'y'],
  ['n', 'str', 'n'],
  ['tRue', 'str', 'tRue'],
  // Nulls.
  ['~', 'null', null],
  ['null', 'null', null],
  ['Null', 'null', null],
  ['NULL', 'null', null],
  ['', 'null', null],
  // Integers: decimal, signs, underscores, octal, hex, binary, base 60.
  ['0', 'int', 0],
  ['42', 'int', 42],
  ['-17', 'int', -17],
  ['+5', 'int', 5],
  ['1_000', 'int', 1000],
  ['0755', 'int', 493],
  ['0x1F', 'int', 31],
  ['0b101', 'int', 5],
  ['1:30', 'int', 90],
  ['-1:30:00', 'int', -5400],
  ['0o17', 'str', '0o17'],
  ['08', 'str', '08'],
  ['0:30', 'str', '0:30'],
  // Floats: a dot is needed, and an exponent needs its sign.
  ['1.5', 'float', 1.5],
  ['.5', 'float', 0.5],
  ['1.', 'float', 1],
  ['-2.50', 'float', -2.5],
  ['1.5e+3', 'float', 1500],
  ['1:30.5', 'float', 90.5],
  ['.inf', 'float', Infinity],
  ['-.inf', 'float', -Infinity],
  ['1e3', 'str', '1e3'],
  ['1.5e3', 'str', '1.5e3'],
  // The merge key and the value indicator keep their own types.
  ['<<', 'merge', '<<'],
  ['=', 'value', '='],
  // A reference is a type of its own; everything else is text.
  ['${HOME}', 'env', '${HOME}'],
  ['hello', 'str', 'hello'],
  ['hello world', 'str', 'hello world'],
  ['x${HOME}', 'str', 'x${HOME}'],
];

for (const [text, type, value] of RESOLUTION) {
  test(`a plain ${JSON.stringify(text)} is read as ${type}`, () => {
    const found = resolvePlain(text);
    assert.equal(found.type, type);
    assert.equal(found.value, value);
  });
}

test('.nan is a float that is not a number', () => {
  const found = resolvePlain('.NaN');
  assert.equal(found.type, 'float');
  assert.ok(Number.isNaN(found.value));
});

test('an integer past 2**53 keeps its digits as a BigInt', () => {
  const found = resolvePlain('12345678901234567890123');
  assert.equal(found.type, 'int');
  assert.equal(found.exact, false);
  assert.equal(found.digits, '12345678901234567890123');
  assert.equal(found.value, 12345678901234567890123n);
  assert.equal(resolvePlain('9007199254740991').exact, true);
  assert.equal(resolvePlain('9007199254740992').exact, false);
});

test('dates and times keep the ISO text a Python reader gives', () => {
  const cases = [
    ['2026-12-31', 'date', '2026-12-31'],
    ['2026-12-31T10:20:30Z', 'datetime', '2026-12-31T10:20:30+00:00'],
    ['2026-12-31 10:20:30.5', 'datetime', '2026-12-31T10:20:30.500000'],
    ['2026-12-31t10:20:30+05:30', 'datetime', '2026-12-31T10:20:30+05:30'],
  ];
  for (const [text, kind, iso] of cases) {
    const found = resolvePlain(text);
    assert.equal(found.type, 'timestamp', text);
    assert.ok(found.value instanceof Timestamp, text);
    assert.equal(found.value.kind, kind, text);
    assert.equal(found.value.iso, iso, text);
  }
});

test('a date or time that does not exist is an error where the loader fails', () => {
  for (const text of ['2026-13-01', '2026-02-30', '2026-12-31 25:00:00']) {
    assert.throws(() => resolvePlain(text), ScalarError, text);
  }
});

test('a value of a core tag is built from its text as written', () => {
  assert.deepEqual(constructTagged('int', '0x10'), { type: 'int', value: 16, digits: '16', exact: true });
  assert.deepEqual(constructTagged('float', '1'), { type: 'float', value: 1 });
  assert.deepEqual(constructTagged('bool', 'Yes'), { type: 'bool', value: true });
  assert.deepEqual(constructTagged('null', 'anything'), { type: 'null', value: null });
  assert.deepEqual(constructTagged('str', '0755'), { type: 'str', value: '0755' });
});

test('a core tag whose text cannot be built is an error', () => {
  assert.throws(() => constructTagged('int', 'abc'), ScalarError);
  assert.throws(() => constructTagged('int', '1.5'), ScalarError);
  assert.throws(() => constructTagged('float', 'abc'), ScalarError);
  assert.throws(() => constructTagged('bool', 'maybe'), ScalarError);
  assert.throws(() => constructTagged('seq', 'x'), ScalarError);
});

test('an explicit float tag takes the text Python float() takes, and nothing else', () => {
  const accepted = [
    ['inf', Infinity],
    ['+inf', Infinity],
    ['-Infinity', -Infinity],
    [' 1.5 ', 1.5],
    ['1_0.5', 10.5],
    ['1e3', 1000],
    ['--1', 1],
    ['+.5', 0.5],
    ['1:30', 90],
    ['7', 7],
    ['1.e+2', 100],
  ];
  for (const [text, value] of accepted) {
    const found = constructTagged('float', text);
    assert.equal(found.type, 'float', text);
    assert.equal(found.value, value, text);
  }
  assert.ok(Number.isNaN(constructTagged('float', 'NaN').value));
  assert.ok(Number.isNaN(constructTagged('float', '-nan').value));
  assert.ok(Object.is(constructTagged('float', '-0').value, -0));
  for (const text of ['0x10', '', '-', '_', '+', '1e', '.', 'e5', '1.5.2', 'infinit', '1 2', '0b1', '0o7']) {
    assert.throws(() => constructTagged('float', text), ScalarError, JSON.stringify(text));
  }
});

test('an explicit integer tag takes the text Python int() takes, and nothing else', () => {
  const arabicIndic = String.fromCodePoint(0x661, 0x662);
  const fullwidth = String.fromCodePoint(0xff11, 0xff12);
  const accepted = [
    [' 12', 12],
    ['0o17', 15],
    [arabicIndic, 12],
    [fullwidth, 12],
    ['--5', 5],
    ['0x 1f', 31],
    ['0x-1f', -31],
    ['-0x1f', -31],
    ['0b11', 3],
    ['1:30', 90],
    ['0755', 493],
    ['1_000', 1000],
    ['+7', 7],
    ['-0', 0],
  ];
  for (const [text, value] of accepted) {
    const found = constructTagged('int', text);
    assert.equal(found.type, 'int', JSON.stringify(text));
    assert.equal(found.value, value, JSON.stringify(text));
  }
  for (const text of ['', '0x', '0b', '0b2', '08', '0o8', '1.5', '1 2', '0x1g', 'abc', '_', ' ', '-', '1:', ':1']) {
    assert.throws(() => constructTagged('int', text), ScalarError, JSON.stringify(text));
  }
});

test('a question mark ends a plain scalar inside a flow collection, so it is not written plain there', () => {
  assert.equal(plainSafe('src/a?.py'), true);
  assert.equal(plainSafe('src/a?.py', true), false);
  assert.equal(plainSyntaxOk('a?b', true), false);
  assert.equal(plainSyntaxOk('a?b'), true);
});

test('a reference is recognized by its start, as ASH recognizes it', () => {
  assert.deepEqual(matchReference('${HOME}'), { name: 'HOME', colon: false, head: '${HOME}' });
  assert.deepEqual(matchReference('${HOME:default}'), {
    name: 'HOME',
    colon: true,
    head: '${HOME:default}',
  });
  assert.equal(matchReference('${HOME} and more').head, '${HOME}');
  assert.equal(matchReference('${ÄB}').name, 'ÄB');
});

test('text that only looks like a reference is not one', () => {
  for (const text of ['x${HOME}', '${}', '$HOME', '${HOME', '$ {HOME}', '']) {
    assert.equal(matchReference(text), null, text);
  }
});

test('a YAML 1.2 reader reads the same scalars another way', () => {
  assert.equal(yaml12Type('on'), 'str');
  assert.equal(yaml12Type('true'), 'bool');
  assert.equal(yaml12Type('0755'), 'int');
  assert.equal(yaml12Type('0o17'), 'int');
  assert.equal(yaml12Type('1e3'), 'float');
  assert.equal(yaml12Type('.5'), 'float');
  assert.equal(yaml12Type('~'), 'null');
  assert.equal(yaml12Type('2026-12-31'), 'str');
  assert.equal(yaml12Type('1:30'), 'str');
});

test('the two readings differ for on, 0755, 1e3 and a date, and agree for text and 755', () => {
  for (const text of ['on', 'yes', '0755', '1e3', '2026-12-31', '1:30']) {
    assert.equal(readingsDiffer(text), true, text);
  }
  for (const text of ['hello', '755', 'true', '~', '0x1F', '${HOME}', '1.5']) {
    assert.equal(readingsDiffer(text), false, text);
  }
});

test('a string is written plain only when both readings give back the same text', () => {
  for (const text of ['hello', 'a b', 'x-y', '3 apples', 'http://example.com', 'path/to/file.py', 'α']) {
    assert.equal(plainSafe(text), true, text);
  }
});

test('a string that either reading would change is not written plain', () => {
  const unsafe = [
    '', 'yes', 'No', 'on', 'null', '~', '0755', '1:30', '42', '1.5', '1e3', '2026-12-31', 'true',
    'k: v', 'x #y', '- x', '?x', ': x', 'a:', ' lead', 'trail ', '#c', '&a', '*a', '!t', '|x', '>x',
    "'q", '"q', '%d', '@a', '`b', '[a]', '{a}', ',a', '---x', '...', 'tab\there', 'line\nbreak',
    '${HOME}', '=', '<<', '.inf', '2026-13-01',
  ];
  for (const text of unsafe) {
    assert.equal(plainSafe(text), false, JSON.stringify(text));
  }
});

test('inside a flow collection the flow indicators are not safe either', () => {
  assert.equal(plainSafe('a,b'), true);
  assert.equal(plainSafe('a,b', true), false);
  assert.equal(plainSafe('a]', true), false);
  assert.equal(plainSyntaxOk('${HOME}'), true);
  assert.equal(plainSyntaxOk('${HOME}', true), false);
});

test('a double-quoted scalar escapes what cannot stay as it is', () => {
  assert.equal(quoteDouble('a"b'), '"a\\"b"');
  assert.equal(quoteDouble('a\\b'), '"a\\\\b"');
  assert.equal(quoteDouble('one\ntwo'), '"one\\ntwo"');
  assert.equal(quoteDouble('tab\t'), '"tab\\t"');
  assert.equal(quoteDouble(String.fromCharCode(1)), '"\\x01"');
  assert.equal(quoteDouble(String.fromCharCode(0x2028)), '"\\' + 'u2028"');
  assert.equal(quoteDouble(''), '""');
});

test('a single-quoted scalar doubles its quote and gives up on line breaks', () => {
  assert.equal(quoteSingle("it's"), "'it''s'");
  assert.equal(quoteSingle(''), "''");
  assert.equal(quoteSingle('one\ntwo'), null);
});

test('the length of a text in UTF-8 bytes is counted without encoding it', () => {
  assert.equal(utf8Length('abc'), 3);
  assert.equal(utf8Length('é'), 2);
  assert.equal(utf8Length('€'), 3);
  assert.equal(utf8Length(String.fromCodePoint(0x1f600)), 4);
});

test('a reference and a date are values that cannot be changed', () => {
  const reference = new Reference('${HOME}', true);
  assert.equal(reference.text, '${HOME}');
  assert.equal(reference.explicit, true);
  assert.equal(String(reference), '${HOME}');
  assert.throws(() => {
    reference.text = 'other';
  }, TypeError);
  const date = new Timestamp('date', '2026-12-31');
  assert.throws(() => {
    date.iso = 'other';
  }, TypeError);
});
