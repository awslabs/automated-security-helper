// The JavaScript translations of the schema's patterns give Python's answer.
//
// ASH checks a pattern with Python's re.search; the editor checks the same value with a
// JavaScript regular expression, translated by hand in the data block. This test runs every
// sample of fixtures/pattern-hazards.json through the translation and requires the answer
// Python gives, and runs the same samples through the Python source read as JavaScript to
// show that they would catch a careless port.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

const block = fixture('editor-data.json');
const { groups } = fixture('pattern-hazards.json');

function translationOf(group) {
  return group.source === 'patterns' ? block.patterns[group.pattern] : block.env.referencePattern;
}

for (const group of groups) {
  test(`the translation of ${group.pattern} gives Python's answer for every sample`, () => {
    const translation = translationOf(group);
    assert.equal(translation.python, group.pattern);
    const regex = new RegExp(translation.js, translation.flags);
    const wrong = group.samples
      .filter((sample) => regex.test(sample.text) !== sample.match)
      .map((sample) => sample.note);
    assert.deepEqual(wrong, []);
  });

  test(`the samples catch a careless port of ${group.pattern}`, () => {
    let caught;
    try {
      const careless = new RegExp(group.pattern);
      caught = group.samples.some((sample) => careless.test(sample.text) !== sample.match);
    } catch {
      caught = true;
    }
    assert.ok(caught, 'the Python source as a JavaScript pattern answers every sample the same');
  });

  test(`the translation of ${group.pattern} is not a stateful expression`, () => {
    const { flags } = translationOf(group);
    assert.ok(flags.includes('u'), 'the u flag makes \\p{L} and code points work');
    assert.ok(!/[gy]/.test(flags), 'a g or y flag would carry lastIndex between calls');
  });
}

test('every pattern of the block has a group of samples', () => {
  const covered = new Set(groups.map((group) => group.pattern));
  for (const pattern of Object.keys(block.patterns)) {
    assert.ok(covered.has(pattern), `no samples for ${pattern}`);
  }
  assert.ok(covered.has(block.env.referencePattern.python));
});

test('every group has samples that match and samples that do not', () => {
  for (const group of groups) {
    assert.deepEqual(new Set(group.samples.map((sample) => sample.match)), new Set([true, false]));
  }
});
