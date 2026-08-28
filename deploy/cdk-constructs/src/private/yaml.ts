// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * A deliberately small, deterministic YAML writer.
 *
 * The committed buildspecs are byte-compared in CI against freshly generated
 * output, so the writer has to be stable across time and across dependency
 * upgrades. A general-purpose YAML library cannot promise that: any release is
 * free to change how it wraps, quotes or orders things, and the day it does,
 * the drift gate fails on a change nobody made. Hand-rolling the ~4 constructs
 * a buildspec needs removes that whole class of failure and removes the
 * package's only runtime dependency.
 *
 * Determinism comes from three rules: keys emit in insertion order (never
 * sorted, never hash-ordered), scalars have exactly one representation each,
 * and nothing consults the clock, the environment or the filesystem.
 */

/** The value shapes a buildspec needs. Internal; never crosses the jsii boundary. */
export type YamlValue = string | number | boolean | YamlValue[] | YamlMap;

/** An ordered mapping. JavaScript preserves string-key insertion order. */
export interface YamlMap {
  [key: string]: YamlValue;
}

/**
 * Scalars safe to emit unquoted.
 *
 * A plain scalar must start with a letter. That single restriction is what makes
 * a string round-trip as a string: `0` would come back as the integer 0, and
 * `python: 3.10` is the classic version of this bug, because YAML reads it as
 * the float 3.1 and the runtime silently becomes Python 3.1. Requiring a leading
 * letter puts every number-shaped string in quotes without needing to enumerate
 * every numeric spelling YAML accepts.
 *
 * Deliberately narrow otherwise. Anything outside it is single-quoted, which is
 * never wrong, so the cost of the conservative choice is only cosmetic.
 */
const PLAIN_SAFE = /^[A-Za-z][A-Za-z0-9_./+-]*$/;

/**
 * Words YAML 1.1 readers coerce to booleans or null.
 *
 * `on` and `no` are the ones that bite in practice: an unquoted `no` becomes
 * `false`. Quoting them keeps them strings.
 */
const RESERVED_PLAIN = new Set([
  'y', 'Y', 'yes', 'Yes', 'YES', 'n', 'N', 'no', 'No', 'NO',
  'true', 'True', 'TRUE', 'false', 'False', 'FALSE',
  'on', 'On', 'ON', 'off', 'Off', 'OFF',
  'null', 'Null', 'NULL', '~', '',
]);

/** Render a scalar in single-quoted style unless it is unambiguously plain. */
export function scalar(value: string | number | boolean): string {
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (PLAIN_SAFE.test(value) && !RESERVED_PLAIN.has(value)) {
    return value;
  }
  // Single-quoted style escapes exactly one character: the quote, by doubling.
  return `'${value.replace(/'/g, "''")}'`;
}

/**
 * Serialize a mapping to YAML.
 *
 * Emits `key: value` for scalars, a nested block for maps, and a block sequence
 * for arrays. Empty maps and empty arrays emit flow style (`{}` / `[]`) because
 * a block form would produce a dangling key.
 */
export function toYaml(value: YamlMap, indentLevel: number = 0): string {
  const pad = '  '.repeat(indentLevel);
  const lines: string[] = [];

  for (const [key, child] of Object.entries(value)) {
    const renderedKey = `${pad}${scalar(key)}:`;

    if (Array.isArray(child)) {
      if (child.length === 0) {
        lines.push(`${renderedKey} []`);
        continue;
      }
      lines.push(renderedKey);
      for (const item of child) {
        if (isMap(item)) {
          // A mapping inside a sequence: first key sits on the dash line.
          const nested = toYaml(item, indentLevel + 2).split('\n');
          lines.push(`${pad}  - ${nested[0].trimStart()}`);
          lines.push(...nested.slice(1));
        } else {
          lines.push(`${pad}  - ${scalar(item as string | number | boolean)}`);
        }
      }
      continue;
    }

    if (isMap(child)) {
      const keyCount = Object.keys(child).length;
      if (keyCount === 0) {
        lines.push(`${renderedKey} {}`);
        continue;
      }
      lines.push(renderedKey);
      lines.push(toYaml(child, indentLevel + 1));
      continue;
    }

    lines.push(`${renderedKey} ${scalar(child)}`);
  }

  return lines.join('\n');
}

function isMap(value: YamlValue): value is YamlMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Render a complete file: a leading comment block, the document, and exactly
 * one trailing newline.
 *
 * Line endings are hard-coded to LF. Letting the platform decide would make the
 * drift gate fail on Windows for a file nobody edited.
 */
export function toYamlFile(header: string[], document: YamlMap): string {
  const comments = header.map((line) => (line.length === 0 ? '#' : `# ${line}`));
  return `${[...comments, toYaml(document)].join('\n')}\n`;
}
