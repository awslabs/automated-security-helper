// The editor's sentences, and the table of places it departs from the schema's verdict.
//
// The schema's verdict is the base. ASH reads some files differently from its schema, so a
// table of departures adjusts the verdict in those places only, and every row of it has a
// reason, a test that runs it through the corpus, and a direction in which it differs. The
// wording is ASH's own where ASH has a constant string, and otherwise a sentence in ASH's
// voice that ends with what a scan does with the file. The module reads no DOM and imports
// only its two neighbors in this directory.

import { asciiLower, declaredByFold, foldSectionKeys } from './spelling.js';
import { resolveRef } from './validate.js';

/** What a scan does with a file the schema refuses. */
export const REFUSES = 'A scan refuses this file (exit 3).';
const IGNORES_KEY = 'A scan ignores this key.';
const IGNORES_ENTRY = 'A scan ignores this entry.';

/**
 * The places the editor's verdict departs from the schema's. `schema` is the schema's
 * verdict for an input the row applies to, and `editor` is the severity the editor gives it,
 * which says what a scan does: an error is a file a scan refuses (exit 3), and a warning or
 * a note is a file it loads. A Python test reads these rows out of this file and runs ASH's
 * own file-load route over the input of each (tests/unit/docs/
 * test_config_editor_departures_match_ash.py), so a row cannot claim what ASH does not do.
 */
export const DEPARTURES = Object.freeze(
  [
    {
      row: 'reference-in-typed-field',
      schema: 'valid',
      editor: 'error',
      reason:
        "The schema admits a reference in a field that is not a string, and ASH's loader refuses it when it reads the file.",
    },
    {
      row: 'ambiguous-plugin-spellings',
      schema: 'valid',
      editor: 'error',
      reason:
        "Two spellings of one plugin's section read as the same section, and ASH refuses a file that holds both.",
    },
    {
      row: 'unknown-key-in-list-entry',
      schema: 'invalid',
      editor: 'warning',
      reason:
        'ASH warns about an unknown key in a suppression or ignore-path entry, and the entry applies to nothing; it is an error when the file asks to fail on unknown keys.',
    },
    {
      row: 'comma-separated-output-formats',
      schema: 'invalid',
      editor: 'warning',
      reason: 'ASH reads a comma-separated string of output formats as the list it spells.',
    },
    {
      row: 'unknown-top-level-key',
      schema: 'valid',
      editor: 'warning',
      reason: 'The root schema admits any extra key, and a scan ignores it.',
    },
    {
      row: 'internal-top-level-field',
      schema: 'valid',
      editor: 'warning',
      reason: 'The field is internal, and ASH warns when a user configuration holds it.',
    },
    {
      row: 'plugin-section-spelling',
      schema: 'valid',
      editor: 'note',
      reason: "ASH reads any spelling of a declared plugin's section name as that section.",
    },
  ].map((departure) => Object.freeze(departure)),
);

const SECTION_KINDS = ['converters', 'reporters', 'scanners'];
const LIST_ENTRIES = { suppressions: 'a suppression', ignore_paths: 'an ignore-path entry' };

const TYPE_PHRASES = {
  object: 'a mapping',
  array: 'a list',
  string: 'a string',
  number: 'a number',
  integer: 'an integer',
  boolean: 'a boolean',
  null: 'null',
};

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const escapeToken = (part) => String(part).replace(/~/g, '~0').replace(/\//g, '~1');
const unescapeToken = (token) => token.replace(/~1/g, '/').replace(/~0/g, '~');
const pointerTokens = (pointer) =>
  pointer === '' ? [] : pointer.slice(1).split('/').map(unescapeToken);
const quoted = (names) => names.map((name) => `'${name}'`).join(', ');

function valueAt(instance, tokens) {
  let node = instance;
  for (const token of tokens) {
    if (node === null || typeof node !== 'object') {
      return undefined;
    }
    node = node[token];
  }
  return node;
}

function describeType(instance) {
  if (instance === null) {
    return 'null';
  }
  if (Array.isArray(instance)) {
    return TYPE_PHRASES.array;
  }
  if (typeof instance === 'object') {
    return TYPE_PHRASES.object;
  }
  if (typeof instance === 'string') {
    return TYPE_PHRASES.string;
  }
  if (typeof instance === 'boolean') {
    return TYPE_PHRASES.boolean;
  }
  return Number.isInteger(instance) ? TYPE_PHRASES.integer : TYPE_PHRASES.number;
}

function joinOr(items) {
  if (items.length <= 1) {
    return items.join('');
  }
  return `${items.slice(0, -1).join(', ')} or ${items[items.length - 1]}`;
}

// The edit distance between two strings, counting a swap of two neighbors as one edit, over
// code points.
function editDistance(left, right) {
  const a = Array.from(left);
  const b = Array.from(right);
  const rows = Array.from({ length: a.length + 1 }, (_row, i) => {
    const row = new Array(b.length + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= b.length; j += 1) {
    rows[0][j] = j;
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      rows[i][j] = Math.min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        rows[i][j] = Math.min(rows[i][j], rows[i - 2][j - 2] + 1);
      }
    }
  }
  return rows[a.length][b.length];
}

/**
 * The candidate closest to `word`, or null. A word that is itself a candidate has nothing
 * to correct. The suggestion has to be a small fraction of the word away, so a short word
 * and a long one that merely share a letter are not offered to each other. Ties go to the
 * candidate that sorts first.
 */
export function didYouMean(word, candidates) {
  if (candidates.includes(word)) {
    return null;
  }
  const lowered = asciiLower(word);
  let best = null;
  let bestDistance = Infinity;
  for (const candidate of [...candidates].sort()) {
    const distance = editDistance(lowered, asciiLower(candidate));
    const longest = Math.max(Array.from(word).length, Array.from(candidate).length);
    const shortest = Math.min(Array.from(word).length, Array.from(candidate).length);
    const limit = Math.min(3, Math.max(1, Math.floor(longest / 3)));
    if (distance <= limit && distance < shortest && distance < bestDistance) {
      best = candidate;
      bestDistance = distance;
    }
  }
  return best;
}

/**
 * The sentence for a failure that no row of the table covers: what is wrong, then what a
 * scan does. `instance` is the value that failed.
 */
export function describeFailure(failure, instance) {
  const { keyword, detail = {} } = failure;
  let sentence;
  switch (keyword) {
    case 'type': {
      const expected = detail.expected.map((type) => TYPE_PHRASES[type] ?? type);
      sentence = `Expected ${joinOr(expected)}, found ${describeType(instance)}.`;
      break;
    }
    case 'enum': {
      const names = detail.allowed.map((value) =>
        typeof value === 'string' ? value : JSON.stringify(value),
      );
      const hint = typeof instance === 'string' ? didYouMean(instance, names) : null;
      sentence = `Not one of the allowed values: ${names.join(', ')}${
        hint === null ? '' : ` (did you mean '${hint}'?)`
      }.`;
      break;
    }
    case 'const':
      sentence = `Expected ${JSON.stringify(detail.expected)}.`;
      break;
    case 'required':
      sentence = `Missing required ${detail.missing.length === 1 ? 'key' : 'keys'} ${quoted(detail.missing)}.`;
      break;
    case 'additionalProperties':
      sentence = `Unknown ${detail.extras.length === 1 ? 'key' : 'keys'} ${quoted(detail.extras)}.`;
      break;
    case 'minimum':
      sentence = `Must be at least ${detail.limit}.`;
      break;
    case 'maximum':
      sentence = `Must be at most ${detail.limit}.`;
      break;
    case 'exclusiveMinimum':
      sentence = `Must be more than ${detail.limit}.`;
      break;
    case 'minLength':
      sentence = `Must be at least ${detail.limit} ${detail.limit === 1 ? 'character' : 'characters'}.`;
      break;
    case 'maxLength':
      sentence = `Must be at most ${detail.limit} ${detail.limit === 1 ? 'character' : 'characters'}.`;
      break;
    case 'minItems':
      sentence = `Needs at least ${detail.limit} ${detail.limit === 1 ? 'item' : 'items'}.`;
      break;
    case 'maxItems':
      sentence = `Takes at most ${detail.limit} ${detail.limit === 1 ? 'item' : 'items'}.`;
      break;
    case 'items':
      sentence = 'This list takes no items.';
      break;
    case 'pattern':
      sentence = 'The text is not in the expected form.';
      break;
    case 'anyOf':
      sentence = 'The value does not match any of the allowed forms.';
      break;
    case 'false':
      sentence = 'This value is not allowed here.';
      break;
    default:
      sentence = `The value does not satisfy '${keyword}'.`;
  }
  return `${sentence} ${REFUSES}`;
}

/** The message shown when the validator cannot judge a schema, as a thrown UnsupportedKeyword says. */
export function validationOffMessage(error) {
  return `Validation is off: this check does not implement '${error.keyword}', so it cannot say whether the file is valid. Run \`ash config validate\` to check it.`;
}

function finding(row, severity, pointer, message, extra = {}) {
  return { row, severity, pointer, message, ...extra };
}

function isReference(block, text) {
  if (typeof text !== 'string') {
    return false;
  }
  const tag = block.env.explicitTag;
  const body = text.startsWith(tag) ? text.slice(tag.length) : text;
  const { js, flags } = block.env.referencePattern;
  return new RegExp(js, flags).test(body);
}

function topLevelKeys(block) {
  const root = block.validationSchema;
  const schema = typeof root.$ref === 'string' ? resolveRef(root, root.$ref) : root;
  return Object.keys(schema.properties ?? {});
}

function entryKeys(block, listName) {
  return Object.values(block.fields)
    .filter((field) => field.parent === `global_settings.${listName}`)
    .map((field) => field.key);
}

function unknownEntryKeyMessage(block, listName, key, severity) {
  const renamed = block.constants.deprecatedKeys[key];
  let lead;
  if (renamed === undefined) {
    const hint = didYouMean(key, entryKeys(block, listName));
    lead = `Unknown key '${key}'${hint === null ? '' : ` (did you mean '${hint}'?)`}`;
  } else {
    lead = `'${key}' is the old name of '${renamed}'`;
  }
  return `${lead} in ${LIST_ENTRIES[listName]}. ${severity === 'error' ? REFUSES : IGNORES_ENTRY}`;
}

/**
 * The editor's verdict for `instance`, the value at the field `path` of the data block (the
 * empty path is a whole document), given the schema's `failures` for it
 * (validate.js's validateField).
 *
 * Returns { valid, findings }. Each finding is { row, severity, pointer, message }: `row`
 * names the row of the table that produced it, or is null for a failure the schema reports
 * as it is, and `pointer` is relative to `instance`. A row replaces the failure it stands in
 * for, so a file is valid exactly when no finding is an error. `options.failOnUnknownKeys`
 * is true when the file asks to fail on unknown keys.
 */
export function judge(block, path, instance, failures, options = {}) {
  const rows = [];
  const replaced = new Set();
  const field = path === '' ? null : (block.fields[path] ?? null);

  // The schema admits a reference where ASH's loader refuses one.
  if (
    field !== null &&
    field.envRef &&
    !field.envAccepted &&
    failures.length === 0 &&
    isReference(block, instance)
  ) {
    rows.push(
      finding(
        'reference-in-typed-field',
        'error',
        '',
        `The reference ${instance} is not accepted in this ${field.kind} field. ${REFUSES}`,
      ),
    );
  }

  // A comma-separated string where a list of output formats belongs.
  if (
    field !== null &&
    field.kind === 'enumList' &&
    typeof instance === 'string' &&
    instance.includes(',')
  ) {
    const pieces = instance.split(',').map((piece) => piece.trim());
    const allowed = Array.isArray(field.enum) ? field.enum : [];
    const index = failures.findIndex((failure) => failure.pointer === '' && failure.keyword === 'anyOf');
    if (index !== -1 && pieces.every((piece) => allowed.includes(piece))) {
      replaced.add(index);
      rows.push(
        finding(
          'comma-separated-output-formats',
          'warning',
          '',
          `Write as a list: ${field.key}: [${pieces.join(', ')}]. ASH reads the comma-separated string as the same list.`,
        ),
      );
    }
  }

  // An unknown key in a suppression or an ignore-path entry.
  failures.forEach((failure, index) => {
    if (failure.keyword !== 'additionalProperties') {
      return;
    }
    const tokens = [...(path === '' ? [] : path.split('.')), ...pointerTokens(failure.pointer)];
    const listName = tokens[1];
    const isEntry =
      tokens.length === 3 &&
      tokens[0] === 'global_settings' &&
      Object.prototype.hasOwnProperty.call(LIST_ENTRIES, listName) &&
      /^\d+$/.test(tokens[2]);
    if (!isEntry) {
      return;
    }
    replaced.add(index);
    const severity = options.failOnUnknownKeys ? 'error' : 'warning';
    for (const key of failure.detail.extras) {
      rows.push(
        finding(
          'unknown-key-in-list-entry',
          severity,
          failure.pointer,
          unknownEntryKeyMessage(block, listName, key, severity),
        ),
      );
    }
  });

  // The keys of a whole document.
  if (path === '' && isObject(instance)) {
    const known = new Set(topLevelKeys(block));
    for (const key of Object.keys(instance)) {
      const pointer = `/${escapeToken(key)}`;
      if (block.constants.invalidTopLevelFields.includes(key)) {
        const message = block.constants.invalidTopLevelFieldWarning.replace('{field}', () => key);
        rows.push(finding('internal-top-level-field', 'warning', pointer, message));
      } else if (!known.has(key)) {
        const hint = didYouMean(key, [...known]);
        const lead = `Unknown key '${key}'${hint === null ? '' : ` (did you mean '${hint}'?)`}`;
        rows.push(finding('unknown-top-level-key', 'warning', pointer, `${lead}. ${IGNORES_KEY}`));
      }
    }
  }

  // The sections of scanners, reporters and converters.
  let sections = [];
  if (SECTION_KINDS.includes(path) && isObject(instance)) {
    sections = [[path, instance, '']];
  } else if (path === '' && isObject(instance)) {
    sections = SECTION_KINDS.filter((kind) => isObject(instance[kind])).map((kind) => [
      kind,
      instance[kind],
      `/${kind}`,
    ]);
  }
  for (const [kind, section, base] of sections) {
    const declared = declaredByFold(block.spelling.canonical[kind] ?? []);
    const folded = foldSectionKeys(declared, Object.keys(section));
    if (folded.ambiguous !== null) {
      const { first, second, target } = folded.ambiguous;
      rows.push(
        finding(
          'ambiguous-plugin-spellings',
          'error',
          `${base}/${escapeToken(second)}`,
          `${kind}.${first} and ${kind}.${second} are two spellings of the ${target} section: ambiguous, keep one. ${REFUSES}`,
        ),
      );
    } else {
      for (const { key, target } of folded.variants) {
        rows.push(
          finding(
            'plugin-section-spelling',
            'note',
            `${base}/${escapeToken(key)}`,
            `'${key}' is read as the ${target} section. Write '${target}' to use the documented spelling.`,
          ),
        );
      }
    }
  }

  const findings = [];
  failures.forEach((failure, index) => {
    if (!replaced.has(index)) {
      const value = valueAt(instance, pointerTokens(failure.pointer));
      findings.push(
        finding(null, 'error', failure.pointer, describeFailure(failure, value), {
          keyword: failure.keyword,
        }),
      );
    }
  });
  findings.push(...rows);
  return { valid: findings.every((found) => found.severity !== 'error'), findings };
}
