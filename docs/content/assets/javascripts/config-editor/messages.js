// The editor's sentences, and the table of places it departs from the schema's verdict.
//
// The schema's verdict is the base. ASH reads some files differently from its schema, so a
// table of departures adjusts the verdict in those places only, and every row of it has a
// reason, a test that runs it through the corpus, and a direction in which it differs. The
// wording is ASH's own where ASH has a constant string, and otherwise a sentence in ASH's
// voice that ends with what a scan does with the file. The module reads no DOM and imports
// only its two neighbors in this directory.

import { asciiLower, declaredByFold, foldSection, foldSectionKeys } from './spelling.js';
import { resolveRef, validateField } from './validate.js';

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
        "The schema admits a reference, and any text its pattern takes for one, in a field that is not a string. ASH's loader refuses a reference there, and any other string, when it reads the file.",
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
        'ASH warns about an unknown key in a suppression, an exclusion, an ignore-path entry or a suppression scope, wherever it sits, and the entry applies to nothing; it is an error when the file asks to fail on unknown keys.',
    },
    {
      row: 'comma-separated-output-formats',
      schema: 'invalid',
      editor: 'warning',
      reason:
        'ASH reads a comma-separated string of output formats as the list it spells, and reads each name in a list without the white space around it.',
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
      reason:
        'The field is internal, and ASH warns when a user configuration holds it. The schema the editor checks leaves out what is inside it, so the editor does not check that.',
    },
    {
      row: 'plugin-section-spelling',
      schema: 'valid',
      editor: 'note',
      reason: "ASH reads any spelling of a declared plugin's section name as that section.",
    },
    {
      row: 'unquoted-date',
      schema: 'valid',
      editor: 'error',
      reason:
        'The schema sees the text of a date, and ASH reads a date written without quotes as a date, not text, and refuses it where a string belongs.',
    },
    {
      row: 'variant-section-contents',
      schema: 'valid',
      editor: 'error',
      reason:
        "ASH reads what is inside a section spelled another way as the declared section's contents, and refuses the file when they are wrong; the schema admits any contents at a key it does not declare.",
    },
  ].map((departure) => Object.freeze(departure)),
);

const SECTION_KINDS = ['converters', 'reporters', 'scanners'];
const NOT_CHECKED = 'This editor does not check what is inside it.';

/**
 * The entry models: the definitions of the schema in which ASH warns about an unknown key and
 * keeps the file, and the entry never applies, wherever in a file the entry sits (an error
 * once the file asks to fail on unknown keys). `noun` is how a message calls an entry of the
 * model, and `ignored` is what a scan does with an entry that holds an unknown key. A
 * Python test reads this table out of this file and loads a document for each model through
 * ASH's own file-load route.
 */
export const ENTRY_MODELS = Object.freeze({
  AshExclusion: { noun: 'an exclusion', ignored: IGNORES_ENTRY },
  AshSuppression: { noun: 'a suppression', ignored: IGNORES_ENTRY },
  IgnorePathWithReason: { noun: 'an ignore-path entry', ignored: IGNORES_ENTRY },
  SuppressionScope: { noun: 'a suppression scope', ignored: 'The suppression it belongs to matches nothing.' },
});

const TYPE_PHRASES = {
  object: 'a mapping',
  array: 'a list',
  string: 'a string',
  number: 'a number',
  integer: 'an integer',
  boolean: 'a boolean',
  null: 'null',
};

// A name read from a file is looked up as an own property only, so a key such as
// `constructor` or `__proto__` names nothing on the prototype.
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const escapeToken = (part) => String(part).replace(/~/g, '~0').replace(/\//g, '~1');
const unescapeToken = (token) => token.replace(/~1/g, '/').replace(/~0/g, '~');
const pointerTokens = (pointer) =>
  pointer === '' ? [] : pointer.slice(1).split('/').map(unescapeToken);
const pointerOf = (tokens) => tokens.map((token) => `/${escapeToken(token)}`).join('');
const quoted = (names) => names.map((name) => `'${name}'`).join(', ');

function valueAt(instance, tokens) {
  let node = instance;
  for (const token of tokens) {
    if (node === null || typeof node !== 'object' || !hasOwn(node, token)) {
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
      const expected = detail.expected.map((type) =>
        hasOwn(TYPE_PHRASES, type) ? TYPE_PHRASES[type] : type,
      );
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

function topLevelKeys(block) {
  const root = block.validationSchema;
  const schema = typeof root.$ref === 'string' ? resolveRef(root, root.$ref) : root;
  return Object.keys(schema.properties ?? {});
}

// The keys the schema declares for the entry model `definition`, without the deprecated
// spellings, which a correction must not point at.
function entryKeys(block, definition) {
  const defs = block.validationSchema.$defs ?? {};
  const properties = hasOwn(defs, definition) ? (defs[definition].properties ?? {}) : {};
  return Object.keys(properties).filter((name) => !hasOwn(block.constants.deprecatedKeys, name));
}

function unknownEntryKeyMessage(block, definition, key, severity) {
  const { deprecatedKeys } = block.constants;
  let lead;
  if (hasOwn(deprecatedKeys, key)) {
    lead = `'${key}' is the old name of '${deprecatedKeys[key]}'`;
  } else {
    const hint = didYouMean(key, entryKeys(block, definition));
    lead = `Unknown key '${key}'${hint === null ? '' : ` (did you mean '${hint}'?)`}`;
  }
  const model = ENTRY_MODELS[definition];
  return `${lead} in ${model.noun}. ${severity === 'error' ? REFUSES : model.ignored}`;
}

const isEntryFailure = (failure) =>
  failure.keyword === 'additionalProperties' &&
  failure.definition !== undefined &&
  hasOwn(ENTRY_MODELS, failure.definition);

// The unknown-key failures of entry models that `failure` stands for, or null. The failure
// is one itself, or a union (an optional scope is `anyOf` its model and null) in which a
// branch fails with nothing but such failures: the entry was meant for that branch.
function entryFailures(failure) {
  if (isEntryFailure(failure)) {
    return [failure];
  }
  if (failure.keyword === 'anyOf' && Array.isArray(failure.detail.branches)) {
    return failure.detail.branches.find((branch) => branch.length > 0 && branch.every(isEntryFailure)) ?? null;
  }
  return null;
}

// What Python's str.strip removes: the characters Unicode counts as white space, and the four
// separators of the C0 block (U+001C to U+001F), which Python counts as spaces and Unicode
// does not. The byte order mark, the zero-width space and the soft hyphen are not spaces to
// either, so a name that carries one is not a name.
const PYTHON_SPACE = /^[\p{White_Space}\x1c-\x1f]+|[\p{White_Space}\x1c-\x1f]+$/gu;

const pythonStrip = (text) => text.replace(PYTHON_SPACE, '');

/**
 * The names ASH reads in a string at output_formats: the string split on commas, each piece
 * stripped the way Python strips, and the empty pieces dropped. "sarif,html," is two names,
 * "" is none and " sarif" is one.
 */
export function readOutputFormats(text) {
  return text
    .split(',')
    .map(pythonStrip)
    .filter((piece) => piece !== '');
}

// The names ASH reads in the value of output_formats when it is a string or a list of strings,
// and null for any other value, which ASH leaves to the field's type check. A list is not split
// on commas and none of its entries is dropped: each is stripped the way Python strips, and an
// entry that is empty once stripped is a name that no format has.
function outputFormatNames(value) {
  if (typeof value === 'string') {
    return readOutputFormats(value);
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) {
    return value.map(pythonStrip);
  }
  return null;
}

// Every value in `instance` that sits at a field of the data block, as { field, pointer,
// value }; `path` is the field that `instance` is the value of, and '' a whole document.
// Keys come from the file, so each is looked up as an own property, and a key that holds a
// character of the path grammar names no field.
function* valuesAtFields(block, path, instance) {
  const lookup = (fieldPath) => (hasOwn(block.fields, fieldPath) ? block.fields[fieldPath] : null);

  function* members(fieldPath, object, pointer) {
    for (const key of Object.keys(object)) {
      if (/[.[\]{}]/.test(key)) {
        continue;
      }
      const child = fieldPath === '' ? key : `${fieldPath}.${key}`;
      const field = lookup(child);
      if (field !== null) {
        yield* visit(child, field, object[key], `${pointer}/${escapeToken(key)}`);
      }
    }
  }

  function* visit(fieldPath, field, value, pointer) {
    yield { field, pointer, value };
    if (Array.isArray(value)) {
      if (field.kind === 'objectList') {
        for (const [index, item] of value.entries()) {
          if (isObject(item)) {
            yield* members(`${fieldPath}[]`, item, `${pointer}/${index}`);
          }
        }
      }
    } else if (isObject(value)) {
      if (field.kind === 'map') {
        const valueField = lookup(`${fieldPath}{}`);
        if (valueField !== null) {
          for (const key of Object.keys(value)) {
            yield* visit(`${fieldPath}{}`, valueField, value[key], `${pointer}/${escapeToken(key)}`);
          }
        }
      } else {
        yield* members(fieldPath, value, pointer);
      }
    }
  }

  if (path === '') {
    if (isObject(instance)) {
      yield* members('', instance, '');
    }
  } else if (lookup(path) !== null) {
    yield* visit(path, lookup(path), instance, '');
  }
}

// The fields whose value is a list of strings: of text, of names, or of either.
const LISTS_OF_TEXT = ['stringList', 'enumList', 'stringOrList'];

// The strings that a value at `field` holds where ASH reads text, as { pointer, text, name }:
// the value itself at a string field and at a field that takes one string or a list of them,
// and each item of a list of strings. `pointer` is that of the value, and `name` is what a
// message calls the string.
function* stringPlaces(field, pointer, value) {
  if (typeof value === 'string') {
    if (field.kind === 'string' || field.kind === 'stringOrList') {
      yield { pointer, text: value, name: field.key };
    }
  } else if (Array.isArray(value) && LISTS_OF_TEXT.includes(field.kind)) {
    for (const [index, item] of value.entries()) {
      if (typeof item === 'string') {
        yield { pointer: `${pointer}/${index}`, text: item, name: `${field.key}[${index}]` };
      }
    }
  }
}

// ASH folds the spellings of each plugin section onto the declared ones before it reads a
// file, and merges a variant into the declared section key by key, so what ASH reads, and
// refuses, is the folded value. Returns { instance, folded, written }: the value as ASH reads
// it, whether any spelling was folded, and a function that gives the pointer, where the file
// wrote it, of a value of that one. A section that holds two spellings of one plugin is left
// as written, because ASH refuses the file for the clash before it reads what is inside.
function foldPluginSections(block, path, instance) {
  const unfolded = { instance, folded: false, written: (pointer) => pointer };
  const declaredOf = (kind) => declaredByFold(block.spelling.canonical[kind] ?? []);
  const foldOne = (kind, section) => {
    const result = foldSection(declaredOf(kind), section);
    return result.section === null || result.variants.length === 0 ? null : result;
  };
  if (SECTION_KINDS.includes(path) && isObject(instance)) {
    const result = foldOne(path, instance);
    return result === null
      ? unfolded
      : { instance: result.section, folded: true, written: result.written };
  }
  if (path !== '' || !isObject(instance)) {
    return unfolded;
  }
  const folds = new Map();
  for (const kind of SECTION_KINDS) {
    const result = isObject(instance[kind]) ? foldOne(kind, instance[kind]) : null;
    if (result !== null) {
      folds.set(kind, result);
    }
  }
  if (folds.size === 0) {
    return unfolded;
  }
  const document = { ...instance };
  for (const [kind, result] of folds) {
    document[kind] = result.section;
  }
  const written = (pointer) => {
    const [kind, ...rest] = pointerTokens(pointer);
    return folds.has(kind) ? `/${kind}${folds.get(kind).written(pointerOf(rest))}` : pointer;
  };
  return { instance: document, folded: true, written };
}

/**
 * The editor's verdict for `instance`, the value at the field `path` of the data block (the
 * empty path is a whole document), given the schema's `failures` for it
 * (validate.js's validateField).
 *
 * Returns { valid, findings }. Each finding is { row, severity, pointer, message }: `row`
 * names the row of the table that produced it, or is null for a failure the schema reports
 * as it is, and `pointer` is relative to `instance`. A row replaces the failure it stands in
 * for, so a file is valid exactly when no finding is an error. Every row applies wherever its
 * input sits in `instance`, so a whole document and a section are judged as their fields are.
 *
 * ASH reads a plugin section spelled another way as the declared section, so what is inside
 * one is judged as the declared section's contents are: the judge folds the spellings, takes
 * the schema's failures for the folded value, and reports every pointer where the file wrote
 * it. A failure the `failures` given (those of `instance` as written) do not show is one only
 * the fold finds, and carries the row 'variant-section-contents'.
 *
 * `options.failOnUnknownKeys` is true when the file asks to fail on unknown keys.
 * `options.unquotedDates` lists the pointers, relative to `instance`, of the values the file
 * wrote as unquoted dates, a string or an item of a list of strings: the reader that knows
 * them passes each date's text in `instance`.
 */
export function judge(block, path, instance, failures, options = {}) {
  const rows = [];
  const replaced = new Set();

  // What ASH reads is the file with each plugin section folded onto its declared spelling, so
  // every row that looks inside the file looks at that value, and `read.written` turns each
  // pointer it reports back into the pointer where the file wrote it.
  const read = foldPluginSections(block, path, instance);
  const seen = read.folded ? validateField(block, path, read.instance) : failures;

  // The rows that belong to one field apply to every value of the instance that sits at a
  // field, the instance itself or a value deep in a whole document.
  const dates = new Set(Array.isArray(options.unquotedDates) ? options.unquotedDates : []);
  const failedAt = (target) => seen.some((failure) => failure.pointer === target);
  for (const { field, pointer, value } of valuesAtFields(block, path, read.instance)) {
    const at = read.written(pointer);
    const failed = failedAt(pointer);

    // The schema admits a reference where ASH's loader refuses one. It also admits text that
    // only looks like a reference to it: its pattern lets a carriage return through a default,
    // and the loader's recognizer stops at one. ASH reads no reference at such a field and
    // takes no other string either, so every string the schema admitted here is refused.
    if (field.envRef && !field.envAccepted && !failed && typeof value === 'string') {
      rows.push(
        finding(
          'reference-in-typed-field',
          'error',
          at,
          `The value ${value} is not accepted in this ${field.kind} field: a reference is refused here, and so is any other string. ${REFUSES}`,
        ),
      );
    }

    // Output formats that the schema refuses and ASH reads as the list of names they spell: a
    // string, which ASH splits on commas, and a list whose entries ASH strips.
    if (field.kind === 'enumList') {
      const names = outputFormatNames(value);
      const index = seen.findIndex(
        (failure) => failure.pointer === pointer && failure.keyword === 'anyOf',
      );
      const allowed = Array.isArray(field.enum) ? field.enum : [];
      if (names !== null && index !== -1 && names.every((name) => allowed.includes(name))) {
        replaced.add(index);
        const list = `${field.key}: [${names.join(', ')}]`;
        const message =
          typeof value === 'string'
            ? `Write as a list: ${list}. ASH reads the string as the same list.`
            : `Write each name without the white space around it: ${list}. ASH strips each name, so it reads the same list.`;
        rows.push(finding('comma-separated-output-formats', 'warning', at, message));
      }
    }

    // A date written without quotes, which ASH reads as a date and refuses wherever it reads
    // text: at a string field, at a field that takes a string or a list of them, and in each
    // item of a list of strings. A value the schema already refuses is left to the schema.
    for (const place of stringPlaces(field, pointer, value)) {
      const written = read.written(place.pointer);
      if (!failed && !failedAt(place.pointer) && dates.has(written)) {
        rows.push(
          finding(
            'unquoted-date',
            'error',
            written,
            `${place.name} must be quoted: an unquoted ${place.text} is read as a date, not text, so put it in quotes. ${REFUSES}`,
          ),
        );
      }
    }
  }

  // An unknown key in an entry of a model ASH warns about instead of refusing, wherever the
  // entry sits.
  seen.forEach((failure, index) => {
    const entries = entryFailures(failure);
    if (entries === null) {
      return;
    }
    replaced.add(index);
    const severity = options.failOnUnknownKeys ? 'error' : 'warning';
    for (const entry of entries) {
      for (const key of entry.detail.extras) {
        rows.push(
          finding(
            'unknown-key-in-list-entry',
            severity,
            read.written(entry.pointer),
            unknownEntryKeyMessage(block, entry.definition, key, severity),
          ),
        );
      }
    }
  });

  // The keys of a whole document.
  if (path === '' && isObject(instance)) {
    const known = new Set(topLevelKeys(block));
    for (const key of Object.keys(instance)) {
      const pointer = `/${escapeToken(key)}`;
      if (block.constants.invalidTopLevelFields.includes(key)) {
        const warning = block.constants.invalidTopLevelFieldWarning.replace('{field}', () => key);
        // The schema the editor checks leaves an internal section out, so what is inside
        // it goes unchecked, and ASH refuses a section with a key it does not define.
        const inside = instance[key];
        const message =
          isObject(inside) && Object.keys(inside).length === 0 ? warning : `${warning} ${NOT_CHECKED}`;
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

  // A failure of the folded value that the schema also shows for the file as written is a
  // plain failure; one it does not show comes from the fold, and is the row's.
  const shown = new Set(failures.map((failure) => JSON.stringify([failure.pointer, failure.keyword])));
  const findings = [];
  seen.forEach((failure, index) => {
    if (!replaced.has(index)) {
      const pointer = read.written(failure.pointer);
      const value = valueAt(read.instance, pointerTokens(failure.pointer));
      const row = shown.has(JSON.stringify([pointer, failure.keyword]))
        ? null
        : 'variant-section-contents';
      findings.push(
        finding(row, 'error', pointer, describeFailure(failure, value), {
          keyword: failure.keyword,
        }),
      );
    }
  });
  findings.push(...rows);
  return { valid: findings.every((found) => found.severity !== 'error'), findings };
}
