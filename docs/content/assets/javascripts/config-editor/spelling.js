// The editor's port of ASH's plugin-section spelling fold.
//
// ASH reads any spelling of a declared plugin's section as that plugin's section: case and
// the "-" and "_" separators are dropped, and one trailing Converter, Scanner or Reporter
// word is ignored, so "CsvReporter" names "csv" and "DetectSecretsScanner" names
// "detect-secrets". Where one mapping holds two spellings of one plugin and neither is the
// declared spelling, ASH refuses the file as ambiguous. Where the declared spelling is
// written as well, ASH merges the variant into it key by key and the declared value wins;
// the port does the same, and says where the file wrote each value of the result. The Python
// original is automated_security_helper/config/plugin_section_names.py; tests run both on one
// file of inputs. The module reads no DOM and imports nothing.

// The plugin-type words a section's spelling may end with.
const TYPE_WORDS = ['converter', 'scanner', 'reporter'];

// Keys come from a file, so each is looked up as an own property, and a pointer is read and
// written the way JSON pointers are: "~" is "~0" and "/" is "~1".
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const escapeToken = (part) => String(part).replace(/~/g, '~0').replace(/\//g, '~1');
const pointerOf = (tokens) => tokens.map((token) => `/${escapeToken(token)}`).join('');
const tokensOf = (pointer) =>
  pointer === ''
    ? []
    : pointer
        .slice(1)
        .split('/')
        .map((token) => token.replace(/~1/g, '/').replace(/~0/g, '~'));

/**
 * `name` with the ASCII capitals lowered and every other character as written. Not
 * toLowerCase: that reads more characters as equal than ASH does (the Kelvin sign becomes
 * a k), so a key would look like a plugin's section here that ASH does not see as one.
 */
export function asciiLower(name) {
  return name.replace(/[A-Z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 32));
}

/** `name` with ASCII case and the "-" and "_" separators dropped. */
export function foldedSectionName(name) {
  return asciiLower(name.replaceAll('-', '').replaceAll('_', ''));
}

// `folded` without one trailing plugin-type word, or null when it has none or is only the word.
function withoutTypeWord(folded) {
  for (const word of TYPE_WORDS) {
    if (folded.endsWith(word) && folded.length > word.length) {
      return folded.slice(0, folded.length - word.length);
    }
  }
  return null;
}

/** The declared section names of one kind, by their folded form. */
export function declaredByFold(names) {
  return new Map(names.map((name) => [foldedSectionName(name), name]));
}

/**
 * The declared section `key` is a spelling of, or null. By the folded form first, then with
 * one trailing type word dropped; the word has to stand whole in the key as written, so a
 * word that a separator splits ("sarif-re_porter") names no plugin.
 */
export function declaredTarget(declared, key) {
  const folded = foldedSectionName(key);
  const direct = declared.get(folded);
  if (direct !== undefined) {
    return direct;
  }
  const stripped = withoutTypeWord(folded);
  if (stripped === null) {
    return null;
  }
  const word = folded.slice(stripped.length);
  if (!asciiLower(key).endsWith(word)) {
    return null;
  }
  return declared.get(stripped) ?? null;
}

/**
 * Fold the keys of one section mapping onto the declared spellings.
 *
 * Returns { keys, variants, ambiguous }. `keys` are the keys left after the fold (a variant
 * is replaced by its declared spelling), or null when two non-declared spellings of one
 * plugin clash. `variants` lists each rewritten key as { key, target }. `ambiguous` is null
 * or { first, second, target }: the two clashing keys, in the order they were met, and the
 * plugin they both name.
 */
export function foldSectionKeys(declared, keys) {
  const declaredNames = new Set(declared.values());
  const seen = new Map();
  const variants = [];
  const result = new Set(keys);
  for (const key of keys) {
    if (declaredNames.has(key)) {
      continue;
    }
    const target = declaredTarget(declared, key);
    if (target === null) {
      continue;
    }
    const earlier = seen.get(target);
    if (earlier !== undefined) {
      return { keys: null, variants, ambiguous: { first: earlier, second: key, target } };
    }
    seen.set(target, key);
    variants.push({ key, target });
    result.delete(key);
    result.add(target);
  }
  return { keys: [...result], variants, ambiguous: null };
}

/**
 * `variant` and `declared` merged key by key, the declared value winning: how ASH reads two
 * spellings of one section in one file. Anything that is not a mapping on both sides is the
 * declared value whole, so a list is never merged. Neither argument is changed.
 */
export function mergedRaw(variant, declared) {
  if (!isObject(variant) || !isObject(declared)) {
    return declared;
  }
  const merged = new Map(Object.entries(variant));
  for (const [key, value] of Object.entries(declared)) {
    merged.set(key, merged.has(key) ? mergedRaw(merged.get(key), value) : value);
  }
  return Object.fromEntries(merged);
}

// The pointer, where the file wrote it, of the value that the merge of `variant` and
// `declared` holds at `tokens`. Both sides wrote the section the merge starts from, at
// `variantAt` and `declaredAt`. A value both wrote is the declared one, and a value one side
// wrote alone is where that side wrote it.
function writtenInMerge(variant, variantAt, declared, declaredAt, tokens) {
  let left = variant;
  let right = declared;
  let leftAt = variantAt;
  let rightAt = declaredAt;
  for (const [index, token] of tokens.entries()) {
    if (!isObject(left) || !isObject(right)) {
      // The declared value was taken whole, whatever lies inside it.
      return `${rightAt}${pointerOf(tokens.slice(index))}`;
    }
    const inVariant = hasOwn(left, token);
    const inDeclared = hasOwn(right, token);
    if (!inVariant || !inDeclared) {
      return `${inDeclared ? rightAt : leftAt}${pointerOf(tokens.slice(index))}`;
    }
    left = left[token];
    right = right[token];
    leftAt += `/${escapeToken(token)}`;
    rightAt += `/${escapeToken(token)}`;
  }
  return rightAt;
}

/**
 * Fold one section mapping as ASH folds it: each variant spelling moves onto its declared
 * spelling, and is merged into the section already there, if any, with the declared value
 * winning. The mapping given is not changed.
 *
 * Returns { section, variants, ambiguous, written }. `section` is the mapping after the fold,
 * or null when two spellings of one plugin clash and ASH refuses the file. `variants` and
 * `ambiguous` are as foldSectionKeys gives them. `written(pointer)` turns the JSON pointer of
 * a value of `section` into the pointer of that value where the file wrote it.
 */
export function foldSection(declared, section) {
  const { variants, ambiguous } = foldSectionKeys(declared, Object.keys(section));
  if (ambiguous !== null) {
    return { section: null, variants, ambiguous, written: (pointer) => pointer };
  }
  const entries = new Map(Object.entries(section));
  const origins = new Map();
  for (const { key, target } of variants) {
    const value = entries.get(key);
    entries.delete(key);
    const merged = entries.has(target);
    origins.set(target, { key, merged });
    entries.set(target, merged ? mergedRaw(value, entries.get(target)) : value);
  }
  const written = (pointer) => {
    const [target, ...rest] = tokensOf(pointer);
    if (target === undefined || !origins.has(target)) {
      return pointer;
    }
    const { key, merged } = origins.get(target);
    const variantAt = `/${escapeToken(key)}`;
    if (!merged) {
      return `${variantAt}${pointerOf(rest)}`;
    }
    const declaredAt = `/${escapeToken(target)}`;
    return writtenInMerge(section[key], variantAt, section[target], declaredAt, rest);
  };
  return { section: Object.fromEntries(entries), variants, ambiguous: null, written };
}
