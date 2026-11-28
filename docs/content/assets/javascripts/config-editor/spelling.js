// The editor's port of ASH's plugin-section spelling fold.
//
// ASH reads any spelling of a declared plugin's section as that plugin's section: case and
// the "-" and "_" separators are dropped, and one trailing Converter, Scanner or Reporter
// word is ignored, so "CsvReporter" names "csv" and "DetectSecretsScanner" names
// "detect-secrets". Where one mapping holds two spellings of one plugin and neither is the
// declared spelling, ASH refuses the file as ambiguous. The Python original is
// automated_security_helper/config/plugin_section_names.py; tests run both on one file of
// inputs. The module reads no DOM and imports nothing.

// The plugin-type words a section's spelling may end with.
const TYPE_WORDS = ['converter', 'scanner', 'reporter'];

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
