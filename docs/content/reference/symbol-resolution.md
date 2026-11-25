# Symbol resolution (tree-sitter)

How ASH turns a suppression's `symbol` into the line spans it covers. This page is the
reference for the resolver in `automated_security_helper/utils/symbol_spans.py`: its API,
the qualified-name grammar, the fail-closed rules, the languages it parses, and its limits.
For writing a symbol-scoped suppression, start with
[Suppress findings](../how-to/suppress-findings.md#symbol); for installing the grammars, see
[Installing the extra](../how-to/suppress-findings.md#installing-the-extra) and the extras
table in [Install](../how-to/install.md#extras).

A suppression with `symbol: MyClass.my_method` covers a finding when the finding's lines
fall inside a definition with that qualified name in the finding's file. A line-number
suppression points at whatever sits on those lines after an edit; a symbol suppression keeps
pointing at the definition, wherever it moves. This repository's own configs
(`.ash/.ash.yaml`, `.ash/.ash_alpha_plugins.yaml`) use symbol scoping for every
suppression that sits inside a named definition; the migration record and its oracle live in
`tests/test_data/suppression_symbol_migration.yaml` and
`tests/unit/config/test_symbol_migration_record.py`.

## The public API {#api}

Everything below is importable from `automated_security_helper.utils.symbol_spans`.

| Name | Signature | What it does |
|---|---|---|
| `SymbolResolver` | `SymbolResolver(source_dir: Path)` | Answers "is this finding inside that symbol?" for one scan root. Parses lazily, only for a file that a symbol suppression otherwise matches, through a cache shared by every resolver. |
| `SymbolResolver.contains` | `contains(file_path, line_start, line_end, symbol) -> bool` | True if lines `line_start..line_end` of `file_path` (relative to the scan root, as suppressions match it) lie wholly inside a definition named `symbol`. Returns `False`, never raises, whenever the span cannot be known, and logs each distinct reason once per `(file, reason)` at WARNING. |
| `index_symbols` | `index_symbols(source: bytes, grammar: SymbolGrammar) -> dict[str, list[tuple[int, int]]]` | Maps each qualified name defined in `source` to its 1-based inclusive line spans. Raises `SymbolsUnavailableError` if the grammar cannot be loaded and `SymbolParseError` if the parse tree contains an error. |
| `grammar_for_path` | `grammar_for_path(file_path: str) -> SymbolGrammar \| None` | The grammar for a path, selected by extension (the table below); `None` for an extension with no grammar. |
| `is_valid_symbol` / `SYMBOL_PATTERN` | `is_valid_symbol(symbol: str) -> bool` | Whether a string is a well-formed dotted qualified name. The pattern is dot-joined segments of `#?(?!\d)[\w$]+`: Unicode identifiers, `$` for JavaScript, a `#` prefix for a JS/TS private member. Matched whole. |
| `symbols_extra_available` | `symbols_extra_available() -> bool` | True if tree-sitter and every grammar in the table import. |
| `clear_symbol_cache` | `clear_symbol_cache() -> None` | Drops every cached parse. For tests. |
| `symbols_extra_install_command` / `symbols_extra_install_hint` | `-> str` | The install command (read from the running distribution's metadata, so it matches the ASH you run) and the full hint the scan warning and `ash config lint` print. |
| `SymbolsUnavailableError` | subclass of `RuntimeError` | tree-sitter or a grammar module could not be imported, or the installed binding's API is not the one this module calls. |
| `SymbolParseError` | subclass of `ValueError` | tree-sitter parsed the file with errors, so its spans are not trusted. |

The suppression matcher asks the resolver last, so a file is parsed only for a finding that
every other field of a symbol-scoped entry already matches, and a config with no `symbol`
never builds a resolver and never imports tree-sitter.

## Qualified names {#qualified-names}

A qualified name is the chain of enclosing definition names from the top of the file,
joined with `.`: `Outer.Inner.method`, `module_function`, `outer_function.inner_function`.

- Only definitions contribute a segment. Control flow and other blocks are transparent, so
  a function defined inside an `if` at module level is just `name`.
- Names are exact and case-sensitive, and there is no suffix matching: `method` alone names
  a top-level `method`, not `Outer.method`.
- A definition's span contains every definition nested in it, so `Outer` also covers
  findings inside `Outer.Inner.method`.
- When several definitions share a qualified name -- a Python property getter and setter,
  `typing.overload` stubs, Java or TypeScript overloads, a function redefined further down
  -- the name covers all of them. That is documented coverage, not ambiguity.
- A `#` prefix on a segment spells a JavaScript or TypeScript private member.

### A worked example {#example}

Each definition here gets the qualified name in its comment:

```python
class Reporter:  # Reporter
    class Formats:  # Reporter.Formats
        def render(self):  # Reporter.Formats.render
            pass


def flatten(rows):  # flatten
    def walk(row):  # flatten.walk
        pass
```

And a config that scopes suppressions to those names:

```yaml
global_settings:
  suppressions:
    - path: src/reporter.py
      rule_id: B701
      symbol: Reporter.Formats.render
      reason: autoescape is off for the plain-text template only
    - path: src/reporter.py
      rule_id: S110
      symbol: Reporter
      reason: covers every finding in the class, nested definitions included
```

The first entry covers findings on `render`'s lines only; the second covers the whole
`Reporter` span, `Formats.render` included. A TypeScript private method is spelled with
its `#`: `symbol: "RetryPolicy.#backoff"`.

## Every way of not knowing a span fails closed {#fail-closed}

Whenever the resolver cannot know a symbol's span, the suppression does not match and the
finding stays visible. For every cause below except the last two, one warning per
`(file, reason)` names the cause; the last two log nothing. A partial parse tree is not
trusted, because an error node can swallow or truncate a definition and give it the wrong
span. The causes:

| Cause | Outcome | The warning names |
|---|---|---|
| the `symbols` extra (or one grammar) is not installed, or its API does not match | no match; finding visible | the missing grammar and the install hint |
| the file's extension has no grammar | no match; finding visible | the extension and the supported list |
| the file does not parse cleanly | no match; finding visible | the language and the first error line |
| the file cannot be read, or lies outside the scan root | no match; finding visible | the error, or the scan root |
| the symbol is not defined in the file (gone, renamed, or misspelled) | no match; finding visible | nothing is logged: a defined-elsewhere name is indistinguishable from a narrow entry, so staleness surfaces as the finding returning and the entry reported unused |
| the finding carries no line, or its range ends before it starts | no match; finding visible | nothing; there is no region to test |

This is the same posture as an expired suppression: a stale reference resurfaces its
findings loudly instead of silently hiding them. The remediation is also the same -- fix
the reference or re-triage the finding. `ash config lint` flags an entry whose `symbol` is
not a well-formed qualified name, an entry whose `path` names a file type with no grammar,
and a config that uses `symbol` while the extra is missing.

This repository's CI keeps the fail-closed path load-bearing: the
`symbols-extra-control` job in `.github/workflows/ash-repo-scan.yml` proves, with
`scripts/verify_symbol_suppressions_extra.py`, that without the extra every entry in the
migration record (`tests/test_data/suppression_symbol_migration.yaml`) matches nothing,
and that with the extra every one resolves. The script reads the record, not the two
configs; a unit test ties the record to the configs entry for entry, so a symbol entry
added to a config also needs its row in the record to be covered by the job.

## Languages and extensions {#languages}

The extension is the only selector; a file whose extension is not here fails closed.

| Extension | Grammar | Addressable definitions |
|---|---|---|
| `.py`, `.pyi` | Python | `class`, `def` (decorators are part of the span) |
| `.js`, `.jsx`, `.mjs`, `.cjs` | JavaScript | class, function and generator declarations; class methods; `const x = () => {}` and class-field function bindings; an `export` keyword is part of the span |
| `.ts`, `.mts`, `.cts` | TypeScript | the JavaScript set plus interfaces, enums, namespaces/modules, type aliases, abstract classes, overload signatures; member decorators are part of the span |
| `.tsx` | TSX | the TypeScript set |
| `.java` | Java | classes, interfaces, enums, records, annotation types, methods, constructors (annotations are part of the span) |

## Limits {#limits}

- **Python module-level assignments are not addressable.** The Python grammar names class
  and function definitions only, so a module-level constant can only be covered by a line
  range. (JS/TS `const` function bindings are addressable because the grammar reads the
  binding's function value.)
- **A symbol covers its whole definition.** A new finding of the same rule anywhere in
  it is suppressed without a report, which a one-line pin never did. For a rule that
  marks a real hazard (a shell call, an injection pattern, a file read), name the
  smallest definition that holds the finding, extract a small helper so the symbol is
  tight, or keep the line pin. This repository's migration test fails a symbol that is
  not the innermost definition holding the old line, or that runs past 60 lines
  without a recorded reason.
- **A shared name covers every definition that bears it** -- getter/setter pairs, overload
  sets, redefinitions. Scope the entry's `path` and `rule_id` accordingly.
- **Spans include decorators, Java annotations, and a leading `export`**, so a finding
  reported on a decorator line is inside the symbol.
- **Line endings and BOM are normalized** (CRLF and lone CR to LF, a leading UTF-8 BOM
  dropped) before parsing, so tree-sitter's rows match the file's line numbers as scanners
  report them. Nothing else is rewritten.
- **Parses are cached** per resolved path and the stat fields that change when the file
  does, bounded at 4096 entries, so one scan parses a file once however many times
  suppressions are applied. A missing extra and an unreadable file are answered but not
  cached, since both can change without the file changing.
- **A name no symbol can spell** -- a string-named TS module, a computed or string-keyed
  method, a destructuring pattern -- is kept as an unspellable segment, so neither it nor
  anything defined inside it is reachable under the enclosing scope's name.

## Choosing between `symbol`, lines, and `scope` {#choosing}

| The finding sits in | Use | Why |
|---|---|---|
| a named function, method, or class in a language the table covers | `symbol` | survives edits that move the code; bounded by the definition plus the entry's `rule_id` and `path` |
| module-level code, a data or config file, a language with no grammar -- or you mean "from here to the end of the file" | `line_start`/`line_end` (open-ended: `line_start` with no `line_end`) | the only reference that exists there; re-pin it when the line moves |
| an IaC resource (CloudFormation, CDK output) | `resource_id`/`resource_type` (see [SuppressionScope](configuration.md)) | resource identity survives template regeneration, which moves every line |

Both forms stay supported: migrating a config to `symbol` is never required, and
`line_start`/`line_end` keep working unchanged.
