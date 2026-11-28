"""One strict YAML reader for the repository's files that have a fixed schema.

The journey files under ``docs/journeys/`` (``*.journey.yaml``) and the storyboard of
the terminal recording (``*.cast.yaml``) each have a schema, and each loader checks it
after the YAML is read. ``yaml.safe_load`` reads some YAML in ways that change the data
before a schema check can see it. ``load`` refuses each by name, file and line:

* an alias or an anchor, which copies a value from another place in the file;
* a merge key, a plain ``<<``, which merges another mapping into the one that holds it;
* a tag. A tag changes what a node is: ``!!merge``, or ``!`` before a quoted ``"<<"``,
  makes a merge key of any word; ``!!value`` makes a key the text of another key, so a
  key given twice is not seen as given twice; ``!!set``, ``!!omap`` and ``!!timestamp``
  build other kinds of values. No file of these schemas has a tag, so every explicit tag
  is refused, whatever it would have made of the node. That leaves a plain ``<<`` as
  the only way to write a merge key, and a quoted ``"<<"`` is an ordinary key;
* a key given twice in one mapping, which ``yaml.safe_load`` resolves by keeping the
  later value without a word.

Each loader calls ``load`` and turns the ``StrictYamlError`` it raises into its own
error type, so the two loaders refuse the same YAML in the same words.
"""

from __future__ import annotations

from typing import Any

import yaml

_STANDARD_TAGS = "tag:yaml.org,2002:"
#: The tag PyYAML resolves a plain ``=`` to. It builds a key with this tag as text.
_VALUE_TAG = _STANDARD_TAGS + "value"
_STR_TAG = _STANDARD_TAGS + "str"


class StrictYamlError(ValueError):
    """The YAML is refused; the message names the file and, where it can, the line."""


def _tag_name(tag: str) -> str:
    """A tag as it is written when it is a standard one (``!!set``), else as it is."""
    if tag.startswith(_STANDARD_TAGS):
        return "!!" + tag.removeprefix(_STANDARD_TAGS)
    return tag


def _refusal(event: Any, schema: str) -> str | None:
    """What the schema has no use for in one parser event, or ``None`` if it is fine.

    An event carries what the file wrote, before the composer resolves anything: it has
    a tag only when the file wrote one, so a tag is found on any node, whatever PyYAML
    would have made of it. A plain scalar or a quoted one has none. A merge key is then
    a plain ``<<`` and nothing else.
    """
    unused = f"is not part of {schema}"
    if isinstance(event, yaml.AliasEvent):
        return f"the YAML alias *{event.anchor} {unused}; write the value out"
    anchor = getattr(event, "anchor", None)
    if anchor:
        return f"the YAML anchor &{anchor} {unused}; write the value out"
    tag = getattr(event, "tag", None)
    if tag is not None:
        return f"the YAML tag {_tag_name(tag)} {unused}; write it without a tag"
    if (
        isinstance(event, yaml.ScalarEvent)
        and event.style is None
        and event.value == "<<"
    ):
        return f"the YAML merge key '<<' {unused}; write each key out"
    return None


def _refuse_features(text: str, source: str, schema: str) -> None:
    """Refuse aliases, anchors, tags and a plain ``<<``, reading the parser's events.

    Nothing is built here, so each refusal names the line of the node at fault.
    """
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        refusal = _refusal(event, schema)
        if refusal is not None:
            raise StrictYamlError(
                f"{source}: line {event.start_mark.line + 1}: {refusal}"
            )


def _key_identity(key: Any) -> tuple[str, str]:
    """What PyYAML builds a scalar key from: the tag it resolved and the text.

    PyYAML builds a key resolved to the value tag (a plain ``=``) as text, so that tag
    counts as the string tag and a plain ``=`` and a quoted ``"="`` are one key. No
    explicit tag is left by the time this runs, so the tag is the resolver's. A key it
    resolves to a number, a boolean or null is no key of any schema these files have,
    and each loader refuses it as an unknown key.
    """
    tag = _STR_TAG if key.tag == _VALUE_TAG else key.tag
    return (tag, key.value)


def _refuse_repeated_keys(node: Any, source: str, path: str = "") -> None:
    """Refuse a key given twice in one mapping, in any mapping of the document.

    PyYAML keeps the later of a key given twice, so a caption written twice in a scene
    would replace the first without a word. ``path`` names the mapping in the message.
    """
    if isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            _refuse_repeated_keys(item, source, f"{path}[{index}]")
    elif isinstance(node, yaml.MappingNode):
        first_line: dict[tuple[str, str], int] = {}
        for key_node, value_node in node.value:
            child = path
            if isinstance(key_node, yaml.ScalarNode):
                line = key_node.start_mark.line + 1
                identity = _key_identity(key_node)
                if identity in first_line:
                    place = f"in {path}" if path else "at the top level"
                    raise StrictYamlError(
                        f"{source}: line {line}: the key {key_node.value!r} is given "
                        f"twice {place} (first on line {first_line[identity]}); the "
                        "later value would replace the earlier one"
                    )
                first_line[identity] = line
                child = f"{path}.{key_node.value}" if path else key_node.value
            _refuse_repeated_keys(value_node, source, child)


def load(text: str, source: str, schema: str) -> object:
    """``text`` as YAML data, or a ``StrictYamlError`` naming what is refused.

    ``source`` is the file name each message starts with. ``schema`` names the schema
    that has no use for the feature, as in "the YAML anchor &x is not part of schema
    v1". Text with no document loads as ``None``, as it does with ``yaml.safe_load``.
    """
    try:
        _refuse_features(text, source, schema)
        loader = yaml.SafeLoader(text)
        try:
            node = loader.get_single_node()
            if node is None:
                return None
            _refuse_repeated_keys(node, source)
            return loader.construct_document(node)
        finally:
            loader.dispose()
    except yaml.YAMLError as exc:
        raise StrictYamlError(f"{source}: not valid YAML: {exc}") from exc
