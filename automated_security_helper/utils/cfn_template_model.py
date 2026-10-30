from collections.abc import Iterable, Mapping
import codecs
import io
import json
import os
import re

import yaml
from cfn_tools.yaml_loader import TAG_MAP, CfnYamlLoader
from cfn_tools.yaml_loader import construct_mapping as _cfn_construct_mapping
from yaml import YAMLError
from yaml.constructor import ConstructorError
from yaml.error import Mark
from yaml.scanner import ScannerError
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field


from typing import TYPE_CHECKING, Annotated, Any, Dict

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)

if TYPE_CHECKING:
    from automated_security_helper.base.plugin_context import PluginContext


def describe_parse_error(exc: BaseException) -> str:
    """Name a parse or validation error without quoting the document.

    The text of these exceptions carries part of the file: PyYAML prints the offending
    line under a caret, and pydantic prints the rejected ``input_value``. That text
    goes to ``ash.log``, so only the exception type and, where the parser knows it, the
    1-based line number are kept.
    """
    line = None
    mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
    if mark is not None and isinstance(getattr(mark, "line", None), int):
        line = mark.line + 1
    elif isinstance(getattr(exc, "lineno", None), int):
        # json.JSONDecodeError
        line = exc.lineno  # type: ignore[attr-defined]
    if line is None:
        return type(exc).__name__
    return f"{type(exc).__name__} at line {line}"


class TemplateDocumentError(YAMLError):
    """Text the YAML loader read but could not build a document from.

    The JSON parser could not read it either, or was not tried: a document nested
    too deep for the loader is not read as JSON (``get_model_from_template_text``).
    cfn_tools' loader raises
    ``TypeError`` for a mapping used as a mapping key, which is how it reads a Helm
    template's ``{{ include ... }}`` ("unhashable type: 'ODict'"), ``ValueError``
    for a scalar it cannot construct, such as ``!!int forty-two``, and
    ``RecursionError`` for a document nested past the recursion limit (a few
    hundred levels). None is a ``YAMLError``, so cdk-nag, which treats only a
    ``YAMLError`` as a file that does not parse, counted a Helm chart as a template
    it failed on and the scan reported ERROR, while cfn-nag passed over the same
    file. As a ``YAMLError`` it is the parse failure it is, for every caller, and it
    crosses the cdk-nag worker boundary as one (``cdk_nag_worker`` keeps the base
    class). A value that could not be built raises the subclass
    :class:`TemplateConstructorError`. The message names the loader's error type
    only: its text can quote the document, and these messages reach ash.log.
    """


class TemplateConstructorError(TemplateDocumentError):
    """A document the YAML loader read but could not build one of the values of.

    Every loader failure that is not a syntax error: a ``ConstructorError`` (an
    explicit tag it refuses, such as ``!!python/name:``, or ``!!binary`` data it
    cannot decode), a ``TypeError`` (a mapping used as a key), a ``ValueError``
    (``!!int forty-two``) and anything else the constructors raise. The syntax was
    fine, so a file whose structure is a template (a top-level Resources mapping) is
    a template ASH failed on, not one it could not parse:
    :func:`unevaluable_template_reason` decides that, and both scanners count such a
    file as a failed target. The line of the value is kept where the loader knew it
    (a ConstructorError carries it), for :func:`describe_parse_error`; the message
    names the error type only.
    """

    problem_mark: Mark | None = None


#: YAML 1.1's implicit timestamp type. CloudFormation reads ``2010-09-09`` and
#: ``2024-13-01`` as strings; PyYAML read them as dates and raised ValueError on a
#: date no calendar holds, so a real template with such a value did not load.
_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"


_ImplicitResolvers = Dict[Any, list[tuple[str, Any]]]

#: The most key/value pairs a mapping may hold once its merge keys (``<<``) are
#: merged in. PyYAML's ``flatten_mapping`` copies every merged mapping's pairs into
#: the merging node, and the anchored nodes are shared, so a chain in which each
#: mapping merges the previous one twice (``b: &b {<<: [*a, *a]}``) doubles at
#: every link: thirty links are a billion pairs from a 1 KB file, in the
#: unsandboxed ASH process. Checked BEFORE a node's merge list is built, from the
#: sizes of the mappings it merges, and summed over the document, so neither one
#: wide merge (``{<<: [*a16, *a16, ...]}``) nor many siblings each merging a
#: large mapping once can allocate past it. A real template merges a few defaults
#: into a few hundred resources and stays far below it.
MERGED_MAPPING_PAIRS_BOUND = 100_000

#: PyYAML's tag for the merge key, ``<<``.
_MERGE_TAG = "tag:yaml.org,2002:merge"


def _flatten_mapping_within_bound(
    loader: Any, flatten: Any, node: yaml.MappingNode
) -> None:
    """``flatten(node)``, refused before the merge is built when it would pass the bound.

    PyYAML's ``flatten_mapping`` flattens each merged mapping, then copies every
    merged pair into one list and prepends it to the node's own pairs. The copy is
    the allocation, so the check runs before it: each merged mapping is flattened
    first (through ``loader.flatten_mapping``, so the same check covers it), their
    sizes are added to the node's own, and the sum is refused when it passes
    ``MERGED_MAPPING_PAIRS_BOUND``. The pairs every merge in the document has added
    are summed on the loader too, so many small merges of one large mapping are
    refused as one large merge is. The loader's sum is advanced as each merged
    mapping is counted, never from a value read before the loop: a merged mapping
    that is flattened inside this call (an anchor constructed later than the
    mapping that merges it, which is every anchor inside a sequence) adds its own
    merges to the sum first, and a write of "the sum before the loop plus this
    node's merges" erased them, so a doubling chain anchored inside a list was
    never refused. ``flatten`` (the base class's) runs only when both sums are
    within the bound; it finds the merged mappings already flat.

    A mapping that merges itself (``a: &a {<<: *a}``) is left to the base class,
    which deletes the merge key before it recurses and builds ``{}``: the
    pre-check flattens each merged mapping while the merging node still holds its
    key, so a merged node that is itself being flattened is skipped here, not
    flattened again. Without the skip the pre-check recursed into the same node
    until ``RecursionError``, and a one-line file was reported as nested past the
    loader's recursion limit.

    Raises:
        ConstructorError: the merge would expand this mapping, or the document's
            merges together, past ``MERGED_MAPPING_PAIRS_BOUND`` pairs.
    """
    done = getattr(loader, "_flattened_node_ids", None)
    if done is None:
        done = set()
        loader._flattened_node_ids = done
    if id(node) in done:
        # Flattened earlier in this document: its pairs are flat and its merge
        # keys are gone, so there is nothing to check or copy. Anchored nodes are
        # shared, and a mapping that merges one alias N times (``{<<: [*a, *a,
        # ...]}``) reached this N times; each time the base class copied and
        # scanned the merged mapping again, about 65,000 Python steps per alias
        # for a 32,768-pair mapping, before the bound was ever compared.
        return
    in_progress = getattr(loader, "_flattening_node_ids", None)
    if in_progress is None:
        in_progress = set()
        loader._flattening_node_ids = in_progress
    entered = id(node) not in in_progress
    if entered:
        in_progress.add(id(node))
    try:
        incoming = 0
        for key_node, value_node in list(node.value):
            if getattr(key_node, "tag", None) != _MERGE_TAG:
                continue
            if isinstance(value_node, yaml.MappingNode):
                merged_nodes = [value_node]
            elif isinstance(value_node, yaml.SequenceNode):
                # A non-mapping item is left for the base class to refuse.
                merged_nodes = [
                    item
                    for item in value_node.value
                    if isinstance(item, yaml.MappingNode)
                ]
            else:
                merged_nodes = []
            for merged_node in merged_nodes:
                if id(merged_node) in in_progress:
                    # The node merges itself, or a mapping that is merging it:
                    # the base class drops the merge key before it recurses, so
                    # nothing is added by it.
                    continue
                loader.flatten_mapping(merged_node)
                added = len(merged_node.value)
                incoming += added
                # Compared as the sums grow, so the refusal comes at the first
                # merged mapping that passes the bound, not after every merged
                # mapping of a wide merge has been flattened and counted. The
                # document's sum is read after the merged mapping was flattened
                # and advanced by this mapping alone: the flatten above may have
                # added that mapping's own merges to it.
                expanded = incoming + len(node.value)
                document_total = getattr(loader, "_merged_pairs_added", 0) + added
                loader._merged_pairs_added = document_total
                if (
                    expanded > MERGED_MAPPING_PAIRS_BOUND
                    or document_total > MERGED_MAPPING_PAIRS_BOUND
                ):
                    raise ConstructorError(
                        None,
                        None,
                        f"a merge key (<<) would expand this mapping to {expanded} "
                        f"key/value pairs or more ({document_total} added by this "
                        f"document's merges), more than the "
                        f"{MERGED_MAPPING_PAIRS_BOUND} ASH reads",
                        node.start_mark,
                    )
        flatten(node)
        done.add(id(node))
    finally:
        if entered:
            in_progress.discard(id(node))


#: The byte order mark as UTF-8 decoding keeps it, U+FEFF, spelled by code point.
_BOM = chr(0xFEFF)


def _without_bom(text: str) -> str:
    """*text* without a leading byte order mark, for ``json.loads``.

    The template text is decoded as UTF-8, which keeps a BOM as U+FEFF; the YAML
    reader skips it, ``json.loads`` refuses it ("Unexpected UTF-8 BOM"). A JSON
    template that YAML refused for its tabs was then refused by JSON for its BOM.
    """
    return text[1:] if text.startswith(_BOM) else text


def _starts_a_json_object(text: str) -> bool:
    """Whether *text*, less a byte order mark and leading whitespace, opens with ``{``.

    A JSON template is a JSON object; a YAML template opens with a key. The JSON
    parser reads such a text first (:func:`get_model_from_template_text`).
    """
    return _without_bom(text).lstrip().startswith("{")


#: What a text has been read as before any parser answered: a sentinel, since
#: ``None`` is a document a parser can return.
_NOT_READ = object()


def _without_the_timestamp_resolver(
    resolvers: _ImplicitResolvers,
) -> _ImplicitResolvers:
    """A copy of a loader's implicit resolvers with the timestamp type left out."""
    return {
        first: [(tag, regexp) for tag, regexp in entries if tag != _TIMESTAMP_TAG]
        for first, entries in resolvers.items()
    }


class _TemplateLoader(CfnYamlLoader):
    """cfn_tools' template loader, reading date-like scalars as the strings they are.

    An ASH subclass, so no third-party code changes: the implicit resolvers are a
    class attribute, and this class gets its own copy without the timestamp type.
    An explicitly tagged ``!!timestamp`` is still built as a date.

    Merge keys (``<<: *base``) are merged, as PyYAML's own loaders merge them:
    cfn_tools' mapping constructor never did, so a valid merge raised a
    ConstructorError. CloudFormation itself does not accept hash merges (its
    template format specification lists them as unsupported), so such a template is
    one a preprocessor flattens before it deploys, and ASH scans what the merged
    document says. A merge of anything but a mapping (``<<: 5``) still raises, and
    so does a merge that grows a mapping past ``MERGED_MAPPING_PAIRS_BOUND``.
    """

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        _flatten_mapping_within_bound(self, super().flatten_mapping, node)


_TemplateLoader.yaml_implicit_resolvers = _without_the_timestamp_resolver(
    CfnYamlLoader.yaml_implicit_resolvers
)

#: The YAML 1.1 types a plain, untagged mapping key resolves to, and which a
#: template never means for a key: a logical id ``2024``, ``On``, ``No`` or ``Null``
#: is text. Loaded as an int, a bool or None, such a key failed the model's
#: ``Dict[str, ...]`` and the whole template counted as a failed target.
_NON_STRING_KEY_TAGS = frozenset(
    {
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:null",
    }
)
_STR_TAG = "tag:yaml.org,2002:str"


def _keys_as_strings(node: yaml.MappingNode) -> None:
    """Retag the plain scalar keys of ``node`` that resolved to a non-string type.

    Only a plain (unquoted, untagged) scalar is retagged: an explicit ``!!int``
    key keeps its tag. Values are left as they resolve.
    """
    for key_node, _ in node.value:
        if (
            isinstance(key_node, yaml.ScalarNode)
            and key_node.style is None
            and key_node.tag in _NON_STRING_KEY_TAGS
        ):
            key_node.tag = _STR_TAG


def _construct_merged_mapping(loader: _TemplateLoader, node: yaml.MappingNode) -> Any:
    loader.flatten_mapping(node)
    _keys_as_strings(node)
    return _cfn_construct_mapping(loader, node)


_TemplateLoader.add_constructor(TAG_MAP, _construct_merged_mapping)


def _load_template_yaml(text: str) -> Any:
    """``cfn_tools.load_yaml`` through :class:`_TemplateLoader`."""
    loader = _TemplateLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _as_parse_failure(load_error: Exception) -> YAMLError:
    """The YAMLError a text that neither YAML nor JSON reads raises.

    A syntax error is raised as the loader raised it, and every other loader
    failure, a ConstructorError included, is a TemplateConstructorError.
    """
    if isinstance(load_error, ConstructorError) or not isinstance(
        load_error, YAMLError
    ):
        error = TemplateConstructorError(
            f"the YAML loader could not build a value: {type(load_error).__name__}"
        )
        error.problem_mark = getattr(load_error, "problem_mark", None)
        return error
    return load_error


#: How deep a JSON document YAML refused may nest, when tabs were not why it refused:
#: a tab-indented one is decided as the same text with spaces
#: (:func:`get_model_from_template_text`), so the YAML loader's own limits apply to
#: it. What is left is JSON that YAML refuses for another reason, such as a key
#: longer than the 1,024 characters YAML allows a simple key. json.loads raises
#: RecursionError at 994 levels on Python 3.10 and 3.11 and reads about 10,000 on
#: 3.12 and 3.13 and more than 20,000 on 3.14, so a limit under all of them answers
#: such a template the same on every version. Past the limit such a template is
#: passed over as a file that could not be parsed, not counted as one ASH could not
#: evaluate: :func:`_has_top_level_resources` reads structure through YAML, which
#: refuses it, and reading it as JSON instead would make the answer past 994 levels
#: depend on the Python version again. The exception is a file that nests past
#: ``EVENT_DEPTH_BOUND`` levels before YAML reaches what it refuses, the long key
#: coming after the deep part or inside it: the event read stops at the bound first,
#: and that counts as a failed target, as any file nested that deep does.
JSON_NESTING_LIMIT = 400

_JSON_TOO_DEEP = f"it is nested past {JSON_NESTING_LIMIT} levels"


def _root_is_a_sequence(text: str) -> bool:
    """Whether the first node of *text*'s YAML event stream opens a sequence.

    A CloudFormation template is a mapping, so a document whose root is a sequence
    is not one, damaged or not: the damage would have to be its first node. Read
    from the event stream, which stops at that node, where a composer parse of a
    deeply nested sequence runs to the recursion limit first: for a JSON test-suite
    file of 100,000 opening brackets, about 1.5 s a parse on Python 3.10, and a
    cfn-nag decision made five of them. False when the stream cannot be read that
    far, so the parsers decide such a text.
    """
    events = yaml.parse(text, Loader=yaml.BaseLoader)
    try:
        for event in events:
            if isinstance(event, yaml.NodeEvent):
                return isinstance(event, yaml.SequenceStartEvent)
    except Exception:
        return False
    finally:
        events.close()
    return False


def _nested_past(value: object, limit: int) -> bool:
    """Whether *value*, read from JSON, nests lists and objects deeper than *limit*."""
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        children: Iterable[object]
        if isinstance(item, dict):
            children = item.values()
        elif isinstance(item, list):
            children = item
        else:
            continue
        if depth > limit:
            return True
        pending.extend((child, depth + 1) for child in children)
    return False


class CloudFormationTemplateModelError(Exception):
    """A document that is CloudFormation but that this model cannot represent.

    This exists to separate two answers that used to share one ``None`` return, and the
    conflation was a false negative rather than a cosmetic problem. Both consumers --
    ``cfn_nag_scanner`` and ``cdk_nag_wrapper`` -- read ``None`` as "this file is not a
    CloudFormation template", which is an expected skip that increments no target
    counter. A real template rejected by this model inherited that treatment, so a scan
    set in which every template tripped the model ended with ``targets_attempted`` at
    zero, which ``ScanResultsContainer.determine_status`` reports as SKIPPED with exit
    code 0. Nothing above TRACE was emitted anywhere along that path.

    The distinction drawn here is "does the loaded document carry a ``Resources``
    mapping". If it does not, the file is not CloudFormation and ``None`` is correct. If
    it does, failing to model it is a limitation of this model, and the consumer must
    count a failed target so the run cannot read as clean. The false-positive direction
    -- some non-template file that happens to carry a ``Resources`` mapping now counts
    as a failed target and logs a warning -- is the safe direction: it is visible and
    fixable, where the previous behavior was neither.
    """

    def __init__(self, template_path: Path | str, error: Exception):
        self.template_path = template_path
        self.error = error
        # The error's own text is left out: a pydantic ValidationError quotes the
        # rejected value, and this message is logged. ``error`` keeps the detail.
        super().__init__(f"{template_path}: {describe_parse_error(error)}")


class CloudFormationResource(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    # The charset CloudFormation documents, not a narrower guess. The AWS CloudFormation
    # User Guide's "Specifying custom resource type names" section states that a custom
    # resource type name may contain alphanumeric characters and the characters _@-, so
    # the previous ^([a-zA-Z0-9:]+)$ rejected type names AWS explicitly permits --
    # `Custom::Ash-Image-Bootstrap`, `Custom::DB_Migrator`, `Custom::My@Thing`. Because
    # `Resources` is a Dict of these, one such resource failed the whole template, and
    # the whole template was then classified as not-CloudFormation and never scanned.
    #
    # The trailing hyphen inside the class is a literal hyphen; it has to stay last.
    Type: Annotated[str, Field(pattern=r"^[a-zA-Z0-9:_@-]+$")]


class CloudFormationTemplateModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
        # A template is scanned content, which an error does not quote
        # (describe_parse_error).
        hide_input_in_errors=True,
    )

    Resources: Dict[str, CloudFormationResource]


def get_model_from_template(
    template_path: Path | None = None,
    *,
    scan_root: Path | str | None = None,
) -> CloudFormationTemplateModel | None:
    """Model *template_path* as CloudFormation, or say which kind of no it is.

    Returns ``None`` only when the file is not CloudFormation: no path was given, or the
    loaded document carries no ``Resources`` mapping. Raises
    :class:`CloudFormationTemplateModelError` when the document does carry one but this
    model rejects it, so the caller can count a failed target instead of an unscanned
    skip. A file that is not parseable YAML or JSON raises a ``YAMLError`` (the
    loader's own, or :class:`TemplateDocumentError` for one it raised as another
    type) -- it never reached this model in the first place, and the two callers
    classify that case for themselves.

    With ``scan_root``, the template is read under the scanned-tree rule
    (``utils/scanned_tree.py``, through :func:`read_template_text`, which admits a
    hard-linked regular file) and a file that breaks it raises
    :class:`~automated_security_helper.utils.scanned_tree.TreeInputRefused` before
    anything is read. Both scanners that call this pass the root they scan.
    """
    if template_path is None:
        return None

    if scan_root is not None:
        text = read_template_text(template_path, scan_root)
    else:
        with open(template_path, mode="r", encoding="utf-8") as f:
            text = f.read()
    return get_model_from_template_text(text, template_path)


def read_template_text(template_path: Path | str, scan_root: Path | str) -> str:
    """The template's text, read under the scanned-tree rule.

    For callers that need the text more than once (cdk-nag models it, maps findings to
    its lines and synthesizes it): reading once and reusing the text means every use
    sees the file that was checked.

    A regular file with more than one hard link is read. Every caller of this
    function reads a file the scan set already lists to decide whether cfn-nag or
    cdk-nag evaluates it, and a hard link to a regular file inside the tree is that
    file's own bytes under a second name: the read follows no link to a path outside
    the tree, which is what the scanned-tree rule's link-count check exists to prevent.
    Refusing it skipped a hard-linked template silently, so a repository that
    hard-links its templates (a build that links generated templates into place,
    a content-addressed checkout) reported clean. What stays refused is unchanged:
    a symlink at the file or at a parent, a path that resolves outside the tree, a
    ``..`` component and a non-regular file.

    Raises:
        TreeInputRefused: The template breaks the rule; nothing was read.
    """
    # TextIOWrapper rather than bytes.decode, so newlines are translated exactly as a
    # text-mode open() translates them.
    with io.TextIOWrapper(
        open_in_scanned_tree(template_path, scan_root, allow_hardlinks=True),
        encoding="utf-8",
    ) as f:
        return f.read()


#: Byte-order marks, longest first (UTF-32 LE's begins with UTF-16 LE's), with the
#: encoding each announces.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32-le"),
    (codecs.BOM_UTF32_BE, "utf-32-be"),
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)


#: The encodings a file holding NUL bytes may be in when it carries no byte-order
#: mark, with the name a record gives each: UTF-16 and UTF-32, either byte order.
#: To a UTF-8 reader such a file is NUL-interleaved text, not an error.
_UNMARKED_WIDE_ENCODINGS = (
    ("utf-16-le", "UTF-16"),
    ("utf-16-be", "UTF-16"),
    ("utf-32-le", "UTF-32"),
    ("utf-32-be", "UTF-32"),
)


def _decode_leniently(data: bytes) -> list[str]:
    """``data`` as text, every reading it could be: by its byte-order mark when it
    has one; else as UTF-8 with every undecodable byte replaced, and, when the bytes
    hold a NUL (what a UTF-16 or UTF-32 file written without a mark looks like to a
    UTF-8 reader), as each of those in both byte orders too
    (:data:`_UNMARKED_WIDE_ENCODINGS`). The caller takes any reading."""
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            return [data[len(mark) :].decode(encoding, errors="replace")]
    readings = [data.decode("utf-8", errors="replace")]
    if b"\x00" in data:
        for encoding, _ in _UNMARKED_WIDE_ENCODINGS:
            readings.append(data.decode(encoding, errors="replace"))
    return readings


#: The three answers of :func:`judge_undecodable_candidate`.
UNDECODABLE_TEMPLATE = "template"
UNDECODABLE_DAMAGED = "damaged"
UNDECODABLE_NOT_A_TEMPLATE = "not-a-template"


def judge_undecodable_candidate(
    template_path: Path | str, scan_root: Path | str
) -> str:
    """For a candidate whose UTF-8 read raised ``UnicodeDecodeError``: what is it?

    The scanners read a candidate as UTF-8 (:func:`read_template_text`). A ``.json``
    or ``.yaml`` file that is not (a UTF-16 ``appsettings.json`` from Windows
    PowerShell's ``Out-File``, a Latin-1 locale file) raised at the read, and the
    three CloudFormation scanners counted it as a failed, unevaluated target with no
    structure read at all, so one such file in a repository failed every one of
    them. The file is read again, under the scanned-tree rule, and decoded as well
    as it can be (:func:`_decode_leniently`: by its byte-order mark, else as UTF-8
    with replacement and, when it holds NUL bytes, as UTF-16 and UTF-32 in both byte
    orders, since such a file written without a mark carries no readable marker
    under a UTF-8 reading), and the readings are judged as the UTF-8 route judges a
    file the parser rejected, so a file's encoding never changes its answer:

    * :data:`UNDECODABLE_TEMPLATE`: a reading's STRUCTURE is a template (a mapping
      with a ``Resources`` mapping, :func:`_structure_says_template`), or the second
      read failed. A template ASH could not decode: the scanners count it as a
      failed, unevaluated target, the tool-absent check as a template. The module's
      rule holds here as on the UTF-8 route: a marker alone never makes a file a
      failed target; that takes a structure read. The first cut answered from the
      marker too, so a Jinja-templated stack saved as cp1252 was a failed target in
      three scanners while its UTF-8 twin was skipped as unparseable.
    * :data:`UNDECODABLE_DAMAGED`: no reading has that structure, but one carries a
      CloudFormation marker (:func:`_could_be_a_template`): a damaged template, as
      the UTF-8 route reads a rejected file with a marker. The scanners name it as
      a template that could not be parsed, at WARNING, counted as nothing; the
      tool-absent check counts it, since only MISSING cannot hide a template.
    * :data:`UNDECODABLE_NOT_A_TEMPLATE`: neither. Skipped and named at WARNING, as
      a Helm chart or a tsconfig.json is.

    The second open takes the same scanned-tree terms as the first
    (:func:`read_template_text`): a regular file with more than one hard link is
    read. The first cut opened with the default, which refuses a hard link, so a
    hard-linked non-UTF-8 candidate passed the first read, raised at the decode, and
    the second open raised ``TreeInputRefused`` out of the callers' except arms,
    which caught ``OSError`` only; one hard-linked Latin-1 .yaml ended the
    discovery. A failure of the second read (``OSError``; ``TreeInputRefused``, a
    plain ``Exception``, for a file swapped under the first read) is answered here,
    not raised: the file is not known not to be a template, and the doubt counts as
    one, so every caller reads the same answer and none needs its own except arm.
    """
    try:
        with open_in_scanned_tree(template_path, scan_root, allow_hardlinks=True) as f:
            data = f.read()
    except (OSError, TreeInputRefused):
        return UNDECODABLE_TEMPLATE
    readings = _decode_leniently(data)
    if any(_structure_says_template(text) for text in readings):
        return UNDECODABLE_TEMPLATE
    if any(_could_be_a_template(text) for text in readings):
        return UNDECODABLE_DAMAGED
    return UNDECODABLE_NOT_A_TEMPLATE


def undecodable_candidate_is_a_template(
    template_path: Path | str, scan_root: Path | str
) -> bool:
    """For a candidate whose UTF-8 read raised ``UnicodeDecodeError``: does the
    tool-absent check count it? True for :data:`UNDECODABLE_TEMPLATE` and
    :data:`UNDECODABLE_DAMAGED` (:func:`judge_undecodable_candidate`): a template
    ASH could not decode and a damaged one both count, since only MISSING cannot
    hide a template; a file that is not CloudFormation does not."""
    return (
        judge_undecodable_candidate(template_path, scan_root)
        != UNDECODABLE_NOT_A_TEMPLATE
    )


def get_model_from_template_text(
    text: str, template_path: Path | str
) -> CloudFormationTemplateModel | None:
    """:func:`get_model_from_template` for text already read; ``template_path`` names it.

    A text that opens with ``{`` (:func:`_starts_a_json_object`) is read by the
    JSON parser first, and by YAML only when JSON rejects it. Every JSON document
    is meant to be YAML too, but the two readings differ where it matters: YAML
    forbids a tab where JSON allows one, and YAML decodes a ``\\uD83D\\uDE00``
    escape pair as two lone surrogates where JSON means the one character they
    encode, so a JSON template read as YAML could carry text no JSON writer
    accepts. Any other text is read as YAML, and as JSON when YAML rejects it. The
    YAML loader is cfn_tools' with date-like scalars read as strings
    (:class:`_TemplateLoader`). When both parsers reject the text, text that does not
    parse always raises a ``YAMLError``: a syntax error as the loader raised it, and
    any value the loader could not build as :class:`TemplateConstructorError`. A
    document nested past the loader's recursion limit raises
    :class:`TemplateDocumentError` without a JSON read, and so does JSON nested past
    ``JSON_NESTING_LIMIT``: how deep ``json.loads`` goes depends on the Python
    version and platform, so reading on would make the outcome depend on them too
    (on 3.12 and later it would read such a template, and cdk-nag would spend
    minutes synthesizing it before failing).

    JSON that YAML refused and that has a tab in it is decided as the same text
    with a space for each tab: in valid JSON a raw tab can only be whitespace, so
    that is the same document, and a template indented with tabs is answered as the
    one indented with spaces. So indentation does not decide a template nested near
    the YAML loader's limits (about 330 levels for mappings, about 490 for
    sequences), where YAML would refuse the tabs before it reached the depth and
    leave JSON to decide. A document whose root is a sequence is not a template,
    and is answered None without a parse (:func:`_root_is_a_sequence`).
    """
    if _root_is_a_sequence(text):
        return None
    template: Any = _NOT_READ
    if _starts_a_json_object(text):
        try:
            template = json.loads(_without_bom(text))
        except RecursionError:
            raise TemplateDocumentError(_JSON_TOO_DEEP) from None
        except ValueError:
            # Not JSON after all (a comment, a trailing comma): YAML decides it,
            # and refuses it as it did before, with the JSON reading tried again
            # below for the tab case.
            template = _NOT_READ
        else:
            if _nested_past(template, JSON_NESTING_LIMIT):
                raise TemplateDocumentError(_JSON_TOO_DEEP) from None
    if template is _NOT_READ:
        try:
            template = _load_template_yaml(text)
        except RecursionError:
            raise TemplateDocumentError(
                "it is nested past the YAML loader's recursion limit"
            ) from None
        except Exception as load_error:
            # Broad on purpose, and not silent: every failure is raised again below
            # as a typed YAMLError, and a constructor failure on a template is a
            # failed target.
            try:
                template = json.loads(_without_bom(text))
            except RecursionError:
                raise TemplateDocumentError(_JSON_TOO_DEEP) from None
            except ValueError:
                raise _as_parse_failure(load_error) from None
            if "\t" in text:
                return get_model_from_template_text(
                    text.replace("\t", " "), template_path
                )
            if _nested_past(template, JSON_NESTING_LIMIT):
                raise TemplateDocumentError(_JSON_TOO_DEEP) from None

    # The one question that separates "not CloudFormation" from "CloudFormation this
    # model cannot represent". cfn_tools' loader returns an ODict, which is a dict
    # and therefore a Mapping, so this admits every real template; a `Resources: {}`
    # template stays admitted, as it was before.
    if not isinstance(template, Mapping) or not isinstance(
        template.get("Resources"), Mapping
    ):
        return None

    try:
        return CloudFormationTemplateModel.model_validate(template)
    except Exception as e:
        # Restored from two commented-out debug lines. At WARNING because a template ASH
        # cannot model is a coverage hole rather than noise, and because DEBUG is below
        # the default level -- with the lines commented out this function emitted nothing
        # at any verbosity, so the only record of an unscanned template was a consumer's
        # TRACE line claiming the file was not CloudFormation.
        #
        # Named by file and error type only. The error's text quotes the rejected value
        # out of the template, and this line is written to ash.log.
        ASH_LOGGER.warning(
            f"Template {template_path} carries a Resources mapping but could not be "
            f"modeled as CloudFormation, so no rule will be evaluated against it: "
            f"{describe_parse_error(e)}"
        )
        raise CloudFormationTemplateModelError(template_path, e) from e


#: The suffixes a CloudFormation template candidate carries, in lower case; a
#: candidate's name is matched case-insensitively (``is_template_candidate``), so
#: ``Stack.YAML`` and ``stack.JSON`` are candidates too. ``.template`` is the
#: extension cfn_nag's own template discovery accepts beside the three others.
CFN_CANDIDATE_SUFFIXES = (".json", ".yaml", ".yml", ".template")


def is_template_candidate(name: str | Path) -> bool:
    """Whether a file name carries one of :data:`CFN_CANDIDATE_SUFFIXES`, in any case."""
    return Path(name).name.lower().endswith(CFN_CANDIDATE_SUFFIXES)


def active_global_ignore_paths(context: "PluginContext") -> list:
    """The global ignore paths a scan drops files for, read from the context.

    For a caller that was given no list (a ``nothing_to_scan_reason``): the
    configuration's unexpired ``global_settings.ignore_paths``, and none at all
    under ``--ignore-suppressions``, which is how the orchestrator hands them to
    ``scan()``. The two selections then agree on which files are scanned.
    """
    from automated_security_helper.utils.suppression_matcher import (
        active_ignore_paths,
    )

    if getattr(context, "ignore_suppressions", False):
        return []
    global_settings = getattr(getattr(context, "config", None), "global_settings", None)
    return active_ignore_paths(getattr(global_settings, "ignore_paths", None) or [])


def cloudformation_candidate_files(
    context: "PluginContext",
    target_type: str,
    global_ignore_paths: Iterable[object] | None = None,
) -> list[str]:
    """The files cfn-nag and cdk-nag consider in one tree, as posix paths, sorted.

    Every JSON and YAML file: the scan set for the source tree, without the files
    the global ignore paths ignore, and every file under the work directory for the
    converted tree. Whether a candidate is a template is the second question,
    answered per file by :func:`get_model_from_template_text`. Shared by both
    scanners and by their ``nothing_to_scan_reason``, so the answer "there is
    nothing to scan" comes from the selection the scan makes.

    ``global_ignore_paths`` is the list the scanner's ``scan()`` was given
    (``core/orchestrator.py``: the operator's unexpired entries, and none under
    ``--ignore-suppressions``), matched as ASH matches them when it drops
    findings (``link_exclusions.drop_ignored``). An empty list ignores nothing.
    None, from a caller that has no list (``nothing_to_scan_reason``), reads the
    same list from the context (:func:`active_global_ignore_paths`).
    """
    if target_type == "converted":
        files = [Path(p) for p in Path(context.work_dir).glob("**/*.*")]
    else:
        from automated_security_helper.utils.get_scan_set import (
            honors_ignore_files,
            scan_set,
        )
        from automated_security_helper.utils.link_exclusions import drop_ignored

        if global_ignore_paths is None:
            global_ignore_paths = active_global_ignore_paths(context)
        files = [
            Path(p)
            for p in drop_ignored(
                scan_set(
                    source=os.fspath(context.source_dir),
                    output=os.fspath(context.output_dir),
                    honor_ignore_files=honors_ignore_files(
                        getattr(context, "config", None)
                    ),
                    run_id=getattr(context, "run_id", None),
                    # In a workspace scan the run's recorded scan set is keyed
                    # on this too; without it the tree was walked again.
                    workspace_output_dir=getattr(context, "workspace_output_dir", None),
                ),
                context.source_dir,
                global_ignore_paths,
            )
        ]
    return sorted(path.as_posix() for path in files if is_template_candidate(path))


class _TagTolerantLoader(yaml.SafeLoader):
    """``SafeLoader`` that reads a tag it does not know as the plain node it tags.

    For the one question :func:`_could_be_a_template` asks of a file the template
    parser rejected: is it a mapping with ``Resources``? mkdocs.yml carries
    ``!!python/name:`` tags, which ``SafeLoader`` refuses to construct and which this
    reads as the string after them. Nothing is executed; the base loader is the safe
    one. Date-like scalars are strings here too, as in :class:`_TemplateLoader`, and
    a merge key is bounded the same way (``MERGED_MAPPING_PAIRS_BOUND``).
    """

    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        _flatten_mapping_within_bound(self, super().flatten_mapping, node)


def _construct_untagged(
    loader: yaml.SafeLoader,
    tag_suffix: str,
    node: yaml.ScalarNode | yaml.SequenceNode | yaml.MappingNode,
) -> Any:
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_scalar(node)


_TagTolerantLoader.add_multi_constructor("", _construct_untagged)
_TagTolerantLoader.yaml_implicit_resolvers = _without_the_timestamp_resolver(
    yaml.SafeLoader.yaml_implicit_resolvers
)


def _without_jsonc_comments(text: str) -> str:
    """*text* with ``//`` and ``/* */`` comments removed outside JSON strings."""
    out: list[str] = []
    i, n, in_string = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


#: What a CloudFormation template carries that other YAML and JSON files do not: the
#: format version, or a resource type in either syntax (``Type: AWS::...`` or
#: ``"Type": "AWS::...``).
_CLOUDFORMATION_MARKER = re.compile(
    r"AWSTemplateFormatVersion|[\"']?\bType[\"']?\s*:\s*[\"']?AWS::"
)

#: What :func:`_could_be_a_template`'s lenient read may raise and still answer the
#: question: the loader's own errors, the exceptions SafeLoader's explicit-tag
#: constructors raise on a value they cannot build (``ValueError`` for ``!!int
#: forty-two``, ``KeyError`` for ``!!bool maybe``, ``AttributeError`` for
#: ``!!timestamp nonsense``, ``IndexError`` for ``!!float ""``), ``TypeError`` for a
#: mapping used as a key, and ``RecursionError`` for a document nested past the
#: recursion limit.
_LENIENT_READ_FAILURES = (
    YAMLError,
    TypeError,
    ValueError,
    KeyError,
    AttributeError,
    IndexError,
    RecursionError,
)


def unmarked_wide_template_reason(text: str) -> str | None:
    """For text the template parser rejected: is it a UTF-16 or UTF-32 template
    written without a byte-order mark, read as UTF-8?

    Such a file decodes as UTF-8 without an error, since NUL is valid UTF-8, so its
    text reaches the parsers NUL-interleaved and both reject it; read as what it is,
    it is a template. The scanners record it as a template ASH could not decode, a
    failed, unevaluated target named in the error record, the same answer the
    UnicodeDecodeError route gives the marked twin (:func:`judge_undecodable_candidate`).
    Before this it was named as a template that could not be parsed and counted as
    nothing, and before that dropped at TRACE: a template in the repository that no
    scanner counted.

    Returns the reason for the record, naming the encoding found, or None when the
    text holds no NUL or no reading of it in :data:`_UNMARKED_WIDE_ENCODINGS` is a
    template by its STRUCTURE (:func:`_structure_says_template`): a failed target
    takes a structure read here as on every other route, so a reading that carries
    only a marker is not a reason; :func:`_could_be_a_template` still counts such a
    reading for the tool-absent check and the unparseable record. A reading that
    still holds a NUL is not text of that encoding and is not tried
    (:func:`_wide_readings`).
    """
    for label, reading in _wide_readings(text):
        if _structure_says_template(reading):
            return (
                f"the file is {label} text without a byte-order mark, read as "
                "UTF-8: a CloudFormation template ASH could not decode"
            )
    return None


def _wide_readings(text: str) -> list[tuple[str, str]]:
    """Text that holds a NUL, read again as UTF-16 and UTF-32 in either byte order
    (:data:`_UNMARKED_WIDE_ENCODINGS`): the ``(label, reading)`` pairs whose reading
    holds no NUL. A reading that still holds one is not text of that encoding and is
    left out; text with no NUL has no readings."""
    if "\x00" not in text:
        return []
    raw = text.encode("utf-8", errors="surrogatepass")
    readings = []
    for encoding, label in _UNMARKED_WIDE_ENCODINGS:
        reading = raw.decode(encoding, errors="replace")
        if "\x00" not in reading:
            readings.append((label, reading))
    return readings


def _lenient_document(text: str) -> tuple[bool, Any]:
    """*text* parsed leniently: YAML with unknown tags read as plain nodes, then JSON
    with comments removed. ``(True, document)`` when either reading yields a document,
    ``(False, None)`` when neither does."""
    loader = None
    try:
        # Built inside the try: the reader refuses a non-printable character as
        # the loader is built, and that ReaderError escaping ended cfn-nag's and
        # cdk-nag's whole scan(), the good templates beside the file included.
        loader = _TagTolerantLoader(text)
        document = loader.get_single_data()
    except _LENIENT_READ_FAILURES as error:
        # ValueError: a scalar SafeLoader cannot construct, such as !!int
        # forty-two. KeyError, AttributeError and IndexError: what its other
        # explicit-tag constructors raise on a value they cannot read (!!bool
        # maybe, !!timestamp nonsense, !!float ""). RecursionError: a document
        # nested past the recursion limit. Any one escaping from here ended
        # cfn-nag's and cdk-nag's whole scan(), the good templates beside the
        # file included, since both ask this from inside the except arm that
        # passes over a file they cannot parse. Recorded, by type only: the
        # error's text can quote the document.
        ASH_LOGGER.debug(
            "The lenient read of a candidate the template parser rejected could "
            f"not build the document: {type(error).__name__}; deciding it from "
            "its JSON reading or its text."
        )
    else:
        return True, document
    finally:
        if loader is not None:
            loader.dispose()
    try:
        return True, json.loads(_without_jsonc_comments(_without_bom(text)))
    except (ValueError, RecursionError):
        return False, None


def _structure_says_template(text: str) -> bool:
    """For text the template parser rejected: is its STRUCTURE a template? True when
    a lenient reading (:func:`_lenient_document`) yields a mapping with a ``Resources``
    mapping; False when the root is a sequence, when neither reading yields a
    document, or when the document is not that shape. The marker plays no part: this
    is the read that makes an undecodable candidate a failed target
    (:func:`judge_undecodable_candidate`, :func:`unmarked_wide_template_reason`)."""
    if _root_is_a_sequence(text):
        return False
    parsed, document = _lenient_document(text)
    return (
        parsed
        and isinstance(document, Mapping)
        and isinstance(document.get("Resources"), Mapping)
    )


def _could_be_a_template(text: str) -> bool:
    """For a file the template parser rejected: could it be a damaged template?

    Parsed again, leniently: YAML with unknown tags read as plain nodes, then JSON with
    comments removed. A document either reading yields is a template when it is a
    mapping with a ``Resources`` mapping. A file neither reads is a template when its
    text carries a CloudFormation marker, which a damaged template keeps and a Helm
    chart or a tsconfig.json does not.

    The marker answers only "could this be a damaged template": the reason a
    SKIPPED target gives, and the tool-absent check's MISSING. It never makes a
    file a failed target; that takes a structure read, on every route: the UTF-8
    route's :func:`unevaluable_template_reason` and :func:`_has_top_level_resources`,
    the non-UTF-8 route's :func:`judge_undecodable_candidate` and the unmarked
    UTF-16/UTF-32 route's :func:`unmarked_wide_template_reason`, which both decide
    with :func:`_structure_says_template`. A file whose root is a sequence could not
    be a template, marker or not (:func:`_root_is_a_sequence`).

    A UTF-16 or UTF-32 file written without a byte-order mark decodes as UTF-8
    without an error (NUL is valid UTF-8), so its text arrives here NUL-interleaved
    and carries no readable marker; such a template was skipped as not
    CloudFormation where its marked twin was named. Text that holds a NUL is read
    again in those encodings (:func:`_wide_readings`), and a reading that answers
    True here counts, so the tool-absent check (:func:`holds_cloudformation_template`)
    and the unparseable record keep in step with the failed-target route.
    """
    if any(_could_be_a_template(reading) for _, reading in _wide_readings(text)):
        return True
    if _root_is_a_sequence(text):
        return False
    parsed, document = _lenient_document(text)
    if not parsed:
        return bool(_CLOUDFORMATION_MARKER.search(text))
    return isinstance(document, Mapping) and isinstance(
        document.get("Resources"), Mapping
    )


def holds_cloudformation_template(
    files: Iterable[str | Path], scan_root: Path | str
) -> bool:
    """True when any of *files* is a CloudFormation template either scanner counts.

    The answer decides between SKIPPED and MISSING when the scanner's tool is absent,
    and only MISSING cannot hide a template, so every doubt counts as a template
    except one. A candidate is not a template when it was read and parsed and carries
    no ``Resources`` mapping, when its root is a sequence, when the scanned-tree rule
    refuses it (the scanners skip that file too), or when the template parser rejects
    it and it is not one by :func:`_could_be_a_template`. The last is how the scanners read it with their tool
    installed: they pass over a file that does not parse, and a repository's
    mkdocs.yml, Helm templates and tsconfig.json are such files.

    A template: a document the model cannot represent (the scanners count it as a
    failed target), a candidate that could not be opened, a candidate that is not
    UTF-8 and whose text, decoded as well as it can be, is a template by
    :func:`undecodable_candidate_is_a_template` (one that is not is skipped by the
    scanners too), and a rejected file that parses leniently to a mapping with
    ``Resources`` or whose text carries a CloudFormation marker, which is what a
    damaged template looks like.
    """
    from automated_security_helper.utils.scanned_tree import TreeInputRefused

    for candidate in files:
        try:
            text = read_template_text(candidate, scan_root)
        except TreeInputRefused:
            continue
        except UnicodeDecodeError:
            # Not UTF-8: judged from its text, decoded as well as it can be, as
            # the scanners judge it, so the two answers agree. A second read that
            # fails is answered inside the judgment as a template, the doubt.
            if undecodable_candidate_is_a_template(candidate, scan_root):
                return True
            continue
        except Exception:
            return True
        try:
            if get_model_from_template_text(text, Path(candidate)) is not None:
                return True
            continue
        except CloudFormationTemplateModelError:
            return True
        except Exception:
            pass
        # A template the scanners count as a failed, unevaluated target (its
        # structure is a template and a value in it could not be built, or it is
        # nested deeper than ASH reads) is a template here too, marker or not:
        # otherwise the tool-absent run read SKIPPED where the tool-present run
        # reported a failed target.
        if unevaluable_template_reason(candidate, scan_root, text=text) is not None:
            return True
        if _could_be_a_template(text):
            return True
    return False


class _StructureLoader(yaml.BaseLoader):
    """PyYAML's BaseLoader: every scalar a string, every tag read as the plain node.

    For :func:`_has_top_level_resources`, which asks about the document's shape and
    nothing else, so no value has to be built: ``!!int forty-two`` is the string it
    says. A key that is a mapping or a sequence still cannot be built, since no
    reading of the document can use one as a key.
    """


#: How deep the event read goes under a mapping root before it stops and counts the
#: file. PyYAML's scanner does work proportional to the depth at every token, so a
#: read to the end of a deep document took minutes; past this a mapping root is
#: answered as a template nested too deep to evaluate, whatever it holds, and a
#: syntax error further in is not seen. At 5,000 the read of a hostile file (one
#: line of opening brackets) took 11 to 23.5 s per scanner per file, growing with
#: about the square of the depth to 1,000 or 2,000 levels; at 1,000 it is about a
#: second. A real template is nowhere near 1,000 levels deep.
EVENT_DEPTH_BOUND = 1000


def _top_level_resources_in_events(text: str) -> bool:
    """:func:`_has_top_level_resources` from the YAML event stream.

    PyYAML's parser keeps its own state stack, so it reads a document at any depth
    (measured at 20,000 levels), where its composer and constructors recurse. Only
    the top-level keys are looked at, and the whole stream has to parse. A root that
    is not a mapping is answered at its first event; under a mapping root the read
    stops past ``EVENT_DEPTH_BOUND`` levels and answers True.

    A root ``Resources`` that comes from an alias (``Resources: *shared``) or from a
    top-level merge key is not seen, so such a file stays a skip. CloudFormation
    accepts neither aliases nor merges.
    """
    # One frame per open collection: [is a mapping, its next node is a key].
    stack: list[list[bool]] = []
    key: str | None = None
    found = False
    documents = 0
    root_seen = False

    def node_done() -> None:
        if stack and stack[-1][0]:
            stack[-1][1] = not stack[-1][1]

    try:
        for event in yaml.parse(text, Loader=yaml.BaseLoader):
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
                if documents > 1:
                    return False
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                stack.pop()
                node_done()
            elif isinstance(event, yaml.NodeEvent):
                if not root_seen:
                    root_seen = True
                    if not isinstance(event, yaml.MappingStartEvent):
                        return False
                if len(stack) == 1 and stack[0][0]:
                    if stack[0][1]:
                        key = (
                            event.value if isinstance(event, yaml.ScalarEvent) else None
                        )
                    elif key == "Resources" and isinstance(
                        event, yaml.MappingStartEvent
                    ):
                        found = True
                if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                    stack.append([isinstance(event, yaml.MappingStartEvent), True])
                    if len(stack) > EVENT_DEPTH_BOUND:
                        return True
                else:
                    node_done()
    except YAMLError:
        return False
    return found


def _has_top_level_resources(text: str) -> bool:
    """Whether the document's structure is a template: a top-level Resources mapping.

    Read with :class:`_StructureLoader`, so a value no constructor can build does not
    hide the structure, and from the event stream for a document nested past the
    recursion limit. JSON indented with tabs, which YAML's scanner refuses, is read
    from the event stream with each tab as a space: in valid JSON a raw tab can only
    be whitespace. So is a document nested past the recursion limit, since its first
    tab can come after the depth, where the loader never read it. Only a scanner
    error takes the tab path. A Helm template's ``{{ .Values.name }}:`` key is a
    mapping no reading can use as a key, so its structure cannot be read and the
    file is not a template; when any YAMLError took the path, a tab anywhere in such
    a file, even in a comment, made it a failed target. A root that is a sequence
    is answered at its first node (:func:`_root_is_a_sequence`). Never decided from
    the text: a Helm or Kubernetes file that carries a template as text has a
    CloudFormation marker and no such structure.
    """
    if _root_is_a_sequence(text):
        return False
    loader = None
    try:
        loader = _StructureLoader(text)
        document = loader.get_single_data()
    except RecursionError:
        return _top_level_resources_in_events(text.replace("\t", " "))
    except ScannerError:
        if "\t" in text:
            return _top_level_resources_in_events(text.replace("\t", " "))
        return False
    except Exception:
        return False
    finally:
        if loader is not None:
            loader.dispose()
    return isinstance(document, Mapping) and isinstance(
        document.get("Resources"), Mapping
    )


def unevaluable_template_reason(
    candidate: str | Path, scan_root: Path | str, text: str | None = None
) -> str | None:
    """Why *candidate* is a template ASH could not evaluate, or None when it is not one.

    A template here is a file whose structure is one (a top-level Resources mapping,
    :func:`_has_top_level_resources`), and ASH could not evaluate it when the parser
    read its syntax and could not build a value, or when it is nested deeper than
    ASH reads (the YAML loader's recursion limit, ``JSON_NESTING_LIMIT`` for JSON
    YAML refused for a reason other than tabs, ``EVENT_DEPTH_BOUND`` for the
    structural read). cfn-nag and cdk-nag count such a file as a failed
    target, as they count a template the model rejects
    (CloudFormationTemplateModelError), so the gate sees it.

    None for a syntax error (a damaged template stays a file that could not be
    parsed), for a file whose structure is not a template (a mkdocs.yml with
    ``!!python/name:`` tags, a Helm or Kubernetes file that carries a template as
    text), for one whose structure cannot be read (a sequence used as a key), and for
    one that cannot be read at all.

    Decided from the file, not from the exception a scanner caught, because cdk-nag
    parses in a worker child and only an exception's name and text cross back. Pass
    *text* when it is already read.
    """
    if text is None:
        try:
            text = read_template_text(candidate, scan_root)
        except Exception:
            return None
    try:
        get_model_from_template_text(text, Path(candidate))
    except TemplateConstructorError as error:
        reason = (
            f"a value in the template could not be built: {describe_parse_error(error)}"
        )
    except TemplateDocumentError as error:
        # The message is one of this module's own: the depth, never document text.
        reason = f"ASH could not evaluate the template: {error}"
    except Exception:
        return None
    else:
        return None
    return reason if _has_top_level_resources(text) else None


NO_CLOUDFORMATION_TEMPLATE = "no CloudFormation template in the scanned files"

#: The reason for a target cfn-nag's or cdk-nag's scan() attempted none of when it
#: passed over a candidate it could not parse that could be a template: one
#: holds_cloudformation_template counts, so the same tree without the tool is MISSING
#: and "no template" would not hold. A file that fails the parser and could not be a
#: template (a mkdocs.yml with python tags, a JSONC tsconfig.json, a Helm template)
#: does not count, and a target with no other candidate gets
#: NO_CLOUDFORMATION_TEMPLATE, as the tool-absent path words it (see
#: ScannerPluginBase._nothing_scanned_reason).
NO_PARSEABLE_CLOUDFORMATION_TEMPLATE = (
    "no CloudFormation template it could parse in the scanned files"
)


def cloudformation_nothing_to_scan_reason(context: "PluginContext") -> str | None:
    """``nothing_to_scan_reason`` for cfn-nag and cdk-nag.

    Both trees a scan gives them: the source tree, and the converted tree when the
    work directory holds any file (ScanPhase adds it as a target then).
    """
    trees = [("source", Path(context.source_dir))]
    work_dir = Path(context.work_dir)
    if work_dir.is_dir() and any(work_dir.rglob("*.*")):
        trees.append(("converted", work_dir))
    for target_type, root in trees:
        if holds_cloudformation_template(
            cloudformation_candidate_files(context, target_type), root
        ):
            return None
    return NO_CLOUDFORMATION_TEMPLATE
