# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A text stream that writes no line a CI runner would read as a command.

GitHub Actions reads a line that starts, after whitespace, with "::" as a
workflow command, and its legacy "##[cmd]" form anywhere in a line; Azure
Pipelines reads "##vso[" and TeamCity "##teamcity[". :class:`CommandSafeStream`
checks each line as it is written, after any layout a writer chose: a "::" that
starts a line, after whitespace and color codes, has its first colon written
``\\x3a``, and "##" with an optional name and "[" anywhere has its first "#"
written ``\\x23``. A bare "##", a Markdown heading's, is no command and is left.
On a terminal everything passes as is, except under a runner that reads these
commands (:data:`COMMAND_READING_RUNNERS`), since a CI job can give ASH a
terminal and the runner still reads every line of it.

This module holds the stream, what it calls, and :func:`json_commands_broken`, its
rule for a JSON document's text. Importing it has no other
effect: it imports neither rich nor typer and builds no console, so a module that
wraps a stream can use it without utils/console.py, whose import sets up rich's
global console. utils/console.py builds every console ASH prints through on this
stream.

Limits: a command form split across two writes is not seen.
"""

from __future__ import annotations

import codecs
import io
import os
import re
import threading
from typing import Any, Callable, TextIO

#: A CSI terminal sequence (Rich's color codes, a cursor move), in the full
#: ECMA-48 grammar utils/error_text.py's CSI_CODES reads: parameter bytes
#: "0"-"?" (colon-form SGR and private modes included), intermediate bytes
#: " "-"/", one final byte "@"-"~". The same set on both sides, so a sequence
#: error_text strips before a runner reads the line is one this check skips too.
_CSI = r"\x1b\[[0-?]*[ -/]*[@-~]"

#: An OSC sequence (a terminal hyperlink, a title), ended by BEL, ESC-backslash
#: or U+009C; its body excludes all three so an unterminated one swallows
#: nothing. A runner that drops terminal sequences before it reads a line
#: drops these as well as color codes.
_OSC = r"\x1b\][^\x1b\x07\x9c]*(?:\x07|\x1b\\|\x9c)"

#: Any terminal sequence a runner drops before it reads a command.
_TERMINAL_SEQUENCE = rf"(?:{_CSI}|{_OSC})"

#: What a runner skips at a line start before it reads a command: whitespace other
#: than a line break, and terminal sequences. Also a byte the checked buffer could
#: not decode on its own (surrogateescape's \udc80-\udcff): a space character
#: whose bytes reach the buffer in two writes is checked in two parts, and its
#: first part, emitted alone, must not end the lead, so such a byte leads the
#: line too, which errs on the side of breaking a command.
_LINE_LEAD = re.compile(rf"(?:[^\S\r\n]|{_TERMINAL_SEQUENCE}|[\udc80-\udcff])*")

#: The first character of a line start's command prefix, "::", with any terminal
#: sequences between its two characters: Rich's highlighter colors parts of a
#: word, and a runner that drops color codes before it reads the line reads the
#: prefix whole. A line-start "##" with no name and "[" after it, a Markdown
#: heading's, is no command.
_LINE_START_PREFIX = re.compile(rf"(:)(?=(?:{_TERMINAL_SEQUENCE})*:)")

#: The first "#" of "##" followed by a name and "[" anywhere in a line ("##[cmd]",
#: "##vso["), with terminal sequences allowed anywhere in it, as the highlighter
#: puts a code before a "[" it colors on its own: "##vso\x1b[0m\x1b[32m[".
#: The backslashes before the "#" are taken only from the start of their run
#: (the lookbehind): a match attempted from inside a run reads the same "#"
#: the attempt from its start read, so it can add nothing, and without the
#: lookbehind a line holding a long run of backslashes and no command was
#: scanned once per backslash, each scan walking the rest of the run.
_NAMED_HASH_COMMAND = re.compile(
    rf"(?<!\\)(\\*)#(?=(?:{_TERMINAL_SEQUENCE})*#(?:[A-Za-z]|{_TERMINAL_SEQUENCE})*\[)"
)

#: What a line start's command prefix has its first character written as.
_LINE_START_ESCAPES = {":": "\\x3a"}

#: The ways a runner ends a line.
_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")

#: The variable each runner that reads workflow commands from a job's output sets
#: in every job: GitHub Actions, Azure Pipelines, TeamCity. Container mode and
#: ./ash pass each one that is set into the container, so the scan there checks a
#: terminal's lines too.
COMMAND_READING_RUNNERS = ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION")


def _hash_command_broken(match: re.Match[str]) -> str:
    """The replacement for a :data:`_NAMED_HASH_COMMAND` match: its first "#"
    written ``\\x23``, with the backslashes before it doubled so the escape put in
    its place reads as one. utils/terminal_text.py's hash_command_broken writes
    the same; it is repeated here so this module imports nothing of ASH's."""
    return match.group(1) * 2 + "\\x23"


#: The first "#" of "##" followed by a name and "[", in a JSON document's text. A
#: serializer writes ESC as an escape, so no terminal sequence sits inside one.
_JSON_NAMED_HASH_COMMAND = re.compile(r"#(?=#[A-Za-z]*\[)")


def json_commands_broken(document: str) -> str:
    """*document*, a JSON text, with the first "#" of each "##name[" written ``\\u0023``.

    A runner reads that form anywhere in a line, and the stream's own escape for
    it, ``\\x23``, is no JSON escape, so a document broken that way no longer
    parsed. JSON's escape parses to the same string. A "::" that starts a line
    cannot occur in a JSON text a serializer wrote, at the line ends the stream
    counts (CR, LF and CRLF): each of its lines starts, after its indentation, with
    a quote, a bracket, a brace, a digit or a literal, and a string's CR and LF are
    written as escapes. Not every serializer escapes U+0085, U+2028 and U+2029
    (pydantic's JSON and ``json.dumps(..., ensure_ascii=False)`` write them as they
    are), so a reader that also ended lines at those would find a line start inside
    a string. For JSON that goes to a pipe or a
    CI log: ``ash report``'s JSON reports, a scanner module's SARIF when it is run
    as a script, and each line of ``ash.log.jsonl``.
    """
    return _JSON_NAMED_HASH_COMMAND.sub(lambda _match: "\\u0023", document)


def _is_terminal(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _under_a_command_reading_runner() -> bool:
    return any(os.environ.get(name) for name in COMMAND_READING_RUNNERS)


class _NullStream:
    """Where a wrap writes when its target is None.

    sys.stdout and sys.stderr are None in a process started with no standard
    streams (pythonw, a service with its descriptors closed). Rich's Console
    discards its output then (its NULL_FILE); a wrap whose target lookup
    returns None discards the same way instead of raising AttributeError from
    None's missing ``write``.
    """

    encoding = "utf-8"
    closed = False

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False


_NULL_STREAM = _NullStream()


class CommandSafeStream:
    """A text stream that writes no line a CI runner would read as a command.

    *target* returns the stream to write to, looked up at each write, so a
    console built at import time follows sys.stdout when a test replaces it.

    On a terminal, Rich's Live replaces sys.stdout (and sys.stderr) with a
    FileProxy that prints what is written to it through its console, above the
    live display. A console must write to the file behind that proxy, as Rich's
    own Console does through ``rich_proxied_file``: written into the proxy, a
    console's output went back into a console, which wrote into the proxy again,
    and an interactive scan hung there.
    """

    def __init__(self, target: Callable[[], TextIO], check_buffer: bool = False):
        self._target = target
        # Whether everything written since the last line break is whitespace or
        # terminal sequences, so the next text still starts the line.
        self._at_line_start = True
        # One stream is written from several threads, each under a lock of its
        # own or none: sys.stderr's wrap in MCP server mode takes two Rich
        # consoles' writes, logging's lastResort, the warning and except hooks,
        # and a scan thread's print. Whether the text starts a line is read and
        # set, and the text written, under this lock: a write that read
        # "mid-line" and landed after another thread's line break would put a
        # command at a line start unchecked. Re-entrant, so a write made from
        # inside a write on the same thread (a signal handler's) does not hang.
        # The lock and the line state belong to this wrap, not to the stream
        # below it: a second wrap of the same stream does not share them. While
        # the stdio server serves, fd 1 points at stderr, so sys.stdout's wrap
        # writes to the same file as sys.stderr's with a line state and a buffer
        # of its own, and this lock does not order the two.
        self._lock = threading.RLock()
        # Whether a write of this wrap is under way: from before its text is
        # checked until the text has reached the target, the line state is
        # committed, and the writes deferred meanwhile have landed. A write
        # made then (a signal handler's, on the same thread; the lock is
        # re-entrant) goes into _pending instead of running: run there, its
        # text would land ahead of the outer text, or inside it, at a line
        # state the check never read.
        self._mid_write = False
        # The writes made while _mid_write was set, in order: a text write's
        # text, a buffer write's bytes. The outer write drains them once its
        # own text has landed, each checked from the line state the text
        # before it left, so a deferred write always lands after the outer
        # text, at the state it is checked from.
        self._pending: list[str | bytes] = []
        # check_buffer True has ``buffer`` check bytes (CommandSafeBuffer), for
        # the stderr wrap; the stdout wrap hands the real buffer on, which
        # carries the MCP SDK's JSON-RPC frames, where an inserted escape would
        # corrupt a frame.
        self._checked_buffer = CommandSafeBuffer(self) if check_buffer else None

    @property
    def target(self) -> TextIO:
        target = self._target()
        if target is None:
            # A process with no standard stream: the writes are discarded, as
            # Rich discards them, rather than raised from None.
            return _NULL_STREAM  # type: ignore[return-value]
        return getattr(target, "rich_proxied_file", target)

    @property
    def buffer(self) -> Any:
        # On a target with no buffer (a StringIO, an IDE console) the lookup
        # raises AttributeError, as it would without the wrap: a probe like
        # click's getattr(stream, "buffer", None) then falls back to text,
        # where the view would pass the probe and raise from its first write.
        if self._checked_buffer is not None and hasattr(self.target, "buffer"):
            return self._checked_buffer
        return self.target.buffer

    def isatty(self) -> bool:
        return _is_terminal(self.target)

    def _passes_as_is(self) -> bool:
        return _is_terminal(self.target) and not _under_a_command_reading_runner()

    def write(self, text: str) -> int:
        with self._lock:
            if self._mid_write:
                # A write made from inside a write of this wrap, a signal
                # handler's on the same thread: deferred, so it lands after
                # the outer text instead of ahead of it or inside it.
                self._pending.append(text)
                return len(text)
            if self._checked_buffer is not None:
                # Bytes a buffer write left held land first, where they were
                # written, not after this text.
                self._checked_buffer._emit_held()
            self._mid_write = True
            # A write deferred after the last drain's final empty check,
            # before _mid_write was cleared, is still in _pending with no
            # write under way to drain it. It lands first: it was made
            # before this text, and left to the drain below it would have
            # landed after it. Its error is held, not raised here: raised
            # from the same try as this text's write, a stranded item's
            # error lost the caller's own text on a wrap whose drain had
            # nothing to do with it. The text lands, then the held error.
            stranded = self._land_stranded()
            try:
                written = self._write_text(text)
            except BaseException:
                self._end_write(failed=True)
                raise
            self._end_write(failed=False)
            if stranded is not None:
                raise stranded
            return written

    def _land_stranded(self) -> BaseException | None:
        """Drain the writes stranded in _pending ahead of a new write, returning
        the first error one of them raised instead of raising it, so the write
        that found them can still land its own text. Run with _mid_write set,
        under the lock."""
        try:
            self._drain_pending()
        except BaseException as exc:
            return exc
        return None

    def writelines(self, lines: Any) -> None:
        """Each line through ``write``, under one hold of the lock.

        Defined here rather than left to ``__getattr__``: forwarded, the
        target's own writelines wrote the lines past the check and left this
        wrap's line state where the last ``write`` had put it.
        """
        with self._lock:
            for line in lines:
                self.write(line)

    def _write_text(self, text: str) -> int:
        """Check *text* from the line state and write it, committing the state
        only once the text has reached the stream. Run with _mid_write set,
        under the lock."""
        target = self.target
        if self._passes_as_is():
            written = target.write(text)
            # The line state follows the checked model (_safe), not
            # text.endswith(...): whitespace or a color code after a line
            # break still starts the line, so a later checked write of this
            # wrap (the target lookup can answer another stream) reads the
            # state the check would have left. Read alone: the checked text
            # itself is not written here.
            self._at_line_start = self._line_state_after(text, self._at_line_start)
            return written
        safe, at_line_start = self._safe(text, self._at_line_start)
        target.write(safe)
        self._at_line_start = at_line_start
        return len(text)

    def _drain_pending(self) -> None:
        """Write what was deferred while _mid_write was set, in order, each
        checked from the line state the text before it left. Run with
        _mid_write still set, so a write made while an item lands is deferred
        and drained by this same loop. An item whose write raises does not
        strand the items after it: the drain goes on, and the first such
        error is raised once the list is empty. Stranded items would land
        after some later write's text, or never. A KeyboardInterrupt raised
        while an item lands is held the same way: the items after it still
        land, and it is raised once the list is empty."""
        error: BaseException | None = None
        if self._checked_buffer is not None and any(
            isinstance(item, str) for item in self._pending
        ):
            # Bytes a buffer write left held land first, where they were
            # written, as write() has them land before its own text: once, at
            # the start, ahead of every deferred item. Emitted only right
            # before the first deferred TEXT item, the tail landed after the
            # deferred BYTE items before it (b"caf\xc3" then [b"B2", "T"] wrote
            # caf, B2, \xc3, T), neither where it was written nor joined to the
            # rest of its character.
            self._checked_buffer._emit_tail()
        while self._pending:
            item = self._pending.pop(0)
            try:
                if isinstance(item, str):
                    if self._checked_buffer is not None:
                        # A text item deferred while this drain ran, after a
                        # byte item landed: the tail is already out (above), so
                        # this is a no-op unless a write since then held one.
                        self._checked_buffer._emit_tail()
                    self._write_text(item)
                elif self._checked_buffer is not None:
                    # Bytes defer only through the wrap's own buffer view.
                    self._checked_buffer._write_bytes(item, deferred=True)
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    def _end_write(self, failed: bool) -> None:
        """Drain the deferred writes and clear _mid_write, ending a write of
        this wrap. When that write itself raised (*failed*), a drain error is
        dropped: the caller acts on the error of the write it made."""
        try:
            self._drain_pending()
        except Exception:
            if not failed:
                raise
        finally:
            self._mid_write = False

    def _safe(self, text: str, at_line_start: bool) -> tuple[str, bool]:
        """*text* with its command forms broken when *at_line_start* starts it,
        and whether the next text starts a line. State goes in and comes out so
        the caller commits it only once the text has reached the stream."""
        pieces = _LINE_BREAK.split(text)
        for index in range(0, len(pieces), 2):
            if index:
                at_line_start = True
            # A "##name[" anywhere, then a "::" that starts the line.
            piece = _NAMED_HASH_COMMAND.sub(_hash_command_broken, pieces[index])
            if at_line_start:
                # _LINE_LEAD can match nothing, so it matches every piece.
                lead_match = _LINE_LEAD.match(piece)
                lead = lead_match.end() if lead_match else 0
                prefix = _LINE_START_PREFIX.match(piece, lead)
                if prefix is not None:
                    escape = _LINE_START_ESCAPES[prefix.group(1)]
                    piece = piece[:lead] + escape + piece[lead + 1 :]
                if lead < len(piece):
                    at_line_start = False
            pieces[index] = piece
        return "".join(pieces), at_line_start

    @staticmethod
    def _line_state_after(text: str, at_line_start: bool) -> bool:
        """Whether the next text starts a line once *text* has been written: the
        state :meth:`_safe` would leave, read without building the checked text.

        For a write that passes as is (no runner reads this stream), only the
        state is needed, and ``_safe`` was run whole to read its second value.
        The answer is the same: a line break puts the following piece at a line
        start, and a piece with anything past its lead (whitespace, terminal
        sequences, escaped bytes) ends one. The hash-command substitution is
        applied to the last piece first, as ``_safe`` applies it: a terminal
        sequence whose intermediate bytes are ``##`` and whose final byte is
        ``[`` is lead unbroken and text once its first ``#`` is escaped, so the
        raw piece and the checked piece disagree on where the lead ends. The
        colon escape puts non-lead text in the place of one non-lead character
        past the lead, so it cannot move the answer.
        """
        pieces = _LINE_BREAK.split(text)
        if len(pieces) > 1:
            at_line_start = True
        last = _NAMED_HASH_COMMAND.sub(_hash_command_broken, pieces[-1])
        if at_line_start:
            lead_match = _LINE_LEAD.match(last)
            lead = lead_match.end() if lead_match else 0
            if lead < len(last):
                at_line_start = False
        return at_line_start

    def retargeted(self, replace: Callable[[TextIO], TextIO]) -> "CommandSafeStream":
        """A new wrap, with this wrap's buffer rule, of what *replace* makes of
        this wrap's target (utils/log.py's Windows UTF-8 fallback, whose
        replacement detaches the stream it is given).

        Under this wrap's lock: bytes a buffer write left held, and a write
        stranded in _pending after the last drain (see ``write``), are written
        to the old target first, so they are not dropped with it, and no write
        of this wrap can land between that and the replacement. This wrap is
        not usable after a *replace* that detached its target.
        """
        with self._lock:
            if self._checked_buffer is not None:
                # _emit_held drains the stranded writes too.
                self._checked_buffer._emit_held()
            elif self._pending and not self._mid_write:
                # As flush() lands a stranded write: left in the old wrap, it
                # went with it.
                self._mid_write = True
                self._end_write(failed=False)
            new_target = replace(self.target)
        return CommandSafeStream(
            lambda: new_target, check_buffer=self._checked_buffer is not None
        )

    def flush(self) -> None:
        with self._lock:
            if self._checked_buffer is not None:
                # A flush right before an exit (os._exit after a stop) is the
                # last chance for bytes a buffer write left held.
                self._checked_buffer._emit_held()
            elif self._pending and not self._mid_write:
                # A write stranded in _pending after the last drain (see
                # write()) lands on the flush too, so a flush right before an
                # exit does not drop it.
                self._mid_write = True
                self._end_write(failed=False)
            flush = getattr(self.target, "flush", None)
            if flush is not None:
                flush()

    def fileno(self) -> int:
        return self.target.fileno()

    def __copy__(self) -> "CommandSafeStream":
        """A fresh wrap of the same target, with the same buffer rule.

        A shallow copy shared this wrap's lock, its list of deferred writes and
        its checked buffer view (whose owner stayed this wrap), while text written
        through the copy used the copy's own line state: two line models over one
        stream, and a write on the copy drained items this wrap had deferred in
        the middle of its own write, the order deferral exists to keep. A new wrap
        has a line state, a lock and a pending list of its own, as a second wrap
        of one stream always has.
        """
        return CommandSafeStream(
            self._target, check_buffer=self._checked_buffer is not None
        )

    @property
    def encoding(self) -> str:
        return getattr(self.target, "encoding", None) or "utf-8"

    def __getattr__(self, name: str) -> Any:
        # Never hand Rich the stream behind this one: Console reads
        # ``rich_proxied_file`` to find the real file under Live's redirect, and
        # would then write past the check. This stream does that lookup itself,
        # in ``target``.
        #
        # Nor a private name: ``target`` reads ``self._target``, so on an
        # instance that has no ``__dict__`` yet (copy.copy builds one and
        # looks its attributes up before it fills them in) the lookup of
        # ``_target`` came back here, read ``target`` again, and recursed
        # until RecursionError. A private attribute is this wrap's own, never
        # forwarded. Nor ``target`` itself: it is a property of this class,
        # so a lookup of it reaches here only when the property raised
        # AttributeError (``_target`` not set yet, on that same half-made
        # instance), and reading ``self.target`` to forward it would recurse
        # the same way.
        if name == "target" or name.startswith(("rich_", "_")):
            raise AttributeError(name)
        return getattr(self.target, name)


def _encoded(text: str) -> bytes:
    """The bytes a checked byte write sends for *text*: its own bytes, with a
    byte UTF-8 does not read ridden through as the surrogate it decoded to."""
    return text.encode("utf-8", "surrogateescape")


class CommandSafeBuffer(io.BufferedIOBase):
    """The byte side of a CommandSafeStream whose buffer is checked.

    It writes to the buffer of the wrap's own target, under the wrap's lock and
    line state, so text through the wrap and bytes through this stay one line
    model. The bytes are decoded as UTF-8 with surrogateescape only to find
    command forms, and encoded the same way back, so every byte outside an
    inserted escape is written as it was, whatever the bytes hold: valid UTF-8
    comes back byte-identical, and a byte UTF-8 does not read rides a lone
    surrogate through. An incomplete multi-byte sequence at a write's end is
    held until the next write or flush, as a text layer holds it.
    """

    def __init__(self, owner: CommandSafeStream):
        self._owner = owner
        self._decoder = codecs.getincrementaldecoder("utf-8")("surrogateescape")

    def _target_buffer(self) -> Any:
        return self._owner.target.buffer

    def writable(self) -> bool:
        return True

    def write(self, data: Any) -> int:
        owner = self._owner
        with owner._lock:
            # Through memoryview, so what a buffered writer rejects with
            # TypeError is rejected here too: bytes(5) is five NUL bytes and
            # bytes([1, 2]) two bytes, which no real buffer would accept.
            given = bytes(memoryview(data))
            if owner._mid_write:
                # A byte write made from inside a write of this wrap, a signal
                # handler's on the same thread: deferred, so it lands after
                # the outer text instead of ahead of it or inside it.
                owner._pending.append(given)
                return len(given)
            owner._mid_write = True
            # As in CommandSafeStream.write: a write stranded in _pending after
            # the last drain lands first, and its error waits for these bytes.
            stranded = owner._land_stranded()
            try:
                written = self._write_bytes(given)
            except BaseException:
                owner._end_write(failed=True)
                raise
            owner._end_write(failed=False)
            if stranded is not None:
                raise stranded
            return written

    def _write_bytes(self, given: bytes, deferred: bool = False) -> int:
        """Check *given* from the line state and write it to the target's
        buffer, committing the state only once the bytes have reached the
        stream. Run with _mid_write set, under the owner's lock."""
        owner = self._owner
        # Text the wrap handed to a text layer that is not write-through
        # (Python's own stderr is line buffered) can still be waiting there.
        # Flushed first, so these bytes land after it, in call order, at the
        # place in the line the check reads them at.
        flush_text = getattr(owner.target, "flush", None)
        if flush_text is not None:
            flush_text()
        target = self._target_buffer()
        if owner._passes_as_is():
            # The bytes an earlier checked write left held (an incomplete
            # character's start) land first, where they were written, as their
            # own bytes; left in the decoder they landed after these bytes, or
            # never. The line state follows the checked model (_safe) over the
            # decoded text, as the text side's pass-as-is path does.
            tail = self._decoder.decode(b"", True)
            self._decoder.reset()
            if tail:
                target.write(_encoded(tail))
            written = target.write(given)
            text = tail + codecs.decode(given, "utf-8", "surrogateescape")
            owner._at_line_start = owner._line_state_after(text, owner._at_line_start)
            return written
        if deferred:
            # A deferred byte write, drained after the write it interrupted:
            # decoded on its own, so it neither takes the tail that write
            # holds as the start of its bytes (the tail belongs with its
            # character's rest, written later) nor leaves a tail of its own
            # in that write's place. An incomplete sequence at its end rides
            # through as escaped bytes, written as they were.
            text = codecs.decode(given, "utf-8", "surrogateescape")
        else:
            text = self._decoder.decode(given)
        safe, at_line_start = owner._safe(text, owner._at_line_start)
        target.write(_encoded(safe))
        owner._at_line_start = at_line_start
        return len(given)

    def _emit_held(self) -> None:
        """Write the bytes the last write left held, an incomplete multi-byte
        sequence's start, to the target. Run before a text write and on each
        flush, under the owner's lock, so the bytes land where they were
        written and a flush right before an exit does not drop them. While a
        write of the owner is under way (this call is a signal handler's
        flush, inside that write) the tail stays held: the write that holds
        it has not reached the target yet, so the tail emitted here would
        land ahead of the text it belongs after, and orphan the character's
        rest. _mid_write is set before the tail is taken from the decoder,
        so a write made between the two (a signal handler's; the target
        lookup is a Python call) is deferred and lands after the tail,
        never between the tail and the line it belongs to."""
        owner = self._owner
        if owner._mid_write:
            return
        owner._mid_write = True
        try:
            self._emit_tail()
        except BaseException:
            owner._end_write(failed=True)
            raise
        owner._end_write(failed=False)

    def _emit_tail(self) -> None:
        """Write the held tail, checked from the line state, with _mid_write
        already set and under the owner's lock: the body of :meth:`_emit_held`,
        also run by the owner's drain before a deferred text item lands, so
        the tail of the byte write that deferred it lands ahead of it."""
        owner = self._owner
        tail = self._decoder.decode(b"", True)
        self._decoder.reset()
        if tail:
            safe, at_line_start = owner._safe(tail, owner._at_line_start)
            self._target_buffer().write(_encoded(safe))
            owner._at_line_start = at_line_start

    def flush(self) -> None:
        # Quiet on a target that is closed or detached, not on a closed view:
        # the target belongs to the wrapped stream, and can be gone while the
        # view is still reachable (a test's teardown, the finalizer's close of
        # a view dropped with its wrap, a reader of a retargeted wrap's view).
        owner = self._owner
        with owner._lock:
            try:
                target = self._target_buffer()
            except (AttributeError, ValueError):
                # The target has no buffer (a StringIO a test put in the
                # stream's place), or raises for one it was detached from.
                return
            if target is None or getattr(target, "closed", False):
                # A detached text layer answers None for its buffer.
                return
            self._emit_held()
            flush = getattr(target, "flush", None)
            if flush is not None:
                flush()

    def close(self) -> None:
        """Mark this view closed, never the stream below.

        io.IOBase.close flushes first, which writes the bytes a byte write left
        held while the target is still open; on a target already closed or
        detached the flush is quiet (above), so the finalizer's close of a view
        dropped with its wrap (a test's teardown, the interpreter's shutdown)
        raises nothing into the unraisable hook.
        """
        if self.closed:
            return
        super().close()

    def fileno(self) -> int:
        return self._target_buffer().fileno()

    def isatty(self) -> bool:
        return self._owner.isatty()

    def __getattr__(self, name: str) -> Any:
        # ``raw`` is the real buffer's unchecked writer: forwarded, it gave a
        # caller of the checked view a byte path past the check. A private
        # name is this view's own (see CommandSafeStream.__getattr__).
        if name.startswith(("rich_", "_")) or name == "raw":
            raise AttributeError(name)
        return getattr(self._target_buffer(), name)
