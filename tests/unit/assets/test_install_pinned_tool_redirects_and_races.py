# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Redirects, overlapping installs and overlapping table loads in install-pinned-tool.

* The https requirement was checked on the URL the script was given. urllib
  follows a redirect to ``http://`` as readily as one to ``https://``, so a pinned
  https URL could be fetched over plain http. The opener ``download`` builds now
  refuses a redirect that leaves https, and the refusal exits ``_EXIT_INTEGRITY``
  with one line on standard error. It used to escape as an ``HTTPError``
  traceback with status 1, which with-retry repeats. A Location with a scheme
  CPython refuses outright (``file:``, ``data:``, ``gopher:``) is caught before
  urllib raises its own ``HTTPError`` carrying the whole URL, so it exits the same
  way.
* Two installs of one rules bundle into one directory raced on the last rename: the
  loser failed with "Directory not empty" although the bundle was in place, or with
  "No such file" when the winner had already moved the old directory aside.
* ``load_pins`` swaps entries in ``sys.modules`` and puts them back. Two overlapping
  calls each saved the other's path-loaded modules as the originals, and the later
  restore left the real modules replaced for good.

Nothing here reaches the network or starts a process.
"""

from __future__ import annotations

import email.message
import errno
import hashlib
import importlib.util
import io
import os
import sys
import threading
import types
import urllib.request
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_races", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


class _Response:
    headers: dict = {}

    def __init__(self, body: bytes):
        self._body = body

    def read(self, size: int) -> bytes:
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestARedirectLeavingHttpsIsRefused:
    @staticmethod
    def _redirect(newurl: str):
        handler = installer._HttpsOnlyRedirects()
        request = urllib.request.Request("https://example.invalid/asset.tar.gz")
        return handler.redirect_request(
            request, io.BytesIO(b""), 302, "Found", {}, newurl
        )

    def test_a_redirect_to_plain_http_exits_with_the_integrity_status(self):
        with pytest.raises(SystemExit) as raised:
            self._redirect("http://example.invalid/asset.tar.gz")
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "non-https" in str(raised.value)

    def test_a_redirect_to_another_scheme_exits_with_the_integrity_status(self):
        with pytest.raises(SystemExit) as raised:
            self._redirect("ftp://example.invalid/asset.tar.gz")
        assert raised.value.code == installer._EXIT_INTEGRITY

    def test_the_refusal_prints_one_line_without_the_query_string(self, capsys):
        with pytest.raises(SystemExit):
            self._redirect("http://example.invalid/asset.tar.gz?sig=SECRET-TOKEN")
        printed = capsys.readouterr().err
        assert "http://example.invalid/asset.tar.gz" in printed
        assert "SECRET-TOKEN" not in printed
        assert len(printed.strip().splitlines()) == 1

    def test_the_refusal_prints_the_answering_url_without_its_credentials(self, capsys):
        # Red before: the message began with ``req.full_url`` as it was, so on a chain
        # (a release host's 302 to a signed object URL, which then answers 302 to
        # http) the signed URL's query string and any user name or password in it
        # were printed to standard error.
        signed = (
            "https://user:PASSWORD-IN-URL@objects.example.invalid/asset.tar.gz"
            "?sig=FIRST-HOP-SECRET&X-Amz-Credential=ALSO-SECRET#fragment-secret"
        )
        handler = installer._HttpsOnlyRedirects()
        with pytest.raises(SystemExit) as raised:
            handler.redirect_request(
                urllib.request.Request(signed),
                io.BytesIO(b""),
                302,
                "Found",
                {},
                "http://example.invalid/asset.tar.gz?sig=SECOND-HOP-SECRET",
            )
        assert raised.value.code == installer._EXIT_INTEGRITY
        printed = capsys.readouterr().err
        assert "https://objects.example.invalid/asset.tar.gz answered 302" in printed
        assert "http://example.invalid/asset.tar.gz" in printed
        for secret in (
            "PASSWORD-IN-URL",
            "FIRST-HOP-SECRET",
            "ALSO-SECRET",
            "fragment-secret",
            "SECOND-HOP-SECRET",
        ):
            assert secret not in printed

    def test_the_port_of_both_urls_is_kept(self, capsys):
        # Red before: ``hostname`` drops the port, so http://host:8080/x printed as
        # http://host/x, naming a different server than the one that answered.
        handler = installer._HttpsOnlyRedirects()
        with pytest.raises(SystemExit):
            handler.redirect_request(
                urllib.request.Request("https://one.invalid:8443/a?sig=S1"),
                io.BytesIO(b""),
                302,
                "Found",
                {},
                "http://two.invalid:8080/b?sig=S2",
            )
        printed = capsys.readouterr().err
        assert "https://one.invalid:8443/a answered 302" in printed
        assert "http://two.invalid:8080/b" in printed
        assert "S1" not in printed and "S2" not in printed

    def test_a_target_that_does_not_parse_is_refused_without_being_echoed(self, capsys):
        # Red before: urlsplit raised ValueError ("Invalid IPv6 URL") out of the
        # handler, a traceback with status 1 that with-retry repeats.
        with pytest.raises(SystemExit) as raised:
            self._redirect("http://[::1/secret-path?token=T")
        assert raised.value.code == installer._EXIT_INTEGRITY
        printed = capsys.readouterr().err
        assert "token=T" not in printed
        assert "secret-path" not in printed

    def test_a_plain_url_is_scheme_host_port_and_path_only(self):
        plain = installer._plain_url
        assert plain("https://h.invalid:8443/a/b?q=1#f") == "https://h.invalid:8443/a/b"
        assert plain("https://u:p@h.invalid/a") == "https://h.invalid/a"
        assert plain("file:///etc/passwd?x=1") == "file:///etc/passwd"
        assert plain("http://[::1/x") == "<unparseable URL>"
        assert len(plain("https://h.invalid/" + "a" * 5000)) <= 200

    def test_a_plain_url_leaves_out_the_parameters_of_a_path_segment(self):
        # Red before: urlsplit leaves ``;params`` in the path, so a credential given
        # as a path parameter was printed with the rest of the path.
        plain = installer._plain_url
        assert (
            plain("https://h.invalid/a;sig=PATH-SECRET/b;x=1?q=2")
            == "https://h.invalid/a/b"
        )
        assert plain("https://u:p@h.invalid:8443/a;t=1") == "https://h.invalid:8443/a"
        # Control: a path with no parameters is as it was.
        assert plain("https://h.invalid/a/b/") == "https://h.invalid/a/b/"

    def test_the_status_text_the_server_sent_is_cut_and_cleaned(self, capsys):
        # Red before: the reason phrase was printed as it came, up to the 64 KiB that
        # http.client reads for a line, with its carriage return and terminal escape.
        reason = "Moved\r\x1b[31mRED" + "x" * 70000
        handler = installer._HttpsOnlyRedirects()
        with pytest.raises(SystemExit) as raised:
            handler.redirect_request(
                urllib.request.Request("https://h.invalid/a"),
                io.BytesIO(b""),
                302,
                reason,
                {},
                "http://h.invalid/b",
            )
        printed = capsys.readouterr().err
        for text in (printed, str(raised.value)):
            assert len(text) < 400
            assert "\r" not in text and "\x1b" not in text
            assert "answered 302 Moved[31mRED" in text
        assert len(printed.strip().splitlines()) == 1

    def test_an_ordinary_status_text_is_printed_whole(self, capsys):
        """Control: ``Found`` and ``Moved Permanently`` are not changed."""
        handler = installer._HttpsOnlyRedirects()
        with pytest.raises(SystemExit):
            handler.redirect_request(
                urllib.request.Request("https://h.invalid/a"),
                io.BytesIO(b""),
                301,
                "Moved Permanently",
                {},
                "http://h.invalid/b",
            )
        assert "answered 301 Moved Permanently: refusing" in capsys.readouterr().err

    @staticmethod
    def _answer(
        location: str,
        code: int = 302,
        source: str = "https://h.invalid/x",
        header: str = "Location",
    ):
        """Hand a 3xx response to the handler's ``http_error_<code>``, as urllib does.

        CPython's ``http_error_302`` refuses schemes other than http, https and ftp
        before it calls ``redirect_request``, so only a call through it reaches that
        branch. ``header`` is the header that carries the target: CPython reads
        ``Location``, and ``URI`` when there is none.
        """
        headers = email.message.Message()
        headers[header] = location
        handler = installer._HttpsOnlyRedirects()
        return getattr(handler, f"http_error_{code}")(
            urllib.request.Request(source), io.BytesIO(b""), code, "Found", headers
        )

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    def test_a_file_location_exits_with_the_integrity_status(self, code, capsys):
        # Red before: CPython raised HTTPError naming the whole Location, status 1;
        # and http_error_308 did not exist on this class at all.
        with pytest.raises(SystemExit) as raised:
            self._answer("file:///etc/passwd?token=LOC-SECRET", code)
        assert raised.value.code == installer._EXIT_INTEGRITY
        printed = capsys.readouterr().err
        assert "file:///etc/passwd" in printed
        assert "LOC-SECRET" not in printed

    @pytest.mark.parametrize("location", ["data:text/plain,x", "gopher://h.invalid/x"])
    def test_other_schemes_exit_with_the_integrity_status(self, location):
        with pytest.raises(SystemExit) as raised:
            self._answer(location)
        assert raised.value.code == installer._EXIT_INTEGRITY

    def test_a_location_that_does_not_parse_exits_with_the_integrity_status(self):
        with pytest.raises(SystemExit) as raised:
            self._answer("http://[::1/x?token=T")
        assert raised.value.code == installer._EXIT_INTEGRITY

    @pytest.mark.parametrize(
        "target",
        [
            "file:///etc/passwd?token=URI-SECRET",
            "http://h.invalid/x?token=URI-SECRET",
            "gopher://h.invalid/x?token=URI-SECRET",
        ],
    )
    def test_a_uri_header_is_checked_like_a_location(self, target, capsys):
        # CPython's http_error_302 takes ``URI`` when there is no ``Location``, and
        # then refuses a scheme it does not know with an HTTPError that names the
        # whole URL, the leak this class exists to remove. The handler reads ``URI``
        # too; nothing showed it.
        with pytest.raises(SystemExit) as raised:
            self._answer(target, header="URI")
        assert raised.value.code == installer._EXIT_INTEGRITY
        assert "URI-SECRET" not in capsys.readouterr().err
        assert "URI-SECRET" not in str(raised.value)

    @pytest.mark.parametrize(
        "code",
        [
            301,
            302,
            303,
            307,
            pytest.param(
                308,
                marks=pytest.mark.skipif(
                    sys.version_info < (3, 11),
                    reason="CPython follows a 308 from 3.11 on",
                ),
            ),
        ],
    )
    def test_an_absolute_https_location_is_followed(self, code):
        """Control: GitHub's redirect to its object host, for every code urllib follows."""
        handler = installer._HttpsOnlyRedirects()
        opened = []
        handler.add_parent(
            types.SimpleNamespace(
                open=lambda new, timeout=None: opened.append(new.full_url) or "ok"
            )
        )
        headers = email.message.Message()
        headers["Location"] = "https://objects.example.invalid/asset.tar.gz?sig=S"
        request = urllib.request.Request("https://h.invalid/a")
        request.timeout = 5

        answered = getattr(handler, f"http_error_{code}")(
            request, io.BytesIO(b""), code, "Found", headers
        )

        assert answered == "ok"
        assert opened == ["https://objects.example.invalid/asset.tar.gz?sig=S"]

    @pytest.mark.parametrize(
        ("source", "location", "secrets"),
        [
            (
                "https://user:PASSWORD@h.invalid/a?sig=FIRST#FRAGMENT",
                "http://x.invalid/b?sig=SECOND",
                ["PASSWORD", "FIRST", "FRAGMENT", "SECOND"],
            ),
            (
                "https://h.invalid/x",
                "file:///etc/passwd?token=LOC-SECRET",
                ["LOC-SECRET"],
            ),
            (
                "https://h.invalid/x",
                "http://[::1/secret-path?token=T",
                ["secret-path", "token=T"],
            ),
            (
                "https://h.invalid/x",
                "ftp://user:FTPPASS@x.invalid/f;k=PARAM?q=FTPKEY#FTPFRAG",
                ["FTPPASS", "PARAM", "FTPKEY", "FTPFRAG"],
            ),
        ],
    )
    def test_the_exit_carries_none_of_the_secrets(
        self, source, location, secrets, capsys
    ):
        # Red before: only standard error was read, and the SystemExit the caller
        # sees carries the same message; a secret there reaches whatever prints it.
        headers = email.message.Message()
        headers["Location"] = location
        handler = installer._HttpsOnlyRedirects()
        with pytest.raises(SystemExit) as raised:
            handler.http_error_302(
                urllib.request.Request(source), io.BytesIO(b""), 302, "Found", headers
            )
        assert raised.value.code == installer._EXIT_INTEGRITY
        printed = capsys.readouterr().err
        carried = [str(raised.value), *(str(arg) for arg in raised.value.args)]
        for secret in secrets:
            assert secret not in printed
            assert all(secret not in text for text in carried)

    def test_a_plain_url_keeps_ipv6_brackets_and_does_not_read_the_port(self):
        plain = installer._plain_url
        assert plain("https://[::1]:8443/a") == "https://[::1]:8443/a"
        # ``.port`` raises ValueError for these; the netloc is printed as written.
        assert plain("http://h.invalid:notaport/x") == "http://h.invalid:notaport/x"
        assert plain("http://h.invalid:99999/x") == "http://h.invalid:99999/x"

    def test_a_relative_location_on_https_is_followed(self):
        """Control: the check joins the Location to the request URL, as urllib will."""
        handler = installer._HttpsOnlyRedirects()
        opened = []
        handler.add_parent(
            types.SimpleNamespace(
                open=lambda new, timeout=None: opened.append(new.full_url) or "ok"
            )
        )
        headers = email.message.Message()
        headers["Location"] = "/c?x=1"
        request = urllib.request.Request("https://h.invalid/a/b")
        # OpenerDirector.open sets the timeout; urllib reads it when it follows.
        request.timeout = 5

        answered = handler.http_error_302(
            request, io.BytesIO(b""), 302, "Found", headers
        )

        assert answered == "ok"
        assert opened == ["https://h.invalid/c?x=1"]

    def test_an_answer_with_no_location_is_left_to_urllib(self):
        """Control: nothing to check, and urllib's own handler returns None."""
        handler = installer._HttpsOnlyRedirects()
        answered = handler.http_error_302(
            urllib.request.Request("https://h.invalid/x"),
            io.BytesIO(b""),
            302,
            "Found",
            email.message.Message(),
        )
        assert answered is None

    def test_the_refusal_leaves_download_with_the_integrity_status(
        self, monkeypatch, tmp_path
    ):
        """Not an HTTPError traceback with status 1, which with-retry would repeat."""

        class _Opener:
            def open(self, url, data=None, timeout=None):
                return installer._HttpsOnlyRedirects().redirect_request(
                    urllib.request.Request(url),
                    io.BytesIO(b""),
                    302,
                    "Found",
                    {},
                    "http://example.invalid/x",
                )

        monkeypatch.setattr(
            installer.urllib.request, "build_opener", lambda *handlers: _Opener()
        )

        with pytest.raises(SystemExit) as raised:
            installer.download("https://example.invalid/x", tmp_path / "x")

        assert raised.value.code == installer._EXIT_INTEGRITY
        assert not (tmp_path / "x").exists()

    def test_a_redirect_to_https_is_followed(self):
        """Control: GitHub's 302 to its object host is the redirect this exists for."""
        followed = self._redirect("https://objects.example.invalid/asset.tar.gz")
        assert followed.full_url == "https://objects.example.invalid/asset.tar.gz"

    def test_download_opens_the_url_through_that_handler(self, monkeypatch, tmp_path):
        built = []

        class _Opener:
            def open(self, url, data=None, timeout=None):
                return _Response(b"abc")

        def build_opener(*handlers):
            built.extend(handlers)
            return _Opener()

        monkeypatch.setattr(installer.urllib.request, "build_opener", build_opener)

        digest = installer.download("https://example.invalid/x", tmp_path / "x")

        assert installer._HttpsOnlyRedirects in built
        assert digest == hashlib.sha256(b"abc").hexdigest()


_MEMBERS = {
    "a.guard": b"rule A { }\n",
    "b.guard": b"rule B { }\n",
}


def _contents_digest(members: dict) -> str:
    lines = "".join(
        f"{name}\t{hashlib.sha256(data).hexdigest()}\n"
        for name, data in sorted(members.items())
    )
    return hashlib.sha256(lines.encode("ascii")).hexdigest()


class _BundleSetup:
    """A one-bundle fake table whose archive is served from memory."""

    def __init__(self, monkeypatch, tmp_path: Path):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in _MEMBERS.items():
                archive.writestr(f"output/{name}", data)
        self.archive = buffer.getvalue()
        self.bundle = types.SimpleNamespace(
            name="demo-rules",
            version="1.0.0",
            url="https://example.invalid/rules.zip",
            sha256=hashlib.sha256(self.archive).hexdigest(),
            contents_sha256=_contents_digest(_MEMBERS),
            member_dir="output",
            member_suffix=".guard",
        )
        pins = types.SimpleNamespace(
            ToolNotProvisionableError=LookupError,
            get_rules_bundle=lambda name: self.bundle,
        )
        monkeypatch.setattr(installer, "load_pins", lambda root: pins)

        def download(url, target):
            target.write_bytes(self.archive)
            return hashlib.sha256(self.archive).hexdigest()

        monkeypatch.setattr(installer, "download", download)
        self.rules = tmp_path / "rules"
        self.final = self.rules / "demo-rules-1.0.0"

    def install(self) -> Path:
        return installer.install_bundle("demo-rules", self.rules, Path("unused"))

    def write_winner(self, members: dict) -> None:
        self.final.mkdir(parents=True)
        for name, data in members.items():
            (self.final / name).write_bytes(data)

    def leftovers(self) -> list:
        return sorted(p.name for p in self.rules.iterdir() if p.name != self.final.name)


class TestTwoInstallsOfOneBundle:
    def test_the_loser_of_the_final_rename_finds_the_pinned_rules_and_succeeds(
        self, monkeypatch, tmp_path
    ):
        setup = _BundleSetup(monkeypatch, tmp_path)
        real_replace = installer.os.replace

        def winner_first(src, dst, *args, **kwargs):
            if Path(dst) == setup.final and Path(src).name.startswith(
                ".ash-rules-staging-"
            ):
                setup.write_winner(_MEMBERS)
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(installer.os, "replace", winner_first)

        installed = setup.install()

        assert installed == setup.final
        assert {p.name: p.read_bytes() for p in setup.final.iterdir()} == _MEMBERS
        assert setup.leftovers() == [], "the loser left its staging directory behind"

    def test_a_populated_directory_that_is_not_the_pin_is_still_an_error(
        self, monkeypatch, tmp_path
    ):
        """Control: only the pinned rules count as someone else's finished install."""
        setup = _BundleSetup(monkeypatch, tmp_path)
        real_replace = installer.os.replace

        def stranger_first(src, dst, *args, **kwargs):
            if Path(dst) == setup.final and Path(src).name.startswith(
                ".ash-rules-staging-"
            ):
                setup.write_winner({"a.guard": b"rule changed { }\n"})
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(installer.os, "replace", stranger_first)

        with pytest.raises(OSError) as raised:
            setup.install()

        # Windows reports a directory renamed onto a populated one as a permission
        # error. The product catches every OSError there and decides by comparing
        # the directory with the pin, so it holds the same way; only the errno of
        # the error that is re-raised differs.
        accepted = (errno.ENOTEMPTY, errno.EEXIST)
        if os.name == "nt":
            accepted += (errno.EACCES,)
        assert raised.value.errno in accepted
        assert setup.leftovers() == []

    def test_an_old_directory_moved_aside_by_the_other_install_is_not_an_error(
        self, monkeypatch, tmp_path
    ):
        setup = _BundleSetup(monkeypatch, tmp_path)
        setup.write_winner({"a.guard": b"an older release\n"})
        real_replace = installer.os.replace

        def other_install_got_there(src, dst, *args, **kwargs):
            if Path(src) == setup.final:
                for child in setup.final.iterdir():
                    child.unlink()
                setup.final.rmdir()
                raise FileNotFoundError(errno.ENOENT, "No such file or directory")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(installer.os, "replace", other_install_got_there)

        installed = setup.install()

        assert (installed / "a.guard").read_bytes() == _MEMBERS["a.guard"]
        assert setup.leftovers() == []


class TestOverlappingTableLoads:
    def test_two_calls_do_not_swap_each_others_originals(self, monkeypatch):
        import automated_security_helper.core.exceptions as real_exceptions

        name = "automated_security_helper.core.exceptions"
        real_load = installer._load_by_path
        first_in, release_first = threading.Event(), threading.Event()
        second_in, release_second = threading.Event(), threading.Event()

        def gated(module_name, path):
            module = real_load(module_name, path)
            if module_name == name:
                who = threading.current_thread().name
                if who == "first":
                    first_in.set()
                    assert release_first.wait(30)
                elif who == "second":
                    second_in.set()
                    assert release_second.wait(30)
            return module

        monkeypatch.setattr(installer, "_load_by_path", gated)
        errors: list = []

        def load():
            try:
                installer.load_pins(PACKAGE_ROOT)
            except BaseException as exc:  # reported below, from the test thread
                errors.append(exc)

        first = threading.Thread(target=load, name="first")
        second = threading.Thread(target=load, name="second")
        first.start()
        assert first_in.wait(30)
        second.start()
        # Without the lock the second call reaches its gate while the first still
        # holds the swapped modules, and saves them as its originals. With it, this
        # wait times out: the second call is queued behind the first.
        second_in.wait(1.5)
        release_first.set()
        first.join(30)
        release_second.set()
        second.join(30)

        assert errors == []
        assert not first.is_alive() and not second.is_alive()
        assert sys.modules[name] is real_exceptions, (
            "an overlapping load_pins put a path-loaded exceptions module back as "
            "the real one"
        )
