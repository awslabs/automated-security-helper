# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The weekly pin check's GitHub lookups survive a 403 to the token.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` sends ``GITHUB_TOKEN`` to the GitHub
releases API only to lift the anonymous rate limit; every endpoint it reads is
public. In the weekly job, the token-carrying request for aquasecurity/trivy's
latest release got 403 on every run, while the same token worked for the other
GitHub lookups and trivy's pin was its latest release, so the job exited 2 (lookup
error) instead of reporting the pins. The cause is not established.

The script now retries a 403 once without the token, logs GitHub's error message
for the next run to show, and never prints the token. These tests pin that and pin
everything that must not change: any other status, a network error, a 403 sent with
no token, and the PyPI and RubyGems lookups. They also pin where the token may go: a
redirect carries it only to the same origin, and a redirect off the allowlisted https
hosts is refused before it is followed.

``tests/unit/test_pinned_tool_version_check.py`` covers the rest of the script. No
test here touches the network. The fake sits at the HTTPS transport, beneath urllib's
own redirect and error handling, so those run for real; anything the test did not
script fails it.
"""

from __future__ import annotations

import email.message
import importlib.util
import io
import json
import socket
import sys
import urllib.error
import urllib.request
import urllib.response
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("_check_pinned_github", SCRIPT)
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Refuse at the transport, which every opener goes through, urlopen's included."""

    def refuse(*args, **kwargs):
        raise AssertionError("a unit test reached the network")

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", refuse)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    # A backstop beneath every transport, the ones not patched above included.
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


# Not a credential; only its absence from the output is asserted.
_FAKE_TOKEN = "unit-test-token-0f3c9a"  # pragma: allowlist secret
_TRIVY = "aquasecurity/trivy"
_TRIVY_LATEST = f"https://api.github.com/repos/{_TRIVY}/releases/latest"

# What the fake transport is told to do with one request: an HTTP status, a body
# (JSON-encoded unless already bytes) and optionally response headers, or an
# exception to raise as the transport would.
Answer = Any


class _FakeTransport:
    """Stands in for the HTTPS (and HTTP) transport; nothing reaches the network.

    Installed as ``HTTPSHandler.https_open``, so urllib's opener, redirect handling
    and error processing all run as they do for real: a 3xx is followed by urllib, a
    4xx or 5xx becomes the ``HTTPError`` urllib raises, with the body on it.
    ``answer(url, headers)`` decides each response. Every request is recorded with
    every header it carried when it was sent, the unredirected ones included.
    """

    def __init__(self, answer: Callable[[str, dict[str, str]], Answer]):
        self.answer = answer
        self.requests: list[tuple[str, dict[str, str]]] = []

    def __call__(self, request):
        headers = dict(request.header_items())
        self.requests.append((request.full_url, headers))
        result = self.answer(request.full_url, headers)
        if isinstance(result, BaseException):
            raise result
        status, body, *extra = result
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        message = email.message.Message()
        for name, value in (extra[0] if extra else {}).items():
            message[name] = value
        response = urllib.response.addinfourl(
            io.BytesIO(payload), message, request.full_url, status
        )
        response.msg = "test"
        return response


def _install(monkeypatch, transport: _FakeTransport) -> _FakeTransport:
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", transport)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", transport)
    return transport


def _in_order(*answers: Answer) -> Callable[[str, dict[str, str]], Answer]:
    pending = list(answers)

    def answer(url: str, headers: dict[str, str]) -> Answer:
        assert pending, f"a request the test did not script: {url}"
        return pending.pop(0)

    return answer


def _trivy_pin():
    return checker.Pin(
        tool="trivy",
        version="v0.75.0",
        ecosystem=checker.GITHUB,
        project=_TRIVY,
        pinned_in=("TOOL_VERSIONS",),
    )


def _with_token(monkeypatch, variable: str = "GITHUB_TOKEN") -> str:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, _FAKE_TOKEN)
    return _FAKE_TOKEN


def _without_token(monkeypatch) -> None:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(name, raising=False)


class TestA403WithTheTokenIsRetriedWithoutIt:
    """One lookup at a time: the retry, what it logs, and what it leaves alone."""

    @pytest.mark.parametrize("variable", ["GITHUB_TOKEN", "GH_TOKEN"])
    def test_403_with_the_token_then_200_without_it_succeeds(
        self, variable, monkeypatch, capsys
    ):
        token = _with_token(monkeypatch, variable)
        opener = _FakeTransport(
            _in_order((403, {"message": "refused"}), (200, {"tag_name": "v0.75.0"}))
        )
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"

        assert len(opener.requests) == 2, opener.requests
        (first_url, first), (retry_url, retry) = opener.requests
        assert first_url == retry_url == _TRIVY_LATEST
        assert first["Authorization"] == f"Bearer {token}"
        assert "Authorization" not in retry
        # Otherwise the retry is the same request.
        assert {k: v for k, v in first.items() if k != "Authorization"} == retry

    def test_403_then_403_is_still_a_lookup_error_that_exits_two(
        self, monkeypatch, capsys
    ):
        _with_token(monkeypatch)
        opener = _FakeTransport(
            _in_order((403, {"message": "first"}), (403, {"message": "second"}))
        )
        _install(monkeypatch, opener)

        results = checker.check([_trivy_pin()])

        assert len(opener.requests) == 2, "exactly one retry, not zero and not a loop"
        [result] = results
        assert result.status == "error"
        assert result.detail.startswith("HTTPError: HTTP Error 403"), result.detail
        assert checker.exit_code(results, fail_on_outdated=False) == checker.EXIT_ERROR
        assert checker.exit_code(results, fail_on_outdated=True) == checker.EXIT_ERROR

    @pytest.mark.parametrize(
        "answer, detail",
        [
            ((401, {"message": "Bad credentials"}), "HTTPError: HTTP Error 401"),
            ((404, {"message": "Not Found"}), "HTTPError: HTTP Error 404"),
            ((429, {"message": "Too Many Requests"}), "HTTPError: HTTP Error 429"),
            ((500, {"message": "Server Error"}), "HTTPError: HTTP Error 500"),
            (urllib.error.URLError("no route to host"), "URLError: <urlopen error"),
        ],
        ids=["401", "404", "429", "500", "url-error"],
    )
    def test_any_other_failure_is_not_retried(
        self, answer, detail, monkeypatch, capsys
    ):
        token = _with_token(monkeypatch)
        opener = _FakeTransport(_in_order(answer))
        _install(monkeypatch, opener)

        results = checker.check([_trivy_pin()])

        assert len(opener.requests) == 1
        assert opener.requests[0][1]["Authorization"] == f"Bearer {token}"
        [result] = results
        assert result.status == "error"
        assert result.detail.startswith(detail), result.detail
        assert checker.exit_code(results, fail_on_outdated=False) == checker.EXIT_ERROR
        assert capsys.readouterr().err == ""

    def test_without_a_token_a_403_is_not_retried(self, monkeypatch, capsys):
        _without_token(monkeypatch)
        opener = _FakeTransport(_in_order((403, {"message": "rate limit exceeded"})))
        _install(monkeypatch, opener)

        results = checker.check([_trivy_pin()])

        assert len(opener.requests) == 1
        assert "Authorization" not in opener.requests[0][1]
        [result] = results
        assert result.status == "error"
        assert result.detail.startswith("HTTPError: HTTP Error 403"), result.detail
        assert checker.exit_code(results, fail_on_outdated=False) == checker.EXIT_ERROR

    def test_an_empty_token_variable_is_no_token(self, monkeypatch, capsys):
        _without_token(monkeypatch)
        monkeypatch.setenv("GITHUB_TOKEN", "")
        opener = _FakeTransport(_in_order((403, {"message": "rate limit exceeded"})))
        _install(monkeypatch, opener)

        [result] = checker.check([_trivy_pin()])

        assert len(opener.requests) == 1
        assert "Authorization" not in opener.requests[0][1]
        assert result.status == "error"

    def test_the_first_403_logs_githubs_message(self, monkeypatch, capsys):
        _with_token(monkeypatch)
        message = "synthetic 403 message from the unit test"
        opener = _FakeTransport(
            _in_order(
                (403, {"message": message, "documentation_url": "https://docs"}),
                (200, {"tag_name": "v0.75.0"}),
            )
        )
        _install(monkeypatch, opener)

        checker.latest_github_release(_TRIVY)

        captured = capsys.readouterr()
        assert message in captured.err
        assert "403 to the authenticated request for repos/aquasecurity/trivy/" in (
            captured.err
        )
        assert captured.out == "", "the log goes to stderr, not into the report"

    def test_the_logged_message_is_truncated_and_stays_on_one_line(
        self, monkeypatch, capsys
    ):
        _with_token(monkeypatch)
        # A message that would start GitHub Actions workflow commands if a newline in
        # it reached the log, and far longer than anyone needs to read.
        message = "first\n::error::injected\r\n::add-mask::x " + "y" * 5000
        opener = _FakeTransport(
            _in_order((403, {"message": message}), (200, {"tag_name": "v0.75.0"}))
        )
        _install(monkeypatch, opener)

        checker.latest_github_release(_TRIVY)

        err = capsys.readouterr().err
        assert "first" in err, "positive control: the message was logged"
        assert len(err.splitlines()) == 1, err
        assert not any(line.lstrip().startswith("::") for line in err.splitlines())
        # Fixed numbers, not the module's limit, so raising the limit fails here.
        assert err.count("y") <= 300
        assert len(err) < 700

    def test_a_token_straddling_the_cut_is_redacted_before_truncation(
        self, monkeypatch, capsys
    ):
        token = _with_token(monkeypatch)
        # The token starts 10 characters before character 300, so truncating first
        # would cut it to its first 10 characters, which redaction then cannot match.
        before = 290
        message = "x" * before + token + "z" * 100
        opener = _FakeTransport(
            _in_order((403, {"message": message}), (200, {"tag_name": "v0.75.0"}))
        )
        _install(monkeypatch, opener)

        checker.latest_github_release(_TRIVY)

        err = capsys.readouterr().err
        assert "<token>" in err, "positive control: the token was redacted"
        assert token[: 300 - before] not in err
        assert token not in err

    @pytest.mark.parametrize(
        "body",
        [b"<html>Forbidden</html>", b"[1, 2]", b'{"message": 7}', b""],
        ids=["not-json", "not-an-object", "message-not-a-string", "empty"],
    )
    def test_a_403_body_with_no_readable_message_still_retries(
        self, body, monkeypatch, capsys
    ):
        _with_token(monkeypatch)
        opener = _FakeTransport(_in_order((403, body), (200, {"tag_name": "v0.75.0"})))
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"
        assert len(opener.requests) == 2
        assert "403" in capsys.readouterr().err

    def test_pypi_and_rubygems_lookups_are_unchanged(self, monkeypatch, capsys):
        _with_token(monkeypatch)
        opener = _FakeTransport(
            _in_order((403, {"message": "pypi"}), (403, {"message": "rubygems"}))
        )
        _install(monkeypatch, opener)

        results = checker.check(
            [
                checker.Pin("bandit", "1.0.0", checker.PYPI, "bandit", ("x",)),
                checker.Pin("cfn-nag", "1.0.0", checker.RUBYGEMS, "cfn-nag", ("x",)),
            ]
        )

        assert [r.status for r in results] == ["error", "error"]
        assert len(opener.requests) == 2, "one request each, no retry"
        assert all("Authorization" not in headers for _, headers in opener.requests)


class TestTheTokenGoesWithARedirectOnlyToItsOrigin:
    """urllib follows a 3xx on its own, and it copies a request's headers to the next hop.

    The token used to be one of those headers, and the allowlist was checked against
    the first URL only, so a 301 from api.github.com to any host received the token.
    Now every hop is checked against the allowlist before urllib follows it, and the
    token goes with a hop only when the hop keeps the scheme, host and port it was
    sent to. GitHub's redirect for a renamed repository is such a hop, and dropping
    the token there made the anonymous rate limit answer 403 on it.
    """

    def _redirect(self, location: str, status: int = 301) -> Answer:
        return (status, b"", {"Location": location})

    @pytest.mark.parametrize(
        "status",
        [
            301,
            302,
            303,
            307,
            pytest.param(
                308,
                marks=pytest.mark.skipif(
                    sys.version_info < (3, 11), reason="urllib follows 308 from 3.11"
                ),
            ),
        ],
    )
    def test_a_redirect_to_another_host_is_refused_and_never_sent(
        self, status, monkeypatch, capsys
    ):
        token = _with_token(monkeypatch)
        elsewhere = "https://elsewhere.example/repos/aquasecurity/trivy/releases/latest"
        opener = _FakeTransport(
            _in_order(self._redirect(elsewhere, status), (200, {"tag_name": "v9.9.9"}))
        )
        _install(monkeypatch, opener)

        results = checker.check([_trivy_pin()])

        assert [url for url, _ in opener.requests] == [_TRIVY_LATEST], (
            "the redirect was followed off the allowlist"
        )
        assert opener.requests[0][1]["Authorization"] == f"Bearer {token}"
        [result] = results
        assert result.status == "error"
        assert result.detail.startswith("ValueError: refusing to fetch"), result.detail
        assert "elsewhere.example" in result.detail
        assert token not in result.detail
        assert checker.exit_code(results, fail_on_outdated=False) == checker.EXIT_ERROR

    @pytest.mark.skipif(
        sys.version_info >= (3, 11), reason="urllib follows 308 from 3.11"
    )
    def test_before_3_11_a_308_is_not_followed_at_all(self, monkeypatch, capsys):
        _with_token(monkeypatch)
        elsewhere = "https://elsewhere.example/repos/aquasecurity/trivy/releases/latest"
        opener = _FakeTransport(_in_order(self._redirect(elsewhere, 308)))
        _install(monkeypatch, opener)

        [result] = checker.check([_trivy_pin()])

        assert [url for url, _ in opener.requests] == [_TRIVY_LATEST]
        assert result.status == "error"
        assert result.detail.startswith("HTTPError: HTTP Error 308"), result.detail

    def test_a_redirect_to_plain_http_is_refused(self, monkeypatch, capsys):
        _with_token(monkeypatch)
        downgraded = "http://api.github.com/repos/aquasecurity/trivy/releases/latest"
        opener = _FakeTransport(_in_order(self._redirect(downgraded)))
        _install(monkeypatch, opener)

        with pytest.raises(ValueError, match="refusing to fetch"):
            checker.latest_github_release(_TRIVY)
        assert [url for url, _ in opener.requests] == [_TRIVY_LATEST]

    def test_a_same_origin_hop_keeps_the_token(self, monkeypatch, capsys):
        """What GitHub answers for a renamed repository: same host, by id."""
        token = _with_token(monkeypatch)
        renamed = "https://api.github.com/repositories/123/releases/latest"
        opener = _FakeTransport(
            _in_order(self._redirect(renamed), (200, {"tag_name": "v0.75.0"}))
        )
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"

        (first_url, first), (hop_url, hop) = opener.requests
        assert (first_url, hop_url) == (_TRIVY_LATEST, renamed)
        assert first["Authorization"] == hop["Authorization"] == f"Bearer {token}"
        assert capsys.readouterr().err == "", "a followed redirect is not a 403"

    def test_a_hop_to_another_allowlisted_host_goes_without_the_token(
        self, monkeypatch, capsys
    ):
        token = _with_token(monkeypatch)
        other = "https://pypi.org/pypi/trivy/json"
        opener = _FakeTransport(
            _in_order(self._redirect(other), (200, {"tag_name": "v0.75.0"}))
        )
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"

        (first_url, first), (hop_url, hop) = opener.requests
        assert (first_url, hop_url) == (_TRIVY_LATEST, other)
        assert first["Authorization"] == f"Bearer {token}"
        assert "Authorization" not in hop
        assert all(token not in value for value in hop.values())
        # The rest of the request survives the hop.
        assert hop["Accept"] == "application/vnd.github+json"

    def test_every_hop_of_a_chain_is_checked(self, monkeypatch, capsys):
        """A check of the first hop alone would follow the second one off the list."""
        token = _with_token(monkeypatch)
        pypi = "https://pypi.org/pypi/trivy/json"
        elsewhere = "https://elsewhere.example/x"
        opener = _FakeTransport(
            _in_order(self._redirect(pypi), self._redirect(elsewhere))
        )
        _install(monkeypatch, opener)

        with pytest.raises(ValueError, match="elsewhere.example"):
            checker.latest_github_release(_TRIVY)

        assert [url for url, _ in opener.requests] == [_TRIVY_LATEST, pypi]
        assert "Authorization" not in opener.requests[1][1]
        assert all(token not in value for value in opener.requests[1][1].values())

    def test_a_token_dropped_on_a_chain_does_not_come_back(self, monkeypatch, capsys):
        """api -> api (same origin) -> pypi -> api: the token on the first two only.

        Once a hop has left the origin, the token is gone for the rest of the chain;
        a later hop back to api.github.com does not recover it.
        """
        token = _with_token(monkeypatch)
        renamed = "https://api.github.com/repositories/123/releases/latest"
        pypi = "https://pypi.org/pypi/trivy/json"
        back = "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v0.75.0"
        opener = _FakeTransport(
            _in_order(
                self._redirect(renamed),
                self._redirect(pypi),
                self._redirect(back),
                (200, {"tag_name": "v0.75.0"}),
            )
        )
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"

        assert [url for url, _ in opener.requests] == [
            _TRIVY_LATEST,
            renamed,
            pypi,
            back,
        ]
        carried = [headers.get("Authorization") for _, headers in opener.requests]
        assert carried == [f"Bearer {token}", f"Bearer {token}", None, None]

    def test_a_403_after_a_redirect_names_the_url_that_answered(
        self, monkeypatch, capsys
    ):
        """The log says the token was refused only when the URL asked for refused it."""
        _with_token(monkeypatch)
        renamed = "https://api.github.com/repositories/123/releases/latest"
        opener = _FakeTransport(
            _in_order(
                self._redirect(renamed),
                (403, {"message": "refused on the hop"}),
                self._redirect(renamed),
                (200, {"tag_name": "v0.75.0"}),
            )
        )
        _install(monkeypatch, opener)

        assert checker.latest_github_release(_TRIVY) == "v0.75.0"

        err = capsys.readouterr().err
        assert repr(renamed) in err and "was redirected to" in err
        assert "authenticated request" not in err
        assert "refused on the hop" in err


class TestTheWeeklyRunWhenOneRepositoryRefusesTheToken:
    """Every real pin, with GitHub refusing the token for trivy alone.

    That is the shape of the failing weekly job: every other lookup succeeds with the
    token, trivy's pin is its latest release, and the run exited 2 on the 403. The run
    is the tool-pin half of main(): ``check`` over ``enumerate_pins``, then
    ``exit_code`` with ``--fail-on-outdated`` and the Markdown report the job writes.
    """

    def _upstreams(self, pins, refuse: Callable[[str, dict[str, str]], bool]):
        """Every upstream answers with the pinned version, unless ``refuse`` says 403."""
        answers: dict[str, Any] = {}
        for pin in pins:
            if pin.ecosystem == checker.GITHUB:
                url = f"https://api.github.com/repos/{pin.project}/releases/latest"
                answers[url] = {"tag_name": pin.version}
            elif pin.ecosystem == checker.PYPI:
                url = f"https://pypi.org/pypi/{pin.project}/json"
                answers[url] = {"info": {"version": pin.version}}
            elif pin.ecosystem == checker.RUBYGEMS:
                url = f"https://rubygems.org/api/v1/versions/{pin.project}/latest.json"
                answers[url] = {"version": pin.version}
            else:
                raise AssertionError(f"no fake upstream for {pin.ecosystem}")
        assert _TRIVY_LATEST in answers, "trivy is no longer a GitHub-release pin"

        def answer(url: str, headers: dict[str, str]) -> Answer:
            if refuse(url, headers):
                return (403, {"message": f"refused, token {_FAKE_TOKEN} echoed"})
            return (200, answers[url])

        return _FakeTransport(answer)

    def _run(self, monkeypatch, capsys, caplog, refuse):
        module = checker.load_pins_module()
        pins = checker.enumerate_pins(module)
        opener = self._upstreams(pins, refuse)
        _install(monkeypatch, opener)
        caplog.set_level("DEBUG")

        results = checker.check(pins)

        code = checker.exit_code(results, fail_on_outdated=True)
        report = checker.render_report(module, results, markdown=True)
        captured = capsys.readouterr()
        log = captured.out + captured.err + caplog.text
        return opener, results, code, report, log

    def test_a_token_refused_for_one_repository_is_not_a_lookup_error(
        self, monkeypatch, capsys, caplog
    ):
        _with_token(monkeypatch)

        opener, results, code, report, log = self._run(
            monkeypatch,
            capsys,
            caplog,
            lambda url, headers: url == _TRIVY_LATEST and "Authorization" in headers,
        )

        assert code == checker.EXIT_OK, report + log
        assert {r.pin.tool: r.status for r in results}["trivy"] == "current"
        trivy_row = next(
            line for line in report.splitlines() if line.startswith("| trivy |")
        )
        assert "| current |" in trivy_row, trivy_row
        unauthenticated = [
            url
            for url, headers in opener.requests
            if url.startswith("https://api.github.com/")
            and "Authorization" not in headers
        ]
        assert unauthenticated == [_TRIVY_LATEST], "only the refused lookup is retried"
        assert _FAKE_TOKEN not in report
        assert _FAKE_TOKEN not in log
        assert "refused, token" in log, "positive control: the message was logged"

    def test_a_retry_that_also_fails_still_exits_two(self, monkeypatch, capsys, caplog):
        _with_token(monkeypatch)

        _, results, code, report, log = self._run(
            monkeypatch, capsys, caplog, lambda url, headers: url == _TRIVY_LATEST
        )

        assert code == checker.EXIT_ERROR
        assert [r.pin.tool for r in results if r.status == "error"] == ["trivy"]
        assert "trivy: lookup failed (HTTPError: HTTP Error 403" in report, report
        assert _FAKE_TOKEN not in report
        assert _FAKE_TOKEN not in log
