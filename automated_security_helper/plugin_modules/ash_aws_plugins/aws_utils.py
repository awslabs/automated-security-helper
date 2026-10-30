# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import random
import threading
import time
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

import botocore.config
import botocore.exceptions

from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.redacted_model import value_tuple

if TYPE_CHECKING:
    # The type botocore-stubs gives ``Config(retries=...)``. It is private to
    # the stubs and botocore has no such name at run time, so it is imported
    # for the type checker only.
    from botocore.config import _RetryDict
    from typing_extensions import Self

# Type variable for the return type of the function
T = TypeVar("T")

#: (reporter key, option) pairs already named by :func:`report_missing_setting`
#: in this process. A workspace builds and checks a reporter for each project,
#: and one missing setting should produce one message.
_MISSING_SETTINGS_NAMED: Set[Tuple[str, str]] = set()
_MISSING_SETTINGS_LOCK = threading.Lock()


def reset_missing_setting_notices() -> None:
    """Forget which missing settings were already named (tests)."""
    with _MISSING_SETTINGS_LOCK:
        _MISSING_SETTINGS_NAMED.clear()


def report_missing_setting(
    reporter_key: str, option: str, environment: Sequence[str]
) -> None:
    """Say, once per process, that an enabled reporter lacks a setting it needs.

    For an AWS reporter's ``validate_plugin_dependencies``, before it returns
    False because ``option`` is unset. The report phase then leaves the reporter
    out, and when no output format was requested nothing else names it, so the
    upload the operator turned on would not happen with no word of why. The
    message names the reporter, the option, the ``--config-overrides`` key that
    sets it and the environment variables its default is read from.

    Logged at ERROR so that it is shown under ``--quiet``, like a requested
    format that produces nothing (``report_phase``). The exit code is not
    changed: it stays a verdict on the scanned code. Only names are logged,
    never a value.
    """
    with _MISSING_SETTINGS_LOCK:
        if (reporter_key, option) in _MISSING_SETTINGS_NAMED:
            return
        _MISSING_SETTINGS_NAMED.add((reporter_key, option))
    from_environment = ""
    if environment:
        from_environment = (
            f", or set {' or '.join(environment)} in the environment, which is "
            f"read only when no config sets {option}"
        )
    ASH_LOGGER.error(
        f"Reporter '{reporter_key}' is enabled but does not run: no {option} is "
        f"set. Set it with --config-overrides "
        f"reporters.{reporter_key}.options.{option}=<value>{from_environment}."
    )


#: The most retries an AWS reporter's options allow, and the longest delay in
#: seconds between two attempts, so no config makes a reporter keep calling an
#: API that refuses it for longer than that.
MAX_RETRIES = 10
MAX_RETRY_DELAY_SECONDS = 60

#: Every region name AWS publishes, for the ``aws_region`` option of each AWS
#: reporter: the two-letter areas plus mx and the eusc, us-isof and eu-isoe
#: partitions, with an optional country segment (eusc-de-east-1). One pattern
#: for the three reporters, so a region one accepts is never a configuration
#: error (exit 3) for another. A value refused here is refused as a
#: configuration error, so the pattern errs wide on NAMES. It is anchored at
#: both ends: a pydantic ``pattern`` is a search, not a whole-value match, so an
#: unanchored pattern admitted any value that merely holds a region name
#: ("us-east-1.attacker.example", "us-east-1/x", a trailing newline), and the
#: value ends up in an endpoint hostname.
AWS_REGION_PATTERN = (
    r"^(af|il|ap|ca|eu|me|sa|us|cn|mx|eusc|us-gov|us-iso|us-isob|us-isof|eu-isoe)"
    r"(-[a-z]{2})?-(central|north|(north(?:east|west))|south|south(?:east|west)|east|west)"
    r"-\d{1,2}$"
)


def check_retry_delays(options: Any) -> Any:
    """``options``, refused when its ``base_delay`` exceeds its ``max_delay``.

    For an AWS reporter's options model validator. A model without
    ``max_delay`` is held to ``MAX_RETRY_DELAY_SECONDS``.
    """
    base = getattr(options, "base_delay", None)
    maximum = getattr(options, "max_delay", MAX_RETRY_DELAY_SECONDS)
    if base is not None and base > maximum:
        raise ValueError(f"base_delay ({base}) must not exceed max_delay ({maximum})")
    return options


# The names of the failures a later try can pass: throttling, service faults
# (5xx) and connection failures. It is the one list in this module that decides
# what is transient: ``failure_is_transient`` (the model checks) calls what it
# names transient, and ``retry_with_backoff`` retries by that same function
# (unless a caller passes a list of its own).
# ``InternalServerException`` is the code the Bedrock control plane answers a
# 500 with. ``ConnectionError`` and ``HTTPClientError`` are botocore's base
# classes for a refused connection, a connect or read timeout, and a closed
# connection. A service answer with an HTTP status of 500 or more counts
# whatever its code (``ServiceUnavailableException`` is sent with 503).
RETRYABLE_EXCEPTIONS = [
    "ThrottlingException",
    "Throttling",
    "ThrottledException",
    "RequestThrottledException",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "TransactionInProgressException",
    "RequestLimitExceeded",
    "BandwidthLimitExceeded",
    "LimitExceededException",
    "RequestThrottled",
    "SlowDown",
    "ServiceUnavailable",
    "InternalServerError",
    "InternalServerException",
    "InternalFailure",
    "ServiceFailure",
    "ConnectionError",
    "HTTPClientError",
]

#: How a control-plane ("bedrock") client retries a call when the operator has
#: said nothing: botocore's standard mode retries a throttle, a service fault
#: and a connection failure with backoff and jitter, and ``total_max_attempts``
#: counts the first call, so three is the call and two retries (botocore's
#: ``Config`` documents both keys). It is the only retry a model listing gets:
#: ``ListingsOnce`` makes none of its own, so a throttling control plane
#: receives one sequence of attempts, not two.
CONTROL_PLANE_RETRIES: "_RetryDict" = {"mode": "standard", "total_max_attempts": 3}


def control_plane_client_config(
    max_retries: Optional[int] = None,
) -> botocore.config.Config:
    """The botocore config for a control-plane client. A new config on each
    call, so no client shares a retries dict with another.

    With no ``max_retries`` the retries are ``CONTROL_PLANE_RETRIES``. With the
    reporter's ``max_retries`` option the client makes that many retries after
    the first call, at most ``MAX_RETRIES`` (the most an option allows), so
    ``max_retries: 0`` sends one attempt. The config sets the client's retries
    outright, so it is what decides them, in place of ``AWS_MAX_ATTEMPTS``,
    ``AWS_RETRY_MODE`` and the shared config file.
    """
    retries = CONTROL_PLANE_RETRIES.copy()
    if max_retries is not None:
        retries["total_max_attempts"] = min(max(max_retries, 0), MAX_RETRIES) + 1
    return botocore.config.Config(retries=retries)


#: botocore's own retries, turned off: ``total_max_attempts`` counts the first
#: call, so one is the call and no retry.
NO_CLIENT_RETRIES: "_RetryDict" = {"mode": "standard", "total_max_attempts": 1}


def reporter_client_config() -> botocore.config.Config:
    """The botocore config for a client whose calls the reporter repeats itself,
    with ``retry_with_backoff`` and the reporter's ``max_retries``,
    ``base_delay`` and ``max_delay`` options.

    The client makes one attempt per call. Built with no config, it retries a
    connection failure on its own, five attempts in botocore's legacy mode, and
    ``retry_with_backoff`` repeats that failure as well, so one failure cost
    about five times the attempts ``max_retries`` allows: a slow model held a
    call for many minutes, a write could land twice, and ``max_retries: 0``
    still sent five requests. The config sets the client's retries outright, in
    place of ``AWS_MAX_ATTEMPTS``, ``AWS_RETRY_MODE`` and the shared config
    file, and is new on each call so no client shares a retries dict with
    another.

    This removes botocore's resend inside each of the reporter's attempts. It
    does not make a call once-only: ``retry_with_backoff`` still repeats a read
    timeout, a closed connection and a 5xx answer, and any of them can come
    after the service accepted a write, so a write can be sent up to
    ``max_retries + 1`` times.
    """
    return botocore.config.Config(retries=NO_CLIENT_RETRIES.copy())


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    retryable_exceptions: Optional[List[str]] = None,
    logger: Optional[Any] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator for AWS API calls that implements exponential backoff with jitter.

    Args:
        max_retries: Maximum number of retries before giving up
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        retryable_exceptions: List of exception names that should trigger a
            retry, matched against the exception's class name and the code of
            its answer. Without it, the decision is ``failure_is_transient``
            (``RETRYABLE_EXCEPTIONS``), which also reads the classes the
            exception derives from, so botocore's connection failures count,
            and the HTTP status of a service answer, so a 5xx counts.
        logger: Logger to use for logging retry attempts

    Returns:
        Decorated function with retry logic
    """
    default_names = retryable_exceptions is None
    if retryable_exceptions is None:
        retryable_exceptions = RETRYABLE_EXCEPTIONS

    if logger is None:
        logger = ASH_LOGGER

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            retries = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # Get the exception name
                    exception_name = e.__class__.__name__
                    error_code = None

                    # Extract error code based on exception type
                    if isinstance(e, botocore.exceptions.ClientError):
                        error_code = e.response.get("Error", {}).get("Code")
                    else:
                        error_code = getattr(e, "code", None)

                    # The default list is the one the model checks read, through
                    # the one function that applies it: botocore's connection
                    # failures have no code and a class name of their own, and
                    # are told by the classes they derive from. A list of the
                    # caller's own is matched by class name and code only.
                    if default_names:
                        retryable = failure_is_transient(error_code, e)
                    else:
                        retryable = exception_name in retryable_exceptions or bool(
                            error_code and error_code in retryable_exceptions
                        )
                    should_retry = retries < max_retries and retryable

                    if not should_retry:
                        # If we shouldn't retry, re-raise the exception
                        raise

                    # Calculate delay with exponential backoff and jitter.
                    #
                    # Clamped non-negative deliberately. ``base_delay`` and
                    # ``max_delay`` reach here from reporter config --
                    # CloudWatchLogsReporter and S3Reporter both declare them as
                    # bare ``float`` fields with no lower bound and hand them
                    # straight to this decorator -- so a negative ``max_delay``
                    # made this expression negative, and ``time.sleep`` raises
                    # ValueError on a negative argument. That ValueError is then
                    # swallowed by the broad ``except Exception`` in
                    # ``_create_log_stream_with_retry``, so the retry silently
                    # became zero retries and the log blamed the log stream.
                    #
                    # The floor is 0.0 rather than some small positive number
                    # because ``base_delay=0`` is a legitimate way to ask for
                    # immediate retries; what must not happen is a *negative*
                    # interval reaching sleep, or an exception escaping from the
                    # arithmetic that is supposed to protect a throttled API.
                    delay = max(
                        0.0,
                        min(
                            base_delay * (2**retries) + random.uniform(0, 1),  # nosec B311 — jitter for retry backoff, not security
                            max_delay,
                        ),
                    )

                    # Log the retry
                    logger.warning(
                        f"Retrying due to {exception_name} ({error_code}). "
                        f"Attempt {retries + 1}/{max_retries} after {delay:.2f}s delay"
                    )

                    # Sleep before retrying
                    time.sleep(delay)
                    retries += 1

        return wrapper

    return decorator


#: How a failed listing is named when the failure carried no error code and was
#: not raised by botocore: it was not a service answer and not a client-side
#: failure of the SDK.
UNEXPECTED_LISTING_ERROR = "unexpected error"

#: The ``modelLifecycle.status`` values of a foundation model Bedrock serves:
#: ACTIVE, and LEGACY for a model on its way out that still answers.
SERVED_LIFECYCLES = frozenset({"ACTIVE", "LEGACY"})


def _botocore_error_name(error: BaseException) -> Optional[str]:
    """The class name of a failure botocore raised on the client side (a missing
    credential, a missing region, a refused parameter, a connection failure: the
    SDK raised it and the class says what it is), or None for any other error,
    ``ClientError`` included: that one has a service code."""
    if isinstance(error, botocore.exceptions.BotoCoreError):
        return type(error).__name__
    return None


class AvailableModels(List[Dict[str, Any]]):
    """The list ``get_available_models`` answers. It is an ordinary list; the
    ``failed`` flag says whether the listing itself failed (a throttled or
    refused control-plane call), so an empty list from a failed listing is told
    apart from the list of a region that has no models, as data and not by
    reading any message. ``failure_code`` is the error code the control plane
    answered a failed listing with, or None when the failure was not a service
    error. ``failure_label`` is how the failure is named when it carried no
    code and botocore raised it (the error's class name); None otherwise."""

    failed: bool = False
    failure_code: Optional[str] = None
    failure_label: Optional[str] = None
    #: Whether a failed listing may pass on a later try (``failure_is_transient``
    #: of its error). Derived from ``failure_code`` when the caller gives no
    #: answer of its own; a connection failure has no code and is told apart
    #: only by the caller that saw the error.
    transient: bool = False
    #: True when the failure was already logged at warning: by
    #: ``get_available_models`` for the call that failed, or by an earlier call
    #: of the same walk (``ListingsOnce`` gave this call the kept failure). A
    #: caller that names the failure again logs it quietly, so one failure is one
    #: warning.
    reported: bool = False
    #: How the inference profile listing failed while the foundation-model
    #: listing succeeded: the error code, the botocore class name, or
    #: ``UNEXPECTED_LISTING_ERROR``; None when it succeeded or when the whole
    #: listing failed (then ``failed`` says so). The list then holds the
    #: on-demand models, which the caller can use, and no model reachable only
    #: through a profile, so a model missing from it may still exist.
    profile_listing_failure: Optional[str] = None
    #: ``failure_is_transient`` of the profile listing's error.
    profile_listing_transient: bool = False
    #: Whether the profile listing failed on the client side (a botocore error
    #: with no service answer), as ``ModelCheck.listing_client_side`` reads it.
    profile_listing_client_side: bool = False
    #: Whether the profile listing's failure was logged when this list was
    #: made (``get_available_models`` logs it once, at warning the first time a
    #: walk sees it and at debug when the walk's wrapper hands it back). A
    #: check that names the failure again for one candidate logs it at debug,
    #: so one failed profile listing is one warning, not one per candidate.
    profile_listing_reported: bool = False

    def __init__(
        self,
        models: Iterable[Dict[str, Any]] = (),
        failed: bool = False,
        failure_code: Optional[str] = None,
        reported: bool = False,
        transient: Optional[bool] = None,
        failure_label: Optional[str] = None,
        profile_listing_failure: Optional[str] = None,
        profile_listing_transient: bool = False,
        profile_listing_client_side: bool = False,
        profile_listing_reported: bool = False,
    ):
        super().__init__(models)
        self.failed = failed
        self.failure_code = failure_code
        self.failure_label = failure_label
        self.reported = reported
        self.transient = (
            failed and failure_is_transient(failure_code)
            if transient is None
            else transient
        )
        self.profile_listing_failure = profile_listing_failure
        self.profile_listing_transient = profile_listing_transient
        self.profile_listing_client_side = profile_listing_client_side
        self.profile_listing_reported = profile_listing_reported


def failure_is_transient(
    error_code: Optional[str], error: Optional[BaseException] = None
) -> bool:
    """Whether a control-plane failure may pass on a later try.

    One classification, an allowlist, and it is ``RETRYABLE_EXCEPTIONS``: a
    failure is transient when its error code is a name in that list
    (throttling, a service fault such as ``InternalServerException``) or when
    ``error`` is an exception whose class, or a class it derives from, is a name
    in it (``ConnectionError`` and ``HTTPClientError`` cover botocore's refused
    connection, connect and read timeouts, and closed connection).

    Everything else is NOT transient: a denial, a bad credential, a
    ``ValidationException``, an error code nobody classified, and a failure that
    carried no code and is not a connection failure. An unclassified failure is
    reported as the failure it is and is not asked again: a later try of a call
    that was refused for a reason this module does not know waits for nothing,
    and calling it "not checked" would hide it from the operator. ``retry_with_backoff``
    makes this call to decide a retry when it is given no list of its own, so
    the two agree; a caller's own list is matched by class name and code only.
    botocore's ``SSLError`` derives from ``ConnectionError``, so a TLS failure
    reads as a connection failure here too.

    An error that carries a ``transient`` flag of its own (``True`` or
    ``False``) is told by it, ahead of the code and the classes: it knows what
    it wraps. ``KeptListingFailure`` is such an error. It names the class of a
    connection failure as its code, since a connection failure has no service
    answer, and that name is no entry of the list.

    A service answer whose HTTP status is 500 or more is transient whatever
    its code: the service failed on its side. ``ServiceUnavailableException``
    is such an answer (Bedrock sends it with 503) and is no entry of the list.
    The same code without a status is told by the list alone.
    """
    if error is not None:
        own = getattr(error, "transient", None)
        if isinstance(own, bool):
            return own
    if error_code is not None and error_code in RETRYABLE_EXCEPTIONS:
        return True
    if error is None:
        return False
    if _answered_with_a_server_status(error):
        return True
    return any(kind.__name__ in RETRYABLE_EXCEPTIONS for kind in type(error).__mro__)


def _answered_with_a_server_status(error: BaseException) -> bool:
    """Whether a service answer carries an HTTP status of 500 or more."""
    if not isinstance(error, botocore.exceptions.ClientError):
        return False
    status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return isinstance(status, int) and not isinstance(status, bool) and status >= 500


def _service_error_code(error: BaseException) -> Optional[str]:
    """The error code a ClientError carries, or None for any other error."""
    if not isinstance(error, botocore.exceptions.ClientError):
        return None
    return error.response.get("Error", {}).get("Code")


class KeptListingFailure(botocore.exceptions.ClientError):
    """A listing that failed earlier in the same walk, given again to a later
    call. It is a ``ClientError``, so a caller that handles the client's errors
    handles it the same way: it carries the original error's response and
    operation name, or, when the original was not a service answer (a refused
    connection has no response), a response that names the original's class.
    ``original`` is the error the first caller saw, ``failure_code`` is the
    service code it carried (None when it was not a service answer),
    ``failure_label`` is the class name of a botocore error that carried no
    code (None otherwise) and ``transient`` is what ``failure_is_transient``
    said of it. Raising this in
    place of the first failure is how a caller tells that the failure was
    already reported once for the walk."""

    def __init__(self, original: BaseException, operation_name: str) -> None:
        if isinstance(original, botocore.exceptions.ClientError):
            response = original.response
            operation_name = original.operation_name
        else:
            response = {
                "Error": {
                    "Code": type(original).__name__,
                    "Message": "the listing failed earlier in this walk",
                }
            }
        super().__init__(response, operation_name)
        self.original = original
        self.failure_code = _service_error_code(original)
        self.failure_label = _botocore_error_name(original)
        self.transient = failure_is_transient(self.failure_code, original)

    def __reduce__(self) -> Tuple[Any, ...]:
        """How ``copy`` and ``pickle`` rebuild a kept failure: from its
        original error. ``ClientError`` rebuilds a plain ``ClientError`` from
        the response, which loses the original, the code and the kind, and is
        no longer caught as a ``KeptListingFailure``."""
        return (type(self), (self.original, self.operation_name))


class ListingsOnce:
    """A control-plane client that asks each listing once.

    ``validate_bedrock_model`` lists the models afresh on every call, so a walk
    over a fallback chain made one pair of listing calls per candidate, into a
    control plane that may be throttling already. This wraps the client for one
    walk: the first call of ``list_inference_profiles`` or
    ``list_foundation_models`` goes to the client and its answer, or the error
    it raised, is given again to every later call with the same arguments, so
    every candidate is checked against one listing.

    The wrapper makes one call and does not retry or wait. Retrying a throttle
    or a service fault belongs to the client, which botocore configures where it
    is built (``control_plane_client_config``); a second round here would send
    the client's whole sequence of attempts into a throttling control plane
    again. The first caller sees the error the client raised. A later caller of
    the same listing sees ``KeptListingFailure``, a ``ClientError`` with the
    original's response, so the failure is reported once. Every other attribute
    is the client's own, private ones included; the wrapper hides only its own
    three names and the dunders. The wrapper is for one walk and is dropped with
    it, so the next walk asks again.
    """

    _LISTINGS = ("list_inference_profiles", "list_foundation_models")
    #: The wrapper's own attributes. On an instance whose ``__init__`` never ran
    #: (a copy rebuilt by ``copy``) they are missing, and reading one would come
    #: back to ``__getattr__`` without end, so they are refused there.
    _OWN_NAMES = ("_client", "_answers", "_reported")

    def __init__(self, client: Any) -> None:
        self._client = client
        self._answers: Dict[Any, Tuple[Any, Optional[BaseException]]] = {}
        self._reported: Set[Any] = set()

    def __getattr__(self, name: str) -> Any:
        # The wrapper's own names and the protocol names (__setstate__,
        # __deepcopy__) are not the client's. Any other name is.
        if name in self._OWN_NAMES or (name.startswith("__") and name.endswith("__")):
            raise AttributeError(name)
        attribute = getattr(self._client, name)
        if name not in self._LISTINGS or not callable(attribute):
            return attribute

        def listing(*args: Any, **kwargs: Any) -> Any:
            key = (name, args, tuple(sorted(kwargs.items())))
            try:
                hash(key)
            except TypeError:
                # Arguments that cannot be a key cannot be matched later.
                return attribute(*args, **kwargs)
            if key not in self._answers:
                try:
                    self._answers[key] = (attribute(*args, **kwargs), None)
                except Exception as error:
                    self._answers[key] = (None, error)
            answer, failure = self._answers[key]
            if failure is None:
                return answer
            if key in self._reported:
                raise KeptListingFailure(failure, name)
            self._reported.add(key)
            raise failure

        return listing


def _inference_profile_summaries(
    bedrock_client: Any, summaries: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """Every inference profile summary the control plane lists, over every page.

    ``ListInferenceProfiles`` pages its answer and hands back ``nextToken`` while
    more remain; the first call carries no token, so a client double that takes
    no arguments answers it as before. A page that repeats the token it was
    asked with ends the walk, so a control plane that answers the same page
    twice cannot make this loop without end.

    The summaries are appended to ``summaries`` as each page is read, so a
    caller that hands in its own list keeps the pages read before a later page
    raised (a throttle on page three loses page three, not pages one and two).
    """
    if summaries is None:
        summaries = []
    kwargs: Dict[str, Any] = {}
    seen_tokens: Set[str] = set()
    while True:
        page = bedrock_client.list_inference_profiles(**kwargs)
        summaries.extend(page.get("inferenceProfileSummaries", []) or [])
        token = page.get("nextToken")
        if not token or token in seen_tokens:
            return summaries
        seen_tokens.add(token)
        kwargs = {"nextToken": token}


def _listing_failure_name(error: BaseException) -> str:
    """How a failed listing is named: its service code, else the class name of a
    botocore error, else ``UNEXPECTED_LISTING_ERROR``."""
    kept_code = getattr(error, "failure_code", None)
    kept_label = getattr(error, "failure_label", None)
    if isinstance(error, KeptListingFailure):
        return kept_code or kept_label or UNEXPECTED_LISTING_ERROR
    return (
        _service_error_code(error)
        or _botocore_error_name(error)
        or UNEXPECTED_LISTING_ERROR
    )


def _note_profile_failure_beside(
    profile_failure: Optional[BaseException], values: Iterable[str]
) -> None:
    """When both listings failed, the foundation listing's failure is the
    warning; the profile listing's, which would otherwise be dropped, is named
    beside it at debug so ash.log says which calls failed."""
    if profile_failure is None:
        return
    ASH_LOGGER.debug(
        text_without_values(
            "The inference profile listing had failed too "
            f"({_listing_failure_name(profile_failure)}): "
            f"{error_text(profile_failure, values)}",
            values,
        )
    )


def get_available_models(
    bedrock_client: Any, values: Iterable[str] = ()
) -> AvailableModels:
    """Get available foundation models in the current region

    Returns:
        List of available models with their details, including inference profile ARNs for models
        that only support inference profiles. A listing that failed answers an
        empty list whose ``failed`` flag is set.

    The two listings are asked apart. A failed ``ListInferenceProfiles`` (a
    principal allowed ``ListFoundationModels`` but not that call, a throttle on
    that call alone) used to discard the foundation-model list with it, so every
    on-demand model the caller could list and invoke read as "No available
    models found in the current region". Now the on-demand models are answered
    and the profile listing's failure is carried on ``profile_listing_failure``,
    so a model missing from the list can be told as unchecked rather than as not
    found. The profile listing is read over every page, and a model routed by
    more than one profile (a geographic one and a global one, say) is listed
    once per profile, each entry carrying its profile's ARN.
    """
    values = list(value_tuple(values))
    profile_failure: Optional[BaseException] = None
    profile_summaries: List[Dict[str, Any]] = []
    try:
        final_model_list = []
        model_profile_map: Dict[str, List[Dict[str, Any]]] = {}
        try:
            _inference_profile_summaries(bedrock_client, profile_summaries)
        except Exception as error:
            # Kept for the answer below: the foundation-model listing is still
            # asked (before, this failure failed the whole call and that listing
            # was never asked), and only when it answers is this failure the
            # listing's own news. When both fail, the foundation listing's
            # failure is the one warned and this one is named beside it at
            # debug, so one failed control plane is one warning. The pages read
            # before the failure are kept: a model one of their profiles routes
            # is listed, and only the profiles on the pages never read are not.
            profile_failure = error
        for profile in profile_summaries:
            for model in [
                item
                for item in profile.get("models", [])
                if item.get("modelArn", None) is not None
            ]:
                model_profile_map.setdefault(model["modelArn"], []).append(profile)
        ASH_LOGGER.debug("Fetching available foundation models...")
        # Get foundation models. A LEGACY model is one Bedrock still serves
        # while it is being retired; it answers Converse as an ACTIVE one does,
        # so it is listed too, and an operator who configured it is not told it
        # is unavailable.
        response = bedrock_client.list_foundation_models()
        active_models = [
            item
            for item in response.get("modelSummaries", [])
            if item.get("modelLifecycle", {}).get("status", "NA") in SERVED_LIFECYCLES
            and "TEXT" in item.get("inputModalities", [])
            and "TEXT" in item.get("outputModalities", [])
        ]
        ASH_LOGGER.debug(f"Found {len(active_models)} served foundation models")
        for model in active_models:
            if "ON_DEMAND" in model.get("inferenceTypesSupported", []):
                final_model_list.append(
                    {
                        "modelId": model.get("modelId", "unknown"),
                        "modelName": model.get("modelName", "unknown"),
                        "modelArn": model.get("modelArn", "unknown"),
                        "providerName": model.get("providerName", "unknown"),
                        "inferenceType": "ON_DEMAND",
                    }
                )
            if "INFERENCE_PROFILE" in model.get("inferenceTypesSupported", []):
                # One entry per profile that routes the model: a model under a
                # geographic profile and a global one is reachable by either
                # ID, so neither is reported as not found.
                for profile in model_profile_map.get(
                    model.get("modelArn", "unknown"), []
                ):
                    final_model_list.append(
                        {
                            "modelId": profile["inferenceProfileId"],
                            "modelName": model.get("modelName", "unknown"),
                            "modelArn": model.get("modelArn", "unknown"),
                            "inferenceProfileArn": profile.get("inferenceProfileArn"),
                            "providerName": model.get("providerName", "unknown"),
                            "inferenceType": "INFERENCE_PROFILE",
                        }
                    )

        if profile_failure is None:
            return AvailableModels(final_model_list)
        failure = _listing_failure_name(profile_failure)
        # Named with the foundation listing's own words, so a reader of ash.log
        # finds one shape of line for a failed listing; the suffix says which
        # call failed and what the list still holds.
        if profile_summaries:
            suffix = (
                f"; the inference profile listing failed after {len(profile_summaries)} "
                "profile(s) were read, so models reachable only through an "
                "inference profile on the pages it never read are not listed"
            )
        else:
            suffix = (
                "; the inference profile listing failed, so models reachable only "
                "through an inference profile are not listed"
            )
        if isinstance(profile_failure, KeptListingFailure):
            # Reported when it first came: this call only reads it.
            log = ASH_LOGGER.debug
            transient = profile_failure.transient
            client_side = profile_failure.failure_code is None and bool(
                profile_failure.failure_label
            )
            described = f"the listing failed earlier in this walk ({failure}){suffix}"
        elif isinstance(profile_failure, botocore.exceptions.ClientError):
            log = ASH_LOGGER.warning
            transient = failure_is_transient(failure, profile_failure)
            client_side = False
            message = profile_failure.response.get("Error", {}).get("Message")
            described = (
                f"Bedrock API error when getting available models "
                f"({failure}): {message}{suffix}"
            )
        else:
            log = ASH_LOGGER.warning
            transient = failure_is_transient(None, profile_failure)
            client_side = bool(_botocore_error_name(profile_failure))
            described = (
                "Unexpected error getting available models: "
                f"{error_text(profile_failure, values)}{suffix}"
            )
        log(text_without_values(described, values))
        return AvailableModels(
            final_model_list,
            profile_listing_failure=failure,
            profile_listing_transient=transient,
            profile_listing_client_side=client_side,
            # Logged just above (at warning, or at debug for a failure the
            # walk's wrapper already reported): a check that names it for one
            # candidate logs it quietly.
            profile_listing_reported=True,
        )
    except KeptListingFailure as kept:
        # The failure was reported when it first came; this call only reads it.
        return AvailableModels(
            failed=True,
            failure_code=kept.failure_code,
            reported=True,
            transient=kept.transient,
            failure_label=kept.failure_label,
        )
    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")
        ASH_LOGGER.warning(
            text_without_values(
                f"Bedrock API error when getting available models "
                f"({error_code}): {error_message}",
                values,
            )
        )
        _note_profile_failure_beside(profile_failure, values)
        return AvailableModels(
            failed=True,
            failure_code=error_code,
            reported=True,
            transient=failure_is_transient(error_code, e),
        )
    except Exception as e:
        ASH_LOGGER.warning(
            f"Unexpected error getting available models: {error_text(e, values)}"
        )
        _note_profile_failure_beside(profile_failure, values)
        return AvailableModels(
            failed=True,
            reported=True,
            transient=failure_is_transient(None, e),
            failure_label=_botocore_error_name(e),
        )


#: The area prefix of the cross-region inference profiles the fallback chains
#: are written with. A configured model under another area is looked up by its
#: family as its ``us.`` spelling, and its candidates are answered under its
#: own area; which spellings of a candidate the calling region lists is the
#: walk's question (``candidate_spellings``), never this table's.
_CHAIN_AREA = "us"

#: The model every chain ends in, and the fallback for a model of no known
#: family, under the configured model's area.
_DEFAULT_FALLBACK = "amazon.nova-pro-v1:0"

#: The cross-region inference profile area whose source regions a region's own
#: name prefix places it in: a request from us-gov-west-1 may name ``us-gov.``
#: profiles, one from eu-west-1 ``eu.`` profiles, one from ap-northeast-1
#: ``apac.`` profiles, one from us-east-1 ``us.`` profiles. Longest prefix
#: first (``us-gov-`` before ``us-``). A region of no row here (ca-, sa-, me-,
#: af-, il-, mx-) has no geography spelling of its own in this table; its
#: candidates are checked under their own and the ``us.`` spelling only. Which
#: profiles a source region lists is what ListInferenceProfiles from that
#: region answers, and the walk reads that listing; this table only names the
#: spellings worth asking it about
#: (https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles-support.html:
#: "Don't rely on the geographic prefix in an inference profile ID alone").
_REGION_AREAS = (
    ("us-gov-", "us-gov"),
    ("us-", "us"),
    ("eu-", "eu"),
    ("ap-", "apac"),
)


def region_area(region: Optional[str]) -> Optional[str]:
    """The inference-profile area a region's own name prefix places it in
    (``_REGION_AREAS``), or None for a region of no known geography or no
    region at all. Read case-insensitively."""
    if not region:
        return None
    lowered = region.lower()
    for prefix, area in _REGION_AREAS:
        if lowered.startswith(prefix):
            return area
    return None


def candidate_spellings(model_id: str, region: Optional[str] = None) -> List[str]:
    """The spellings of one chain candidate worth checking against the calling
    region's listing, in the order to check them: the candidate as the chain
    spells it (the configured model's own area), then the same model under the
    region's own geography (``region_area``), then under ``us.``, the area the
    chains are written in; each spelling once. A model id with no area (an
    on-demand id) has one spelling.

    Why more than one: a profile's geographic prefix says nothing about where
    it can be called from (the Bedrock docs say so in as many words), so a
    ``global.`` configured model in us-east-1 needs the ``us.`` spelling of
    its candidates (us-east-1 lists those), a ``us-gov.`` one in GovCloud needs
    the ``us-gov.`` spelling (GovCloud lists no ``us.`` profile), and an
    ``eu.`` one called from us-east-1 needs ``us.`` too. The listing, read once
    per walk, decides; a spelling it does not name costs one dictionary lookup.
    """
    area = _profile_area(model_id)
    if area is None:
        return [model_id]
    rest = model_id[len(area) + 1 :]
    spellings = [model_id]
    for other in (region_area(region), _CHAIN_AREA):
        if other is None or other == area.lower():
            continue
        spelling = f"{other}.{rest}"
        if spelling not in spellings:
            spellings.append(spelling)
    return spellings


def _profile_area(model_id: str) -> Optional[str]:
    """The area prefix of a cross-region inference profile id
    (``eu.anthropic.claude-...`` names ``eu``), or None for a model id with
    none (``anthropic.claude-...``, ``amazon.titan-...``). A profile id is
    ``<area>.<provider>.<model>`` and a model id ``<provider>.<model>``, and no
    provider or model name holds a dot, so the id with two dots has an area."""
    area, _, rest = model_id.partition(".")
    if not area or "." not in rest:
        return None
    return area


def get_fallback_model(current_model_id: str) -> Optional[str]:
    """
    Get a fallback model ID if the current model is unavailable.

    The chains are written as the ``us.`` cross-region profiles. A model under
    another area (``eu.anthropic.claude-...``, ``us-gov.anthropic...``,
    ``global.anthropic...``) is looked up as its ``us.`` spelling, so its
    family's chain is found whatever the area, and its fallback is answered
    under its own area (``eu.anthropic.claude-...``): the operator's geography
    is the first spelling to try. Whether the calling region lists that
    spelling, its own geography's, or the ``us.`` one is the walk's question,
    answered by the listing through ``candidate_spellings``; this function
    only names the next candidate. The area is read case-insensitively and
    the candidates carry the area's own spelling (``US.anthropic...`` gets
    ``us.amazon.nova-...``, never ``US.amazon...``, which Converse does not
    know).

    Args:
        current_model_id: The current model ID that failed

    Returns:
        A fallback model ID: the next model of the current model's chain, the
        chain's first model when the current one is not in it, or the default
        model (``_DEFAULT_FALLBACK``) for a model of no known family and for a
        chain's last member, under the current model's area. The walk ends a
        chain on a repeat, never on None here.
    """
    area = _profile_area(current_model_id)
    area_lower = area.lower() if area is not None else None
    lookup = current_model_id
    if area is not None:
        lookup = f"{_CHAIN_AREA}.{current_model_id[len(area) + 1 :]}"

    def under_area(model: str) -> str:
        if area_lower is None or area_lower == _CHAIN_AREA:
            return model
        if model.startswith(f"{_CHAIN_AREA}."):
            return f"{area_lower}.{model[len(_CHAIN_AREA) + 1 :]}"
        return model

    # Define fallback chains for different model families
    fallback_chains = {
        "anthropic.claude-": [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-3-5-haiku-20241022-v1:0",
        ],
        "us.anthropic.claude-": [
            "us.anthropic.claude-sonnet-4-20250514-v1:0",
            # "us.anthropic.claude-opus-4-20250514-v1:0",
            "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
            "us.anthropic.claude-3-5-sonnet-20240620-v1:0",
        ],
        "amazon.titan-": [
            "amazon.titan-text-express-v1",
            "amazon.titan-text-lite-v1",
        ],
        "us.amazon.nova-": [
            "us.amazon.nova-pro-v1:0",
            "us.amazon.nova-lite-v1:0",
            "us.amazon.nova-micro-v1:0",
        ],
        "us.meta.llama3-": [
            "us.meta.llama3-3-70b-instruct-v1:0",
            "us.meta.llama3-2-1b-instruct-v1:0",
            "us.meta.llama3-2-3b-instruct-v1:0",
            "us.meta.llama3-2-11b-instruct-v1:0",
            "us.meta.llama3-1-8b-instruct-v1:0",
        ],
        "us.meta.llama4-": [
            "us.meta.llama4-scout-17b-instruct-v1:0",
            "us.meta.llama4-maverick-17b-instruct-v1:0",
        ],
    }

    # Find the appropriate fallback chain
    for prefix, models in fallback_chains.items():
        if lookup.startswith(prefix):
            # Find the current model in the chain
            try:
                current_index = models.index(lookup)
                # Return the next model in the chain if available
                if current_index < len(models) - 1:
                    return under_area(models[current_index + 1])
            except ValueError:
                # If the current model isn't in our predefined list,
                # return the first model in the chain
                return under_area(models[0])

    # If no specific fallback chain is found, return a default model
    return under_area(f"{_CHAIN_AREA}.{_DEFAULT_FALLBACK}")


class _ModelCheckType(type):
    """Builds a ModelCheck from its pair and its kind, with no ``__new__`` of its own.

    The tuple is made by tuple's own constructor from the pair, so a copy or a
    pickle, which rebuilds it from ``tuple(check)`` and restores the instance
    dict, gives back the same pair and the same kind.
    """

    def __call__(
        cls,
        is_valid: bool,
        reason: Optional[str] = None,
        transient: bool = False,
        listing_failure: Optional[str] = None,
        listing_client_side: bool = False,
        model_id: Optional[str] = None,
    ) -> Any:
        check = super().__call__((is_valid, reason))
        check.transient = transient
        check.listing_failure = listing_failure
        check.listing_client_side = listing_client_side
        check.model_id = model_id
        return check


# A tuple subclass cannot declare non-empty __slots__ (CPython refuses), so the
# flag below lives in the instance dict.
class ModelCheck(Tuple[bool, Optional[str]], metaclass=_ModelCheckType):  # noqa: SLOT001
    """What ``validate_bedrock_model`` answers: ``(is_valid, reason)``, so a
    caller can unpack it as a pair.

    ``transient`` is set on a False that says nothing about the model: the
    control plane did not give a usable answer (the listing failed, or the
    check itself failed), so a later check can come back True. A False about
    the model (it is not in the list, access is denied, it is not found) is
    not transient. The kind is data the check sets where it knows it; it is
    never read back from the reason, which is text a caller redacts and a
    maintainer rewords.

    ``listing_failure`` is set on a False that came from a failed model listing,
    transient or not: the error code the control plane answered with, else the
    class name of the botocore error that failed it, else
    ``UNEXPECTED_LISTING_ERROR`` for an error outside botocore. It is None for
    every other answer. A caller that names the models a check left unchecked uses it
    to tell a refused listing from a region that does not list the model.

    ``listing_client_side`` is set on a False whose listing botocore failed on the
    client side, so that no service answered it and nothing was refused (a
    missing credential or region, a refused parameter, a failed connection):
    ``listing_failure`` then holds the error's class name. It is False for a
    service's own answer, a denied call included.

    ``model_id`` is set on a True: the model id as the listing spells it, which
    is the id to call Converse with. It differs from the id that was checked
    when the check matched it case-insensitively; the check used to answer
    True then and the caller kept calling with its own spelling, which the
    service does not know. It is None on a False.
    """

    transient: bool
    listing_failure: Optional[str]
    listing_client_side: bool
    model_id: Optional[str]

    if TYPE_CHECKING:
        # The call shape, for a type checker only. At run time the metaclass's
        # __call__ above builds the instance and this class declares no
        # constructor of its own (the shown-text scan refuses a constructor
        # looked up outside the escapers). mypy reads a class's constructor
        # from its own __new__ or __init__ and takes no notice of a metaclass
        # __call__ that returns the class, so without this declaration it
        # checked every ModelCheck(False, reason, transient=...) against
        # tuple's one-iterable constructor: too many arguments, unknown
        # keywords, a bool where an iterable was expected. The declaration
        # mirrors _ModelCheckType.__call__ parameter for parameter; keep the
        # two in step.
        def __new__(
            cls,
            is_valid: bool,
            reason: Optional[str] = None,
            transient: bool = False,
            listing_failure: Optional[str] = None,
            listing_client_side: bool = False,
            model_id: Optional[str] = None,
        ) -> Self: ...


def check_is_transient(check: Any) -> bool:
    """Whether a ``validate_bedrock_model`` answer is a False that may pass:
    the control plane gave no usable answer, so a caller does not count the
    model as gone. An answer that carries no kind (a pair a caller built) is
    about the model."""
    return bool(getattr(check, "transient", False))


def check_listing_failure(check: Any) -> Optional[str]:
    """How the model listing failed, when a ``validate_bedrock_model`` answer is
    a False that came from a failed listing: the error code, the class name of a
    botocore error, or ``UNEXPECTED_LISTING_ERROR`` for any other error. None
    for any other answer, and for a pair a caller built."""
    return getattr(check, "listing_failure", None)


def check_listing_client_side(check: Any) -> bool:
    """Whether a ``validate_bedrock_model`` answer is a False whose listing
    botocore failed on the client side, so that no service answered it. False
    for a service's own answer, for any other answer, and for a pair a caller
    built."""
    return bool(getattr(check, "listing_client_side", False))


def check_model_id(check: Any) -> Optional[str]:
    """The model id a True ``validate_bedrock_model`` answer names, as the
    listing spells it: the id to call Converse with. None for a False, and for
    a pair a caller built."""
    model_id = getattr(check, "model_id", None)
    return model_id if isinstance(model_id, str) and model_id else None


def _profile_listing_failed(
    available_models: Any, shown: str, values: Sequence[str]
) -> ModelCheck:
    """The check's answer for a model the on-demand list does not name while
    the inference profile listing failed: a listing failure about the check
    (the model may be routed by a profile nobody could list), named by how that
    listing failed, never "not found in available models".

    Logged at debug when the listing already reported the failure
    (``profile_listing_reported``), so a walk over a chain of profile models
    logs one failed listing once, not once per candidate; at warning only for a
    list that never reported it."""
    failure = getattr(available_models, "profile_listing_failure", None)
    reason = (
        f"Model {shown} is not an on-demand model in this region and the "
        f"inference profile listing failed: {failure}"
    )
    log = (
        ASH_LOGGER.debug
        if getattr(available_models, "profile_listing_reported", False)
        else ASH_LOGGER.warning
    )
    log(text_without_values(reason, values))
    return ModelCheck(
        False,
        text_without_values(reason, values),
        transient=bool(getattr(available_models, "profile_listing_transient", False)),
        listing_failure=failure,
        listing_client_side=bool(
            getattr(available_models, "profile_listing_client_side", False)
        ),
    )


def validate_bedrock_model(
    bedrock_client: Any,
    model_id: str,
    *,
    values: Iterable[str] = (),
    label: Optional[str] = None,
) -> ModelCheck:
    """
    Validate that a Bedrock model is available and accessible.

    A False comes with a reason; ``check_is_transient`` says whether the
    refusal is about the model or about the check.

    Args:
        bedrock_client: Boto3 Bedrock client
        model_id: The model ID to validate
        values: The values and keys the caller's config read from the
            environment, as for ``error_text``. The model id is a configured
            value, so every line logged here and every returned error string
            (the caller records them) is redacted with these. Given by name
            only.
        label: How the log lines and the error message name the model, when not
            by its ID: the reference a config file wrote for an ID it read from
            the environment (config/environment_record.py). Given by name
            only, so a value passed after the model cannot be taken for the
            label or the label for the values, and printed.

    Returns:
        A ``ModelCheck``: the pair (is_valid, error_message), with the kind of a
        False on its ``transient`` flag.
    """
    shown = label or model_id
    values = list(value_tuple(values))
    try:
        # Get all available models
        available_models = get_available_models(bedrock_client, values)
        if not available_models:
            if getattr(available_models, "failed", False):
                # The listing itself failed, so the list says nothing about
                # the model. The code the control plane answered with says
                # whether a later check can pass: only what
                # ``failure_is_transient`` names can (throttling, a service
                # fault, a connection failure). A denial, a bad credential, a
                # ValidationException and a code nobody classified cannot.
                code = getattr(available_models, "failure_code", None)
                failure_label = getattr(available_models, "failure_label", None)
                failure = code or failure_label or UNEXPECTED_LISTING_ERROR
                reason = f"the model listing failed: {failure}"
                # A failure already logged at warning (by the listing call that
                # failed, or by an earlier candidate of the walk) is not
                # logged at warning again: one failure, one warning.
                log = (
                    ASH_LOGGER.debug
                    if getattr(available_models, "reported", False)
                    else ASH_LOGGER.warning
                )
                log(text_without_values(reason, values))
                return ModelCheck(
                    False,
                    text_without_values(reason, values),
                    transient=bool(
                        getattr(
                            available_models, "transient", failure_is_transient(code)
                        )
                    ),
                    listing_failure=failure,
                    # A class name and no code: botocore raised it before any
                    # service answered.
                    listing_client_side=not code and bool(failure_label),
                )
            if getattr(available_models, "profile_listing_failure", None):
                # No on-demand model, and the profile listing failed: the
                # region may still route the model through a profile.
                return _profile_listing_failed(available_models, shown, values)
            # An empty list from a listing that succeeded is a region with no
            # models, which is about the model.
            ASH_LOGGER.warning("No available models found in the current region")
            return ModelCheck(False, "No available models found in the current region")

        # Extract model IDs from the available models
        available_model_ids = [model.get("modelId") for model in available_models]
        # Converse takes a model's ARN and an inference profile's ARN as a model
        # identifier too, so an ARN the listing carries names a listed model: a
        # foundation-model ARN names an ON_DEMAND entry, a profile ARN an
        # INFERENCE_PROFILE entry. A profile entry carries its model's ARN as
        # well, but Converse refuses that ARN for a model only a profile routes
        # ("with on-demand throughput isn't supported"), so it is not an
        # identifier the check may say yes to.
        listed_arns = set()
        for model in available_models:
            if model.get("inferenceType") == "ON_DEMAND":
                arn = model.get("modelArn")
            else:
                arn = model.get("inferenceProfileArn")
            if arn and arn != "unknown":
                listed_arns.add(arn)

        # Check if the requested model is in the available models
        if model_id in available_model_ids or model_id in listed_arns:
            ASH_LOGGER.debug(text_without_values(f"Model {shown} is available", values))
            return ModelCheck(True, model_id=model_id)

        # If model not found directly, try to find a matching model ID (case
        # insensitive). The answer names the listed spelling: Converse knows
        # that one, not the spelling that was checked.
        for available_id in available_model_ids:
            if available_id and model_id and available_id.lower() == model_id.lower():
                ASH_LOGGER.debug(
                    text_without_values(
                        f"Found model {available_id if label is None else 'one'} "
                        f"matching {shown} (case insensitive)",
                        values,
                    )
                )
                return ModelCheck(True, model_id=available_id)

        # If still not found, check if it's an inference profile model
        for model in available_models:
            if (
                model.get("inferenceType") == "INFERENCE_PROFILE"
                and model.get("modelId") == model_id
            ):
                ASH_LOGGER.debug(
                    text_without_values(
                        f"Model {shown} is available as an inference profile",
                        values,
                    )
                )
                return ModelCheck(True, model_id=model_id)

        if getattr(available_models, "profile_listing_failure", None):
            # The on-demand models were listed and this is not one of them; the
            # profile listing failed, so whether a profile routes it is unknown.
            # That is a listing failure about the check, not "not found".
            return _profile_listing_failed(available_models, shown, values)

        # Model not found in available models
        ASH_LOGGER.warning(
            text_without_values(
                f"Model {shown} not found in available models: {available_model_ids}",
                values,
            )
        )
        return ModelCheck(
            False,
            text_without_values(f"Model {shown} not found in available models", values),
        )

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        error_message = e.response.get("Error", {}).get("Message")

        ASH_LOGGER.warning(
            text_without_values(
                f"Bedrock API error ({error_code}): {error_message}", values
            )
        )

        if error_code == "AccessDeniedException":
            reason = f"Access denied to model {shown}: {error_message}"
        elif error_code == "ResourceNotFoundException":
            reason = f"Model {shown} not found: {error_message}"
        else:
            reason = f"Error validating model {shown}: {error_message}"
        return ModelCheck(
            False,
            text_without_values(reason, values),
            transient=failure_is_transient(error_code, e),
        )
    except Exception as e:
        described = text_without_values(
            f"Unexpected error validating model {shown}: {error_text(e, values)}",
            values,
        )
        ASH_LOGGER.warning(described)
        return ModelCheck(False, described, transient=failure_is_transient(None, e))
