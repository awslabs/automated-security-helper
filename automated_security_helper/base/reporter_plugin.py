"""Module containing the ReporterPlugin base class.

Workspace mode, and why a reporter has to declare what it does
--------------------------------------------------------------
A workspace scan produces one SARIF run per project, all in one
``AshAggregatedResults``. That shape is new: every reporter in this repository
was written when there was exactly one run, and several of them read
``runs[0]`` and stop. ``github_ghas_reporter`` is the clearest case -- against an
N-run model it emits the first project's findings and drops the rest, with no
error, no warning, and a smaller output file that looks entirely plausible. A
security reporter that under-reports in silence is the worst outcome workspace
mode can have, and it is why no workspace-level report was emitted at all before
this contract existed.

The fix is not to make every reporter merge. Merging is genuinely wrong for
some: an SBOM for N independently versioned deliverables is N SBOMs, and a
reporter that publishes to a shared destination would double-publish. So instead
each reporter *states* what it does with an N-project model, via
:class:`ReporterWorkspaceBehaviour`, and
``automated_security_helper.workspace.reporting`` holds it to that statement.

The default is ``PER_PROJECT``, deliberately
--------------------------------------------
An undeclared reporter -- a third-party plugin, or a new built-in whose author
did not think about workspaces -- gets ``PER_PROJECT``. That is the fail-closed
choice and it is not a refusal: the reporter's per-project artefacts under
``projects/<key>/reports/`` are still produced and still correct, because each
project is scanned as a complete single-project run. All the default withholds
is a workspace-level file the reporter has not said it can produce correctly,
and the driver writes a manifest recording that withholding, so nothing is
silent.

``MERGED`` was rejected as the default because it is fail-open: it hands an
unprepared reporter a shape it has never seen and trusts it. ``UNSUPPORTED`` was
rejected because it would fail an entire workspace run for any external plugin.
"""

from abc import abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, ClassVar, Generic, TypeVar
from typing_extensions import Self

from pydantic import Field, model_validator

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.log import ASH_LOGGER


class ReporterWorkspaceBehaviour(str, Enum):
    """What a reporter does when the model covers more than one project.

    A ``str`` Enum so a declaration reads as its own documentation in a log line
    and in the workspace report manifest, without a lookup table.

    The four members are exhaustive over the useful answers, and each is a
    different claim about *why*:

    ``MERGED``
        One workspace-level artefact covering every project, with the project
        carried inside it -- a column, a field, a section, or a SARIF run. The
        reporter has been shown to handle N runs.

    ``PER_PROJECT``
        No workspace-level artefact. The per-project files the projects' own
        report phases already wrote are the answer. Chosen when merging would be
        wrong rather than merely unimplemented: the consumer ingests against a
        single repository root, or the artefact is an independently versioned
        deliverable, or the reporter publishes a side effect that a second
        invocation would duplicate.

    ``WORKSPACE_SCOPED``
        A workspace-level artefact that is *not* a merge -- it reports on
        workspace-level state only. Distinct from ``MERGED`` because a consumer
        must not read it as covering the projects. ``unused_suppressions`` is the
        only one: merged, it would read the unified file's empty
        ``used_suppressions`` and declare every suppression unused, which is a
        false report rather than an incomplete one.

    ``UNSUPPORTED``
        The reporter refuses to run at workspace level, and the refusal fails the
        run. Reserved for a reporter that can produce neither a correct merged
        artefact nor a meaningful per-project one; no reporter shipped in this
        repository is in that position today. It exists because "silently emit
        nothing" is the defect this whole contract prevents, so a reporter that
        genuinely cannot participate needs a way to say so loudly.
    """

    MERGED = "merged"
    PER_PROJECT = "per-project"
    WORKSPACE_SCOPED = "workspace-scoped"
    UNSUPPORTED = "unsupported"


class ReporterPluginConfigBase(PluginConfigBase):
    options: Annotated[ReporterOptionsBase, Field(description="Reporter options")] = (
        ReporterOptionsBase()
    )
    extension: str | None = None


T = TypeVar("T", bound=ReporterPluginConfigBase)


class ReporterPluginBase(PluginBase, Generic[T]):
    """Base reporter plugin with some methods of the IReporter abstract class
    implemented for convenience.
    """

    config: T | ReporterPluginConfigBase | None = None
    dependencies_satisfied: bool = True

    #: What this reporter does with a multi-project model. See the module
    #: docstring for why the default is ``PER_PROJECT`` and not ``MERGED``.
    #:
    #: A ``ClassVar`` rather than a pydantic field, for two reasons. It is a
    #: property of the reporter *class*, not of an instance's configuration, so
    #: it must be readable before instantiation -- the workspace driver decides
    #: whether to build the instance at all. And ``PluginBase`` sets
    #: ``use_enum_values=True``, which would coerce a field holding an enum down
    #: to its bare string on assignment; a ClassVar is untouched by that, so
    #: identity comparisons against enum members keep working.
    workspace_behaviour: ClassVar[ReporterWorkspaceBehaviour] = (
        ReporterWorkspaceBehaviour.PER_PROJECT
    )

    @model_validator(mode="after")
    def setup_paths(self) -> Self:
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")
        return self

    def configure(
        self,
        config: ReporterPluginConfigBase | None = None,
    ) -> None:
        """Configure the reporter with provided configuration."""
        if config:
            self.config = config

    def _pre_report(self) -> None:
        self.start_time = datetime.now(timezone.utc)

    def _post_report(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    @staticmethod
    def sarif_field_mappings() -> dict[str, str] | None:
        """
        Get mappings from SARIF fields to this reporter's output format.

        This method should be implemented by reporter classes to provide
        information about how SARIF fields map to their specific output format.

        Returns:
            Optional[Dict[str, str]]: Dictionary mapping SARIF field paths to
                                     reporter-specific field paths, or None if
                                     no mappings are available.
        """
        return None

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements.

        Defaults to returning True as most reporter plugins are entirely Python based."""
        return self.dependencies_satisfied

    ### Methods that require implementation by plugins.
    @abstractmethod
    def report(self, model: AshAggregatedResults) -> str | None:
        """Execute the reporter against the aggregated AshAggregatedResults.

        Returns a string containing the report or the response from the remote
        receiving the report.
        """
        pass
