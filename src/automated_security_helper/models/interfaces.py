# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from pathlib import Path

from automated_security_helper.models.asharp_model import ASHARPModel


class IOutputReporter(ABC):
    """Interface for output reporters/formatters."""

    @abstractmethod
    def format(
        self,
        model: ASHARPModel,
        output_path: Path | None = None,
    ) -> str | Path:
        """Format ASH model into output string.

        If output_path is not None, save the formatted content to the provided Path and
        return the Path back to the caller.

        If output_path is None (default), return the formatted string content back to
        the caller.
        """
        pass
