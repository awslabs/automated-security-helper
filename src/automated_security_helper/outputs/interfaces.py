# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from abc import ABC, abstractmethod

from automated_security_helper.models.asharp_model import ASHARPModel


class IOutputFormatter(ABC):
    """Interface for output formatters."""

    @abstractmethod
    def format(self, model: ASHARPModel) -> str:
        """Format ASH model into output string."""
        pass
