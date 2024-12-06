# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal, Optional, List, Dict, Any, Union
from typing import Tuple


class ASHARPModel(BaseModel):
    def to_json_schema(
        self,
        format: Literal["dict", "str"] = "dict",
        *args,
        **kwargs,
    ) -> Dict[str, Any] | str:
        if format == "dict":
            return self.model_dump(*args, **kwargs)
        return self.model_dump_json(*args, **kwargs)

class AshFinding(BaseModel):
    pass

class AshScanner(BaseModel):
    pass

class AshReportBase(BaseModel):
    model_config = ConfigDict(extra="allow")

    metadata: Dict[str, Any] = Field(default_factory=dict)
    scan_date: datetime = Field(default=datetime.now())
    configuration: Dict[str, Any] = Field(default_factory=dict)

    findings: List[AshFinding] = Field(default_factory=list)
    sbom: Dict[str, Any] = Field(default_factory=dict)
    dependencies: Dict[str, Any] = Field(default_factory=dict)
    scanners: List[AshScanner] = Field(default_factory=list)