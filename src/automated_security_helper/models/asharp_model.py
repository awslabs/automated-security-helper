# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict, Any, Union


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
