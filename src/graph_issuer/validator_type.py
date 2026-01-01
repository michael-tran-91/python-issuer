from __future__ import annotations
from pydantic import BaseModel, model_validator, Field, ConfigDict, field_validator
from typing import Dict, List, Set, Union, Literal, Optional

#------------------ BASE PROJECT
class CommonModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")