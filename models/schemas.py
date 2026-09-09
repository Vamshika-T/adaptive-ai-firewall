from pydantic import BaseModel, Field
from typing import Dict, Any
from datetime import datetime


class ToolRequest(BaseModel):
    request_id: str
    session_id: str
    user_id: str
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)