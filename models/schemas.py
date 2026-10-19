
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime


class ToolRequest(BaseModel):
    request_id: str
    session_id: str
    user_id: str

    tool: str

    arguments: Dict[str, Any] = Field(default_factory=dict)

    # Information about the user's original objective.
    intent: str = ""

    # Resources or information that influenced this action.
    # Examples: ["email:E003"], ["document:DOC004"]
    context_sources: List[str] = Field(default_factory=list)

    # IDs of previously recorded artifacts that influenced this request.
    # These IDs must refer to artifacts in the same session.
    parent_artifact_ids: List[str] = Field(default_factory=list)
    output_artifact_id: Optional[str] = None

    # Whether the current request is influenced by untrusted context.
    tainted: bool = False

    # Optional metadata describing where the request originated.
    source_type: str = "agent"
    function_call_id: Optional[str] = None

    timestamp: datetime = Field(default_factory=datetime.now)


class SecurityContext(BaseModel):
    """
    Security information constructed by the firewall
    while inspecting a ToolRequest.
    """

    user_id: str

    role: str = ""
    department: str = ""

    resource: str = ""
    sensitivity: str = "PUBLIC"

    provenance_trusted: bool = True
    tainted: bool = False
    provenance_sources: List[Dict[str, Any]] = Field(
        default_factory=list
    )
    intent: str = ""

    previous_actions: List[Dict[str, Any]] = Field(
        default_factory=list
    )


class ActionRecord(BaseModel):
    """
    A normalized record of a tool action stored in session history.
    """

    request_id: str
    session_id: str
    user_id: str

    tool: str
    resource: str

    decision: str
    risk_score: float

    tainted: bool
    provenance_trusted: bool

    timestamp: datetime = Field(default_factory=datetime.now)
