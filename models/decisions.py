from typing import List, Literal
from pydantic import BaseModel, Field


DecisionAction = Literal[
    "ALLOW",
    "MONITOR",
    "ESCALATE",
    "BLOCK"
]


class SecurityDecision(BaseModel):
    request_id: str
    action: DecisionAction
    risk_score: float = Field(
        default=0.0,
        ge=0,
        le=100
    )
    reasons: List[str] = Field(
        default_factory=list
    )