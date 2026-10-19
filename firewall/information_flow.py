
"""
Artifact-level information-flow tracking for the AI firewall.

Tracks data returned by enterprise tools, preserves lineage when
artifacts are derived from earlier artifacts, and checks whether
sensitive artifact content is being sent to an external destination.

This module complements, but does not replace, RBAC, ABAC,
provenance tracking, or the existing risk engine.
"""

import json
from typing import Any, Dict, List, Optional


SENSITIVITY_LEVELS = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3,
}

INTERNAL_EMAIL_DOMAINS = {
    "company.com",
}


def _normalise(value: Any) -> str:
    """Convert a value into a consistent searchable representation."""
    if isinstance(value, str):
        return value.casefold().strip()

    try:
        return json.dumps(
            value,
            sort_keys=True,
            default=str,
        ).casefold()
    except (TypeError, ValueError):
        return str(value).casefold()


def _extract_values(value: Any) -> List[str]:
    """Extract meaningful scalar values from an artifact."""
    values = []

    if isinstance(value, dict):
        for key, item in value.items():
            values.extend(_extract_values(item))

    elif isinstance(value, (list, tuple, set)):
        for item in value:
            values.extend(_extract_values(item))

    elif value is not None:
        text = _normalise(value)

        # Avoid treating tiny/common values as evidence of leakage.
        if len(text) >= 4:
            values.append(text)

    return values


class InformationFlowTracker:
    """
    Maintains artifact lineage within each session.

    Artifacts receive unique session-scoped IDs. Derived artifacts
    inherit the highest sensitivity and provenance of their parents.

    Outbound checks use exact-content matching. They do not provide
    complete semantic detection of paraphrased or transformed data.
    """

    def __init__(self):
        self.session_artifacts: Dict[
            str, List[Dict[str, Any]]
        ] = {}

    def record_artifact(
        self,
        session_id: str,
        tool: str,
        resource: str,
        result: Any,
        sensitivity: str,
        provenance_sources=None,
        parent_artifact_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Record an artifact and return its metadata."""

        classification = (
            sensitivity.upper()
            if isinstance(sensitivity, str)
            else "RESTRICTED"
        )

        if classification not in SENSITIVITY_LEVELS:
            classification = "RESTRICTED"

        artifacts = self.session_artifacts.setdefault(
            session_id, []
        )

        artifact_id = (
            f"{session_id}:artifact:{len(artifacts) + 1}"
        )

        artifact = {
            "artifact_id": artifact_id,
            "tool": tool,
            "resource": resource,
            "sensitivity": classification,
            "provenance_sources": list(
                provenance_sources or []
            ),
            "parent_artifact_ids": list(
                parent_artifact_ids or []
            ),
            "values": _extract_values(result),
            "serialized_content": _normalise(result),
        }

        artifacts.append(artifact)

        # Do not expose the stored content or extracted values.
        return {
            "artifact_id": artifact["artifact_id"],
            "tool": artifact["tool"],
            "resource": artifact["resource"],
            "sensitivity": artifact["sensitivity"],
            "provenance_sources": list(
                artifact["provenance_sources"]
            ),
            "parent_artifact_ids": list(
                artifact["parent_artifact_ids"]
            ),
        }

    def record_derived_artifact(
        self,
        session_id: str,
        tool: str,
        resource: str,
        result: Any,
        parent_artifact_ids: List[str],
    ) -> Dict[str, Any]:
        """
        Record transformed data while inheriting parent sensitivity
        and provenance.

        Parent IDs must refer to artifacts in the same session.
        """

        if not parent_artifact_ids:
            raise ValueError(
                "A derived artifact must have at least one parent"
            )

        artifacts = self.session_artifacts.get(session_id, [])

        artifacts_by_id = {
            artifact["artifact_id"]: artifact
            for artifact in artifacts
        }

        parents = []

        for parent_id in parent_artifact_ids:
            parent = artifacts_by_id.get(parent_id)

            if parent is None:
                raise ValueError(
                    f"Unknown parent artifact: {parent_id}"
                )

            parents.append(parent)

        # Inherit the most restrictive parent classification.
        sensitivity = max(
            (
                parent["sensitivity"]
                for parent in parents
            ),
            key=lambda level: SENSITIVITY_LEVELS.get(level, 3),
        )

        # Preserve all parent provenance sources.
        provenance_sources = sorted({
            source
            for parent in parents
            for source in parent["provenance_sources"]
        })

        return self.record_artifact(
            session_id=session_id,
            tool=tool,
            resource=resource,
            result=result,
            sensitivity=sensitivity,
            provenance_sources=provenance_sources,
            parent_artifact_ids=list(parent_artifact_ids),
        )

    @staticmethod
    def is_external_destination(recipient: str) -> bool:
        """Treat unrecognized email domains as external."""
        recipient = (recipient or "").strip().casefold()

        if "@" not in recipient:
            return True

        domain = recipient.rsplit("@", 1)[1]

        return domain not in INTERNAL_EMAIL_DOMAINS

    def check_outbound_payload(
        self,
        session_id: str,
        recipient: str,
        payload: Any,
    ) -> Dict[str, Any]:
        """
        Check outbound content against recorded confidential or
        restricted artifacts.

        This uses exact-content matching. It cannot reliably detect
        paraphrases, encoded data, or all transformed representations.
        """

        if not self.is_external_destination(recipient):
            return {
                "allowed": True,
                "reason": "Destination is an internal email domain",
                "matched_artifacts": [],
            }

        outbound = _normalise(payload)

        # Deterministic content-label checks supplement artifact matching.
        # This catches explicitly labelled confidential data even when the
        # application has not yet recorded a matching source artifact (for
        # example, a tool request that directly supplies a confidential body).
        # This is intentionally conservative and is not a semantic DLP system.
        explicit_sensitive_markers = (
            "confidential company information",
            "confidential information",
            "restricted information",
            "highly confidential",
            "payroll data",
            "payroll information",
            "employee information",
            "salary information",
            "social security number",
            "ssn:",
            "credit card number",
            "private key",
            "access token",
            "api key:",
        )
        matched_markers = [
            marker for marker in explicit_sensitive_markers
            if marker in outbound
        ]
        if matched_markers:
            return {
                "allowed": False,
                "reason": (
                    "Outbound payload contains an explicit confidential, "
                    "restricted, or credential-like data marker"
                ),
                "matched_artifacts": [],
                "matched_markers": matched_markers,
            }

        matches = []

        for artifact in self.session_artifacts.get(
            session_id, []
        ):
            sensitivity = artifact["sensitivity"]

            if SENSITIVITY_LEVELS.get(
                sensitivity, 3
            ) < SENSITIVITY_LEVELS["CONFIDENTIAL"]:
                continue

            serialized = artifact["serialized_content"]

            if len(serialized) >= 12 and serialized in outbound:
                matches.append({
                    "artifact_id": artifact["artifact_id"],
                    "resource": artifact["resource"],
                    "tool": artifact["tool"],
                    "sensitivity": sensitivity,
                    "match_type": "serialized_artifact",
                    "parent_artifact_ids": list(
                        artifact["parent_artifact_ids"]
                    ),
                })
                continue

            matched_values = [
                value
                for value in artifact["values"]
                if len(value) >= 6 and value in outbound
            ]

            if matched_values:
                matches.append({
                    "artifact_id": artifact["artifact_id"],
                    "resource": artifact["resource"],
                    "tool": artifact["tool"],
                    "sensitivity": sensitivity,
                    "match_type": "artifact_values",
                    "matched_value_count": len(
                        matched_values
                    ),
                    "parent_artifact_ids": list(
                        artifact["parent_artifact_ids"]
                    ),
                })

        if matches:
            return {
                "allowed": False,
                "reason": (
                    "Outbound payload contains content from a "
                    "confidential or restricted artifact"
                ),
                "matched_artifacts": matches,
            }

        return {
            "allowed": True,
            "reason": (
                "No exact-content match with recorded "
                "confidential or restricted artifacts"
            ),
            "matched_artifacts": [],
        }


    def check_sensitive_write(
        self,
        session_id: str,
        tool: str,
        arguments: Any,
        parent_artifact_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Enforce destination-specific sensitivity limits for write actions.

        Explicit parent IDs are treated as evidence of data dependency even when
        the payload is paraphrased or transformed. When parent IDs are absent,
        exact scalar-value matches are used as a conservative fallback. This
        does not claim semantic detection of arbitrary transformed data.
        """
        tool_name = (tool or "").strip().casefold()
        write_tools = {
            "send_email_message",
            "update_crm_record",
            "update_database_record",
            "insert_database_record",
            "delete_database_record",
        }
        looks_like_write = tool_name.startswith((
            "update_", "create_", "delete_", "insert_",
            "write_", "send_", "submit_", "upsert_",
        ))
        if tool_name not in write_tools and not looks_like_write:
            return {
                "allowed": True,
                "reason": "Action is not classified as a write operation",
                "matched_artifacts": [],
            }

        # Internal destinations may legitimately process confidential data,
        # but restricted data needs a separately reviewed destination policy.
        if tool_name == "send_email_message":
            recipient = (arguments or {}).get("recipient", "") if isinstance(arguments, dict) else ""
            if self.is_external_destination(recipient):
                max_sensitivity = "INTERNAL"
                destination = "external email"
            else:
                max_sensitivity = "RESTRICTED"
                destination = "internal email"
        elif tool_name == "update_crm_record":
            max_sensitivity = "CONFIDENTIAL"
            destination = "internal CRM write"
        else:
            # Unknown/future write tools fail conservatively for data above
            # INTERNAL until an explicit destination policy is added.
            max_sensitivity = "INTERNAL"
            destination = f"write tool {tool_name}"

        artifacts = self.session_artifacts.get(session_id, [])
        by_id = {item["artifact_id"]: item for item in artifacts}
        relevant = {}
        for artifact_id in parent_artifact_ids or []:
            artifact = by_id.get(artifact_id)
            if artifact is None:
                return {
                    "allowed": False,
                    "reason": f"Write blocked: unknown parent artifact ID {artifact_id}",
                    "matched_artifacts": [{"artifact_id": artifact_id, "reason": "unknown_parent"}],
                }
            relevant[artifact_id] = artifact

        # If explicit lineage was not supplied, search for exact source values
        # in the proposed arguments. Parent IDs remain the preferred mechanism.
        payload_text = _normalise(arguments)
        for artifact in artifacts:
            if artifact["artifact_id"] in relevant:
                continue
            if any(len(value) >= 6 and value in payload_text for value in artifact["values"]):
                relevant[artifact["artifact_id"]] = artifact

        max_level = SENSITIVITY_LEVELS[max_sensitivity]
        violations = []
        for artifact in relevant.values():
            source_level = SENSITIVITY_LEVELS.get(artifact["sensitivity"], 3)
            if source_level > max_level:
                violations.append({
                    "artifact_id": artifact["artifact_id"],
                    "resource": artifact["resource"],
                    "tool": artifact["tool"],
                    "sensitivity": artifact["sensitivity"],
                    "parent_artifact_ids": list(artifact["parent_artifact_ids"]),
                })

        if violations:
            return {
                "allowed": False,
                "reason": (
                    f"{destination} exceeds its allowed sensitivity "
                    f"({max_sensitivity}); sensitive source lineage was detected"
                ),
                "matched_artifacts": violations,
            }

        return {
            "allowed": True,
            "reason": (
                f"{destination} passed destination-specific information-flow policy "
                f"(maximum {max_sensitivity})"
            ),
            "matched_artifacts": [],
        }

    def get_artifacts(self, session_id: str) -> List[Dict[str, Any]]:
        """Return artifact metadata without exposing stored content."""
        return [
            {
                "artifact_id": artifact["artifact_id"],
                "tool": artifact["tool"],
                "resource": artifact["resource"],
                "sensitivity": artifact["sensitivity"],
                "provenance_sources": list(
                    artifact["provenance_sources"]
                ),
                "parent_artifact_ids": list(
                    artifact["parent_artifact_ids"]
                ),
            }
            for artifact in self.session_artifacts.get(
                session_id, []
            )
        ]

    def reset_session(self, session_id: str):
        """Clear tracked artifacts for a completed session."""
        self.session_artifacts.pop(session_id, None)
