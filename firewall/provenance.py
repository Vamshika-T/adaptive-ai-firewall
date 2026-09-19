import json
from pathlib import Path
from typing import Any, Dict, List


EMAIL_FILE = (
    Path(__file__).parent.parent
    / "data"
    / "emails.json"
)

DOCUMENT_FILE = (
    Path(__file__).parent.parent
    / "data"
    / "documents.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ---------------------------------------------------------
# Source-level provenance
# ---------------------------------------------------------

def check_email_provenance(email_id):
    emails = load_json(EMAIL_FILE)

    for email in emails:
        if email["email_id"] == email_id:

            trusted = email.get(
                "trusted",
                False
            )

            return {
                "trusted": trusted,
                "tainted": not trusted,
                "source_type": email.get(
                    "source_type",
                    "unknown"
                ),
                "classification": email.get(
                    "classification",
                    "UNKNOWN"
                ),
                "resource": "email",
                "id": email_id
            }

    return {
        "trusted": False,
        "tainted": True,
        "source_type": "unknown",
        "classification": "UNKNOWN",
        "resource": "email",
        "id": email_id
    }


def check_document_provenance(document_id):
    documents = load_json(DOCUMENT_FILE)

    for document in documents:
        if document["document_id"] == document_id:

            trusted = document.get(
                "trusted",
                False
            )

            return {
                "trusted": trusted,
                "tainted": not trusted,
                "source_type": document.get(
                    "source_type",
                    "unknown"
                ),
                "classification": document.get(
                    "classification",
                    "UNKNOWN"
                ),
                "resource": "document",
                "id": document_id
            }

    return {
        "trusted": False,
        "tainted": True,
        "source_type": "unknown",
        "classification": "UNKNOWN",
        "resource": "document",
        "id": document_id
    }


# ---------------------------------------------------------
# Evaluate request context provenance
# ---------------------------------------------------------

def evaluate_provenance(context_sources):

    if not context_sources:
        return {
            "trusted": True,
            "tainted": False,
            "sources": []
        }

    sources = []
    overall_trusted = True
    overall_tainted = False

    for source in context_sources:

        if source.startswith("email:"):

            email_id = source.split(
                "email:",
                1
            )[1]

            result = check_email_provenance(
                email_id
            )

        elif source.startswith("document:"):

            document_id = source.split(
                "document:",
                1
            )[1]

            result = check_document_provenance(
                document_id
            )

        else:

            result = {
                "trusted": False,
                "tainted": True,
                "source_type": "unknown",
                "classification": "UNKNOWN",
                "resource": "unknown",
                "id": source
            }

        sources.append(result)

        if not result["trusted"]:
            overall_trusted = False

        if result["tainted"]:
            overall_tainted = True

    return {
        "trusted": overall_trusted,
        "tainted": overall_tainted,
        "sources": sources
    }


# ---------------------------------------------------------
# Session-level provenance / taint state
# ---------------------------------------------------------

class ProvenanceTracker:
    """
    Maintains provenance and taint state for each agent session.

    Provenance determines whether context can be trusted.
    Taint persists within a session until explicitly reset.
    """

    def __init__(self):
        self.session_sources: Dict[
            str,
            List[Dict[str, Any]]
        ] = {}

        self.session_tainted: Dict[
            str,
            bool
        ] = {}

    def _ensure_session(self, session_id):

        if session_id not in self.session_sources:
            self.session_sources[session_id] = []

        if session_id not in self.session_tainted:
            self.session_tainted[session_id] = False

    def process_context_sources(
        self,
        session_id,
        context_sources
    ):

        self._ensure_session(session_id)

        result = evaluate_provenance(
            context_sources
        )

        self.session_sources[
            session_id
        ].extend(
            result["sources"]
        )

        if result["tainted"]:
            self.session_tainted[
                session_id
            ] = True

        return {
            "trusted": result["trusted"],
            "tainted": self.session_tainted[
                session_id
            ],
            "sources": result["sources"]
        }

    def is_tainted(self, session_id):

        self._ensure_session(session_id)

        return self.session_tainted[
            session_id
        ]

    def is_trusted(self, session_id):

        self._ensure_session(session_id)

        sources = self.session_sources[
            session_id
        ]

        if not sources:
            return True

        return all(
            source["trusted"]
            for source in sources
        )

    def get_sources(self, session_id):

        self._ensure_session(session_id)

        return list(
            self.session_sources[
                session_id
            ]
        )

    def reset_session(self, session_id):

        self.session_sources.pop(
            session_id,
            None
        )

        self.session_tainted.pop(
            session_id,
            None
        )