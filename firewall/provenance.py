import json
from pathlib import Path


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
                "source_type": email.get(
                    "source_type",
                    "unknown"
                ),
                "resource": "email",
                "id": email_id
            }

    return {
        "trusted": False,
        "source_type": "unknown",
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
                "source_type": document.get(
                    "source_type",
                    "unknown"
                ),
                "resource": "document",
                "id": document_id
            }

    return {
        "trusted": False,
        "source_type": "unknown",
        "resource": "document",
        "id": document_id
    }


def evaluate_provenance(context_sources):

    if not context_sources:
        return {
            "trusted": True,
            "sources": []
        }

    sources = []
    overall_trusted = True

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
                "source_type": "unknown",
                "resource": "unknown",
                "id": source
            }

        sources.append(result)

        if not result["trusted"]:
            overall_trusted = False

    return {
        "trusted": overall_trusted,
        "sources": sources
    }