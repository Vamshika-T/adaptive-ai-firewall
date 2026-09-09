import json
from pathlib import Path


DATA_FILE = Path(__file__).parent.parent / "data" / "documents.json"


def load_documents():
    """Load documents from the simulated enterprise data."""
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def search_documents(keyword):
    """Search documents by title or content."""

    documents = load_documents()
    keyword = keyword.lower()

    results = []

    for document in documents:
        if (
            keyword in document["title"].lower()
            or keyword in document["content"].lower()
        ):
            results.append(document)

    return results


def read_document(document_id):
    """Return a document by document ID."""

    documents = load_documents()

    for document in documents:
        if document["document_id"] == document_id:
            return document

    return None