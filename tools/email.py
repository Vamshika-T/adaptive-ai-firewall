import json
from pathlib import Path


DATA_FILE = Path(__file__).parent.parent / "data" / "emails.json"


def load_emails():
    """Load all emails from the simulated enterprise data."""
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def read_email_inbox(user_email):
    """Return emails received by the specified user."""
    emails = load_emails()

    return [
        email
        for email in emails
        if email["recipient"].lower() == user_email.lower()
    ]


def send_email_message(sender, recipient, subject, body):
    """Simulate sending an email."""
    print(f"Sending email from {sender} to {recipient}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")

    return {
        "status": "success",
        "message": "Email sent successfully",
        "sender": sender,
        "recipient": recipient,
        "subject": subject
    }