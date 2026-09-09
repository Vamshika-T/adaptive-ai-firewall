import json
from pathlib import Path


DATA_FILE = Path(__file__).parent.parent / "data" / "calendar.json"


def load_events():
    """Load calendar events from the simulated enterprise data."""
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_calendar_events(user_email, date):
    """Return calendar events for a user on a specific date."""

    events = load_events()

    matching_events = []

    for event in events:
        if (
            event["date"] == date
            and user_email.lower() in [
                participant.lower() for participant in event["participants"]
            ]
        ):
            matching_events.append(event)

    return matching_events