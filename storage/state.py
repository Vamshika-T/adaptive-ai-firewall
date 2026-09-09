from typing import List, Dict, Any


class SessionState:

    def __init__(self, session_id: str, user_id: str):
        self.session_id = session_id
        self.user_id = user_id
        self.action_history: List[Dict[str, Any]] = []

    def add_action(self, action: Dict[str, Any]):
        self.action_history.append(action)

    def get_history(self):
        return self.action_history

    def clear_history(self):
        self.action_history = []