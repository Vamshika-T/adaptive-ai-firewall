class ResourceGuard:

    def __init__(
        self,
        max_requests_per_session=50,
        max_deep_inspections=10
    ):
        self.max_requests_per_session = (
            max_requests_per_session
        )

        self.max_deep_inspections = (
            max_deep_inspections
        )

        self.session_requests = {}
        self.session_deep_inspections = {}

    def check_request_budget(self, session_id):

        count = self.session_requests.get(
            session_id,
            0
        )

        if count >= self.max_requests_per_session:
            return False, (
                "Session request limit exceeded"
            )

        self.session_requests[session_id] = (
            count + 1
        )

        return True, "Request budget available"

    def check_deep_inspection_budget(
        self,
        session_id
    ):

        count = self.session_deep_inspections.get(
            session_id,
            0
        )

        if count >= self.max_deep_inspections:
            return False, (
                "Deep inspection budget exceeded"
            )

        self.session_deep_inspections[session_id] = (
            count + 1
        )

        return True, "Deep inspection budget available"

    def reset_session(self, session_id):

        self.session_requests.pop(
            session_id,
            None
        )

        self.session_deep_inspections.pop(
            session_id,
            None
        )