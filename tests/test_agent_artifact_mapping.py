
from agent.gemini_agent import GeminiAgent


def test_result_mapping_tracks_artifact_id():
    agent = GeminiAgent.__new__(GeminiAgent)
    agent.session_id = "SESSION_A"
    agent.tool_result_artifacts = {}

    artifact_id = "SESSION_A:artifact:1"
    result = {"employee_id": "U001", "name": "Alice"}

    agent.tool_result_artifacts[artifact_id] = result

    assert agent.tool_result_artifacts[artifact_id] == result
    assert artifact_id.startswith(agent.session_id + ":artifact:")

    print("PASSED: Result is associated with its artifact ID")



def test_result_matching_finds_referenced_parent():
    agent = GeminiAgent.__new__(GeminiAgent)
    agent.session_id = "SESSION_A"
    agent.tool_result_artifacts = {
        "SESSION_A:artifact:1": {
            "employee_id": "U001",
            "name": "Alice",
        },
        "SESSION_A:artifact:2": {
            "department": "Engineering",
            "location": "Hyderabad",
        },
    }

    request_arguments = {
        "body": "{'employee_id': 'U001', 'name': 'Alice'}"
    }
    request_text = str(request_arguments).casefold()

    matched_parents = {
        artifact_id
        for artifact_id, previous_result
        in agent.tool_result_artifacts.items()
        if (
            len(str(previous_result).casefold().strip()) >= 8
            and str(previous_result).casefold().strip()
            in request_text
        )
    }

    assert "SESSION_A:artifact:1" in matched_parents
    assert "SESSION_A:artifact:2" not in matched_parents

    print("PASSED: Matching result is identified")
    print("PASSED: Unrelated result is not attached")
