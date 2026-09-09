from storage.state import SessionState


session = SessionState(
    session_id="SESSION001",
    user_id="U001"
)


session.add_action({
    "tool": "read_email_inbox",
    "arguments": {
        "user_email": "alice@company.com"
    }
})


session.add_action({
    "tool": "query_database",
    "arguments": {
        "table": "payroll"
    }
})


print("Session ID:", session.session_id)
print("User ID:", session.user_id)

print("\nAction History:")

for action in session.get_history():
    print(action)