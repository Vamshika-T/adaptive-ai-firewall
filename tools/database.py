import json
from pathlib import Path


DATA_DIR = Path(__file__).parent.parent / "data"


def load_json(filename):
    """Load a JSON data file from the data directory."""
    file_path = DATA_DIR / filename

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def query_database(table):
    """Return all records from the requested simulated database table."""

    if table == "employees":
        return load_json("employees.json")

    if table == "customers":
        return load_json("customers.json")

    if table == "payroll":
        return [
            {
                "employee_id": "U001",
                "salary": 75000,
                "bank_account": "FAKE-ACC-001"
            },
            {
                "employee_id": "U002",
                "salary": 90000,
                "bank_account": "FAKE-ACC-002"
            },
            {
                "employee_id": "U003",
                "salary": 85000,
                "bank_account": "FAKE-ACC-003"
            }
        ]

    raise ValueError(f"Unknown database table: {table}")


def search_employee(employee_id):
    """Search for an employee by employee ID."""

    employees = load_json("employees.json")

    for employee in employees:
        if employee["employee_id"] == employee_id:
            return employee

    return None


def search_customer(customer_id):
    """Search for a customer by customer ID."""

    customers = load_json("customers.json")

    for customer in customers:
        if customer["customer_id"] == customer_id:
            return customer

    return None