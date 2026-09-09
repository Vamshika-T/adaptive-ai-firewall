import json
from pathlib import Path


DATA_DIR = Path(__file__).parent.parent / "data"


def load_json(filename):
    file_path = DATA_DIR / filename

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def query_database(table):
    if table == "employees":
        return load_json("employees.json")

    if table == "customers":
        return load_json("customers.json")

    if table == "payroll":
        return load_json("payroll.json")

    raise ValueError(f"Unknown database table: {table}")


def search_employee(employee_id):
    employees = load_json("employees.json")

    for employee in employees:
        if employee["employee_id"] == employee_id:
            return employee

    return None


def search_customer(customer_id):
    customers = load_json("customers.json")

    for customer in customers:
        if customer["customer_id"] == customer_id:
            return customer

    return None