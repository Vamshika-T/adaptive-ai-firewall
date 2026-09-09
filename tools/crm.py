import json
from pathlib import Path


DATA_FILE = Path(__file__).parent.parent / "data" / "customers.json"


def load_customers():
    """Load customers from the simulated CRM data."""
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_customer(customer_id):
    """Return a customer by customer ID."""

    customers = load_customers()

    for customer in customers:
        if customer["customer_id"] == customer_id:
            return customer

    return None


def update_crm_record(customer_id, field, value):
    """Simulate updating a customer CRM record."""

    customers = load_customers()

    for customer in customers:
        if customer["customer_id"] == customer_id:
            customer[field] = value

            print(
                f"Updated customer {customer_id}: "
                f"{field} = {value}"
            )

            return {
                "status": "success",
                "customer_id": customer_id,
                "updated_field": field,
                "new_value": value
            }

    return {
        "status": "error",
        "message": f"Customer {customer_id} not found"
    }