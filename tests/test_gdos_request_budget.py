"""Regression test for the per-session request budget used by the firewall."""
import unittest

from firewall.resource_limits import ResourceGuard


class TestGdosRequestBudget(unittest.TestCase):
    def test_requests_over_budget_are_rejected(self):
        guard = ResourceGuard(
            max_requests_per_session=3,
            max_deep_inspections=10,
        )

        results = [
            guard.check_request_budget("gdos-test")[0]
            for _ in range(5)
        ]

        self.assertEqual(results, [True, True, True, False, False])


if __name__ == "__main__":
    unittest.main()
