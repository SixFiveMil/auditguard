"""
Unit tests for Gatekeeper: Verifying approval gates and rate limiting.
"""

import time
import unittest
from core.gatekeeper import Gatekeeper, RequestDeniedError


class TestGatekeeper(unittest.TestCase):

    def test_approved_hook_returns_token(self):
        # Hook simulates human typing 'yes'
        gate = Gatekeeper(
            rate_limit_per_second=10.0,
            require_interactive=False,
            approval_hook=lambda req: True,
        )
        token = gate.authorize_request("GET", "https://staging.target.com/api")
        self.assertTrue(len(token) > 0)

    def test_denied_hook_raises_exception(self):
        # Hook simulates human typing 'no'
        gate = Gatekeeper(
            rate_limit_per_second=10.0,
            require_interactive=False,
            approval_hook=lambda req: False,
        )
        with self.assertRaises(RequestDeniedError):
            gate.authorize_request("POST", "https://staging.target.com/api", data={"test": 1})

    def test_rate_limiter_paces_requests(self):
        # 5 requests per second -> ~0.2s interval
        gate = Gatekeeper(
            rate_limit_per_second=5.0,
            require_interactive=False,
            approval_hook=lambda req: True,
        )
        t1 = time.time()
        gate.authorize_request("GET", "https://staging.target.com/1")
        gate.authorize_request("GET", "https://staging.target.com/2")
        t2 = time.time()
        self.assertGreaterEqual(t2 - t1, 0.18)


if __name__ == "__main__":
    unittest.main()
