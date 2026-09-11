"""
Unit tests for ScopeHarvester: Passive gathering, security.txt, and vendor detection.
"""

import unittest
from unittest.mock import MagicMock, patch

import httpx

from core.harvester import ScopeHarvester


class TestScopeHarvester(unittest.TestCase):

    def setUp(self):
        self.harvester = ScopeHarvester(timeout=5.0)

    @patch("httpx.Client.get")
    def test_search_public_programs(self, mock_get):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "programs": [
                {"name": "GitLab", "url": "https://hackerone.com/gitlab", "bounty": True, "domains": ["gitlab.com"]},
                {"name": "OtherCo", "url": "https://bugcrowd.com/other", "bounty": False, "domains": ["other.io"]},
            ]
        }
        mock_get.return_value = mock_resp

        results = self.harvester.search_public_programs("gitlab")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "GitLab")
        self.assertTrue(results[0]["bounty"])

    @patch("httpx.Client.get")
    def test_fetch_security_txt_parsing(self, mock_get):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.text = (
            "Contact: mailto:security@example.com\n"
            "Policy: https://example.com/security-policy\n"
            "Acknowledgments: https://example.com/hall-of-fame\n"
        )
        mock_get.return_value = mock_resp

        data = self.harvester.fetch_security_txt("example.com")
        self.assertIsNotNone(data)
        self.assertEqual(data.get("contact"), "mailto:security@example.com")
        self.assertEqual(data.get("policy"), "https://example.com/security-policy")

    @patch("httpx.Client.get")
    def test_detect_third_party_vendor_cname(self, mock_get):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Answer": [
                {"name": "support.example.com", "data": "example.zendesk.com."}
            ]
        }
        mock_get.return_value = mock_resp

        vendor = self.harvester.detect_third_party_vendor("support.example.com")
        self.assertIsNotNone(vendor)
        self.assertEqual(vendor["vendor"], "Zendesk Support")

    @patch("httpx.Client.get")
    def test_direct_self_hosted_has_no_vendor_trap(self, mock_get):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Answer": [
                {"name": "api.example.com", "data": "elb-prod.us-east-1.amazonaws.com."}
            ]
        }
        mock_get.return_value = mock_resp

        vendor = self.harvester.detect_third_party_vendor("api.example.com")
        self.assertIsNone(vendor)


if __name__ == "__main__":
    unittest.main()
