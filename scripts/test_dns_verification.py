"""Manual check of the DNS verification flow against the configured database.

Creates its own throwaway user, origin and domain in PostgreSQL, checks a
matching TXT record verifies the domain, and removes all three afterwards.
"""
import os
import sys
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../dashboard/backend')))

from services.auth_service import AuthService  # noqa: E402
from services.dynamodb_service import DynamoDBService  # noqa: E402
from services.dns_service import verify_domain_dns  # noqa: E402


class TestDNSVerification(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db = DynamoDBService()
        self.auth = AuthService()
        tag = uuid.uuid4().hex[:8]
        self.user = self.auth.create_user(email=f"dns-test-{tag}@example.com", username=f"dns_{tag}",
                                          password=uuid.uuid4().hex)
        self.origin_id = str(uuid.uuid4())
        assert self.db.create_origin({"id": self.origin_id, "admin_user_id": self.user["user_id"],
                                      "label": "dns-test", "ip": "203.0.113.10", "port": 80})
        self.test_domain_name = f"e2e-test-{tag}.example.com"
        self.test_token = f"waf-token-test-{tag}"
        self.domain_id = self.db.create_domain({
            "origin_id": self.origin_id, "domain_name": self.test_domain_name,
            "verification_token": self.test_token, "dns_verified": False, "ssl_status": "none",
        })["id"]

    async def asyncTearDown(self):
        self.db.hard_delete_origin(self.origin_id)   # domains go with it
        self.auth.delete_user(self.user["user_id"])

    @patch('services.dns_service.resolve_txt')
    @patch('services.dns_service.resolve_cname')
    async def test_verification_success(self, mock_cname, mock_txt):
        mock_cname.return_value = ""
        mock_txt.return_value = [f"waf-verification-token={self.test_token}"]
        self.assertTrue(verify_domain_dns(self.test_domain_name, self.test_token))

        pending = [d for d in self.db.list_domains(dns_verified=False) if d["id"] == self.domain_id]
        self.assertEqual(len(pending), 1)
        self.assertTrue(verify_domain_dns(pending[0]["domain_name"], pending[0]["verification_token"]))
        self.db.update_domain(self.domain_id, {"dns_verified": True, "ssl_status": "pending"})

        updated = self.db.get_domain(self.domain_id)
        self.assertTrue(updated["dns_verified"])
        self.assertEqual(updated["ssl_status"], "pending")


if __name__ == "__main__":
    unittest.main()
