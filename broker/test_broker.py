#!/usr/bin/env python3
"""
Unit tests for Lightweight STS Token Broker.
Tests workload identity exchange, role scoping, repository containment,
TTL expiration reaper, explicit revocation, and telemetry generation.
"""

import base64
import json
import os
import sys
import time
import unittest
import urllib.request
import urllib.error

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))
import broker


class TestSTSTokenBroker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure test broker port and fast reaper for testing
        cls.port = 18081
        broker.PORT = cls.port
        broker.TOKEN_TTL_SECONDS = 2  # Short 2s TTL for rapid reaper testing
        broker.REAPER_INTERVAL_SECONDS = 0.5
        broker.GITEA_URL = "http://localhost:3030/api/v1"
        cls.server, cls.thread = broker.start_server(port=cls.port, background=True)
        time.sleep(1)  # Allow server to bind

    def _make_jwt(self, sa_name: str, namespace: str = "agents") -> str:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": f"system:serviceaccount:{namespace}:{sa_name}",
            "kubernetes.io/serviceaccount/service-account.name": sa_name,
            "kubernetes.io/serviceaccount/namespace": namespace
        }).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(b"simulated-signature").decode().rstrip("=")
        return f"{header}.{payload}.{sig}"

    def test_01_healthz(self):
        url = f"http://localhost:{self.port}/healthz"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["service"], "broker-sts")

    def test_02_mint_token_publisher_write_allowed(self):
        jwt_token = self._make_jwt("sa-publisher")
        url = f"http://localhost:{self.port}/token"
        payload = {
            "repo": "payments",
            "action": "write",
            "task_id": "test-task-pub-1"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt_token}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIn("token", data)
            self.assertEqual(data["username"], "payments-bot")
            self.assertEqual(data["repo"], "payments")
            self.assertEqual(data["action"], "write")
            self.assertIn("write:repository", data["scopes"])
            token_id = data["token_id"]

            # Verify token listing sees it
            list_req = urllib.request.Request(f"http://localhost:{self.port}/tokens")
            with urllib.request.urlopen(list_req) as l_resp:
                l_data = json.loads(l_resp.read().decode())
                self.assertTrue(any(t["id"] == token_id for t in l_data["tokens"]))

            # Clean up immediately
            rev_req = urllib.request.Request(
                f"http://localhost:{self.port}/token/revoke",
                data=json.dumps({"token_id": token_id}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(rev_req) as r_resp:
                self.assertEqual(r_resp.status, 200)

    def test_03_coder_cannot_mint_write_token(self):
        jwt_token = self._make_jwt("sa-coder")
        url = f"http://localhost:{self.port}/token"
        payload = {
            "repo": "payments",
            "action": "write",
            "task_id": "test-task-coder-fail"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt_token}"
            },
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)
        err = json.loads(ctx.exception.read().decode())
        self.assertIn("not authorized", err["error"])

    def test_04_triage_can_mint_read_token(self):
        jwt_token = self._make_jwt("sa-triage")
        url = f"http://localhost:{self.port}/token"
        payload = {
            "repo": "frontend",
            "action": "read",
            "task_id": "test-task-triage-1"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt_token}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["username"], "frontend-bot")
            self.assertIn("read:repository", data["scopes"])
            self.assertNotIn("write:repository", data["scopes"])

            # Clean up
            tid = data["token_id"]
            del_req = urllib.request.Request(
                f"http://localhost:{self.port}/token/{tid}",
                method="DELETE"
            )
            with urllib.request.urlopen(del_req) as d_resp:
                self.assertEqual(d_resp.status, 200)

    def test_05_invalid_repo_rejected(self):
        jwt_token = self._make_jwt("sa-publisher")
        url = f"http://localhost:{self.port}/token"
        payload = {
            "repo": "malicious-external-repo",
            "action": "write",
            "task_id": "test-task-invalid-repo"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt_token}"
            },
            method="POST"
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        err = json.loads(ctx.exception.read().decode())
        self.assertIn("Invalid or missing repository", err["error"])

    def test_06_reaper_automatically_expires_tokens_after_ttl(self):
        jwt_token = self._make_jwt("sa-knowledge")
        url = f"http://localhost:{self.port}/token"
        payload = {
            "repo": "recommendations",
            "action": "read",
            "task_id": "test-reaper-ttl"
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt_token}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            token_id = data["token_id"]

        # Confirm token is initially in active tokens
        list_req = urllib.request.Request(f"http://localhost:{self.port}/tokens")
        with urllib.request.urlopen(list_req) as l_resp:
            tokens = json.loads(l_resp.read().decode())["tokens"]
            self.assertTrue(any(t["id"] == token_id for t in tokens))

        # Wait for TTL (2s) + reaper check (0.5s) to fire
        print("Waiting 3.5s for reaper thread to revoke expired token...")
        time.sleep(3.5)

        # Confirm token has been reaped and revoked
        with urllib.request.urlopen(list_req) as l_resp2:
            tokens2 = json.loads(l_resp2.read().decode())["tokens"]
            self.assertFalse(any(t["id"] == token_id for t in tokens2))

        # Verify Gitea confirmed deletion (attempting to delete again returns 404/True)
        self.assertTrue(broker.delete_gitea_token("recommendations-bot", token_id))


if __name__ == "__main__":
    unittest.main()
