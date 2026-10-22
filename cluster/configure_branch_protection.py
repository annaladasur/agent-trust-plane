#!/usr/bin/env python3
"""
Configure Gitea Branch Protection for Agent Repositories (Milestone M7)

Enforces required status check `atp/merge-gate` on branch `main` across all
Online Boutique microservice repositories (frontend, payments, recommendations, platform).
"""

import json
import os
import sys
import urllib.error
import urllib.request

from gitea_auth import admin_auth

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3030/api/v1")
REPOS = ["frontend", "payments", "recommendations", "platform"]
STATUS_CHECK_CONTEXT = "atp/merge-gate"


def configure_repo_branch_protection(repo: str) -> dict:
    headers = {
        "Authorization": f"Basic {admin_auth()}",
        "Content-Type": "application/json"
    }

    payload = {
        "rule_name": "main",
        "enable_status_check": True,
        "status_check_contexts": [STATUS_CHECK_CONTEXT],
        "required_approvals": 0,
        "enable_push": False,
        "enable_push_whitelist": True,
        "push_whitelist_usernames": ["gitea_admin"]
    }

    # Check if rule already exists
    list_url = f"{GITEA_URL}/repos/online-boutique/{repo}/branch_protections"
    try:
        req = urllib.request.Request(list_url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            existing_rules = json.loads(resp.read().decode())
    except Exception as e:
        existing_rules = []

    has_main = any(r.get("rule_name") == "main" or r.get("branch_name") == "main" for r in existing_rules)

    if has_main:
        # Update existing rule
        update_url = f"{GITEA_URL}/repos/online-boutique/{repo}/branch_protections/main"
        req = urllib.request.Request(update_url, data=json.dumps(payload).encode(), headers=headers, method="PATCH")
    else:
        # Create new rule
        req = urllib.request.Request(list_url, data=json.dumps(payload).encode(), headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            print(f"  ✅ Branch protection configured for online-boutique/{repo}: rule='main', status_checks=['{STATUS_CHECK_CONTEXT}']")
            return result
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  ❌ Failed to configure branch protection for {repo}: HTTP {e.code} - {err}")
        raise


def main():
    print("============================================================")
    print("Configuring Gitea Branch Protection Merge Gate on 'main'...")
    print(f"Required Status Check: '{STATUS_CHECK_CONTEXT}'")
    print("============================================================")

    for repo in REPOS:
        configure_repo_branch_protection(repo)

    print("All repositories protected by ATP Merge Gate successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
