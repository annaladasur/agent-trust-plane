#!/usr/bin/env python3
"""
ATP Merge Gate Controller & Status Check Service (Milestone M7)

Enforces deterministic merge gating via:
1. Cryptographic non-repudiation: verifies Cosign signature against cosign.pub.
2. OPA Policy Evaluation: evaluates policies/merge/attestation.rego.
3. Gitea Status Reporting: posts required commit status 'atp/merge-gate'.
4. Audit Trail: posts structured in-toto Statement v1 record to PR discussion.

Closes Review Findings C1, C4, Evidence E5, E6, E8.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from attest.build_statement import DEFAULT_PUBKEY_PATH, verify_statement
from cluster.gitea_auth import admin_auth

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3030/api/v1")
POLICIES_DIR = os.path.join(os.path.dirname(__file__), "..", "policies")
STATUS_CHECK_CONTEXT = "atp/merge-gate"


def evaluate_opa_merge_policy(
    statement: Optional[Dict[str, Any]],
    signature_verified: bool,
    head_sha: str,
    approvers: Optional[List[str]] = None
) -> Tuple[bool, List[str]]:
    """
    Evaluate policies/merge/attestation.rego using local OPA engine.
    Fails closed if statement is missing, signature unverified, or policy denies.
    """
    human_approvers = approvers if approvers is not None else ["user:alice", "user:admin"]

    opa_input = {
        "signature_verified": bool(signature_verified),
        "pr": {
            "head_sha": head_sha
        }
    }
    if statement is not None:
        opa_input["statement"] = statement

    # Pass configured approvers via data.atp.approvers
    data_overlay = {
        "atp": {
            "approvers": human_approvers
        }
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as data_file:
        json.dump(data_overlay, data_file)
        data_path = data_file.name

    try:
        cmd = [
            "opa", "eval",
            "-d", POLICIES_DIR,
            "-d", data_path,
            "-I",
            "data.merge.attestation"
        ]
        res = subprocess.run(
            cmd,
            input=json.dumps(opa_input),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if res.returncode != 0:
            return False, [f"OPA evaluation error: {res.stderr.strip()}"]

        out = json.loads(res.stdout)
        results = out.get("result", [])
        if not results:
            return False, ["OPA returned no evaluation result (fail closed)"]

        val = results[0]["expressions"][0]["value"]
        allow = bool(val.get("allow", False))
        denies = list(val.get("deny", []))

        return allow, denies

    finally:
        if os.path.exists(data_path):
            os.remove(data_path)


def post_commit_status(
    repo: str,
    head_sha: str,
    state: str,
    description: str,
    target_url: str = ""
) -> Dict[str, Any]:
    """
    Post commit status to Gitea for context 'atp/merge-gate'.
    State must be 'success', 'failure', or 'pending'.
    """
    headers = {
        "Authorization": f"Basic {admin_auth()}",
        "Content-Type": "application/json"
    }

    payload = {
        "state": state,
        "context": STATUS_CHECK_CONTEXT,
        "description": description[:250],
        "target_url": target_url or "http://localhost:16686"
    }

    url = f"{GITEA_URL}/repos/online-boutique/{repo}/statuses/{head_sha}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        raise RuntimeError(f"Gitea set status failed: HTTP {e.code} - {err}")


def post_pr_comment(repo: str, pr_number: int, comment: str) -> Dict[str, Any]:
    """Post audit comment to PR on Gitea."""
    headers = {
        "Authorization": f"Basic {admin_auth()}",
        "Content-Type": "application/json"
    }
    url = f"{GITEA_URL}/repos/online-boutique/{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(url, data=json.dumps({"body": comment}).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"Warning: could not post comment to PR #{pr_number}: {e}")
        return {}


def process_pull_request_gate(
    repo: str,
    pr_number: int,
    head_sha: str,
    statement: Optional[Dict[str, Any]],
    bundle: Optional[Dict[str, Any]],
    pubkey_path: str = DEFAULT_PUBKEY_PATH,
    trace_id: str = "",
    approvers: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Complete Gate Evaluation Workflow:
    1. Cryptographically verify signature with cosign
    2. Evaluate OPA merge policy
    3. Post commit status to Gitea
    4. Post audit summary to PR
    """
    t_start = time.time()
    sig_verified = False

    if statement and bundle:
        try:
            sig_verified = verify_statement(statement, bundle, pubkey_path=pubkey_path)
        except Exception as e:
            print(f"Warning: Signature verification encountered error: {e}")
            sig_verified = False
    elif statement and not bundle:
        sig_verified = False

    allow, denies = evaluate_opa_merge_policy(
        statement=statement,
        signature_verified=sig_verified,
        head_sha=head_sha,
        approvers=approvers
    )

    state = "success" if allow else "failure"
    if allow:
        desc = "ATP decision record verified (Cosign signature + OPA merge policy passed)"
    else:
        reasons = "; ".join(denies) if denies else "Policy denied merge"
        desc = f"ATP merge gate DENIED: {reasons}"

    target_url = f"http://localhost:16686/trace/{trace_id}" if trace_id else "http://localhost:16686"
    status_resp = post_commit_status(
        repo=repo,
        head_sha=head_sha,
        state=state,
        description=desc,
        target_url=target_url
    )

    # Post markdown audit summary to PR
    verdict_badge = "🟢 **MERGE ALLOWED**" if allow else "🔴 **MERGE DENIED**"
    audit_comment = (
        f"### 🛡️ ATP In-Toto Decision Record Verification\n\n"
        f"**Verdict:** {verdict_badge}\n"
        f"- **Head Commit:** `{head_sha}`\n"
        f"- **Signature Verified:** `{'true' if sig_verified else 'false'}` (verified via `cosign.pub`)\n"
        f"- **Policy Evaluation:** `{'passed' if allow else 'failed'}` (`policies/merge/attestation.rego`)\n"
        f"- **Trace ID:** `{trace_id or 'none'}`\n"
        f"- **Evaluation Latency:** `{round((time.time() - t_start)*1000, 1)}ms`\n\n"
    )

    if denies:
        audit_comment += "**Violations / Deny Reasons:**\n"
        for d in denies:
            audit_comment += f"- ❌ `{d}`\n"
        audit_comment += "\n"

    if statement:
        pred = statement.get("predicate", {})
        audit_comment += (
            "<details><summary><b>View In-Toto Statement v1 (Cryptographic Record)</b></summary>\n\n"
            f"```json\n{json.dumps(statement, indent=2)}\n```\n"
            "</details>\n"
        )

    post_pr_comment(repo, pr_number, audit_comment)

    return {
        "repo": repo,
        "pr_number": pr_number,
        "head_sha": head_sha,
        "signature_verified": sig_verified,
        "allow": allow,
        "denies": denies,
        "state": state,
        "status_id": status_resp.get("id"),
        "latency_ms": round((time.time() - t_start) * 1000, 1)
    }


def main():
    parser = argparse.ArgumentParser(description="ATP Merge Gate Evaluator")
    parser.add_argument("--repo", default="frontend", help="Target repository")
    parser.add_argument("--pr", type=int, required=True, help="PR number")
    parser.add_argument("--head-sha", required=True, help="Head commit SHA")
    parser.add_argument("--record-file", help="Path to JSON file containing decision record (statement + bundle)")
    parser.add_argument("--pubkey", default=DEFAULT_PUBKEY_PATH, help="Path to cosign.pub")
    parser.add_argument("--trace-id", default="", help="W3C trace ID")

    args = parser.parse_args()

    statement = None
    bundle = None
    if args.record_file and os.path.isfile(args.record_file):
        with open(args.record_file, "r") as f:
            rec = json.load(f)
            statement = rec.get("statement")
            bundle = rec.get("bundle")

    result = process_pull_request_gate(
        repo=args.repo,
        pr_number=args.pr,
        head_sha=args.head_sha,
        statement=statement,
        bundle=bundle,
        pubkey_path=args.pubkey,
        trace_id=args.trace_id
    )

    print(json.dumps(result, indent=2))
    return 0 if result["allow"] else 1


if __name__ == "__main__":
    sys.exit(main())
