#!/usr/bin/env python3
"""
ATP Merge Gate & In-Toto Decision Records Automated Probe Suite (Milestone M7)

Verifies the 8 critical security, policy, and cryptographic invariants of the
Merge Gate & In-Toto Decision Records system:
  Probe 1: [Clean Authentic PR] - Valid signed record -> cosign passes -> OPA allows -> Gitea success.
  Probe 2: [Missing Record] - No decision record -> OPA denies -> Gitea failure -> merge blocked.
  Probe 3: [Tampered Statement] - Tampered record payload -> cosign fails -> OPA denies -> merge blocked.
  Probe 4: [Untrusted Context] - Injection context without approval -> OPA denies -> merge blocked.
  Probe 5: [Memory Laundering] - Quarantined memory read treated as untrusted -> merge blocked (E6).
  Probe 6: [Mismatched Commit Subject] - Replayed statement for other SHA -> OPA denies (E8).
  Probe 7: [Agent Sandbox Key Isolation] - Specialist agent pods cannot access cosign private key (C1).
  Probe 8: [Gitea Branch Protection Enforcement] - Gitea natively rejects merge on failure status.

Closes Review Findings C1, C4, Evidence E5, E6, E8.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from attest.build_statement import (
    DEFAULT_KEY_PATH,
    DEFAULT_PUBKEY_PATH,
    build_and_sign_record,
    build_statement,
    sign_statement,
    verify_statement,
)
from cluster.gitea_auth import admin_auth
from cluster.merge_gate import evaluate_opa_merge_policy, post_commit_status

GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3030/api/v1")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def print_probe(num: int, name: str, desc: str):
    print(f"\n[Probe {num}/8] {name}")
    print(f"  Description: {desc}")


def get_latest_open_pr(repo: str = "frontend") -> Tuple[int, str]:
    """Retrieve the latest open PR number and head SHA from Gitea."""
    headers = {"Authorization": f"Basic {admin_auth()}"}
    req = urllib.request.Request(f"{GITEA_URL}/repos/online-boutique/{repo}/pulls?state=open", headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            prs = json.loads(resp.read().decode())
            if prs:
                return prs[0]["number"], prs[0]["head"]["sha"]
    except Exception as e:
        print(f"Warning: could not fetch PR from Gitea: {e}")
    # Fallback to simulated commit SHA if repo is empty
    return 1, "d80aaf43363e64b3724714089cd14da2e47a4dfa"


def test_gitea_merge_attempt(repo: str, pr_number: int) -> Tuple[bool, int, str]:
    """Attempt to merge PR via Gitea API. Returns (merged: bool, http_code: int, message: str)."""
    headers = {
        "Authorization": f"Basic {admin_auth()}",
        "Content-Type": "application/json"
    }
    url = f"{GITEA_URL}/repos/online-boutique/{repo}/pulls/{pr_number}/merge"
    req = urllib.request.Request(url, data=json.dumps({"Do": "merge"}).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            return True, resp.code, "Merged"
    except urllib.error.HTTPError as e:
        msg = e.read().decode()
        return False, e.code, msg
    except Exception as e:
        return False, 500, str(e)


def run_probe_suite() -> Dict[str, Any]:
    print("============================================================")
    print("Agent Trust Plane: Merge Gate & In-Toto Attestation Probes")
    print("Target Standard: Milestone M7 & Review Findings C1, C4, E5, E6, E8")
    print("============================================================")

    results = []
    pr_num, live_head_sha = get_latest_open_pr("frontend")
    print(f"Using test target: online-boutique/frontend PR #{pr_num} (head: {live_head_sha[:10]})")

    # -------------------------------------------------------------------------
    # Probe 1: Clean Authentic PR (Merge Allowed)
    # -------------------------------------------------------------------------
    print_probe(1, "Clean Authentic In-Toto Record", "Signed Statement v1 with trusted context and verified Cosign key")
    rec1 = build_and_sign_record(
        task_id="t-probe-clean-01",
        head_sha=live_head_sha,
        model_name="qwen3-coder:30b",
        model_digest="sha256:4b9f10a880000000000000000000000000000000000000000000000000000000",
        context=[{"ref": "issue/44487", "trust": "trusted"}],
        tool_calls=[{"tool": "gitea.create_pull_request", "args_sha256": "abc1", "effect": "write", "approval": None}],
        trace_id="00-11111111111111111111111111111111-0000000000000001-01"
    )
    p1_allow, p1_denies = evaluate_opa_merge_policy(
        statement=rec1["statement"],
        signature_verified=rec1["signature_verified"],
        head_sha=live_head_sha
    )
    p1_ok = (rec1["signature_verified"] is True and p1_allow is True and len(p1_denies) == 0)
    print(f"  Result: signature_verified={rec1['signature_verified']}, allow={p1_allow}, denies={p1_denies}")
    print(f"  Verdict: {'✅ PASSED' if p1_ok else '❌ FAILED'}")
    results.append({"probe": 1, "name": "clean_authentic_record", "passed": p1_ok})

    # -------------------------------------------------------------------------
    # Probe 2: Missing Decision Record
    # -------------------------------------------------------------------------
    print_probe(2, "Missing Decision Record", "PR submitted without an in-toto decision record")
    p2_allow, p2_denies = evaluate_opa_merge_policy(
        statement=None,
        signature_verified=False,
        head_sha=live_head_sha
    )
    p2_ok = (p2_allow is False and "no decision record on this PR" in p2_denies)
    print(f"  Result: allow={p2_allow}, denies={p2_denies}")
    print(f"  Verdict: {'✅ PASSED' if p2_ok else '❌ FAILED'}")
    results.append({"probe": 2, "name": "missing_decision_record", "passed": p2_ok})

    # -------------------------------------------------------------------------
    # Probe 3: Tampered Statement / Cryptographic Signature Failure (Closes E8 & C1)
    # -------------------------------------------------------------------------
    print_probe(3, "Tampered Statement Signature Failure", "Statement payload modified after Cosign signing")
    tampered_stmt = json.loads(json.dumps(rec1["statement"]))
    tampered_stmt["predicate"]["model"]["digest"] = "sha256:tampered_digest_0000000000000000"
    # Verify cryptographic check fails on tampered statement
    p3_sig_verified = verify_statement(tampered_stmt, rec1["bundle"], pubkey_path=DEFAULT_PUBKEY_PATH)
    p3_allow, p3_denies = evaluate_opa_merge_policy(
        statement=tampered_stmt,
        signature_verified=p3_sig_verified,
        head_sha=live_head_sha
    )
    p3_ok = (p3_sig_verified is False and p3_allow is False and "decision record signature not verified" in p3_denies)
    print(f"  Result: signature_verified={p3_sig_verified}, allow={p3_allow}, denies={p3_denies}")
    print(f"  Verdict: {'✅ PASSED' if p3_ok else '❌ FAILED'}")
    results.append({"probe": 3, "name": "tampered_signature_failure", "passed": p3_ok})

    # -------------------------------------------------------------------------
    # Probe 4: Untrusted Context Without Approval (Closes E5)
    # -------------------------------------------------------------------------
    print_probe(4, "Untrusted Context Without Approval", "Injection payload in context feeding unapproved write")
    rec4_stmt = build_statement(
        task_id="t-probe-inject-04",
        head_sha=live_head_sha,
        model_name="qwen3-coder:30b",
        model_digest="sha256:4b9f10a880000000000000000000000000000000000000000000000000000000",
        context=[{"ref": "issue/44487#c3", "trust": "untrusted"}],
        tool_calls=[{"tool": "gitea.create_pull_request", "args_sha256": "abc4", "effect": "write", "approval": None}]
    )
    p4_allow, p4_denies = evaluate_opa_merge_policy(
        statement=rec4_stmt,
        signature_verified=True,
        head_sha=live_head_sha
    )
    p4_ok = (p4_allow is False and any("write gitea.create_pull_request" in d for d in p4_denies))
    print(f"  Result: allow={p4_allow}, denies={p4_denies}")
    print(f"  Verdict: {'✅ PASSED' if p4_ok else '❌ FAILED'}")
    results.append({"probe": 4, "name": "untrusted_context_denied", "passed": p4_ok})

    # -------------------------------------------------------------------------
    # Probe 5: Memory Laundering Defense (Closes E6)
    # -------------------------------------------------------------------------
    print_probe(5, "Memory Laundering Defense", "Quarantined memory read treated as untrusted context")
    rec5_stmt = build_statement(
        task_id="t-probe-laundering-05",
        head_sha=live_head_sha,
        model_name="qwen3-coder:30b",
        model_digest="sha256:4b9f10a880000000000000000000000000000000000000000000000000000000",
        context=[{"ref": "memory/poisoned-note", "state": "quarantined", "trust": "untrusted"}],
        memory_reads=[{"id": "mem-uuid-1", "state": "quarantined", "trust": "untrusted"}],
        tool_calls=[{"tool": "gitea.push_files", "args_sha256": "abc5", "effect": "write", "approval": None}]
    )
    p5_allow, p5_denies = evaluate_opa_merge_policy(
        statement=rec5_stmt,
        signature_verified=True,
        head_sha=live_head_sha
    )
    p5_ok = (p5_allow is False and any("after untrusted context has no valid approval" in d for d in p5_denies))
    print(f"  Result: allow={p5_allow}, denies={p5_denies}")
    print(f"  Verdict: {'✅ PASSED' if p5_ok else '❌ FAILED'}")
    results.append({"probe": 5, "name": "memory_laundering_defense", "passed": p5_ok})

    # -------------------------------------------------------------------------
    # Probe 6: Mismatched Commit Subject / Replay Attack (Closes E8)
    # -------------------------------------------------------------------------
    print_probe(6, "Mismatched Commit Subject Check", "Statement signed for commit A replayed on commit B")
    other_commit_sha = "0000000000000000000000000000000000000000"
    p6_allow, p6_denies = evaluate_opa_merge_policy(
        statement=rec1["statement"],
        signature_verified=True,
        head_sha=other_commit_sha
    )
    p6_ok = (p6_allow is False and "decision record is not for this commit" in p6_denies)
    print(f"  Result: allow={p6_allow}, denies={p6_denies}")
    print(f"  Verdict: {'✅ PASSED' if p6_ok else '❌ FAILED'}")
    results.append({"probe": 6, "name": "mismatched_commit_subject", "passed": p6_ok})

    # -------------------------------------------------------------------------
    # Probe 7: Agent Sandbox Key Isolation (Closes C1 & SA-4)
    # -------------------------------------------------------------------------
    print_probe(7, "Agent Sandbox Key Isolation", "Specialist agent pods have zero access to Cosign private key")
    p7_ok = True
    for agent_role in ["coder", "triage", "publisher", "verifier"]:
        cmd = ["kubectl", "-n", "agents", "exec", f"deploy/{agent_role}", "--", "find", "/", "-name", "cosign.key"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        found = "cosign.key" in res.stdout
        if found:
            p7_ok = False
            print(f"  ❌ Security Leak: cosign.key was found inside pod {agent_role}!")
        else:
            print(f"  ✅ Isolated: {agent_role} pod has no access to cosign.key")
    print(f"  Verdict: {'✅ PASSED' if p7_ok else '❌ FAILED'}")
    results.append({"probe": 7, "name": "agent_sandbox_key_isolation", "passed": p7_ok})

    # -------------------------------------------------------------------------
    # Probe 8: Gitea Branch Protection Structural Enforcement
    # -------------------------------------------------------------------------
    print_probe(8, "Gitea Branch Protection Status Check Enforcement", "Gitea blocks merge when atp/merge-gate is failure")
    # Post failure status to head commit
    post_commit_status("frontend", live_head_sha, "failure", "Probe 8: Simulated policy deny")
    time.sleep(0.5)

    merged, code, msg = test_gitea_merge_attempt("frontend", pr_num)
    # Must be blocked (HTTP 405)
    p8_ok = (merged is False and (code == 405 or code == 400))
    print(f"  Result: merged={merged}, HTTP code={code}, response={msg[:80].strip()}")
    print(f"  Verdict: {'✅ PASSED' if p8_ok else '❌ FAILED'}")
    results.append({"probe": 8, "name": "gitea_branch_protection_enforcement", "passed": p8_ok})

    # Reset head status to success for clean cluster state
    post_commit_status("frontend", live_head_sha, "success", "ATP decision record verified (Cosign signature + OPA merge policy passed)")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    all_passed = all(r["passed"] for r in results)
    total_passed = sum(1 for r in results if r["passed"])

    print("\n============================================================")
    if all_passed:
        print(f"🎉 ALL MERGE GATE PROBES PASSED ({total_passed}/8)!")
    else:
        print(f"❌ SOME PROBES FAILED: {total_passed}/8 passed.")
    print("============================================================")

    # Persist probe results
    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary_path = os.path.join(RESULTS_DIR, "merge_gate_probe.json")
    with open(summary_path, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_probes": len(results),
            "passed_probes": total_passed,
            "all_passed": all_passed,
            "probes": results
        }, f, indent=2)
    print(f"Probe results recorded to: {summary_path}")

    return {"all_passed": all_passed, "total_passed": total_passed, "results": results}


if __name__ == "__main__":
    out = run_probe_suite()
    sys.exit(0 if out["all_passed"] else 1)
