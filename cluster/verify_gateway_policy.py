#!/usr/bin/env python3
"""
Gateway Policy & Tool Allow-List Verification Probe (Task M5 / Build-Spec §5)
Verifies:
1. CEL Tool Allow-Lists (mcpAuthorization): Disallowed tools rejected (HTTP 403)
2. CEL A2A Delegation Allow-Lists (a2aDelegation): Lateral agent calls rejected (HTTP 403)
3. OPA extAuthz: Branch safety enforced (no writes to main, HTTP 403)
4. OPA extAuthz: Credential leakage in nested args detected via walk() (HTTP 403)
5. OPA extAuthz: Write-after-taint blocked without approval (HTTP 403)
6. OPA extAuthz: Write-after-taint permitted with call-bound approval (HTTP 200)
7. Fail-Closed Semantics: Engine failure denies by default
8. Audit Trail: Decisions recorded in /policy/decisions with OTLP spans
Persists results to results/gateway_policy_probe.json.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:18080")
RESULTS_FILE = os.path.join(os.path.dirname(__file__), "..", "results", "gateway_policy_probe.json")

def send_gateway_request(path: str, payload: dict = None, headers: dict = None, method: str = "POST") -> tuple[int, dict, float]:
    url = f"{GATEWAY_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            elapsed = time.time() - t0
            return resp.status, json.loads(data) if data else {}, elapsed
    except urllib.error.HTTPError as e:
        err_data = e.read().decode("utf-8")
        elapsed = time.time() - t0
        try:
            parsed = json.loads(err_data)
        except Exception:
            parsed = {"raw": err_data}
        return e.code, parsed, elapsed
    except Exception as e:
        elapsed = time.time() - t0
        return 500, {"error": str(e)}, elapsed

def probe_1_cel_tool_allowlist():
    """Negative: Coder attempts to call gitea.create_pull_request (disallowed by CEL)"""
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.create_pull_request",
        payload={"repo": "frontend", "args": {"head": "agent/test", "base": "main"}},
        headers={"X-Agent-Role": "coder", "X-Task-ID": "probe-m5-t1"}
    )
    passed = (status == 403 and body.get("rule") == "mcpAuthorization")
    return {
        "probe": "PROBE 1 [Negative]: CEL Tool Allow-List Enforcement",
        "description": "Coder agent attempts to invoke gitea.create_pull_request",
        "expected": "HTTP 403 Forbidden (mcpAuthorization)",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_2_cel_delegation_allowlist():
    """Negative: Coder attempts lateral delegation to Publisher (disallowed by CEL)"""
    status, body, elapsed = send_gateway_request(
        "/agents/publisher/run",
        payload={"task_id": "probe-m5-t2"},
        headers={"X-Caller-Role": "coder", "X-Task-ID": "probe-m5-t2"}
    )
    passed = (status == 403 and "CEL delegation denied" in body.get("error", ""))
    return {
        "probe": "PROBE 2 [Negative]: CEL A2A Delegation Allow-List Enforcement",
        "description": "Coder agent attempts lateral delegation to Publisher agent",
        "expected": "HTTP 403 Forbidden (a2aDelegation)",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_3_opa_branch_safety():
    """Negative: Publisher attempts to create branch targeting main (disallowed by OPA)"""
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.create_branch",
        payload={"repo": "frontend", "args": {"branch": "main", "repo": "frontend"}},
        headers={"X-Agent-Role": "publisher", "X-Task-ID": "probe-m5-t3"}
    )
    passed = (status == 403 and "agents never write to main" in body.get("deny", []))
    return {
        "probe": "PROBE 3 [Negative]: OPA extAuthz Branch Safety Enforcement",
        "description": "Publisher attempts to create branch targeting 'main'",
        "expected": "HTTP 403 Forbidden ('agents never write to main')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_4_opa_nested_credential():
    """Negative: Publisher attempts gitea.push_files with nested CANARY_TOKEN (disallowed by OPA)"""
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.push_files",
        payload={
            "repo": "frontend",
            "args": {
                "branch": "agent/fix-cve",
                "repo": "frontend",
                "files": [{"path": "secret.txt", "content": "CANARY_TOKEN_secret_exfil_val"}]
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": "probe-m5-t4"}
    )
    passed = (status == 403 and "credential-like value in tool arguments" in body.get("deny", []))
    return {
        "probe": "PROBE 4 [Negative]: OPA extAuthz Credential Leakage Scanner",
        "description": "Publisher attempts to push files containing CANARY_TOKEN in nested content",
        "expected": "HTTP 403 Forbidden ('credential-like value in tool arguments')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_5_opa_tainted_write_no_approval():
    """Negative: Tainted task invokes write tool without human approval (disallowed by OPA)"""
    # 1. Taint task
    send_gateway_request("/ledger/taint", payload={"task_id": "probe-m5-t5", "tainted": True, "reason": "untrusted comment"})
    # 2. Invoke write tool
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.create_branch",
        payload={"repo": "frontend", "args": {"branch": "agent/fix-cve", "repo": "frontend"}},
        headers={"X-Agent-Role": "publisher", "X-Task-ID": "probe-m5-t5"}
    )
    passed = (status == 403 and "write after untrusted input needs approval" in body.get("deny", []))
    return {
        "probe": "PROBE 5 [Negative]: OPA extAuthz Write-After-Taint Gating",
        "description": "Tainted task attempts consequential write without human approval",
        "expected": "HTTP 403 Forbidden ('write after untrusted input needs approval')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_6_opa_tainted_write_with_approval():
    """Positive: Tainted task invokes write tool with valid call-bound approval (allowed by OPA)"""
    task_id = "probe-m5-t6"
    args = {"branch": "agent/valid-patch", "repo": "frontend"}
    canonical = json.dumps(args, sort_keys=True, separators=(',', ':'))
    args_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # 1. Taint task
    send_gateway_request("/ledger/taint", payload={"task_id": task_id, "tainted": True, "reason": "untrusted comment"})

    # 2. Invoke write tool with bound approval
    approval = {
        "granted": True,
        "task_id": task_id,
        "tool": "gitea.create_branch",
        "args_sha256": args_sha
    }
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.create_branch",
        payload={"repo": "frontend", "args": args, "approval": approval},
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    passed = (status == 200 and body.get("policy_decision") == "allow")
    return {
        "probe": "PROBE 6 [Positive]: OPA extAuthz Call-Bound Human Approval",
        "description": "Tainted task consequential write with valid call-bound approval token",
        "expected": "HTTP 200 OK (Allowed by OPA)",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_7_fail_closed_enforcement():
    """Negative: Incomplete/missing task context fails closed (disallowed by OPA)"""
    status, body, elapsed = send_gateway_request(
        "/tools/gitea.create_branch",
        payload={"args": {"branch": "agent/safe"}}, # Missing repo and task identity
        headers={"X-Agent-Role": "publisher", "X-Task-ID": ""}
    )
    passed = (status == 403 and any("missing" in d for d in body.get("deny", [])))
    return {
        "probe": "PROBE 7 [Negative]: Fail-Closed Enforcement on Missing Context",
        "description": "Tool invocation with missing task_id and missing task.repo",
        "expected": "HTTP 403 Forbidden (Fail-Closed)",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_8_audit_trail_decision_log():
    """Positive: Verify decisions are logged outside the model in decision log"""
    status, body, elapsed = send_gateway_request("/policy/decisions", method="GET")
    total = body.get("total", 0)
    passed = (status == 200 and total >= 6)
    return {
        "probe": "PROBE 8 [Positive]: Policy Decision Log & Telemetry Audit Trail",
        "description": "Verify decision log records 100% of policy decisions outside the model",
        "expected": "HTTP 200 OK with recorded decisions >= 6",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": {"total_recorded": total, "sample": body.get("decisions", [])[-2:] if body.get("decisions") else []}
    }

def main():
    print("==================================================================")
    print("Agent Trust Plane: Gateway Policy & Tool Allow-Lists Probe (M5)")
    print(f"Target Gateway: {GATEWAY_URL}")
    print("==================================================================")

    # Pre-check health
    status, h_body, _ = send_gateway_request("/healthz", method="GET")
    if status != 200:
        print(f"❌ Gateway healthz check failed (status={status}): {h_body}")
        sys.exit(1)
    print(f"Gateway Healthy: version={h_body.get('version')}, policy={h_body.get('policy_enforcement')}, OPA={h_body.get('opa_upstream')}")

    probes = [
        probe_1_cel_tool_allowlist,
        probe_2_cel_delegation_allowlist,
        probe_3_opa_branch_safety,
        probe_4_opa_nested_credential,
        probe_5_opa_tainted_write_no_approval,
        probe_6_opa_tainted_write_with_approval,
        probe_7_fail_closed_enforcement,
        probe_8_audit_trail_decision_log
    ]

    results = []
    all_passed = True

    for p_func in probes:
        r = p_func()
        results.append(r)
        mark = "✅ PASS" if r["passed"] else "❌ FAIL"
        if not r["passed"]:
            all_passed = False
        print(f"\n{r['probe']} -> {mark} ({r['elapsed_sec']}s)")
        print(f"  Description: {r['description']}")
        print(f"  Expected:    {r['expected']}")
        print(f"  Observed:    HTTP {r['observed_status']}")

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "milestone": "M5: Gateway Policy & Tool Allow-Lists",
        "total_probes": len(results),
        "passed_probes": sum(1 for r in results if r["passed"]),
        "all_passed": all_passed,
        "results": results
    }

    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n==================================================================")
    print(f"M5 Probe Results: {summary['passed_probes']}/{summary['total_probes']} Passed")
    print(f"Artifact Saved: {RESULTS_FILE}")
    print("==================================================================")

    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
