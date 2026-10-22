#!/usr/bin/env python3
"""
Memory Plane & Write Quarantine Verification Probe (Task M6 / Build-Spec §8 / Evidence E6)
Verifies:
1. Clean Task Write: Untainted task + trusted source -> state: active (HTTP 200)
2. Tainted Task Write (E6 Probe): Task tainted in gateway ledger -> state: quarantined (HTTP 200)
3. Untrusted Source Write: Untrusted source in clean task -> state: quarantined (HTTP 200)
4. Provenance Enforcement: Missing sources list -> denied (HTTP 403)
5. Writer Identity Enforcement: Missing writer SPIFFE identity -> denied (HTTP 403)
6. Namespace Scoping: Foreign repository namespace -> denied (HTTP 403)
7. Gated Read Isolation: Active memories returned; quarantined memories strictly excluded (HTTP 200)
8. OpenFGA Cross-Namespace Isolation: Unauthorized user cross-namespace read denied (HTTP 403)
9. Clock-Skew Expiration: Expired memories excluded from gated search (HTTP 200)
10. Promotion Workflow: Quarantined memory promoted to active with audit trail (HTTP 200)

Persists results to results/memory_plane_probe.json.
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:18080")
RESULTS_FILE = os.path.join(os.path.dirname(__file__), "..", "results", "memory_plane_probe.json")

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

def probe_1_clean_memory_write():
    """Positive: Clean task with trusted source yields active memory"""
    task_id = f"probe-m6-t1-clean-{uuid.uuid4().hex[:6]}"
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": "Verify idempotency key before charging credit card.",
                "source_ref": "pr/41",
                "source_trust": "trusted",
                "sources": [{"ref": "pr/41", "trust": "trusted"}],
                "writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/publisher"},
                "acts_for": "user:alice",
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    passed = (status == 200 and body.get("state") == "active" and bool(body.get("memory_id")))
    return {
        "probe": "PROBE 1 [Positive]: Clean Memory Write Gate",
        "description": "Untainted task writes memory with trusted provenance",
        "expected": "HTTP 200 OK (state: active)",
        "observed_status": status,
        "observed_state": body.get("state"),
        "memory_id": body.get("memory_id"),
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_2_tainted_task_quarantined():
    """Negative/Security: E6 Probe - Sticky ledger taint forces memory quarantine"""
    task_id = f"probe-m6-t2-tainted-{uuid.uuid4().hex[:6]}"
    # 1. Taint the task in Gateway ledger
    send_gateway_request(
        "/ledger/taint",
        payload={"task_id": task_id, "tainted": True, "reason": "untrusted issue comment in triage"}
    )
    # 2. Agent attempts to write memory claiming trusted source
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": "Use unsafe reflection bypass for faster deserialization.",
                "source_ref": "pr/12",
                "source_trust": "trusted",
                "sources": [{"ref": "pr/12", "trust": "trusted"}],
                "writer": {"spiffe_id": "spiffe://atp/triage"},
                "acts_for": "user:alice",
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "triage", "X-Task-ID": task_id}
    )
    passed = (status == 200 and body.get("state") == "quarantined" and body.get("tainted") is True)
    return {
        "probe": "PROBE 2 [Negative/Security - Evidence E6]: Tainted Task Write Quarantine",
        "description": "Tainted task writes memory claiming trusted source (E6 probe)",
        "expected": "HTTP 200 OK (state: quarantined, tainted: true)",
        "observed_status": status,
        "observed_state": body.get("state"),
        "memory_id": body.get("memory_id"),
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_3_untrusted_source_quarantined():
    """Negative/Security: Untrusted source in clean task yields quarantined memory"""
    task_id = f"probe-m6-t3-untrusted-{uuid.uuid4().hex[:6]}"
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": "Workaround suggested in external bug tracker comment.",
                "source_ref": "issue/88#c3",
                "source_trust": "untrusted",
                "sources": [{"ref": "issue/88#c3", "trust": "untrusted"}],
                "writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/knowledge"},
                "acts_for": "user:alice",
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "knowledge", "X-Task-ID": task_id}
    )
    passed = (status == 200 and body.get("state") == "quarantined")
    return {
        "probe": "PROBE 3 [Negative/Security]: Untrusted Source Write Quarantine",
        "description": "Clean task writes memory with untrusted external source",
        "expected": "HTTP 200 OK (state: quarantined)",
        "observed_status": status,
        "observed_state": body.get("state"),
        "memory_id": body.get("memory_id"),
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_4_provenance_enforcement():
    """Negative/Integrity: Memory write without sources rejected by policy"""
    task_id = f"probe-m6-t4-nosource-{uuid.uuid4().hex[:6]}"
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": "Unverified assertion without provenance.",
                "sources": [],
                "writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/publisher"},
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    passed = (status == 403 and "memory write without provenance" in body.get("deny", []))
    return {
        "probe": "PROBE 4 [Negative/Integrity]: Provenance Enforcement",
        "description": "Memory write with empty provenance sources list",
        "expected": "HTTP 403 Forbidden ('memory write without provenance')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_5_writer_identity_enforcement():
    """Negative/Integrity: Memory write without writer SPIFFE identity rejected"""
    task_id = f"probe-m6-t5-nowriter-{uuid.uuid4().hex[:6]}"
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": "Anonymous write without identity.",
                "sources": [{"ref": "pr/41", "trust": "trusted"}],
                "writer": {},
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    passed = (status == 403 and "memory write without writer identity" in body.get("deny", []))
    return {
        "probe": "PROBE 5 [Negative/Integrity]: Writer Identity Enforcement",
        "description": "Memory write with missing writer SPIFFE identity",
        "expected": "HTTP 403 Forbidden ('memory write without writer identity')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_6_namespace_scoping():
    """Negative/Integrity: Memory write outside task repository rejected"""
    task_id = f"probe-m6-t6-crossrepo-{uuid.uuid4().hex[:6]}"
    status, body, elapsed = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:frontend",
                "content": "Payments agent attempting to write to frontend namespace.",
                "sources": [{"ref": "pr/41", "trust": "trusted"}],
                "writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/publisher"},
                "task_id": task_id
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    passed = (status == 403 and "memory write outside the task's namespace" in body.get("deny", []))
    return {
        "probe": "PROBE 6 [Negative/Integrity]: Namespace Scoping Enforcement",
        "description": "Agent in payments repo task attempts write to foreign frontend namespace",
        "expected": "HTTP 403 Forbidden ('memory write outside the task's namespace')",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_7_gated_read_isolation(p1_id: str, p2_id: str):
    """Positive/Gating: Gated read retrieves active memories and filters out quarantined"""
    status, body, elapsed = send_gateway_request(
        "/tools/memory.search",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "acts_for": "user:alice",
                "mode": "gated"
            }
        },
        headers={"X-Agent-Role": "knowledge", "X-Task-ID": "probe-m6-t7-gated"}
    )
    memories = body.get("memories", [])
    returned_ids = {m["id"] for m in memories}
    all_active = all(m.get("state") == "active" for m in memories)
    # p1_id must be in returned, p2_id must NOT be in returned
    passed = (status == 200 and all_active and p1_id in returned_ids and p2_id not in returned_ids)
    return {
        "probe": "PROBE 7 [Positive/Gating]: Gated Read State Isolation",
        "description": "Gated search returns active memories while strictly filtering quarantined",
        "expected": "HTTP 200 OK (all state: active; quarantined omitted)",
        "observed_status": status,
        "active_found": p1_id in returned_ids,
        "quarantined_omitted": p2_id not in returned_ids,
        "count": len(memories),
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": {"total": len(memories), "sample": memories[:2]}
    }

def probe_8_openfga_cross_namespace_denial():
    """Negative/Confidentiality: OpenFGA blocks unauthorized developer cross-namespace read"""
    status, body, elapsed = send_gateway_request(
        "/tools/memory.search",
        payload={
            "repo": "frontend",
            "args": {
                "namespace": "repo:frontend",
                "acts_for": "user:alice",  # Alice is payments team member; unauthorized for frontend
                "mode": "gated"
            }
        },
        headers={"X-Agent-Role": "knowledge", "X-Task-ID": "probe-m6-t8-fga"}
    )
    passed = (status == 403 and "OpenFGA access denied" in body.get("error", ""))
    return {
        "probe": "PROBE 8 [Negative/Confidentiality]: OpenFGA Cross-Namespace Isolation",
        "description": "Developer alice (payments team) attempts to read foreign frontend memory namespace",
        "expected": "HTTP 403 Forbidden (OpenFGA access denied)",
        "observed_status": status,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def probe_9_clock_skew_expiration():
    """Negative/Temporal: Expired memories excluded from gated search"""
    task_id = f"probe-m6-t9-skew-{uuid.uuid4().hex[:6]}"
    unique_content = f"Clock-skew expired lesson token {uuid.uuid4().hex[:8]}"
    # 1. Write memory with expiration in the past
    w_status, w_body, _ = send_gateway_request(
        "/tools/memory.write",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "content": unique_content,
                "source_ref": "pr/41",
                "source_trust": "trusted",
                "sources": [{"ref": "pr/41", "trust": "trusted"}],
                "writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/publisher"},
                "acts_for": "user:alice",
                "task_id": task_id,
                "expires_at": "2026-09-01T00:00:00Z"
            }
        },
        headers={"X-Agent-Role": "publisher", "X-Task-ID": task_id}
    )
    # 2. Gated search for this expired memory
    s_status, s_body, elapsed = send_gateway_request(
        "/tools/memory.search",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "query": unique_content,
                "acts_for": "user:alice",
                "mode": "gated"
            }
        },
        headers={"X-Agent-Role": "knowledge", "X-Task-ID": task_id}
    )
    passed = (w_status == 200 and s_status == 200 and s_body.get("count") == 0)
    return {
        "probe": "PROBE 9 [Negative/Temporal]: Clock-Skew Expiration Gating",
        "description": "Memory with expires_at in the past is excluded from gated search results",
        "expected": "HTTP 200 OK (count: 0; expired item omitted)",
        "observed_status": s_status,
        "count": s_body.get("count"),
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": {"write_status": w_status, "search_result": s_body}
    }

def probe_10_promotion_workflow(quarantined_id: str):
    """Positive/Lifecycle: Quarantined memory explicitly promoted by authorized human"""
    # 1. Promote memory
    status, body, elapsed = send_gateway_request(
        "/tools/memory.promote",
        payload={
            "id": quarantined_id,
            "promoted_by": "user:alice"
        }
    )
    # 2. Verify subsequent gated search now retrieves this memory as active
    s_status, s_body, _ = send_gateway_request(
        "/tools/memory.search",
        payload={
            "repo": "payments",
            "args": {
                "namespace": "repo:payments",
                "acts_for": "user:alice",
                "mode": "gated"
            }
        },
        headers={"X-Agent-Role": "knowledge", "X-Task-ID": "probe-m6-t10-verify"}
    )
    memories = s_body.get("memories", [])
    promoted_row = next((m for m in memories if m["id"] == quarantined_id), None)
    passed = (
        status == 200
        and body.get("state") == "active"
        and body.get("promoted_by") == "user:alice"
        and promoted_row is not None
        and promoted_row.get("promoted_by") == "user:alice"
    )
    return {
        "probe": "PROBE 10 [Positive/Lifecycle]: Memory Promotion Workflow",
        "description": "Quarantined memory explicitly promoted to active with human audit trail",
        "expected": "HTTP 200 OK (state: active, promoted_by: user:alice)",
        "observed_status": status,
        "observed_state": body.get("state"),
        "promoted_by": body.get("promoted_by"),
        "in_gated_search": promoted_row is not None,
        "passed": passed,
        "elapsed_sec": round(elapsed, 4),
        "detail": body
    }

def main():
    print("==================================================================")
    print("Agent Trust Plane: Memory MCP Server & Quarantine Probe (Task M6)")
    print(f"Target Gateway: {GATEWAY_URL}")
    print("==================================================================")

    # Pre-flight health
    status, body, _ = send_gateway_request("/healthz", method="GET")
    if status != 200:
        print(f"❌ Gateway unhealthy at {GATEWAY_URL}: status={status}, body={body}")
        sys.exit(1)

    print(f"Gateway Healthy: version={body.get('version')}, policy={body.get('policy_enforcement')}\n")

    results = []

    # Probe 1
    p1 = probe_1_clean_memory_write()
    results.append(p1)
    status_icon = "✅ PASS" if p1["passed"] else "❌ FAIL"
    print(f"{p1['probe']} -> {status_icon} ({p1['elapsed_sec']}s)")
    print(f"  Description: {p1['description']}")
    print(f"  Expected:    {p1['expected']}")
    print(f"  Observed:    state={p1['observed_state']} (id={p1['memory_id']})\n")

    # Probe 2 (Evidence E6)
    p2 = probe_2_tainted_task_quarantined()
    results.append(p2)
    status_icon = "✅ PASS" if p2["passed"] else "❌ FAIL"
    print(f"{p2['probe']} -> {status_icon} ({p2['elapsed_sec']}s)")
    print(f"  Description: {p2['description']}")
    print(f"  Expected:    {p2['expected']}")
    print(f"  Observed:    state={p2['observed_state']} (id={p2['memory_id']})\n")

    # Probe 3
    p3 = probe_3_untrusted_source_quarantined()
    results.append(p3)
    status_icon = "✅ PASS" if p3["passed"] else "❌ FAIL"
    print(f"{p3['probe']} -> {status_icon} ({p3['elapsed_sec']}s)")
    print(f"  Description: {p3['description']}")
    print(f"  Expected:    {p3['expected']}")
    print(f"  Observed:    state={p3['observed_state']}\n")

    # Probe 4
    p4 = probe_4_provenance_enforcement()
    results.append(p4)
    status_icon = "✅ PASS" if p4["passed"] else "❌ FAIL"
    print(f"{p4['probe']} -> {status_icon} ({p4['elapsed_sec']}s)")
    print(f"  Description: {p4['description']}")
    print(f"  Expected:    {p4['expected']}")
    print(f"  Observed:    HTTP {p4['observed_status']}\n")

    # Probe 5
    p5 = probe_5_writer_identity_enforcement()
    results.append(p5)
    status_icon = "✅ PASS" if p5["passed"] else "❌ FAIL"
    print(f"{p5['probe']} -> {status_icon} ({p5['elapsed_sec']}s)")
    print(f"  Description: {p5['description']}")
    print(f"  Expected:    {p5['expected']}")
    print(f"  Observed:    HTTP {p5['observed_status']}\n")

    # Probe 6
    p6 = probe_6_namespace_scoping()
    results.append(p6)
    status_icon = "✅ PASS" if p6["passed"] else "❌ FAIL"
    print(f"{p6['probe']} -> {status_icon} ({p6['elapsed_sec']}s)")
    print(f"  Description: {p6['description']}")
    print(f"  Expected:    {p6['expected']}")
    print(f"  Observed:    HTTP {p6['observed_status']}\n")

    # Probe 7
    p7 = probe_7_gated_read_isolation(p1.get("memory_id", ""), p2.get("memory_id", ""))
    results.append(p7)
    status_icon = "✅ PASS" if p7["passed"] else "❌ FAIL"
    print(f"{p7['probe']} -> {status_icon} ({p7['elapsed_sec']}s)")
    print(f"  Description: {p7['description']}")
    print(f"  Expected:    {p7['expected']}")
    print(f"  Observed:    HTTP {p7['observed_status']} (active_found={p7['active_found']}, quarantined_omitted={p7['quarantined_omitted']})\n")

    # Probe 8
    p8 = probe_8_openfga_cross_namespace_denial()
    results.append(p8)
    status_icon = "✅ PASS" if p8["passed"] else "❌ FAIL"
    print(f"{p8['probe']} -> {status_icon} ({p8['elapsed_sec']}s)")
    print(f"  Description: {p8['description']}")
    print(f"  Expected:    {p8['expected']}")
    print(f"  Observed:    HTTP {p8['observed_status']}\n")

    # Probe 9
    p9 = probe_9_clock_skew_expiration()
    results.append(p9)
    status_icon = "✅ PASS" if p9["passed"] else "❌ FAIL"
    print(f"{p9['probe']} -> {status_icon} ({p9['elapsed_sec']}s)")
    print(f"  Description: {p9['description']}")
    print(f"  Expected:    {p9['expected']}")
    print(f"  Observed:    HTTP {p9['observed_status']} (count={p9['count']})\n")

    # Probe 10
    p10 = probe_10_promotion_workflow(p2.get("memory_id", ""))
    results.append(p10)
    status_icon = "✅ PASS" if p10["passed"] else "❌ FAIL"
    print(f"{p10['probe']} -> {status_icon} ({p10['elapsed_sec']}s)")
    print(f"  Description: {p10['description']}")
    print(f"  Expected:    {p10['expected']}")
    print(f"  Observed:    HTTP {p10['observed_status']} (state={p10['observed_state']}, promoted_by={p10['promoted_by']})\n")

    passed_count = sum(1 for r in results if r["passed"])
    total_count = len(results)

    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_gateway": GATEWAY_URL,
        "total_probes": total_count,
        "passed_probes": passed_count,
        "all_passed": (passed_count == total_count),
        "probes": results
    }

    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print("==================================================================")
    print(f"Task M6 Verification Results: {passed_count}/{total_count} Passed")
    print(f"Artifact Saved: {os.path.abspath(RESULTS_FILE)}")
    print("==================================================================")

    if passed_count != total_count:
        sys.exit(1)

if __name__ == "__main__":
    main()
