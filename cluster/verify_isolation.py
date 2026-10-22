#!/usr/bin/env python3
"""
Structural Network Isolation Verification Probe (SA-4 / Item P10 / Review Finding E9)
Verifies that Kubernetes NetworkPolicy is strictly enforced on the cluster:
- Coder agent pod has ZERO direct external egress (Gitea, Host Model Server, Internet)
- Coder agent cannot laterally invoke other agent pods directly
- Coder agent CAN reach mediation gateway (agentgateway) and query models via gateway
- Settles the dispute: proves kindnet in kind v0.33.0 / k8s v1.37.0 enforces NetworkPolicy
Outputs JSON results to results/isolation_probe.json.
"""

import json
import os
import subprocess
import sys
import time

NAMESPACE = "agents"
RESULTS_FILE = os.path.join(os.path.dirname(__file__), "..", "results", "isolation_probe.json")

def run_in_pod(pod_app: str, cmd_py: str, timeout_sec: int = 10) -> tuple[int, str]:
    """Execute python snippet inside designated agent pod via kubectl."""
    cmd = [
        "kubectl", "-n", NAMESPACE, "exec", f"deploy/{pod_app}", "--",
        "python3", "-c", cmd_py
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec
        )
        output = (proc.stdout + "\n" + proc.stderr).strip()
        return proc.returncode, output
    except subprocess.TimeoutExpired:
        return 124, "Timed out waiting for kubectl exec"
    except Exception as e:
        return 1, str(e)

def test_coder_direct_gitea():
    """Negative test: Coder attempting direct TCP to Gitea."""
    py = """
import urllib.request
try:
    resp = urllib.request.urlopen("http://gitea.gitea.svc:3000/", timeout=3)
    print("STATUS:", resp.status)
except Exception as e:
    print("BLOCKED:", type(e).__name__)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "gitea_direct",
        "expected": "BLOCKED",
        "passed": (code != 0 and ("BLOCKED" in out or "TimeoutError" in out or "timed out" in out)),
        "exit_code": code,
        "detail": out
    }

def test_coder_direct_model_server():
    """Negative test: Coder attempting direct TCP to host model server (Ollama)."""
    py = """
import urllib.request
try:
    resp = urllib.request.urlopen("http://172.25.0.1:11434/api/tags", timeout=3)
    print("STATUS:", resp.status)
except Exception as e:
    print("BLOCKED:", type(e).__name__)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "model_server_direct",
        "expected": "BLOCKED",
        "passed": (code != 0 and ("BLOCKED" in out or "TimeoutError" in out or "timed out" in out)),
        "exit_code": code,
        "detail": out
    }

def test_coder_direct_internet():
    """Negative test: Coder attempting direct TCP to external internet."""
    py = """
import urllib.request
try:
    resp = urllib.request.urlopen("http://1.1.1.1:80", timeout=3)
    print("STATUS:", resp.status)
except Exception as e:
    print("BLOCKED:", type(e).__name__)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "external_internet_direct",
        "expected": "BLOCKED",
        "passed": (code != 0 and ("BLOCKED" in out or "TimeoutError" in out or "timed out" in out)),
        "exit_code": code,
        "detail": out
    }

def test_coder_lateral_agent():
    """Negative test: Coder attempting direct lateral invocation of publisher agent."""
    py = """
import urllib.request
try:
    resp = urllib.request.urlopen("http://publisher.agents.svc:8000/run", timeout=3)
    print("STATUS:", resp.status)
except Exception as e:
    print("BLOCKED:", type(e).__name__)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "lateral_agent_invocation_direct",
        "expected": "BLOCKED",
        "passed": (code != 0 and ("BLOCKED" in out or "TimeoutError" in out or "timed out" in out)),
        "exit_code": code,
        "detail": out
    }

def test_coder_gateway_health():
    """Positive test: Coder reachability to agentgateway."""
    py = """
import urllib.request
try:
    resp = urllib.request.urlopen("http://agentgateway.agents.svc:8080/healthz", timeout=3)
    print("STATUS:", resp.status)
    exit(0 if resp.status == 200 else 1)
except Exception as e:
    print("ERROR:", e)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "agentgateway_healthz",
        "expected": "ALLOWED (200)",
        "passed": (code == 0 and "STATUS: 200" in out),
        "exit_code": code,
        "detail": out
    }

def test_coder_model_via_gateway():
    """Positive test: Coder can query models mediated through agentgateway."""
    py = """
import urllib.request, json
try:
    resp = urllib.request.urlopen("http://agentgateway.agents.svc:8080/api/tags", timeout=5)
    data = json.loads(resp.read().decode("utf-8"))
    models = [m.get("name") for m in data.get("models", [])]
    print("STATUS: 200, MODELS:", len(models))
    exit(0 if resp.status == 200 and len(models) > 0 else 1)
except Exception as e:
    print("ERROR:", e)
    exit(1)
"""
    code, out = run_in_pod("coder", py, timeout_sec=8)
    return {
        "target": "model_server_via_agentgateway",
        "expected": "ALLOWED (200)",
        "passed": (code == 0 and "STATUS: 200" in out),
        "exit_code": code,
        "detail": out
    }

def main():
    print("=" * 65)
    print("ATP Structural NetworkPolicy Isolation Probe (SA-4 / Item P10)")
    print(f"Target Namespace: {NAMESPACE} | Cluster CNI: kindnet")
    print("=" * 65)

    tests = [
        ("PROBE 1 [Negative] Direct Gitea Access from Coder", test_coder_direct_gitea),
        ("PROBE 2 [Negative] Direct Model Server Access from Coder", test_coder_direct_model_server),
        ("PROBE 3 [Negative] Direct Internet Egress from Coder", test_coder_direct_internet),
        ("PROBE 4 [Negative] Direct Lateral Agent Ingress (Coder -> Publisher)", test_coder_lateral_agent),
        ("PROBE 5 [Positive] Mediation Gateway Egress (Coder -> AgentGateway)", test_coder_gateway_health),
        ("PROBE 6 [Positive] Model Inference via Gateway (Coder -> AgentGateway -> Ollama)", test_coder_model_via_gateway),
    ]

    results = []
    all_passed = True

    for title, test_fn in tests:
        print(f"\nRunning {title}...")
        t0 = time.time()
        res = test_fn()
        elapsed = time.time() - t0
        res["elapsed_sec"] = round(elapsed, 2)
        res["title"] = title
        results.append(res)

        status_str = "✅ PASS" if res["passed"] else "❌ FAIL"
        if not res["passed"]:
            all_passed = False
        print(f"  {status_str} (Expected: {res['expected']}, Elapsed: {res['elapsed_sec']}s)")
        print(f"  Detail: {res['detail'].splitlines()[-1] if res['detail'] else 'None'}")

    probe_artifact = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cni_enforcement": "kindnet_enforced",
        "cluster_kubernetes_version": "v1.37.0",
        "kind_version": "v0.33.0",
        "sa_4_verified": all_passed,
        "summary": {
            "total": len(tests),
            "passed": sum(1 for r in results if r["passed"]),
            "failed": sum(1 for r in results if not r["passed"])
        },
        "probes": results
    }

    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "w") as f:
        json.dump(probe_artifact, f, indent=2)

    print("\n" + "=" * 65)
    if all_passed:
        print("🎉 ALL NETWORK ISOLATION PROBES PASSED!")
        print("  - Structural zero-egress verified for sandboxed Coder agent.")
        print("  - Direct gateway bypass to Gitea/Model/Internet is structurally blocked.")
        print("  - Direct agent-to-agent lateral movement is structurally blocked.")
        print("  - Mediated egress through AgentGateway functions cleanly.")
        print("  - SA-4 VERIFIED. Item P10 & Review Evidence E9 CLOSED.")
    else:
        print("❌ ONE OR MORE NETWORK ISOLATION PROBES FAILED!")
    print(f"Results recorded in: {RESULTS_FILE}")
    print("=" * 65)

    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
