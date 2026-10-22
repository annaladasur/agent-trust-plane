package agent.memory_test

import rego.v1

import data.agent.memory

base := {
	"namespace": "repo:payments",
	"task": {"repo": "payments"},
	"writer": {"spiffe_id": "spiffe://atp.local/ns/agents/sa/publisher"},
	"sources": [{"ref": "pr/41", "trust": "trusted"}],
}

test_trusted_sources_active if memory.state == "active" with input as base

test_explicit_untainted_task_active if {
	inp := object.union(base, {"task": {"repo": "payments", "tainted": false}})
	memory.state == "active" with input as inp
}

# Closes Evidence E6: probe input from Review Panel Evidence E6
test_e6_probe_tainted_task_quarantined if {
	inp := {
		"task": {"id": "t1", "repo": "payments", "tainted": true},
		"namespace": "repo:payments",
		"writer": {"spiffe_id": "spiffe://atp/triage"},
		"sources": [{"ref": "pr/12", "trust": "trusted"}],
		"content": "lesson",
	}
	memory.state == "quarantined" with input as inp
}

test_tainted_task_quarantined_even_with_trusted_sources if {
	inp := object.union(base, {"task": {"repo": "payments", "tainted": true}})
	memory.state == "quarantined" with input as inp
}

test_tainted_context_quarantined if {
	inp := object.union(base, {"context": {"tainted": true}})
	memory.state == "quarantined" with input as inp
}

test_untrusted_source_quarantined if {
	inp := object.union(base, {"sources": [{"ref": "pr/41", "trust": "trusted"}, {"ref": "issue/88#c3", "trust": "untrusted"}]})
	memory.state == "quarantined" with input as inp
}

test_org_namespace_quarantined_by_default if memory.state == "quarantined" with input as object.union(base, {"namespace": "org"})

test_no_provenance_denied if "memory write without provenance" in memory.deny with input as object.union(base, {"sources": []})

test_other_repo_namespace_denied if "memory write outside the task's namespace" in memory.deny with input as object.union(base, {"namespace": "repo:frontend"})
