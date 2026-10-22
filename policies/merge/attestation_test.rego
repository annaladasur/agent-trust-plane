package merge.attestation_test

import rego.v1

import data.merge.attestation

approvers := ["user:alice"]

pr_call := {"tool": "gitea.create_pull_request", "args_sha256": "abc", "approval": null}

stmt := {
	"_type": "https://in-toto.io/Statement/v1",
	"subject": [{"name": "pr/41", "digest": {"gitCommit": "9f2c"}}],
	"predicateType": "https://atp.local/agent-decision/v0.1",
	"predicate": {
		"task_id": "t-0412",
		"model": {"name": "model-a", "digest": "sha256:abc"},
		"context": [{"ref": "issue/88", "trust": "trusted"}],
		"tool_calls": [pr_call],
	},
}

untrusted := {"ref": "issue/88#c3", "trust": "untrusted"}

good_approval := {
	"by": "user:alice",
	"granted": true,
	"task_id": "t-0412",
	"tool": "gitea.create_pull_request",
	"args_sha256": "abc",
}

with_stmt(s) := {"statement": s, "signature_verified": true, "pr": {"head_sha": "9f2c"}}

base := with_stmt(stmt)

# The base record with untrusted context added and the PR call's approval replaced.
tainted_with_approval(a) := with_stmt(json.patch(stmt, [
	{"op": "add", "path": "/predicate/context/-", "value": untrusted},
	{"op": "replace", "path": "/predicate/tool_calls/0/approval", "value": a},
]))

allowed(inp) if attestation.allow with input as inp with data.atp.approvers as approvers

# --- Records that should pass ---

test_clean_record_allows_merge if allowed(base)

test_untrusted_context_approved_write_allows if allowed(tainted_with_approval(good_approval))

test_memory_write_after_untrusted_is_not_a_merge_blocker if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": untrusted},
		{"op": "replace", "path": "/predicate/tool_calls/0", "value": {"tool": "memory.write", "args_sha256": "m1", "approval": null}},
	])
	allowed(with_stmt(s))
}

test_read_after_untrusted_needs_no_approval if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": untrusted},
		{"op": "replace", "path": "/predicate/tool_calls/0", "value": {"tool": "gitea.get_file_contents", "args_sha256": "r1", "approval": null}},
	])
	allowed(with_stmt(s))
}

# --- Record integrity ---

test_missing_record_blocks if not allowed({"pr": {"head_sha": "9f2c"}})

test_unsigned_record_blocks if not allowed(object.union(base, {"signature_verified": false}))

test_signature_flag_must_be_boolean_true if not allowed(object.union(base, {"signature_verified": "true"}))

test_record_for_other_commit_blocks if not allowed(object.union(base, {"pr": {"head_sha": "0000"}}))

test_missing_head_sha_blocks if not allowed(object.remove(base, ["pr"]))

test_missing_model_digest_blocks if {
	s := json.patch(stmt, [{"op": "remove", "path": "/predicate/model/digest"}])
	not allowed(with_stmt(s))
}

test_missing_task_id_blocks if {
	s := json.patch(stmt, [{"op": "remove", "path": "/predicate/task_id"}])
	not allowed(with_stmt(s))
}

test_wrong_statement_type_blocks if {
	s := json.patch(stmt, [{"op": "replace", "path": "/_type", "value": "https://in-toto.io/Statement/v0.1"}])
	not allowed(with_stmt(s))
}

# --- Evidence E5 probes (Reviews/2026-10-03-panel/Evidence.md). Each allowed before the fix. ---

test_e5_probe_empty_approval_denies if not allowed(tainted_with_approval({}))

test_e5_probe_missing_context_denies if {
	s := json.patch(stmt, [{"op": "remove", "path": "/predicate/context"}])
	not allowed(with_stmt(s))
}

test_e5_probe_write_labelled_read_denies if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": untrusted},
		{"op": "replace", "path": "/predicate/tool_calls/0", "value": {"tool": "gitea.push_files", "effect": "read", "args_sha256": "p1", "approval": null}},
	])
	not allowed(with_stmt(s))
}

test_e5_probe_approval_by_publisher_agent_denies if {
	a := object.union(good_approval, {"by": "spiffe://atp/publisher"})
	not attestation.allow with input as tainted_with_approval(a)
		with data.atp.approvers as ["user:alice", "spiffe://atp/publisher"]
}

test_e5_probe_mismatched_args_sha256_denies if {
	not allowed(tainted_with_approval(object.union(good_approval, {"args_sha256": "def"})))
}

test_e5_probe_wrong_predicate_type_denies if {
	s := json.patch(stmt, [{"op": "replace", "path": "/predicateType", "value": "https://slsa.dev/provenance/v1"}])
	not allowed(with_stmt(s))
}

# --- Approval binding ---

test_approval_for_other_task_denies if {
	not allowed(tainted_with_approval(object.union(good_approval, {"task_id": "t-9999"})))
}

test_approval_for_other_tool_denies if {
	not allowed(tainted_with_approval(object.union(good_approval, {"tool": "gitea.push_files"})))
}

test_refused_approval_denies if {
	not allowed(tainted_with_approval(object.union(good_approval, {"granted": false})))
}

test_approver_not_on_list_denies if {
	not allowed(tainted_with_approval(object.union(good_approval, {"by": "user:mallory"})))
}

test_agent_name_as_user_denies if {
	a := object.union(good_approval, {"by": "user:publisher"})
	not attestation.allow with input as tainted_with_approval(a)
		with data.atp.approvers as ["user:publisher"]
}

test_no_approvers_configured_denies if {
	not attestation.allow with input as tainted_with_approval(good_approval)
}

test_call_without_args_hash_denies if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": untrusted},
		{"op": "replace", "path": "/predicate/tool_calls/0", "value": {"tool": "gitea.create_pull_request", "approval": object.union(good_approval, {"args_sha256": ""})}},
	])
	not allowed(with_stmt(s))
}

# --- Fail closed on shape ---

test_empty_context_denies if {
	s := json.patch(stmt, [{"op": "replace", "path": "/predicate/context", "value": []}])
	not allowed(with_stmt(s))
}

test_missing_tool_calls_denies if {
	s := json.patch(stmt, [{"op": "remove", "path": "/predicate/tool_calls"}])
	not allowed(with_stmt(s))
}

test_context_without_trust_label_counts_as_untrusted if {
	s := json.patch(stmt, [{"op": "add", "path": "/predicate/context/-", "value": {"ref": "issue/88#c4"}}])
	not allowed(with_stmt(s))
}

test_unknown_tool_counts_as_write if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": untrusted},
		{"op": "replace", "path": "/predicate/tool_calls/0", "value": {"tool": "gitea.delete_branch", "args_sha256": "d1", "approval": null}},
	])
	not allowed(with_stmt(s))
}

test_unnamed_tool_call_denies if {
	s := json.patch(stmt, [{"op": "add", "path": "/predicate/tool_calls/-", "value": {"args_sha256": "x1", "approval": null}}])
	not allowed(with_stmt(s))
}

# --- Task C3: Memory Laundering Defense ---

# Closes Task C3 / Evidence E6: reading a quarantined memory write (even if marked trust: "trusted")
# is treated as untrusted context, so unapproved writes fail at the merge gate.
test_e6_memory_laundering_quarantined_read_treated_as_untrusted_denies_merge if {
	quarantined_mem := {
		"ref": "memory:pr/12-rule",
		"type": "memory",
		"trust": "trusted",
		"state": "quarantined",
	}
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": quarantined_mem},
	])
	not allowed(with_stmt(s))
}

test_e6_memory_laundering_ref_prefix_quarantined_denies_merge if {
	quarantined_mem := {
		"ref": "memory:injected-rule-44",
		"trust": "trusted",
		"state": "quarantined",
	}
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": quarantined_mem},
	])
	not allowed(with_stmt(s))
}

test_e6_memory_laundering_quarantined_in_memory_reads_array_denies_merge if {
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/memory_reads", "value": [
			{"ref": "memory:t1", "state": "quarantined", "trust": "trusted"},
		]},
	])
	not allowed(with_stmt(s))
}

test_active_trusted_memory_read_allows_merge if {
	active_mem := {
		"ref": "memory:pr/12-rule",
		"type": "memory",
		"trust": "trusted",
		"state": "active",
	}
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": active_mem},
	])
	allowed(with_stmt(s))
}

test_quarantined_memory_read_with_human_approval_allows_merge if {
	quarantined_mem := {
		"ref": "memory:pr/12-rule",
		"type": "memory",
		"trust": "trusted",
		"state": "quarantined",
	}
	s := json.patch(stmt, [
		{"op": "add", "path": "/predicate/context/-", "value": quarantined_mem},
		{"op": "replace", "path": "/predicate/tool_calls/0/approval", "value": good_approval},
	])
	allowed(with_stmt(s))
}
