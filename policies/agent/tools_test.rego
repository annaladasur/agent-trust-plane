package agent.tools_test

import rego.v1

import data.agent.tools

base := {
	"agent": "publisher",
	"task_id": "t-1",
	"task": {"repo": "payments"},
	"tool": {"name": "gitea.create_pull_request"},
	"args": {"repo": "payments", "head": "agent/t-1", "base": "main"},
	"args_sha256": "abc",
	"context": {"tainted": false},
	"approval": {"granted": false},
}

test_publisher_can_open_pr_from_agent_branch if tools.allow with input as base

test_coder_cannot_open_pr if not tools.allow with input as object.union(base, {"agent": "coder"})

test_orchestrator_has_no_tools if not tools.allow with input as object.union(base, {"agent": "orchestrator"})

test_tainted_write_denied_without_approval if {
	inp := object.union(base, {"context": {"tainted": true}})
	not tools.allow with input as inp
	"write after untrusted input needs approval" in tools.deny with input as inp
}

test_tainted_write_allowed_with_bound_approval if {
	inp := object.union(base, {
		"context": {"tainted": true},
		"approval": {"granted": true, "task_id": "t-1", "tool": "gitea.create_pull_request", "args_sha256": "abc"},
	})
	tools.allow with input as inp
}

test_approval_for_other_args_rejected if {
	inp := object.union(base, {
		"context": {"tainted": true},
		"approval": {"granted": true, "task_id": "t-1", "tool": "gitea.create_pull_request", "args_sha256": "zzz"},
	})
	not tools.allow with input as inp
}

test_tainted_read_allowed if {
	inp := object.union(object.remove(base, ["args"]), {
		"agent": "knowledge",
		"tool": {"name": "graph.hybrid_search"},
		"args": {"repo": "payments", "query": "who owns paymentservice"},
		"context": {"tainted": true},
	})
	tools.allow with input as inp
}

test_push_to_main_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.push_files"},
		"args": {"repo": "payments", "branch": "main"},
	})
	"agents never write to main" in tools.deny with input as inp
}

test_pr_from_non_agent_branch_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {"repo": "payments", "head": "feature/x", "base": "main"},
	})
	not tools.allow with input as inp
}

test_cross_repo_target_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {"repo": "frontend", "head": "agent/t-1", "base": "main"},
	})
	"tool target is outside the task's repo" in tools.deny with input as inp
}

test_token_in_args_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {"repo": "payments", "head": "agent/t-1", "body": "debug ghp_abcdef123456"},
	})
	"credential-like value in tool arguments" in tools.deny with input as inp
}

test_triage_memory_write_allowed_when_tainted if {
	inp := object.union(object.remove(base, ["args"]), {
		"agent": "triage",
		"tool": {"name": "memory.write"},
		"args": {"repo": "payments", "content": "lesson"},
		"context": {"tainted": true},
	})
	tools.allow with input as inp
}

test_coder_cannot_write_memory if {
	inp := object.union(object.remove(base, ["args"]), {
		"agent": "coder",
		"tool": {"name": "memory.write"},
		"args": {"repo": "payments"},
	})
	not tools.allow with input as inp
}

test_null_approval_is_not_an_approval if {
	inp := object.union(base, {
		"context": {"tainted": true},
		"approval": {"granted": null, "task_id": "t-1", "tool": "gitea.create_pull_request", "args_sha256": "abc"},
	})
	not tools.allow with input as inp
}

# -----------------------------------------------------------------------------
# Evidence E7 & Reviewer Probe Regression Tests (Plan task C2)
# -----------------------------------------------------------------------------

test_e7_probe_create_branch_new_branch_name_main_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.create_branch"},
		"args": {"repo": "payments", "new_branch_name": "main"},
	})
	not tools.allow with input as inp
	"agents never write to main" in tools.deny with input as inp
}

test_e7_probe_create_branch_new_branch_name_agent_allowed if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.create_branch"},
		"args": {"repo": "payments", "new_branch_name": "agent/fix-cve"},
	})
	tools.allow with input as inp
}

test_e7_probe_push_files_ref_main_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.push_files"},
		"args": {"repo": "payments", "ref": "main"},
	})
	not tools.allow with input as inp
	"agents never write to main" in tools.deny with input as inp
}

test_e7_probe_push_files_ref_agent_allowed if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.push_files"},
		"args": {"repo": "payments", "ref": "refs/heads/agent/fix-cve"},
	})
	tools.allow with input as inp
}

test_e7_probe_create_pr_missing_repo_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {"owner": "other-org", "head": "agent/t-1", "base": "main"},
	})
	not tools.allow with input as inp
	"gitea tool requires repo in arguments" in tools.deny with input as inp
}

test_e7_probe_create_pr_missing_tainted_context_denied if {
	inp := object.remove(base, ["context"])
	not tools.allow with input as inp
	"missing or invalid context.tainted" in tools.deny with input as inp
}

test_e7_probe_other_org_owner_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {"owner": "other-org", "repo": "payments", "head": "agent/t-1", "base": "main"},
	})
	not tools.allow with input as inp
	"tool target owner is outside the task's owner" in tools.deny with input as inp
}

test_e7_probe_nested_credential_in_files_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.push_files"},
		"args": {
			"repo": "payments",
			"branch": "agent/t-1",
			"files": [{"path": "secret.txt", "content": "debug key: ghp_1234567890abcdef"}],
		},
	})
	not tools.allow with input as inp
	"credential-like value in tool arguments" in tools.deny with input as inp
}

test_e7_probe_canary_token_in_arguments_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"args": {
			"repo": "payments",
			"head": "agent/t-1",
			"base": "main",
			"body": "leaking canary sec_canary_0123456789abcdef now",
		},
	})
	not tools.allow with input as inp
	"credential-like value in tool arguments" in tools.deny with input as inp
}

test_missing_branch_on_create_branch_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.create_branch"},
		"args": {"repo": "payments"},
	})
	not tools.allow with input as inp
	"create_branch requires branch or new_branch_name" in tools.deny with input as inp
}

test_missing_ref_on_push_files_denied if {
	inp := object.union(object.remove(base, ["args"]), {
		"tool": {"name": "gitea.push_files"},
		"args": {"repo": "payments"},
	})
	not tools.allow with input as inp
	"push_files requires branch or ref" in tools.deny with input as inp
}
