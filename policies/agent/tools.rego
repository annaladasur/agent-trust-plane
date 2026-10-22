# Per-call tool policy, evaluated by agentgateway (via ext-authz) before every MCP tool call.
# The decision lives outside the agent's runtime (AISVS 1.0 5.2.5, 9.5.3).
# Fails closed on missing or unexpected arguments (Evidence E7, plan task C2).
package agent.tools

import rego.v1

import data.lib.tooltable

# Which MCP tools each agent may call at posture P2 (AISVS 9.5.1, 9.3.1), and which
# tools write. Both live in lib/tooltable.rego, shared with the merge gate.
agent_tools := tooltable.agent_tools

write_tools := tooltable.write_tools

default allow := false

allow if {
	input.tool.name in agent_tools[input.agent]
	count(deny) == 0
}

effect := "write" if input.tool.name in write_tools

else := "read"

# -----------------------------------------------------------------------------
# Input & Context Integrity (Fail closed)
# -----------------------------------------------------------------------------

# Every tool call must carry task identity and valid context.
has_task_id if non_empty_string(input.task_id)

deny contains "missing or invalid task_id" if not has_task_id

has_task_repo if non_empty_string(input.task.repo)

deny contains "missing or invalid task.repo" if not has_task_repo

has_valid_tainted_context if is_boolean(input.context.tainted)

deny contains "missing or invalid context.tainted" if not has_valid_tainted_context

task_owner := input.task.owner if non_empty_string(input.task.owner)
else := "online-boutique"

# -----------------------------------------------------------------------------
# Taint & Approval Enforcement
# -----------------------------------------------------------------------------

# Once untrusted content has entered the task, writes need a human approval bound to
# this exact call (AISVS 9.3.5, 9.2.1, 9.2.8). input.context.tainted is computed by the
# gateway from the provenance of tool responses in this task (docs/taint.md). The agent
# never reports it and cannot clear it.
deny contains "write after untrusted input needs approval" if {
	effect == "write"
	input.tool.name != "memory.write" # memory writes are gated by provenance instead (memory.rego)
	input.context.tainted == true
	not approval_valid
}

approval_valid if {
	is_object(input.approval)
	input.approval.granted == true
	non_empty_string(input.task_id)
	input.approval.task_id == input.task_id
	input.approval.tool == input.tool.name
	non_empty_string(input.args_sha256)
	input.approval.args_sha256 == input.args_sha256
}

# -----------------------------------------------------------------------------
# Repo and Owner Scoping
# -----------------------------------------------------------------------------

gitea_tools := {
	"gitea.get_issue",
	"gitea.list_issue_comments",
	"gitea.get_file_contents",
	"gitea.get_commit_status",
	"gitea.create_branch",
	"gitea.push_files",
	"gitea.create_pull_request",
}

has_args_repo if non_empty_string(input.args.repo)

# All Gitea tools require repo in arguments, and it must match the task's repo
deny contains "gitea tool requires repo in arguments" if {
	input.tool.name in gitea_tools
	not has_args_repo
}

deny contains "tool target is outside the task's repo" if {
	has_args_repo
	input.args.repo != input.task.repo
}

# If owner is specified, it must match the authorized task owner
deny contains "tool target owner is outside the task's owner" if {
	non_empty_string(input.args.owner)
	input.args.owner != task_owner
}

# -----------------------------------------------------------------------------
# Per-tool argument schemas & branch safety
# -----------------------------------------------------------------------------

has_create_branch_target if non_empty_string(input.args.branch)
has_create_branch_target if non_empty_string(input.args.new_branch_name)

# For gitea.create_branch, branch can be in args.branch or args.new_branch_name (Gitea API)
create_branch_target := input.args.branch if non_empty_string(input.args.branch)
else := input.args.new_branch_name if non_empty_string(input.args.new_branch_name)

deny contains "create_branch requires branch or new_branch_name" if {
	input.tool.name == "gitea.create_branch"
	not has_create_branch_target
}

deny contains "agents never write to main" if {
	input.tool.name == "gitea.create_branch"
	has_create_branch_target
	not valid_agent_branch(create_branch_target)
}

has_push_files_target if non_empty_string(input.args.branch)
has_push_files_target if non_empty_string(input.args.ref)

# For gitea.push_files, branch can be in args.branch or args.ref
push_files_target := input.args.branch if non_empty_string(input.args.branch)
else := input.args.ref if non_empty_string(input.args.ref)

deny contains "push_files requires branch or ref" if {
	input.tool.name == "gitea.push_files"
	not has_push_files_target
}

deny contains "agents never write to main" if {
	input.tool.name == "gitea.push_files"
	has_push_files_target
	not valid_agent_branch(push_files_target)
}

has_args_head if non_empty_string(input.args.head)

# For gitea.create_pull_request: head and base are required, head must be agent branch
deny contains "create_pull_request requires head" if {
	input.tool.name == "gitea.create_pull_request"
	not has_args_head
}

has_args_base if non_empty_string(input.args.base)

deny contains "create_pull_request requires base" if {
	input.tool.name == "gitea.create_pull_request"
	not has_args_base
}

deny contains "PR must come from an agent branch" if {
	input.tool.name == "gitea.create_pull_request"
	has_args_head
	not valid_agent_branch(input.args.head)
}

valid_agent_branch(b) if startswith(b, "agent/")
valid_agent_branch(b) if startswith(b, "refs/heads/agent/")

# -----------------------------------------------------------------------------
# Credential protection: walk() nested arguments
# -----------------------------------------------------------------------------

# Secrets never travel through tool arguments the model wrote (AISVS 9.5.4).
# Recursively scans all nested structures (files[].content, headers, etc.).
deny contains "credential-like value in tool arguments" if {
	some _, v in walk(input.args)
	is_string(v)
	regex.match(`(?i)(ghp_|gho_|glpat-|xox[bp]-|-----BEGIN [A-Z ]*PRIVATE KEY|CANARY_TOKEN|sec_canary_[0-9a-fA-F]+)`, v)
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

non_empty_string(x) if {
	is_string(x)
	x != ""
}
