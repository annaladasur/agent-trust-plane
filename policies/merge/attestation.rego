# Merge gate: a required status check on every agent PR. It reads the PR's decision record
# (an in-toto Statement signed by the platform) and refuses the merge when the record is
# missing or unsigned, or when untrusted context fed a write without a matching approval.
# This is what makes the record a control, not only evidence (AISVS 1.0 9.4.2, 12.4.2; AC.8.1).
#
# It fails closed (Evidence E5, plan task C1, panel finding C3):
#   - A call's effect comes from the shared tool table (lib/tooltable.rego), never from the
#     record. A tool the table doesn't list as a read counts as a write.
#   - An approval counts only when a configured human approver, outside the agent
#     identities, granted it for this task, this tool and this exact argument hash.
#   - A record without a context list, a tool_calls list, a task_id, the expected
#     predicateType or a model digest is refused.
#   - Context counts as trusted only when it says "trusted". A missing label is untrusted.
#
# Configuration: data.atp.approvers is the list of human principals allowed to approve
# (for example "user:alice"). It comes from deployment config, never from the record.
# With no list configured, no approval is valid.
package merge.attestation

import rego.v1

import data.lib.tooltable

statement_type := "https://in-toto.io/Statement/v1"

predicate_type := "https://atp.local/agent-decision/v0.1"

default allow := false

allow if count(deny) == 0

stmt := input.statement

pred := input.statement.predicate

deny contains "no decision record on this PR" if not input.statement

# Only a boolean true counts. A string or any other truthy value doesn't.
deny contains "decision record signature not verified" if not input.signature_verified == true

deny contains "decision record is not an in-toto Statement v1" if {
	input.statement
	not stmt._type == statement_type
}

deny contains "decision record has the wrong predicateType" if {
	input.statement
	not stmt.predicateType == predicate_type
}

deny contains "decision record is not for this commit" if {
	input.statement
	not subject_matches
}

subject_matches if {
	non_empty_string(input.pr.head_sha)
	some s in stmt.subject
	s.digest.gitCommit == input.pr.head_sha
}

deny contains "decision record has no model digest" if {
	input.statement
	not has_model_digest
}

deny contains "decision record has no task_id" if {
	input.statement
	not has_task_id
}

# A record that omits its context can't show the context was trusted.
deny contains "decision record has no context list" if {
	input.statement
	not has_context
}

# An agent PR always comes from at least one tool call; a record without them hides them.
deny contains "decision record has no tool_calls list" if {
	input.statement
	not has_tool_calls
}

deny contains msg if {
	some i, call in pred.tool_calls
	not has_tool_name(call)
	msg := sprintf("tool call %d has no tool name", [i])
}

# Presence checks are helper rules on purpose. OPA hoists an undefined function argument
# out of `not`, so `not f(pred.missing)` is undefined rather than true, and the deny
# would silently never fire. Each helper takes no argument or a defined one.
has_model_digest if non_empty_string(pred.model.digest)

has_task_id if non_empty_string(pred.task_id)

has_context if non_empty_array(pred.context)

has_tool_calls if non_empty_array(pred.tool_calls)

has_tool_name(call) if non_empty_string(call.tool)

untrusted_context if {
	some c in pred.context
	not is_trusted_context(c)
}

untrusted_context if {
	some m in pred.memory_reads
	not is_trusted_memory_read(m)
}

# Context items count as trusted only if trust == "trusted" AND, for memory reads,
# the memory state is "active". A quarantined or non-active memory read is untrusted context
# (Plan Task C3; closes E6 memory laundering across tasks).
is_trusted_context(c) if {
	c.trust == "trusted"
	not is_non_active_memory(c)
}

is_non_active_memory(c) if {
	non_empty_string(c.state)
	c.state != "active"
}

is_non_active_memory(c) if {
	c.type == "memory"
	not c.state == "active"
}

is_non_active_memory(c) if {
	is_string(c.ref)
	startswith(c.ref, "memory")
	not c.state == "active"
}

is_trusted_memory_read(m) if {
	m.state == "active"
	m.trust == "trusted"
}


deny contains msg if {
	untrusted_context
	some i, call in pred.tool_calls
	is_write(call)
	not call.tool == "memory.write" # memory writes are gated by provenance instead (memory.rego)
	not approved(call)
	msg := sprintf("write %s (call %d) after untrusted context has no valid approval", [tool_name(call), i])
}

# The record's own "effect" field is ignored.
is_read(call) if call.tool in tooltable.read_tools

is_write(call) if not is_read(call)

# An approval must be granted by a configured human approver, for this task, this tool
# and these exact arguments. This is the same binding tools.rego checks per call.
approved(call) if {
	a := call.approval
	is_object(a)
	a.granted == true
	human_approver(a.by)
	a.task_id == pred.task_id
	a.tool == call.tool
	non_empty_string(call.args_sha256)
	a.args_sha256 == call.args_sha256
}

approvers := {p | some p in data.atp.approvers}

human_approver(p) if {
	non_empty_string(p)
	p in approvers
	not agent_identity(p)
}

# Workload and agent identities. Listing one of these as an approver doesn't make it human.
agent_identity(p) if startswith(p, "spiffe://")

agent_identity(p) if startswith(p, "system:serviceaccount:")

agent_identity(p) if startswith(p, "agent:")

agent_identity(p) if p in tooltable.agent_names

agent_identity(p) if {
	some name in tooltable.agent_names
	endswith(p, sprintf(":%s", [name]))
}

tool_name(call) := call.tool if non_empty_string(call.tool)

else := "<unnamed>"

non_empty_string(x) if {
	is_string(x)
	x != ""
}

non_empty_array(x) if {
	is_array(x)
	count(x) > 0
}
