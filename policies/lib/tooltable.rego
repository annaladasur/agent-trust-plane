# The tool table: which MCP tools each agent may call, and which of them write.
# Shared by the per-call tool policy (agent/tools.rego) and the merge gate
# (merge/attestation.rego), so a write is a write in both places. The merge gate never
# trusts the effect a decision record claims for a call (Evidence E5, plan task C1).
package lib.tooltable

import rego.v1

# Which MCP tools each agent may call at posture P2 (AISVS 9.5.1, 9.3.1).
agent_tools := {
	"orchestrator": set(),
	"triage": {"gitea.get_issue", "gitea.list_issue_comments", "osv.query", "memory.write"},
	"knowledge": {"graph.cypher_read", "graph.hybrid_search", "gitea.get_file_contents", "memory.search", "memory.write"},
	"coder": {"sandbox.read_file", "sandbox.write_file", "sandbox.apply_patch"},
	"verifier": {"gitea.get_commit_status", "gitea.get_file_contents", "memory.write"},
	"publisher": {"gitea.create_branch", "gitea.push_files", "gitea.create_pull_request", "memory.write"},
}

write_tools := {
	"sandbox.write_file", "sandbox.apply_patch", "gitea.create_branch",
	"gitea.push_files", "gitea.create_pull_request", "memory.write",
}

known_tools contains t if {
	some ts in agent_tools
	some t in ts
}

# Only tools in this set count as reads. Anything else, including a tool missing from
# the table, counts as a write.
read_tools := known_tools - write_tools

# Agent names. An approval given by an agent identity is never a human approval.
agent_names := {name | some name, _ in agent_tools}
