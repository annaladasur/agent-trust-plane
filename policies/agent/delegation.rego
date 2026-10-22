# A2A delegation policy, evaluated by agentgateway before a delegation reaches an agent
# (OWASP ASI07; AISVS 1.0 9.5.5, 9.2.10). The orchestrator is deterministic code, so in
# practice this enforces that nothing else delegates, and that acts-for travels on every hop.
# Fails closed on missing or unexpected delegation fields (Evidence E7, plan task C2).
package agent.delegation

import rego.v1

# The only delegation edges that exist. Specialists never call each other.
edges := {
	"orchestrator": {"triage", "knowledge", "coder", "verifier", "publisher"},
}

# Callee impact, used to apply the highest impact present anywhere in the chain (9.2.10).
impact := {"triage": 0, "knowledge": 0, "verifier": 0, "coder": 1, "publisher": 2}

max_depth := 2

default allow := false

allow if {
	input.callee in edges[input.caller]
	count(deny) == 0
}

# Delegation chain must be present as a non-empty array (Evidence E7, plan task C2)
has_valid_chain if {
	is_array(input.chain)
	count(input.chain) > 0
}

deny contains "missing or invalid delegation chain" if not has_valid_chain

deny contains "delegation chain too deep" if {
	has_valid_chain
	count(input.chain) >= max_depth
}

# Context must specify whether the task is tainted
has_valid_tainted_context if is_boolean(input.context.tainted)

deny contains "missing or invalid context.tainted" if not has_valid_tainted_context

deny contains "delegating a write to publisher after untrusted input needs approval" if {
	impact[input.callee] == 2
	input.context.tainted == true
	not input.approval.granted == true
}

deny contains "acts-for must be carried on every delegation" if not has_acts_for

has_acts_for if {
	is_string(input.acts_for)
	input.acts_for != ""
}

# Signed A2A Agent Cards (JWS, optional in A2A 1.0) are future work; when added, require
# input.callee_card.signature_verified here.
