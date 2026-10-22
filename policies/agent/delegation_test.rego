package agent.delegation_test

import rego.v1

import data.agent.delegation

base := {
	"caller": "orchestrator",
	"callee": "knowledge",
	"chain": ["orchestrator"],
	"acts_for": "user:alice",
	"context": {"tainted": false},
	"approval": {"granted": false},
}

test_orchestrator_to_specialist_allowed if delegation.allow with input as base

test_specialist_to_specialist_denied if not delegation.allow with input as object.union(base, {"caller": "triage", "callee": "publisher"})

test_missing_acts_for_denied if not delegation.allow with input as object.remove(base, ["acts_for"])

test_tainted_publisher_needs_approval if {
	inp := object.union(base, {"callee": "publisher", "context": {"tainted": true}})
	not delegation.allow with input as inp
}

test_tainted_read_delegation_allowed if delegation.allow with input as object.union(base, {"context": {"tainted": true}})

test_depth_limit if not delegation.allow with input as object.union(base, {"chain": ["orchestrator", "knowledge"]})

test_null_acts_for_denied if not delegation.allow with input as object.union(base, {"acts_for": null})

test_null_approval_publisher_denied if {
	inp := object.union(base, {"callee": "publisher", "context": {"tainted": true}, "approval": {"granted": null}})
	not delegation.allow with input as inp
}

# -----------------------------------------------------------------------------
# Plan Task C2 Regression Tests
# -----------------------------------------------------------------------------

test_missing_chain_denied if {
	inp := object.remove(base, ["chain"])
	not delegation.allow with input as inp
	"missing or invalid delegation chain" in delegation.deny with input as inp
}

test_empty_chain_denied if {
	inp := object.union(base, {"chain": []})
	not delegation.allow with input as inp
	"missing or invalid delegation chain" in delegation.deny with input as inp
}

test_missing_tainted_context_denied if {
	inp := object.remove(base, ["context"])
	not delegation.allow with input as inp
	"missing or invalid context.tainted" in delegation.deny with input as inp
}
