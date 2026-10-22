# Memory write gate, evaluated by the memory MCP server on every memory.write
# (OWASP ASI06; AISVS 1.0 8.2.3, 8.3.3, 12.5.4).
# Closes Evidence E6 (Task C3): enforces automatic write quarantine on every memory
# written during a tainted task, consuming task taint from the gateway ledger.
package agent.memory

import rego.v1

# New memories start quarantined unless every source they came from is trusted
# AND the task is not tainted. Taint is sticky for the whole task (docs/taint.md).
default state := "quarantined"

state := "active" if {
	not is_tainted
	count(input.sources) > 0
	every s in input.sources {
		s.trust == "trusted"
	}
	input.namespace == sprintf("repo:%s", [input.task.repo])
}

# Task taint is maintained by agentgateway's ledger and passed in input.task.tainted
# (or input.context.tainted). If tainted is true, memory writes are quarantined.
is_tainted if input.task.tainted == true

is_tainted if input.context.tainted == true

# Every write must carry provenance (source, writer identity, timestamp).
deny contains "memory write without provenance" if count(input.sources) == 0

deny contains "memory write without writer identity" if not input.writer.spiffe_id

deny contains "memory write outside the task's namespace" if {
	input.namespace != sprintf("repo:%s", [input.task.repo])
	input.namespace != "org"
}
