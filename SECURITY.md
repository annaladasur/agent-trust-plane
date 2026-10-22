# Security scope

This is an educational reference implementation, not a production security boundary. Do not expose the prototype services to untrusted networks or give them production credentials.

Read [known limitations](docs/KNOWN-LIMITATIONS.md), especially the unverified JWT claims, development credential fallbacks and mutable local state. Rego tests verify rule behavior for supplied inputs; they do not establish that the prototype authenticates those inputs correctly or prevents every bypass.

Do not post credentials, private traces or exploit details affecting real deployments in public issues. Use the repository's private vulnerability-reporting feature if available; otherwise open a minimal issue asking for a private reporting channel without sensitive details. No response-time or support commitment is implied.
