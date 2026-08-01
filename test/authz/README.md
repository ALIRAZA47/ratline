# `test/authz` — the authorization matrix

The matrix is **generated from the route table** (RL-M1-024), so an endpoint
added without coverage fails the build rather than passing unnoticed.

Every role × every endpoint × own-resource / other-team-resource /
nonexistent-resource. Cross-tenant access is tested explicitly for every resource
type, never assumed. Unauthorized and nonexistent responses are compared byte for
byte (RL-M1-026).

Results are written to `.ratline/metrics.json`, which `./scripts/tasks render`
reports in `docs/STATUS.md`.
