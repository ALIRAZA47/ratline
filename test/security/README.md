# `test/security` — the security suite

A task with `risk: high` cannot be marked `done` until it names an artifact in
here or in `test/authz/` — enforced by `./scripts/tasks done`, not by memory.

Coverage required by brief §6.7: command injection through every user-controllable
field reaching an agent; path traversal in site paths and the file manager;
cross-tenant access on every resource type; secret leakage into logs, error
traces and metrics labels; rate limiting on all auth endpoints including
password reset; session fixation; CSRF; signed-webhook replay.

**Nothing here may mock the thing it tests** (brief §9).
