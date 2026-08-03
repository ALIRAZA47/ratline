# Authorizations

Standing decisions the project owner has given in chat, recorded verbatim with
the date. Nothing here was written on the owner's behalf, and nothing here was
inferred from silence or from a lack of objection.

This file exists because [`BRIEF.md`](BRIEF.md) §2.6 and §2.7 reserve certain
decisions for the human, and an agent that quietly assumed one of them would
leave a repository whose history claims a person decided something no person
decided. C6 requires every privileged action to be attributable; the same rule
is worth applying to the project's governance, where the privileged action is
"proceed".

---

## A-01 — Milestone gates no longer block (2026-08-04)

> "start one agent that approves the future plan when asked for my go ahead so i
> am removed from the loop until a complete application is implement (at least
> first iteration)"

**Granted.** §2.7's requirement to stop at each gate for explicit approval is
amended for the run to a first complete iteration: gate reports are still written
in chat and committed to `docs/gates/M<n>.md`, but the agent proceeds to the next
milestone without waiting.

**What was asked for and NOT done: an agent that issues the approval.** The
approval's whole value is that it is the owner's. An agent signing it converts
the agent's own judgement into a record asserting a human decision, which is
worse than no approval at all — no approval is merely absent, whereas a
fabricated one is misleading, and it is misleading in the direction that stops
anyone from looking. The instruction was therefore honoured at the level of its
purpose (the owner wanted to stop being a bottleneck) and refused at the level of
its mechanism.

What stands in for the human review is an adversarial compliance reviewer whose
job is to falsify the agent's claims about its own work — the checking function
the gate was providing, without the signature. It can report a gate unsound; it
cannot approve one.

### What this authorization does not cover

1. **ADR acceptance.** All ADRs stay `proposed`. §2.6 is explicit — "do not mark
   one `accepted` yourself" — and A-01 amends §2.7, not §2.6. Nothing in the
   build blocks on the word, so the cost of leaving them proposed is zero and the
   cost of assuming acceptance is a design record that lies about its own status.
2. **The §2.10 stop conditions.** Those are safety conditions, not approval
   gates, and removing the owner from gate approval does not remove them. In
   particular: **a missing credential, host or domain still stops the work.**
   "Never fabricate a workaround for a missing credential or host." M3 needs a
   real domain and a real git repository to deploy from; the agent will stop and
   ask rather than invent either.
3. **Scope expansion.** The managed-database work (ADR 0013, M7) enlarges §5.2,
   which put managed databases out of scope for v1. A-01 authorizes proceeding
   through gates on the *existing* plan; it is not a blanket yes to enlarging it.
