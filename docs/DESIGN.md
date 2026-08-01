# Ratline — design plan

**Status:** proposed, awaiting approval at the M0 gate
**Date:** 2026-08-01
**Task:** RL-M0-022

The audience lives in this tool during incidents. Every choice below is settled
by one question: **does this help someone at 2am who is frightened and in a
hurry?** Density and scannability beat polish, while still feeling deliberate.

---

## 1. The organising rule

> **Colour means status. Nothing else is allowed to be saturated.**

Ratline has no brand accent colour. Every saturated hue on screen carries
operational meaning, so a spot of red is *always* a failure and never a
decorative button. The brand shows up in **form** — warm neutrals, rope-derived
linework, the type pairing, the tension line — not in hue.

This is the single most consequential decision here. It costs the marketing
palette and buys an interface where colour is signal at a glance from across a
room, which is what §6.6 asks for.

Corollary: **status is never colour alone.** Every status carries a glyph as
well, because roughly one in twelve men has a red/green deficiency and incidents
are not the moment to find out.

---

## 2. Palette

Warm near-black rather than the blue-grey slate every admin panel ships with —
tarred rope, not a spreadsheet.

### Named values

| Token | Dark (default) | Light | Use |
| --- | --- | --- | --- |
| `--tar` | `#14110F` | `#FBF8F4` | Page canvas |
| `--pitch` | `#1E1A17` | `#FFFFFF` | Cards, rails, raised surfaces |
| `--hemp` | `#D8B98A` | `#8A6F45` | Rope linework, active markers, focus rings |
| `--chalk` | `#EDE7DF` | `#1A1613` | Primary text |
| `--chalk-dim` | `#9A918A` | `#5E564F` | Secondary text, labels |

Five values. Everything else is one of these at an opacity, or a status colour.
Hairlines are `--hemp` at 12%; hover is `--chalk` at 4%.

### Status language — used identically everywhere

| Status | Glyph | Dark | Light | Meaning |
| --- | --- | --- | --- | --- |
| Healthy | `●` | `#4FB477` | `#1F7A46` | Running, succeeded, valid |
| Working | `◐` | `#59A5D8` | `#1D6FA5` | Deploying, provisioning, building |
| Attention | `▲` | `#E0A33E` | `#8A5A00` | Degraded, expiring, needs action |
| Failed | `✕` | `#FF6369` | `#C0272D` | Failed, down, revoked |
| Idle | `○` | `#7A736C` | `#8A837C` | Never deployed, disabled, unknown |

Failed uses `#FF6369` rather than a mid red so body-size text clears 4.5:1 on
`--tar`. The darker `#E5484D` is available as `--st-fail-mark` for large marks
and fills where contrast is not the constraint.

Break-glass is the one exception to the palette: full-bleed `--st-fail` banner
for the whole duration of the elevation. It is meant to be uncomfortable.

---

## 3. Type

Self-hosted, all of it. C5 means the dashboard must work on an air-gapped VPN
with no external origin reachable — a font CDN would break exactly when someone
needs the tool most.

| Role | Face | Why |
| --- | --- | --- |
| Display | **Archivo Expanded**, 600/700 | Industrial grotesque with real width. Screen titles, status counts, section heads. The expansion is the signature — it reads as signage, not as a dashboard. |
| Body / UI | **Public Sans**, 400/500 | Built for dense government forms, which is exactly this problem. Holds up at 13px in a table. Unglamorous and correct. |
| Mono | **JetBrains Mono**, 400/700, **ligatures off** | Tall x-height, unambiguous `0`/`O` and `1`/`l`, wide language coverage for terminal output. Ligatures are actively wrong in logs — `!=` must look like two characters. |

Scale, 13px base because density wins: `11 / 12 / 13 / 15 / 18 / 24 / 32`.
Tables and logs sit at 12–13. Numerals are tabular everywhere a number can
change.

---

## 4. Layout — "the shroud"

A fixed structure that never moves, so muscle memory survives a stressful night.

```
┌────────────────────────────────────────────────────────────┐
│ ▓▓▓ BREAK-GLASS ACTIVE — 41 min left — Ali · "prod outage" │ ← only when active
├──────┬─────────────────────────────────────────────────────┤
│      │ acme / marketing-www   [production]      ⌘K   ◍     │ 44px
│ rail ├─────────────────────────────────────────────────────┤
│ 200  │ ══════════════ tension line ═══════════════════════ │ 2px
│      ├─────────────────────────────────────────────────────┤
│ ▌Hosts│ ┌─────────────┬───────────────────────────────────┐│
│  Sites│ │ facts       │ content                           ││
│  Deploys│ │ 280px     │ tabs, tables, streams             ││
│  Audit│ │ identifiers │                                   ││
│  Team │ │ status      │                                   ││
│      │ │ quick actions│                                   ││
└──────┴─┴─────────────┴───────────────────────────────────┴─┘
```

- **Rail**, 200px, always visible, never collapses into a hamburger. The active
  item is marked by a **lashing** — a 2px `--hemp` vertical bar with a small
  notch at its midpoint, the way a rope is whipped at its end. That notch is the
  whole rigging metaphor. No rope textures, no knots as icons, no ship's wheels.
- **Top bar**, 44px: breadcrumb, environment chip (colour-coded, production is
  unmissable), ⌘K, actor menu.
- **Detail pattern**: narrow *facts* column that never scrolls away —
  identifiers, current status, the two or three actions you would actually take
  during an incident — beside a wide content column.
- **Tables**: 32px rows, no zebra striping, hairline rules, sticky headers,
  first column always the identifier. Row density is the point.

---

## 5. Signature element — the tension line

A 2px rule directly beneath the top bar, present on every screen, that **carries
live operational state**.

- **At rest:** `--hemp` at 12%. Nearly invisible. A slack rope.
- **Under load:** becomes taut in the colour of the active operation — a deploy
  turns it `working` blue, a failure turns it `failed` red — with a slow
  travelling highlight along its length. The line reads as a rope under strain.
- **On the live deployment screen** it becomes the **deploy spine**: each build
  step is a short perpendicular tick (a *lashing*) along its length, positioned
  proportionally to elapsed time. Completed steps are `healthy`, the running one
  pulses `working`, a failed step leaves a red knot. Clicking a lashing jumps
  the log to that step.

One element, one meaning everywhere: **something is under load right now.** It
is glanceable from across a room, which is the actual requirement.

**Reduced motion:** the travel and pulse stop; the line stays solid in the
status colour and the lashings stay. No information is carried by motion alone.

---

## 6. The live deployment screen

The signature screen. This is where the boldness goes.

**Log surface.** Full-bleed, virtualised, JetBrains Mono 12.5/18. Must stay
smooth at high line rates — an `npm ci` on a large tree emits thousands of lines
in seconds. Terminal colour sequences (16, 256 and truecolor) are parsed and
mapped into the palette's luminance range, so a log's red matches the interface's
red instead of fighting it.

**Left gutter.** Step boundaries with elapsed time per step. Click to scroll.

**Failure handling — the part that matters.** When a step fails, a summary card
**pins above the log and stays pinned**, showing the failing command, its exit
status, and the last twenty lines of its output. It does not scroll away as more
output arrives. `e` or the button jumps to the first error line. This is the
single most useful thing the screen can do, because the failure is almost never
at the bottom by the time you look.

**Tail follow.** On by default; disengages the moment you scroll up; a `Resume
tail` pill appears and stays until you take it. Nothing yanks the viewport out
from under a reader.

**Keyboard.** `j`/`k` line, `J`/`K` step, `e` first error, `/` search, `f`
toggle follow, `y` copy permalink to the highlighted line.

**Copy.** Steps are named for what they do — `Install dependencies`,
`Build`, `Health check`, `Activate release` — not `Step 3/7`.

---

## 7. Voice

Active voice. Plain operator nouns. Buttons named for what happens.

| Instead of | Write |
| --- | --- |
| "Submit" | "Deploy to production" |
| "An error occurred" | "Build failed at Install dependencies — exit 1. See the log below." |
| "No data available" | "No hosts yet. Connect your first host to get started." |
| "Are you sure?" | "Roll back marketing-www to release 20260801-1432?" |

Errors state what broke and what to do next. Empty states invite the next
action. Destructive confirmations name the specific thing, never "this item".

Glossary discipline (see `GLOSSARY.md`): **Host**, never "server" in interface
copy. Site, Release, Deployment, Grant, Break-glass, Agent.

---

## 8. Accessibility

- Body text meets 4.5:1 in both modes; large text and marks meet 3:1.
- Status is never colour alone — glyph plus colour plus text label.
- Every interactive element reachable by keyboard, with a visible `--hemp` focus
  ring at 2px offset. Focus is never suppressed.
- `prefers-reduced-motion` removes the tension line's travel, log auto-scroll
  easing, and every transition over 120ms.
- The command palette is the keyboard route to every action, and it lists only
  actions the current actor may take (RL-M1-029).

---

## 9. Review pass

§6.6 asks for a review against the brief, revising anything that reads as a
default rather than a choice. What that pass changed:

| First instinct | Why it was rejected | What replaced it |
| --- | --- | --- |
| Slate/zinc neutrals with a blue primary | The default of every admin dashboard shipped since 2020. Also collides directly with `working` blue. | Warm near-black, and **no brand hue at all** — colour reserved for status |
| Inter for everything | The most defaulted typeface in software. Says nothing. | Archivo Expanded / Public Sans / JetBrains Mono |
| Rope textures, knot iconography, ladder motifs | Reads as theme-park nautical within one screen, and §1 of the brief warns against the escape-route association | Linework only: one lashing notch on the active rail item, one tension line |
| A signature element that is decorative — a hero chart, a gradient | Decoration in an incident tool is noise | The tension line, which **carries state** and is the deploy spine on the signature screen |
| Collapsible sidebar | Saves pixels, costs muscle memory at 2am | Fixed 200px rail, always visible |
| Toast notifications for deploy outcomes | They disappear before you look | Persistent pinned failure summary; state lives on the page |

---

## 10. Open questions

### 10.1 The environment chip contradicts §1 — needs a ruling

§4 specifies an "environment chip (colour-coded, production is unmissable)".
§1 says colour means status and nothing else may be saturated. **Those cannot
both hold.** An environment is not a status: production is not a failure, and
staging is not a warning. Colouring the chip would put a second, competing
meaning on saturated colour — the exact thing §1 exists to prevent — and the
first time an operator sees an amber chip beside an amber status they will read
one as the other.

This was written into the plan in M0 and only surfaced when the tokens were
built (RL-M1-027). No environment palette has been invented; the tokens
deliberately stop short of one.

**Recommendation: distinguish the chip by form, not hue.** Production gets a
filled chip in `--chalk` on `--tar` — maximum contrast, no saturation — while
non-production environments get an outlined chip in `--chalk-dim`. That reads as
"heavier means more dangerous" at a glance and across a room, costs no hue, and
leaves the status language uncontested. The break-glass banner stays the single
sanctioned exception to §1, because it *is* a status.

**RL-M1-028 needs this settled before the shell is built.**

### 10.2 Two contrast values sit at their limits

Properties of this plan, not of the implementation. Both are encoded as rules in
the token registry, so retuning either breaks a test rather than sliding by.

- **`--st-idle` does not reach 4.5:1** in either mode (4.03:1 dark, 3.53:1
  light on `--tar`). It is therefore mark-only: the `○` carries it and the label
  beside it is set in `--chalk-dim`. Correct for "unknown / never deployed",
  which should recede — but it means idle can never become a text colour.
- **`--hemp` in light mode is 4.47:1** on `--tar`, three hundredths under the
  body-text bar. Fine as specified, because it is only ever linework, markers
  and the focus ring, all of which are non-text at 3:1. **It must not become a
  text colour in light mode.**

### 10.3 Fonts

Archivo, Public Sans and JetBrains Mono are all open-licensed and self-hostable,
which C5 requires. If there is an existing brand or a licensed family already in
use, say so at the gate — the palette and layout survive a type substitution, but
the display face carries most of the personality here and swapping it late is
expensive.

Note that the display face must carry a **width axis**. The static Archivo
package ships only the normal width and physically cannot render the Expanded
width §3 calls the signature, so the variable package is used instead. Any
substitute needs the same property.
