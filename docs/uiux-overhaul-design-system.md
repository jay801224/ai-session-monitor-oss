# UI/UX Overhaul Design System

## Scope and freeze

This document freezes the P1 visual contract for P2–P6. It defines the
identity channels and interaction rules that later UI work consumes; it does
not require a dashboard implementation in P1. The contract remains
stdlib-only, keeps collected data on the machine, and does not introduce an
LLM dependency. Revision `_v2` amends the body-slot clause only: the single
shared silhouette is now the Signal Desk case, alongside office2's per-session
sprite. Every other frozen rule is unchanged.

## Color/identity channels

Identity is carried by four independent channels: batch colour, vendor shape,
size (parent versus subagent), and status. A renderer must keep the channels
separate so a busy office remains readable without motion or colour alone.

Two renderers consume this contract and differ only in the body slot: the
Signal Desk view (`ui/dashboard.html`) keeps one shared operator figure, while
office2 (`ui/office_proto.html`) draws a per-session sprite. Neither renderer
may move an identity channel onto the body slot.

| Channel | Meaning | Rendering rule |
| --- | --- | --- |
| Batch | A launch group | Apply the deterministic batch colour to `.floorglow` or the desk base, never to the body. All members of one `group_key` share it. |
| Vendor | Product/source family | Render one 12×12 emblem plus its registry ring colour beside the body. Vendor identity is emblem shape plus that registry colour; the body is never tinted or swapped per vendor. |
| Size | Parent or subagent | A subagent renders at the `.mini` scale and inherits only the parent's batch-floor colour, keeping its own vendor emblem and its own status. Size is the only channel that separates a parent from a subagent, so a subagent must stay strictly smaller than a parent at the same zoom. Enlarging subagent sprites is allowed only while that size gap stays visible; equal-size parent and subagent deletes the channel and is out of contract. |
| Status | Work state | Render a static glyph, not a colour-coded pose: solid for working, half-solid for standby, hourglass for queue context, hollow for stopped, and slashed hollow for stale. Queue is a placement/work kind, not a fifth `work_kind` value. |

### Per-session sprite identity (office2)

office2 replaces the single shared silhouette with one sprite per session. The
sprite is chosen by a stable hash of `session_id` over a closed list of local
assets (`CREATURES` in `ui/office_proto.html`), so one session keeps one
creature across reloads while a restarted session may legitimately change. The
sprite is a recall aid for "which session is that" — it is not a fifth identity
channel: it encodes no batch, vendor, status, or hierarchy meaning, and no code
path may read it back as data.

Because the body now varies per session, the other four channels must stay off
it: vendor remains the emblem and its registry ring, status remains the pose
plus the nameplate glyph (a stopped or stale sprite is desaturated, never
recoloured per vendor), batch remains the floor glow, and size remains the
parent/subagent distinction above. A helper token with no session of its own
(for example a CLI-bridge job) hashes its own stable key instead of borrowing
a session's creature.

### Token registry

The registry is the single P1 source for colour tokens. `STATUS_GLYPH` has one
neutral ink shared by every glyph; status is therefore conveyed by glyph shape,
not by a different state colour.

```json
{
  "BATCH_PALETTE": ["#8156D8", "#D08A32", "#2B9A92", "#C74B79"],
  "SRCCOLOR": ["#F0883E", "#58A6FF", "#3FB950", "#A371F7", "#39C5CF"],
  "STATUS_GLYPH": ["#E6EDF3"]
}
```

`BATCH_PALETTE` is closed and must exclude every `SRCCOLOR` and
`STATUS_GLYPH` value. A stable hash of `group_key` selects a batch entry.
`SRCCOLOR` is keyed by the source names `cc`, `codex`, `antigravity`, `hermes`,
and `copilot`; a missing source uses the existing neutral UI fallback rather
than adding an inline approximate colour.

## Vendor emblem template

Every vendor emblem occupies the same 12×12 view box and uses the same stroke
weight. The following template is the only shape slot a vendor variant may
change; the body slot behind it — a shared operator figure in Signal Desk, a
per-session sprite in office2 — is never a vendor variant.

```svg
<svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" focusable="false">
  <path d="M2 6h8M6 2v8" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
</svg>
```

`VENDOR_EMBLEM` maps each source to one instance of this template family. A
`miniSVG` child inherits its parent's batch-floor token but keeps its own
vendor emblem; it does not become an unbadged generic dot. Emblems are
decorative only, so the adjacent accessible name must still identify the
source and session.

## Tooltip spec

Tooltips are secondary help, never the only available name or instruction.

- Show after a 1.5-second hover or focus delay; once visible, allow roughly
  0.7 seconds of pointer travel from trigger to bubble without dismissing it.
- Keep the Launch affordance's purpose visible in its label or nearby copy;
  the tooltip elaborates rather than replacing that explanation.
- Every icon-only control needs an accessible name (`aria-label`). Focus
  invokes the same tooltip path as hover, and Escape dismisses an open bubble.
  A native `title` is not the tooltip content source.
- Build bubble text with `textContent`; populate a trigger's `data-tip` via an
  escaped/property-set value. Preset configuration is untrusted input and must
  not be concatenated into HTML.

## Office zones

Zones are a work taxonomy, not new visual identities.

| Zone | Included rows | Excluded rows |
| --- | --- | --- |
| Working | `work_kind: working`; code and docs are one working zone | Remote rows without an active local-tail signal |
| Standby | `work_kind: standby` and the safe remote fallback | Queue rows |
| CLI queue | `work_kind: cli_queue` supplied by the read-only queue contract | A fabricated extra status |

Zone assignment is determined only by `work_kind`; `working`, `standby`,
`stopped`, and `stale` status glyphs never select a zone. P6 may position these
zones, but it must use the shared batch, vendor, hierarchy, and status lookups
above rather than redefine any identity channel per zone.

## Floor plan and movement

The office renders as a top-down floor plan, not a grid of cards. Zones are
rooms bounded by walls, agents are seated on a shared floor, and an agent that
changes work state visibly moves between rooms. This section governs the spatial
rendering that later UI consumes; it adds no new identity channel.

- Rooms and walls: partition walls, doorways, and the building outline are drawn
  in a single inline SVG overlay layered under the desks; zones remain semantic
  DOM sections. No canvas or WebGL, and at most one such overlay.
- Floor and depth: depth comes from a background-only lit and receding floor
  (gradient plus vignette). No transform or perspective is applied to any
  measured or interactive layer (desks, desk grid, zones, floor), so FLIP
  reparenting and layout geometry stay correct.
- Seated agents: a desk is an operator seated on the floor (transparent seat,
  contact shadow), not an opaque card.
- Agent figure: the body slot is either one shared, simple, limbed silhouette
  (Signal Desk) or a per-session sprite from the closed local asset list
  (office2). Either way it stays simple, readable at small size, and able to
  move, and it keeps the parent/subagent size gap. Vendor identity stays on the
  emblem and its registry ring colour only; the body and face are never tinted
  or swapped per vendor. A photoreal per-vendor face is out of contract.
- Movement is event-driven and honest: an agent animates between rooms only when
  its real `work_kind` or status changes (working to standby to stopped). There
  is no constant or fabricated motion. `prefers-reduced-motion: reduce` disables
  all animation, keeping only the final placement. Movement conveys no data that
  is not real.
- Excluded: fabricated telemetry gauges (CPU, memory, disk, network, latency),
  load sparklines, floor selectors, and zoom controls have no real data source
  and must not be rendered.

## Pool display

The pool display classifies infrastructure provenance as `system`,
`ai_opened`, or `ai_scheduled`. It is a label for review, not a claim that a
heuristic is authoritative. Ports/processes and scheduled tasks remain visually
distinct; the pool must not imply that a system process was created by an AI.
The source field is supplied by the D4 contract.

## Layout

Preserve a clear hierarchy: controls and summary first, active office zones
second, pool and queue information as supporting detail. At narrow widths,
stack regions in that order and retain readable labels beside compact marks.
Do not rely on hover, colour, or animation as the sole way to discover status,
source, or control purpose. P2 owns concrete spacing, breakpoints, and DOM
changes after this P1 contract.

## Drift guard

One lookup registry governs all future mini, desk, and zone rendering paths.
No rendering path may introduce an inline near-match token.

| Registry | Canonical key | Consumer rule |
| --- | --- | --- |
| Batch floor | `BATCH_PALETTE` | Select by stable `group_key` hash. |
| Vendor identity | `SRCCOLOR` plus `VENDOR_EMBLEM` | Select by normalized source name; render on the emblem and ring, never on the body slot. |
| Status mark | `STATUS_GLYPH` | Select by status shape with common neutral ink. |
| Session creature | `CREATURES` (office2 local assets) | Select by stable `session_id` hash; presentation only, never read back as data. |
| Size/child identity | parent batch lookup plus own vendor lookup | `.mini` inherits only its parent batch; its vendor, status, and creature stay its own, and its rendered size stays strictly below the parent's. |

`check-color-tokens` enforces that the three colour registries in this document
are non-empty hexadecimal sets with no overlap. It intentionally validates this
P1 document only: P5 is responsible for applying the registry to UI code.

`check-avatar-identity` and `check-signal-desk-zone-vendor` both read
`ui/dashboard.html` only, so they assert the Signal Desk body slot: its single
shared `assets/signal-desk/operator-head-v1.png` head and its five same-asset
vendor ring treatments. They are Signal Desk oracles by construction and do not
apply to office2's per-session sprites, which live in `ui/office_proto.html` and
are covered by the office2 checks. Their shared-asset assertions therefore stand
as written — they say nothing about office2.
