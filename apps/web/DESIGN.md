# DSRclone design system — True-black flat

Adopted 2026-10-23 (owner order: rebuild the UI with the taste +
impeccable skills). Direction dealt by taste-skill `draw.mjs --app`
(kind devtools, dark, seed 2134747149): style **true-black-flat**,
chosen over data-terminal because the product is read in long
sessions with heavy tabular data, and severity colour must stay
unambiguous data.

## The move
Elevation by lightness alone. Sidebar, top bar and page share one
true-black ground; surfaces step up #000 → #111 → #2a2a2a. No
borders + shadows on resting cards (floats — menus, dialogs, the
mobile drawer — keep a real shadow). The active nav item is marked
by brightness only: its label goes #B4B4B4 → white. The primary
action is an inverted white pill with black text. Colour lives on
data and status, never on chrome.

## Tokens (implemented in tailwind.config.ts by remapping slate)
- ground #000000 (slate-950) · surface #111111 (slate-900) ·
  rule/border #1A1A1A (slate-800) · raised #2A2A2A (slate-700) ·
  control edge #444444 (slate-600)
- ink #FFFFFF · secondary #B4B4B4 (slate-300) · meta #949494
  (slate-400) — every text grey holds 4.5:1 on its surface
- data hue #4CB3F0 (the product's own blue, per the sheet's face
  rule) — progress, running state, links on name cells; never on
  buttons, tabs or nav
- status pairs (dark tints, same-hue ink): positive #3FC07A on
  #172A1D · negative #E5566F on #2C1A20 · warning #E5A93B on
  #2B2414 · severity HIGH #F0883E on #2E1D16 · LOW = the data hue
- Type: Inter (400/500/600), one face. Title 20/600, section 16/500,
  KPI 24/500, body 14, small 12. Tabular figures on tables/numbers.
- Radius: card 20px (rounded-xl), controls pill or 12px, chips full.
- Signature element: **the Road** — home leads with one divided
  track (Target → Plan & approve → Run the scan → Read findings →
  Get the report) with the primary action in its header.

## Bans (from the sheet + house rules)
No navy/slate tint, no eyebrows (mono uppercase kickers), no
tracked uppercase labels, no icon-in-tinted-square KPIs, no
sparklines on KPIs, no fabricated numbers (empty states stay
honest sentences), no gradients/glass/glows, no accent on chrome.

## Kept exceptions
- The admin page keeps its owner-pinned Dashdark look (layout and
  violet accent); it only inherits palette-adjacent plumbing.
- Form placeholders use RFC documentation examples (example.com,
  203.0.113.10) as format hints — annotated in code.
- Verification strings render mono: literal values copied exactly.
- Impeccable detector's "overused font: Inter" warning is accepted:
  the dealt sheet prescribes Inter and Operate surfaces take
  workhorse faces.
