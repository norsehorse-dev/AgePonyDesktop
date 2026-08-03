# AgePony Desktop — UI overhaul

Started 2026-08-03, against 1.0.0. Working document.

## Why

Two users said the same thing in different words within a day of 1.0.0 shipping. One said the
interface elements clash and are not obvious, and named two specifics: the sidebar's selected item
gets an oval highlight *and* a bar, and circles are being used where checkboxes are meant. The other
said PGPony Desktop looks better. Both are right, and the second is the more useful complaint,
because the difference between the two apps is not taste.

PGPony Desktop has a design system. `Brand.kt` declares a spacing scale, a radius scale, and twelve
components built on top of them, and every screen composes from those. AgePony Desktop had a theme
file: about half that vocabulary, no scales at all, and `app.rs` alone spacing things by 14, 10, 12,
2, 16, 8 and 4. It read as approximate because it was.

The circles were not a style choice. `install_style` set one corner radius, `R_BUTTON = 12`, on every
widget visual state. egui draws a checkbox about 14px square and a `selectable_label` about 20px
tall, and a 12px radius on either is a circle or an oval. Worse, the loop was never load-bearing:
every surface `theme.rs` paints by hand passes its own radius to `rect_filled`, so the only widgets
it ever reached were the two that broke.

## Shape of the new UI

Mirrors PGPony Desktop's information architecture in AgePony's own colour. Same bones, so the family
reads as one hand; not a reskin, because the palette, the mark and the interaction model stay ours.

- **Navigation rail**, 112px, icon over a centred label, one selection indicator.
- **Screen header** on every destination: title, one sentence, and the destination's primary actions.
- **Files**, replacing Encrypt and Decrypt as separate destinations. Drop anything; the app groups by
  what it is. `App::handle_drops` already routes on extension, so the app has always known what was
  meant. This makes that the front door rather than a hidden convenience, and a mixed drop stops
  forcing a choice about which half to discard.
- **A per-file queue** with the output name stated before anything runs, per-row progress, and
  per-row failure that does not stop the rest.
- **Settings** as a destination, which retires the appearance control wedged into the sidebar foot.
- **Modals** for rename, delete and identity import, replacing rows that expand and push the list
  down the screen.
- **Status strip** along the foot, replacing ad-hoc status text.

## The two scales

Both mirror PGPony's, so a screen built in one app measures the same in the other.

| | values |
| --- | --- |
| `theme::space` | 4 · 8 · 12 · 16 · 24 · 32 |
| `theme::radius` | 6 · 12 · 18 |

Radius is chosen by the size of the thing being rounded, which is the lesson the checkbox taught.
Small widgets take `SM`; buttons, cards and rows take `MD`; panels, the drop zone and modals take
`LG`.

## The surface ladder

The palette was never the problem. The brand ramp sat on egui's default neutral greys, and an accent
scattered over neutral grey is what "it's all grey and boring" described. Every surface now carries a
little of the brand hue, so the window reads as one material.

| | dark | light |
| --- | --- | --- |
| window, rail | `#0B1211` | `#EFF4F3` |
| content pane | `#101917` | `#F7FAF9` |
| cards, rows | `#14201E` | `#FFFFFF` |
| deepest (inputs, key blocks) | `#070D0C` | `#FFFFFF` |
| borders | `#2C3D3A` | `#C3D4D1` |

## Icons

Lucide, ISC, subset from `lucide-static`'s `lucide.ttf` to the nineteen glyphs the UI draws: 848 KB
down to 8 KB. The codepoints are Lucide's own Private Use Area assignments, kept rather than remapped
so the mapping can be checked against upstream's `info.json`.

The icon face is its own font family rather than an entry in the proportional fallback chain. Sharing
a family would let a missing icon fall through to Inter and render as a box, which is precisely the
failure the `GLYPHS` test exists to stop. Three tests cover it: every declared icon has a glyph, no
codepoint is declared twice, and no text face accidentally covers an icon codepoint.

## Order of work

1. **Scales, surface ladder, icon font, radius fix.** — *done, 17 tests green*
2. **Rail.** — *done*
3. `theme` components: `screen_head`, `status_bar`, `modal`, `queue_row`, `drop_zone`. — *done, 19
   tests green*
4. `panels/files.rs`: merge encrypt and decrypt behind one destination, with the grouped queue.
   `EncryptState` and `DecryptState` fold into one `FilesState`; the crypto calls do not change.
5. `panels/settings.rs`: appearance, and whatever else has been living in corners.
6. Migrate `identities.rs` and `recipients.rs` to the new components, and move rename, delete and
   import into modals.
7. Delete the dead vocabulary from `theme.rs` once nothing calls it.

Steps 1 to 3 are self-contained and already fix both defects the users reported, so they can ship
ahead of the rest if a 1.0.1 is wanted before the redesign lands. Nothing calls the step 3 components
yet, which is deliberate: they are the vocabulary step 4 is written in, and landing them separately
keeps the panel rewrite from being reviewed alongside four hundred lines of drawing code.

Step 3 turned up one thing worth recording. `f32::clamp` propagates NaN rather than clamping it, so
`0.0 / 0.0` on a zero-length file survives a `clamp(0.0, 1.0)` and becomes a rectangle with a NaN
width. `agepony-core` and `tasks.rs` both special-case a zero denominator already, so nothing live
could reach it, but the guard is now explicit in `theme::fill_fraction` and tested, because a drawing
primitive should not depend on every caller upstream staying careful.

## Decisions taken, and the ones still open

Taken: mode control sits per group rather than once per screen; the drop zone stays visible as a slim
strip once files are queued, so adding a sixth file does not mean reaching for the button; the rail
keeps its active-identity card at the foot; all three dialogs go modal.

Open: whether `Files` should keep a manual override for a file the extension heuristic gets wrong —
an `.age` file that was renamed, or a file that happens to end in `.age` and is not one. The header
probe in `agepony-core` can answer this properly rather than guessing from the name, and probably
should.

## Verification

The GUI cannot be run in the cloud sandbox, so the loop is `cargo check`, `cargo clippy
--all-targets` and `cargo test -p agepony-desktop`, with the Mac for anything visual. `theme.rs`
carries the tests that can be made mechanical: font coverage both ways, icon coverage, no undeclared
symbol in any source string, segments tiling their container exactly, and the shipped faces staying
under 400 KB.
