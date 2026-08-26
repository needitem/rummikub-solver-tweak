# rummikub-solver-tweak

An **own-device** Rummikub (`com.rummikubfree`, IL2CPP/Unity) assistant tweak for
rootless jailbroken iOS (ElleKit/Theos). For personal use on your own device.

## What it does

- **Ad suppression** — no-ops AppLovin MAX interstitial / app-open / banner ads
  (rewarded ads left intact).
- **Live board/hand reader** — reads the on-screen tiles at runtime via the
  IL2CPP API (`RmkbGameView3D.Tiles` → `TileContainer` → `Card`), so it always
  reflects the current state (sorting/moves included). No capture step needed.
- **Optimal-move solver** — a fast C implementation of the Den Hertog & Hulshof
  (2006) integer-programming model as a dynamic program, maximising the number of
  rack tiles you can place (runs + groups + jokers, full table rearrangement).
  Validated against the [`rummikub-solver`](https://pypi.org/project/rummikub-solver/)
  reference on 900+ random states.
- **Hand overlay** — a floating **👁 손패** toggle rings the tiles in your hand
  that can go out this turn, live, over a transparent pass-through window (the
  game stays playable underneath). It re-solves twice a second, so the rings
  follow the hand and board as they change.
- **⚙︎ AUTO** — a start/stop toggle that plays the solution through the game's
  own move pipeline, including board-to-board rearrangement, re-reading the live
  board each tick and carrying on from wherever tiles actually landed. Tapping it
  again stops the run; the next tap re-solves against the board as it is then.

Both buttons are draggable — they float over a live board, so wherever they
default to will sometimes be exactly where you need to reach.

## Layout

| File | Purpose |
|------|---------|
| `Tweak.xm` | The tweak: ad hooks, IL2CPP tile reader, camera projection, AR overlay, solver bridge |
| `rksolver.h` | Header-only `rk_solve()` — the DP solver + move reconstruction |
| `solver/rksolve.c` | Standalone CLI build of the solver (`cc -O2 -o rksolve solver/rksolve.c`) for testing |
| `Makefile`, `control`, `rkreader.plist` | Theos packaging (filters to `com.rummikubfree`) |

## Build (Theos, rootless)

Needs Theos with an **iOS ≤ 18 SDK** (built here against iPhoneOS 16.5 — a too-new
SDK stamp makes the bundle fail to load on iOS 18).

```bash
export THEOS=$HOME/theos
make package        # → packages/*.deb  (arm64 + arm64e)
```

Install the `.deb` with `dpkg -i`. On a manual (non-Sileo) install, add the
dylib's cdhash to the jailbreak trust cache:

```bash
for h in $(ldid -h /var/jb/usr/lib/TweakInject/rkreader.dylib | sed -n 's/^CDHash=//p'); do
  jbctl trustcache add "$h"
done
```

Relaunch the game, enter a match, then use **👁 손패** to see what you can play
or **⚙︎ AUTO** to have it played — tap it again to stop.

## Notes / limitations

- Objective is *max tiles placed*; it does not enforce the 30-point initial-meld
  rule, so before your first meld the suggestion may assume board access you don't
  have yet.
- AUTO occasionally needs a second tap to finish the last set.
- The tweak writes no log. Earlier versions kept a trace in the app container to
  work out the move pipeline; that is understood now and the logging is gone.

> Authorized personal use only, on your own device, against the free single-player
> / vs-AI game. Not for cheating against human opponents.
