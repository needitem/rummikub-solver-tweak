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
- **On-screen AR overlay** — a floating **🧮 SOLVE** button; tapping projects each
  recommended set onto the real tiles with connecting lines, and rings the rack
  tiles you should play, over a transparent pass-through window (game stays
  playable).

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

Relaunch the game, enter a match, tap **🧮 SOLVE**.

## Notes / limitations

- Objective is *max tiles placed*; it does not enforce the 30-point initial-meld
  rule, so before your first meld the suggestion may assume board access you don't
  have yet.
- The overlay is a snapshot taken when you tap SOLVE; re-tap after sorting/moving.
- Heavy rearrangements produce many crossing lines (shows groupings, not target
  slots).

> Authorized personal use only, on your own device, against the free single-player
> / vs-AI game. Not for cheating against human opponents.
