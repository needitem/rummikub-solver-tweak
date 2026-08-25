# Analysis notes

Reverse-engineering artifacts behind the offsets and call sequences used in
`Tweak.xm`. The game binary (`UnityFramework`) and `global-metadata.dat` are
deliberately **not** included here — they are the game's own files.

| File | What it is |
|------|------------|
| `recon_autoplace.txt` | IL2CPP dump of `RmkbGameDataManipulator`, `RmkbGameView3D`, `TileContainer`, `Card`, `RmkbGameData` (fields + offsets + method signatures) |
| `recon_round2.txt` | `RmkbMovesData` / `BaseMovesData` / `RmkbGameClient` layout, plus the class-name scan used to find the move/turn owners |
| `recon_round3.txt` | Enum values (`MoveType`, `RmkbMoveDetails`, `CardLocation`, `MovmentType`) and nested types |
| `decompile_move.log` | Ghidra decompilation of `OnMouseUp` / `FireMoveMadeEvent` / `MouseDownOnTile` |
| `DecompileMove.py` | Headless Ghidra script that produced the above |

## Key facts established

Board/grid
- Board cells are absolute, offset by the board origin: `RmkbGameData` holds
  `BoardSizeX` (0x90), `BoardSizeWidth` (0x94), `BoardSizeY` (0x98),
  `BoardSizeHeight` (0x9c). A rack tile lives at `y = 0`.
- `RmkbGameView3D.GetBoardWorldPosition(x, y)` takes **board-relative** cells,
  not absolute ones — measured: cell (101,103) sits at world (-4.61,-0.14) and
  `GetBoardWorldPosition(1, 3)` returns exactly that.
- The manipulator's `_grid` is a 200x200 backing store, *not* the playable area.

Moves — what `OnMouseUp` actually does
```
md = new RmkbMovesData()          // ctor only
md.TargetLocation   = 2           // 0x1c  (Board)
md.TargetPositionX  = cell.x      // 0x20
md.TargetPositionY  = cell.y      // 0x24
for each dragged card:
    md.MovedCards.Add(card.CardID)
    card.MoveType = 2             // Card 0x34 — set before firing
view.FireMoveMadeEvent(md)        // virtual, vtable +0x1c8
```
It never sets `TypeOfMove`, `MoveMakingSeat`, `MoveDetails` or
`PreferredCardToAttatchTo`; those keep their constructor defaults.

Behaviour observed at runtime
- The game chooses the final column itself — a tile can land a cell away from
  the requested one and still form the intended set.
- A move is refused if the resulting board would be illegal (e.g. duplicating a
  colour inside a group), so a plan that is valid as a *final* layout can still
  be rejected step by step.
- `MoveMakingSeat` is not the gate: seats 0..3 were all refused identically.
- Hooking the move path is unsafe. `ValidateAndApplyMove` returns a value type
  (indirect x8 return) and a pointer-returning hook corrupts it;
  `FireMoveMadeEvent` / `PrepareTileObjects` hooks read payloads at fixed
  offsets that do not always hold. All three crashed the game on a real drag —
  observe by polling the tile state instead.
- `PrepareTileObjects` must not be called standalone to force a repaint: it
  tears down and rebuilds the tile pool and leaves the board visually wrecked.
