# VTable Diff

**IDA Pro 9.1 plugin** for tracking changes in virtual tables (vtables) between two builds of the same module.

The plugin exports a vtable from the "old" build of a binary, then in the "new" build finds the matching vtable and aligns the slots between them, even if functions were reordered, added, removed, or shifted due to code changes. The result can be viewed as an IDA window, an interactive HTML report, or a full dump printed to the console.

---

## What it does

- **Exports a vtable** from the current database to JSON: addresses, names, and a "fingerprint" of every virtual function (instruction mnemonics, strings, calls, constants, offsets, masked byte pattern).
- **Compares a vtable** from a JSON file (old build) with a vtable in the currently open database (new build) and matches slots based on function similarity, not just index position.
- **Detects shifts**: shows how many positions each slot moved by (`+2`, `-1`, etc.) and groups adjacent slots with the same shift into ranges.
- **Highlights added, removed, and uncertain** slots (low confidence matches, statuses "low"/"guess"). These are the ones worth checking manually first.
- **Locates a vtable in three ways**: by address, by symbol name (`??_7CBase@@6B@`), or by RTTI class name (`CSource2Client`). Works even on stripped x64/x86 MSVC binaries by parsing RTTI (TypeDescriptor -> RTTI Complete Object Locator -> vtable).
- **Automatically detects the slot count** of a vtable by scanning for pointers into executable code.
- **Transfers user-defined names** of functions from the old database to confidently matched slots in the new one.
- **Generates an interactive HTML report** (search, status filters, sorting, per-function details, match highlighting, CSV export). Useful for documenting and sharing results without opening IDA.
<p align="center">
  <img src="https://github.com/user-attachments/assets/a81efdff-e4d4-41ba-b5c4-2f7a97233a8a" width="49%">
  <img src="https://github.com/user-attachments/assets/f0ce0cc0-410b-4a89-9193-bb2729f901ee" width="49%">
</p>

- **Useful during analysis**: when a vtable layout changes between versions of a game or application (a virtual method was added or removed), the plugin quickly shows which old signatures, hooks, and offsets need to be fixed for the new version.

---

## How it works (short version)

1. For every vtable slot a function "fingerprint" is built: a sequence of instruction mnemonics, strings, calls and cross-referenced names, constants, `[reg+disp]` offsets, and a masked byte pattern (address operands zeroed out). Thin thunk jumps (`jmp real_func`) are resolved down to the real function.
2. A similarity score is computed between every pair of old and new functions (intersection of string/call/constant sets, plus mnemonic sequence similarity and size similarity).
3. Matching is built in three passes:
   - **anchors**: unambiguous high-confidence matches;
   - **aligned**: Needleman-Wunsch alignment inside the gaps between anchors (preserves slot order);
   - **guess**: positional one-to-one matching of the remaining slots when old and new counts agree.
4. Each result gets a confidence label: `exact`, `high`, `medium`, `low`, `guess`, or `REMOVED` / `NEW` if no pair was found.

---

## Installation

1. Download the plugin file (`vtable_diff.py`).
2. Copy it into the `plugins` directory of your IDA Pro installation.
3. Restart IDA Pro.
4. Confirm the plugin is loaded: `Edit → Plugins` should list `VTable Diff: export` and `VTable Diff: compare`.
5. The plugin can also be launched at any time with the hotkey **Ctrl-Alt-V**, without going through the menu.

---

## Usage

### Step 1. Export the vtable from the old build

1. Open the **old** version of the binary in IDA Pro.
2. Optionally place the cursor on the vtable (used as a default hint), then run:
   `Edit → Plugins → VTable Diff: export`
3. Enter the address, symbol name, or RTTI class name of the vtable.
4. If multiple candidates are found, a selection list will appear.
5. Confirm or adjust the detected slot count.
6. Save the result as a `*.json` file.

### Step 2. Compare with the new build

1. Open the **new** version of the binary in IDA Pro.
2. Run: `Edit → Plugins → VTable Diff: compare`
3. Select the JSON file exported in step 1.
4. Specify the matching vtable in the new database (address, symbol, or RTTI class).
5. Confirm the slot count.
6. The plugin performs the matching and offers ways to view the result:
   - an **IDA window** with the list of slots (double-click to jump);
   - an **HTML report** (saved to a file and opened in the browser);
   - the **console**, a full text dump of the matching.

The **Ctrl-Alt-V** hotkey opens a short "Export / Compare" dialog without going through the menu.

---

## How to specify a vtable

The input field accepts:

| Format | Example | Description |
|---|---|---|
| Address (hex) | `0x180045A10` | Direct address of the vtable |
| Symbol name | `??_7CBaseEntity@@6B@` | Exact vftable symbol name |
| RTTI class name | `CSource2Client` | RTTI lookup (works on stripped x64/x86 MSVC) |

If multiple vtables match the query, a selection list appears with columns: address, slot count, this-offset, COL address (for multiple inheritance), symbol name.

---

## Match confidence labels

| Label | Meaning |
|---|---|
| `exact` | Identical byte pattern of the function |
| `high` | High similarity |
| `medium` | Medium similarity, worth checking |
| `low` | Low confidence, check manually |
| `guess` | Matched by position (slot counts agree) |
| `REMOVED` | Slot existed in the old vtable, no match found in the new one |
| `NEW` | Slot only exists in the new vtable |

---

## Requirements

- IDA Pro 9.1 (uses the `ida_*` Python API modules of this version).
- Python 3 (bundled with IDA).
- No external dependencies, only the Python standard library and the IDA SDK are used.

---

## Known limitations

- RTTI lookup by class name targets the MSVC ABI (x86/x64).
- Match quality depends on how much "signal" a function carries (strings, calls, constants). Confidence is intentionally capped for very small, trivial functions.
- Up to 4096 slots and 3000 instructions per function are analyzed per pass (limits are set via the `MAX_ENTRIES` / `MAX_INSN` constants).
