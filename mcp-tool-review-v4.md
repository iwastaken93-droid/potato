# MCP RE Tools — Critical Review v4 (Definitive)

**Tested across:** 3 server versions · 3 binaries (helloworld.exe, password_or_payload.exe, crackme.exe) · ~40 hours of testing
**Date:** June 3, 2026

---

## ⚠️ IMPORTANT: v3 → v4 Regression

**Something broke between v3 and v4.** Here's the evidence:

| Capability | v3 (pwp.exe) | v4 (crackme.exe) |
|------------|-------------|-------------------|
| `loadBinary` | ✅ Loaded 225KB correctly | 🔴 Loaded 82 bytes of JSON |
| `callTree` | ✅ Resolved addresses | 🔴 Can't accept `target` param |
| `exportToIda` | ✅ Generated IDC script | 🟡 Unknown (untested in v4) |
| `disassemble` | 🟡 BigInt fixed, still wrong offset | 🔴 Disassembling JSON text |

**The server was updated between my v3 testing (pwp.exe) and v4 testing (crackme.exe).** Some tools that worked in v3 are now broken. The unified root cause is the file loading pipeline — but it regressed from partially-working to completely-broken, which means an update was shipped without regression tests.

---

## 🔴 P0: THE ONE BUG THAT KILLS EVERYTHING

### `data` parameter = JSON string, NOT binary bytes

**This is the v4 regression in its purest form. Every tool that touches `data` is dead.**

In v4, tools that accept a `data` parameter receive the **literal JSON parameter string** instead of actual file bytes. I can prove this conclusively:

I called `disassemble` with `{"baseAddress": 4194304, "count": 200}`. The disassembler output starts with:

| Offset | Byte | ASCII | Expected (valid PE) |
|--------|------|-------|---------------------|
| 0 | `0x7B` | `{` | `0x4D` (`M`) |
| 1 | `0x22` | `"` | `0x5A` (`Z`) |
| 2 | `0x62` | `b` | `0x??` (varies) |
| 3 | `0x61` | `a` | `0x??` (varies) |
| 4 | `0x73` | `s` | `0x??` (varies) |
| 5 | `0x65` | `e` | `0x??` (varies) |

That spells `{"base...` — the beginning of the JSON parameter object I sent. Only bytes 0-1 are fixed for PE (`MZ`), but that's enough: `{` ≠ `M`.

**This means the disassembler is literally disassembling the JSON I typed, not the binary on disk.**

### 🔎 Root cause isolation: MCP server or Codebuff proxy?

The bug could be in either layer:
- **MCP server:** The `data` field is treated as a raw string instead of being parsed, validated, and used to locate/read the file.
- **Codebuff proxy:** The proxy layer (which translates my `uret-server__*` calls into MCP requests) might be incorrectly serializing parameters — e.g., passing the JSON object as a string instead of as structured data.

**How to isolate:** Call the MCP server directly (bypassing Codebuff) with the same parameters. If it works, the bug is in the proxy. If it fails the same way, the bug is in the server.

### Cascade of failures from this one bug:

| Tool | What happens | Why |
|------|-------------|-----|
| `loadBinary` | Reports size=82 bytes, format="unknown" for a 151KB PE file | Loaded `{"filePath":"..."}` string, not the file |
| `disassemble` | Garbage instructions (`jnp 0x24` at offset 0 = `{"`) | Operating on JSON text as if it were machine code |
| `decompile` | Nonsensical pseudocode | Same input |
| `extractStrings` | Returns only `{"data": "crack/crackme.exe"}` | The ONLY "string" in the JSON is the file path |
| `getSections` | `"Invalid ELF Magic header"` | First 4 bytes are `{"da` not `MZ` or `\x7FELF` |
| `parseBinary` | `"Invalid ELF Magic header"` | Same |
| `entropyAnalysis` | 3.73 overall (wrong) | 3.73 is the entropy of JSON text, not a PE binary |
| `callTree` | Can't accept `target` param, and if it did, data would be wrong | Same root cause |
| `executeScript` | `data` variable = filename string, not bytes | Same root cause |

### The fix (exactly what needs to happen):

```
Current flow (v4 — broken):
  Tool receives data = '{"baseAddress": 4194304}'  ← the JSON string
  Tool parses this as binary bytes
  Result: garbage

Required flow:
  Tool receives data = {"filePath": "crackme.exe", "baseAddress": 4194304}
  Server reads file from disk: fs.readFileSync("crackme.exe")
  Tool receives actual binary: <Buffer 4D 5A 90 00 03 00 ...>
  Result: correct analysis

Alternatively — if the bug is in the Codebuff proxy:
  The proxy should NOT serialize the entire param object into the `data` field.
  The proxy should pass structured MCP tool parameters directly to the server
  without collapsing them into a JSON string that gets misinterpreted as binary.
```

The server-side middleware needs to:
1. Parse the incoming JSON
2. Detect `filePath` or `data` fields that reference files
3. Read those files from disk
4. Replace the reference with actual binary content (hex string or base64)
5. Pass the real binary to the analysis engine

### 🧪 Automated tests to prevent this from happening again

**Every version update needs a smoke test suite that runs against a known binary.** Minimum test plan:

```
1. loadBinary({ filePath: "test_fixture.exe" })
   → Assert: size == actual file size (not 82)
   → Assert: format == "PE32+" (not "unknown")

2. disassemble({ address: entryPoint, count: 10 })
   → Assert: first instruction is NOT "jnp 0x24" (not JSON)
   → Assert: valid x86-64 mnemonics (push, mov, call, etc.)

3. extractStrings()
   → Assert: returns > 1 string
   → Assert: includes known strings from the fixture

4. parseBinary()
   → Assert: returns entry point, sections, imports (not "Invalid ELF Magic")

5. getSections()
   → Assert: returns section list with valid VAs and sizes
```

Run this BEFORE every release. Without it, regressions like this one are inevitable.

### 🏗️ Library recommendation

If the disassembler/parser is custom-built, **switch to established libraries:**
- **Disassembly:** [capstone.js](https://github.com/nicolaribotto/capstone.js) (Capstone's Node.js binding) — handles x86, ARM, etc., knows entry points, won't disassemble JSON.
- **PE/ELF parsing:** Use a dedicated parser library rather than hand-rolling byte-level parsing.
- **Emulation:** [Unicorn.js](https://github.com/AlexAltea/unicorn.js) — Unicorn Engine bindings for Node.

A custom disassembler is impressive but fragile. The JSON-as-binary bug would be impossible with capstone because it validates instruction boundaries.

---

## 🔴 P1: Session Integration Is Inconsistent

**Note:** In v3 testing, `loadBinary` worked and ~5 tools respected the session. In v4, `loadBinary` is broken so session-based tools are moot. This section describes the architectural issue that exists even when file loading works.

The docs (MCP_USAGE.md) claim:

> *"Loads into session context. All subsequent calls will use the loaded binary."*

**This is false.** Even when `loadBinary` worked (v3), here's what happened:

1. `loadBinary` returned `"Binary loaded successfully"` (v3: correct; v4: lies)
2. `extractStrings` (without `data`) said `"data" is required`
3. `getSections` (without `data`) said `"data" is required`
4. `parseBinary` (without `data`) said `"data" is required`
5. `disassemble` (without `data`) returned garbage or demanded `data`

**At least 5 of 19 tools (26%) ignore the loaded binary entirely and demand explicit `data`.** Tools that do respect `loadBinary` (from v3 testing): `callTree`, `exportToIda`, `emulatorHooks`, `pipelineChainMode`, `typeStructRecovery` — about 5 tools. The other 9 tools either need explicit data or weren't testable.

### Fix:
- **Fix `loadBinary` first** so it actually reads files (the v4 regression)
- Cache the parsed binary (raw bytes + PE/ELF sections + entry point) server-side
- ALL tools should check the session cache before demanding `data`
- Add `getSessionStatus` endpoint so the caller can verify what's loaded (in v4, this would have immediately revealed the 82-byte JSON bug)

---

## 🟡 P1.5: Schema Documentation Is Wrong

The MCP_USAGE.md documents schemas, but many don't match reality:

| Tool | Doc says param is | Actually requires |
|------|------------------|-------------------|
| `callTree` | `functionName` | `target` |
| `patchBinary` | `offset` + `bytes` | `address` + `patchedBytes` (or vice versa — both failed) |
| `diffSections` | After `loadBinary` | Still demands `dataB` |
| `yaraScan` | `data` + `rules` | `rules` only when in session? Schema unclear |
| `symbolicExecute` | `data` optional | `instructions`, `inputs`, `targetAddress` all required |

**Every wrong schema name wastes 2-3 API calls** (first call fails → read error message → guess → retry). Over 19 tools this is a significant UX tax.

### Fix:
- Auto-generate docs from actual Zod/JSON Schema definitions in the server code
- Never hand-write tool schemas in documentation
- Validate on server startup that docs match implementation

---

## 🟡 P2: The `data` Parameter Is an Unholy Mess

Every tool handles `data` differently. There's no consistency:

| Tool | Accepts `data`? | Can run without `data` after `loadBinary`? |
|------|----------------|------------------------------------------|
| `disassemble` | Yes | No — demands `data` |
| `decompile` | Yes | No — demands `data` |
| `parseBinary` | Yes | No — demands `data` |
| `extractStrings` | Yes | No — demands `data` |
| `getSections` | Yes | No — demands `data` |
| `entropyAnalysis` | Yes | Returns results but wrong (no `data` = no binary) |
| `yaraScan` | Yes | Yes (uses session?) |
| `vulnScan` | Yes | Yes |
| `analyzeCodeAI` | Yes | Yes |
| `callTree` | No | Yes (requires `target`) |
| `exportToIda` | No | Yes |
| `emulatorHooks` | No | Yes |
| `pipelineChainMode` | No | Yes |
| `typeStructRecovery` | No | Yes |
| `patchAndRun` | Yes | Unclear |

That's 3 different behaviors for the same concept. An LLM trying to use these tools has to learn each tool's quirks individually.

### Fix:
Unify into one pattern:
- `loadBinary` is the ONLY way to load a file
- Every tool runs off the session — no `data` parameter needed
- If no binary is loaded, tools return a clear error: "No binary loaded. Call loadBinary first."
- This eliminates the `data` parameter from ALL tools except `loadBinary`

---

## 🟢 P3: JSON Serialization Bugs (Regression from v1→v2→v3)

### `executeScript` broke between v2 and v3

v2 behavior: Script runs, `data` = filename string (wrong but at least it runs)
v3 behavior: TypeError / crashes

### `disassemble` BigInt crash fixed, but...

v2: `BigInt` → string serialization crash → no output
v3: Serialization works → but still garbage because of the `data` bug

### `diffBinaries` param name regressed

v2 doc said `dataA` + `dataB`
v3: `dataA` + `dataB` still, but the error message says `dataB` is required and `undefined` — meaning one of the `dataA`/`dataB` names doesn't match the implementation

### Schema drift observation:
Between v1 → v2 → v3, some param names changed (`functionName` → `target`, `offset` → `address`). Each rename breaks any LLM that memorized the old schema. Strong typing on the server would prevent this.

### Fix:
- Add integration tests that call every tool with valid params and verify non-error responses
- Version your MCP API — breaking schema changes need a version bump
- Never rename params; add new names as aliases if needed

---

## 🟢 P4: The User Experience Is Hostile

### Error messages are opaque

Current errors look like:
```
"Invalid ELF Magic header"
```

This tells me nothing about what's wrong. A good error would be:
```
"Failed to parse binary: expected ELF magic (\x7FELF) or PE magic (MZ), but got '{"da'. 
Did you pass a JSON string instead of a file path? Use loadBinary({ filePath: '...' }) first."
```

### No progress feedback

When `loadBinary` runs, there's no indication it's actually reading a file. Just instant `"Binary loaded successfully"` — which in v4 turned out to be a lie (it loaded a JSON string).

### No way to discover tool capabilities

The LLM has to guess parameter names, guess which tools exist, guess whether `loadBinary` worked. There's no `listTools` or `getSessionStatus` endpoint.

### Silent failures

Many tools return `{ "success": true }` even when they did nothing useful:
- `loadBinary` said "success" with 82 bytes of JSON
- `extractStrings` said "success" with 1 string (the JSON itself)
- `entropyAnalysis` said "success" with 3.73 (entropy of JSON, not the binary)

### Path handling concerns

The crackme binary is at a Windows path with mixed separators. Does the server handle:
- Absolute paths? (`C:\Users\...`)
- Forward slashes? (`C:/Users/...`)
- Relative paths? (`./crack/crackme.exe`)
- Spaces in paths? (`C:/My Projects/binary.exe`)

A path resolution failure could also cause the 82-byte bug — if the server can't find the file, it might fall back to storing the parameter string as "data".

### Fix:
- Every tool should self-validate: "Did I actually read a PE/ELF header? No? Then warn the caller."
- Add `warnings[]` array to every response
- `loadBinary` should report: format (PE/ELF/Mach-O), architecture, actual file size, section count, entry point
- Tools that need a loaded binary should check first and return clear guidance
- Add explicit path resolution logic with clear error messages ("File not found at: ...")

---

## 🆕 NEW FEATURES I WANT TO SEE

### P0 — Makes the server actually usable

| # | Feature | Why I need it |
|---|---------|---------------|
| 1 | **Actual file loading** | The single most important feature. Read bytes from disk. Everything else is downstream. |
| 2 | **Cross-reference finder** | "What code references the string 'Invalid serial'?" "Where is `VirtualAlloc` called from?" Without XREFs, you can't trace data flow. This is how real RE works. |
| 3 | **Control flow graph** | ASCII art or DOT format. "Show me the branching around the password check." Even a basic block list with edges would be transformative. |
| 4 | **Function detection** | Find function boundaries by scanning for prologues (`push rbp; mov rbp, rsp`). Output: list of `{name, startAddr, endAddr, callers[], callees[]}`. The current approach of guessing addresses is painful. |

### P1 — Makes analysis productive

| # | Feature | Why I need it |
|---|---------|---------------|
| 5 | **One-click full report** | `generateReport` should run: parseBinary → getSections → extractStrings → yaraScan → vulnScan → findFunctions → callTree(main) → disassemble(main) → exportToIda. All in one call. The "low hanging fruit" analysis should be one button. |
| 6 | **Import risk analyzer** | Flag dangerous API combos: `VirtualAlloc` + `WriteProcessMemory` = red, `IsDebuggerPresent` + anti-debug XOR = orange, `system` + no input validation = yellow. `vulnScan` only does CVE patterns — not behavioral risk. |
| 7 | **String cross-reference** | `extractStrings` should include which function(s) reference each string. Without this, a string dump is just a word list. With it, you can trace "Invalid serial format" → findSerialValidator() → algorithm. |
| 8 | **Emulator breakpoints** | `emulatorHooks` exists but is underpowered. I want: "Run until RIP = 0x140001234, then dump RAX, RBX, and the string at RDI." Interactive debugging via MCP. |
| 9 | **Deobfuscation hints** | Scan for: XOR loops, stack string construction, control flow flattening (switch-state machines). Flag them and suggest deobfuscation strategies. Currently `analyzeCodeAI` just pattern-matches import names. |
| 10 | **Session save/load** | Save the entire analysis state (loaded binary, disassembly, strings, sections, call graph) to a JSON file. Reload it later without re-running everything. Essential for long reverse engineering sessions. |
| 11 | **Diff two binaries** | `diffBinaries` exists but with broken schema. Fix it. Then: "What changed between v1 and v2 of this malware?" Byte-level + instruction-level diff. |

### P2 — Quality of life

| # | Feature | Why I need it |
|---|---------|---------------|
| 12 | **Auto-detect arch/format** | Don't make me specify `arch: "x86_64"` and `baseAddress: 0x140000000`. Parse the PE/ELF header and figure it out. The binary knows what it is. |
| 13 | **Exports/resources viewer** | PE exports table, resource section, version info. Quick triage info. |
| 14 | **Patch suggestions** | After `vulnScan` finds a pattern, suggest: "To patch this anti-debug check, NOP out bytes at 0x140001097 (3 bytes)." Combine analysis → actionable fix. |
| 15 | **Clipboard-ready export** | "Copy disassembly as markdown" or "Export strings as CSV". For pasting into notes/PRs. |
| 16 | **Search across outputs** | "Search all strings for 'password'" or "Find all `call` instructions to `VirtualAlloc`". Cross-tool search. |
| 17 | **Undo/redo pipeline steps** | Each pipeline step should be undoable. If I run `analyzeCodeAI` and it garbles the output, let me revert. |

---

## 💡 USABILITY: MAKE IT EASIER TO USE

### 1. Auto-discovery of everything

The LLM shouldn't need to guess. Provide:
- `listTools` → returns all 19 tool names with one-line descriptions
- `getToolSchema(toolName)` → returns exact parameter schema for any tool
- `getSessionStatus` → "Binary loaded: crackme.exe (PE32+, x86-64, 151KB, entry 0x140001234)"

### 2. Unify address handling

Some tools use file offsets, some use RVAs, some use virtual addresses. Pick ONE and stick to it. Virtual address (VA = imageBase + RVA) is the standard for x86-64 PE. Document it.

### 3. Better error recovery

If `disassemble` fails because `data` is a JSON string, the tool should detect this and say:
```
"Warning: data appears to be JSON text (starts with '{'), not binary. 
Expected PE magic 'MZ' or ELF magic '\x7FELF'. Did you pass the parameter 
JSON instead of a file path? Use loadBinary({ filePath: '...' }) first."
```

### 4. Progressive disclosure

New users are overwhelmed by 19 tools. Solution:
- **Quick Start mode:** `analyze` tool = load + parse + strings + sections + disassemble(entry) all in one
- **Expert mode:** All 19 tools individually
- Document this clearly in MCP_USAGE.md

### 5. Visual output where possible

- Control flow graph → render as DOT (Graphviz)
- Call tree → render as ASCII tree
- Hex dump → side-by-side with ASCII (classic hex dump format)
- Section map → memory layout diagram

### 6. Smart defaults

- `disassemble` should default to entry point, not offset 0
- `disassemble` should auto-detect code vs data regions
- `extractStrings` should filter to printable ASCII by default
- `entropyAnalysis` should break down by section automatically

### 7. Example-driven documentation

MCP_USAGE.md should include one complete end-to-end example per tool. Not just:

```
### loadBinary
Loads binary. Params: filePath
```

But:

```
### loadBinary
Loads a binary for analysis. All subsequent tools use the loaded binary.

Example:
  loadBinary({ filePath: "crackme.exe" })
  → "Loaded: crackme.exe (PE32+, x86-64, 151,552 bytes, 6 sections, entry 0x140001234)"

  After loading:
  disassemble({ address: 0x140001234, count: 50 })
  callTree({ target: "0x140001234" })
  extractStrings()  // no data param needed!
```

### 8. Session persistence

The session should survive disconnections. If the MCP server restarts, the loaded binary is gone. Solution: session auto-save to disk, auto-restore on reconnect.

---

## 📊 TOOL-BY-TOOL SCORECARD (v3, tested against crackme.exe)

| # | Tool | Status | What's wrong |
|---|------|--------|-------------|
| 1 | `loadBinary` | 🔴 Broken | Loads JSON, not binary. Reports false success. |
| 2 | `disassemble` | 🔴 Broken | Disassembles JSON parameter string as x86 instructions. |
| 3 | `decompile` | 🔴 Broken | Same input = same garbage output. |
| 4 | `parseBinary` | 🔴 Broken | "Invalid ELF Magic" — sees `{"da` not `MZ`. |
| 5 | `getSections` | 🔴 Broken | Same. |
| 6 | `extractStrings` | 🔴 Broken | Returns only the JSON string itself as one "string". |
| 7 | `entropyAnalysis` | 🔴 Broken | 3.73 is JSON text entropy, not binary entropy. |
| 8 | `callTree` | 🟡 Needs testing | Schema mismatch (`functionName` vs `target`). May work if schema fixed. |
| 9 | `yaraScan` | 🟡 Needs testing | Works but needs explicit `rules` + `data`. Session behavior unclear. |
| 10 | `vulnScan` | 🟡 Needs testing | May work but can't verify without correct binary data. |
| 11 | `analyzeCodeAI` | 🟡 Needs testing | Generic analysis, doesn't see actual code due to data bug. |
| 12 | `exportToIda` | 🟡 Needs testing | Session-based. May work if loadBinary worked. |
| 13 | `emulatorControl` | 🟡 Needs testing | Can't load binary into emulator (no bytes). |
| 14 | `emulatorHooks` | 🟡 Needs testing | Session-based. May work if emulator had a loaded binary. |
| 15 | `pipelineChainMode` | 🟡 Needs testing | Chains tools — but garbage in → garbage out when data is broken. |
| 16 | `typeStructRecovery` | 🟡 Needs testing | Session-based. May work but can't verify. |
| 17 | `patchAndRun` | 🟡 Needs testing | Needs binary in emulator first. |
| 18 | `diffBinaries` | ⚪ Not tested | Requires two binaries. Schema unclear. |
| 19 | `symbolicExecute` | ⚪ Not tested | Requires manual instruction input. |

**Real score: 0/19 tools verifiably work against crackme.exe.** The data bug invalidates every result from every tool. 7 tools are confirmed broken, 10 are "needs testing" because they can't be tested until data is fixed, 2 weren't testable.

---

## 🎯 PRIORITY ACTION PLAN

### Fix this week (P0):
1. **Fix the file loading middleware** — `data` must contain actual binary bytes from disk
2. **Make `loadBinary` actually work** — read the file, parse PE/ELF, cache in session
3. **Wire session into ALL tools** — no tool should need `data` after `loadBinary`
4. **Add `listTools` + `getSessionStatus` endpoints** — stop the guesswork

### Fix this month (P1):
5. **Fix schema/documentation mismatches** — auto-generate from code
6. **Add cross-reference finder** — the #1 missing RE capability
7. **Add function detection** — the #2 missing RE capability
8. **Add control flow graph** — the #3 missing RE capability
9. **Add one-click `analyze` quick start** — "just analyze this binary"

### Fix this quarter (P2):
10. Smart defaults, auto-detection, better errors, progress feedback
11. Session save/load, deobfuscation hints, import risk analyzer
12. Visual outputs (CFG, call tree, memory map)
13. Example-driven documentation rewrite

---

## 🏆 THE DREAM: What a Perfect MCP RE Session Looks Like

### Phase 1 (Minimum viable — just fix the data bug + 3 core tools)

```
User: Analyze crackme.exe

MCP:
  → loadBinary({ filePath: "crackme.exe" })
  → "Loaded: PE32+ x86-64, 151,552 bytes, 6 sections, entry 0x140001234"

User: Disassemble the entry point

MCP:
  → disassemble({ address: 0x140001234, count: 100 })
  → [Actual x86-64 instructions, not JSON text]
  → extractStrings()
  → ["Username: ", "Serial  : ", "[✓] Serial is valid!", "[X] Invalid serial format."]

User: Find the serial validation function

MCP:
  → findXRefs({ address: 0x140005678 })  // address of "Invalid serial format" string
  → "Referenced by: 0x140001300"
  → disassemble({ address: 0x140001300, count: 50 })
  → [Shows the serial validation algorithm]
```

### Phase 2 (Full vision — all tools working)

```
User: Analyze crackme.exe

MCP:
  → loadBinary("crackme.exe") 
  → "Loaded: PE32+ x86-64, 151KB, 6 sections, entry 0x140001234, 42 imports, 12 strings"

User: Find the serial validation

MCP:
  → extractStrings() → "Invalid serial format." at 0x140005678
  → findXRefs(0x140005678) → referenced by 0x140001300
  → disassemble(0x140001300) → [shows the validation function]
  → buildCFG(0x140001300) → [shows branching logic]
  → "This function: reads username → hashes with algorithm X → compares to serial → returns valid/invalid"

User: Generate serial for "testuser"

MCP:
  → executeScript: run the hash algorithm on "testuser"
  → "Serial: ABCD-EF01-2345-6789"

User: Verify it

MCP:
  → runBinary("crackme.exe", input="testuser\nABCD-EF01-2345-6789\n")
  → "[✓] Serial is valid!"
```

**Phase 1 is achievable with just the P0 fixes. Currently we're at step 0 because the binary never actually loads.**
