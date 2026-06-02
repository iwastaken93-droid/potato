# MCP Tool Review v2 — Updated Server Analysis

**Date:** June 2, 2026
**Test Binary:** `password_or_payload.exe` (PE32+ 64-bit, 11,776 bytes, MSVC 14.50)
**Server Path:** `C:/Users/NaThA/hacks/antigravity_things/agy/mcp_server/potato/src/mcp-server.ts`

---

## Executive Summary

The updated server shows **significant improvement** over v1. Previously 2/11 tools worked; now **7/12 tools work correctly** (58% vs 18%). Three critical bugs from v1 have been fixed or partially addressed, and four new tools were added. However, the core disassembly/decompilation pipeline remains broken, which severely limits the server's primary use case.

| Category | v1 | v2 | Delta |
|----------|----|----|-------|
| ✅ Working | 2 | 7 | +5 |
| 🟡 Partial | 2 | 1 | -1 |
| ❌ Broken | 5 | 3 | -2 |
| ⚪ Not tested | 2 | 1 | -1 |
| 🆕 New tools | 0 | 4 | +4 |

---

## Detailed Tool-by-Tool Analysis

### ✅ Tool #1: `parseBinary` — **FIXED! Now supports PE format**

**v1 Status:** ❌ Broken (ELF-only, returned "Invalid ELF Magic header" for PE files)

**v2 Status:** ✅ Works correctly

**What changed:** The parser now properly detects PE format and returns comprehensive header data.

**Results from test binary:**
```json
{
  "format": "pe",
  "header": {
    "machine": 34404,        // x86-64
    "numberOfSections": 6,
    "characteristics": 34
  },
  "sections": [
    { "name": ".text",  "virtualSize": 4188, "virtualAddress": 4096 },
    { "name": ".rdata", "virtualSize": 4008, "virtualAddress": 12288 },
    { "name": ".data",  "virtualSize": 1664, "virtualAddress": 16384 },
    { "name": ".pdata", "virtualSize": 384,  "virtualAddress": 20480 },
    { "name": ".rsrc",  "virtualSize": 480,  "virtualAddress": 24576 },
    { "name": ".reloc", "virtualSize": 48,   "virtualAddress": 28672 }
  ],
  "imports": [
    {
      "dllName": "KERNEL32.dll",
      "imports": [
        { "name": "VirtualAlloc", "iatRva": 12288 },
        { "name": "IsDebuggerPresent", "iatRva": 12304 },
        // ... 17 total imports from KERNEL32
      ]
    },
    // 6 more DLLs: VCRUNTIME140, api-ms-win-crt-stdio/runtime/math/locale/heap
  ]
}
```

**Quality:** Excellent. Returns section VA, raw offset, characteristics, AND full import tables with IAT/ILT RVAs per DLL. This is production-quality PE parsing.

**Score:** 9/10 (missing: entry point RVA, image base, DLL characteristics flags, export table)


### ✅ Tool #2: `yaraScan` — Works correctly (unchanged)

**v1 → v2:** No regression. All 4 custom rules matched correctly:

| Rule | Result | Offset | Match |
|------|--------|--------|-------|
| `DebuggerCheck` | ✅ Matched | 8522 | `IsDebuggerPresent` string |
| `DebuggerCheck` | ✅ Matched | 3608 | `ff 15 0a 16 00 00 85 c0 75` (call + test + jnz pattern) |
| `VirtualAllocExec` | ✅ Matched | 8490 | `VirtualAlloc` string |
| `ShellExec` | ✅ Matched | 8686 | `system` string |
| `PasswordPrompt` | ✅ Matched | 6266 | `Password` string |
| `AntiDebug` | ❌ No match | — | Hex pattern not found at expected location |

**Score:** 8/10 (minor: `rules` param is required even for default scanning; default ruleset would be nice)


### ✅ Tool #3: `vulnScan` — Works correctly (unchanged)

**Result:** `"vulnerabilities": []` — no known vulnerability patterns detected. Correct for this clean binary.

**Score:** 7/10 (adequate but basic — could flag imported dangerous functions like `system`, `VirtualAlloc` with EXECUTE permissions)


### 🆕 Tool #4: `extractStrings` — NEW! Works perfectly

**v1:** Did not exist.  
**v2:** Comprehensive string extraction with encoding detection and tagging.

**Results from test binary:** 170 strings extracted, including:

| Offset | String | Tags |
|--------|--------|------|
| 6256 | `Enter the Password: ` | — |
| 6280 | `pass is correct!` | — |
| 6304 | `passwort is incorrect` | — |
| 6328 | `pause` | — |
| 8490 | `VirtualAlloc` | `api` |
| 8522 | `IsDebuggerPresent` | `api` |
| 8540 | `KERNEL32.dll` | `filepath` |
| 8686 | `system` | `api` |

**Quality:** Excellent. Tags (`api`, `filepath`) are extremely useful. Supports ASCII + wide-char detection. Includes virtual addresses.

**Score:** 10/10 — no complaints.


### 🆕 Tool #5: `getSections` — NEW! Works correctly

Returns all 6 PE sections with proper metadata (name, virtualSize, virtualAddress, sizeOfRawData, pointerToRawData, characteristics). Identical data to `parseBinary` sections but cleaner output focused on sections only.

**Score:** 8/10 (useful but redundant with parseBinary — consider merging or adding section entropy/permissions analysis)


### 🆕 Tool #6: `entropyAnalysis` — NEW! Works correctly

**Result:** Overall entropy 4.86, no high-entropy blocks detected. Confirms the binary is not packed/encrypted (consistent with a standard MSVC compiled exe).

**Score:** 7/10 (works but could benefit from per-section entropy breakdown)


### 🆕 Tool #7: `hexDump` — NEW! Works correctly

Returns full formatted hex dump with offsets, hex, and ASCII columns. 11,730+ lines for this 11KB binary. Properly formatted.

**Score:** 8/10 (works well but should support range parameters to limit output size)


### 🟡 Tool #8: `analyzeCodeAI` — **IMPROVED! Now gives meaningful results**

**v1 Status:** ❌ Broken (returned identical boilerplate for all inputs)  
**v2 Status:** 🟡 Partially working — provides relevant analysis but has limitations

**v2 Result:**
```json
{
  "summary": "Implements security protections or anti-analysis checks, aiming to determine 
               if the process is currently being inspected inside a debugger or emulator.",
  "functionality": [
    "Queries the Process Environment Block (PEB) for the BeingDebugged flag.",
    "Checks NtGlobalFlag or reads processor Thread Information Block directly.",
    "May issue specialized API requests (e.g., IsDebuggerPresent, CheckRemoteDebuggerPresent, or ptrace).",
    "Conditional branching changes program behavior or terminates execution if debugging is detected."
  ],
  "patterns": [{
    "name": "Anti-Debugging & Evasion",
    "confidence": 95,
    "matchedElements": [
      "PEB dereference (fs:[0x30] or gs:[0x60])",
      "API check: IsDebuggerPresent",
      "Branching logic indicating execution deviation"
    ]
  }],
  "suggestions": [
    "For binary hardening, anti-debugging makes basic static analysis harder but is 
     easily bypassed with hooks, plugins (ScyllaHide), or instruction patching.",
    "Consider using advanced control-flow flattening or code virtualization instead 
     of basic PEB checks."
  ]
}
```

**What improved:** The analysis is now contextually relevant. It correctly identified anti-debugging behavior with high confidence, provided actionable hardening suggestions, and recognized imported API patterns. The v1 boilerplate problem is resolved.

**Remaining issues:**
- The pseudocode generated is generic/incorrect (shows 32-bit `fs:[30h]` on a 64-bit binary — should be `gs:[60h]`)
- It still doesn't seem to be analyzing the ACTUAL disassembly — the output is pattern-matched from imports/strings rather than from instruction-level analysis
- No mention of `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` or shellcode execution capability

**Score:** 6/10 (vastly improved from v1's 2/10, but still pattern-matching rather than true disassembly analysis)


### ❌ Tool #9: `disassemble` — STILL BROKEN (BigInt serialization)

**v1 Status:** ❌ Broken (disassembled from offset 0 — DOS header)  
**v2 Status:** ❌ Broken (different error: "Do not know how to serialize a BigInt")

**Error:**
```
"Do not know how to serialize a BigInt"
```

**Root cause:** The disassembler is encountering 64-bit addresses (BigInt values in JS) and the JSON serializer doesn't know how to handle them. This is a new bug — v1 didn't get far enough to hit this issue.

**Impact:** **Critical.** Disassembly is the core tool for binary analysis. Without it, the server can't actually reverse engineer code.

**Fix priority:** P0 — fix BigInt serialization (use `.toString()` before JSON.stringify)

**Score:** 0/10 (non-functional)


### ❌ Tool #10: `decompile` — STILL BROKEN (offset bug persists)

**v1 Status:** ❌ Broken (decompiled DOS header instead of code)  
**v2 Status:** ❌ Still broken with same root cause

**Result:** Produced 700+ lines of garbage pseudocode starting from offset 0 (DOS "MZ" header bytes interpreted as instructions). Example garbage output:
```
mov(qword ptr [rsp + 0x24], rbx);
or(qword ptr [rax + 0x-77], rcx);   // negative offset! 
je(0x14000102d);
```

**Root cause:** The decompiler is being fed disassembly from offset 0 (DOS header) instead of the actual `.text` section at the entry point. Since `disassemble` now crashes with a BigInt error, the decompiler may be receiving corrupted input.

**Impact:** Critical. Second core tool, non-functional.

**Fix priority:** P0 — depends on fixing `disassemble` first

**Score:** 0/10 (non-functional)


### ❌ Tool #11: `executeScript` — STILL BROKEN (data is filename, not binary)

**v1 Status:** 🟡 Partial (scripts ran but `data` was the filename string, sandbox too restrictive)  
**v2 Status:** ❌ Still broken with same root cause + new error

**Error:**
```
"result": "data.substring is not a function"
```

**Root cause:** The `data` parameter passed to the script sandbox is the string `"pwp.exe"` (the filename) rather than the actual binary bytes. Additionally, the `data` variable in the sandbox appears to be a Buffer-like object in some contexts but a string in others — `substring` fails because it expects a string method on a non-string type.

**Impact:** The scripting engine is the most flexible analysis tool. Without proper binary data access, it's useless for custom analysis.

**Fix priority:** P0 — load binary file content into `data` variable; ensure `data` is typed consistently (Buffer/Uint8Array)

**Score:** 1/10 (executes but can't access binary data)


### 🟡 Tool #12: `emulatorControl` — Still partial (can reset but not run)

**v1→v2:** Same state. `reset` works (sets rip=0, rsp=1880096752). But `run`, `step`, `writeMem` can't load binary instructions. The emulator has no way to ingest a binary file.

**Score:** 3/10 (infrastructure works, can't do anything useful)


### ⚪ Not Tested: `patchBinary`, `diffBinaries`, `symbolicExecute`

Same limitations as v1. `patchBinary` schema is unclear (offset vs address, bytes vs patchedBytes). `diffBinaries` requires two binaries. `symbolicExecute` requires manual instruction arrays.

---

## Comparison: v1 vs v2 — What Changed

| Aspect | v1 | v2 |
|--------|----|----|
| PE support in parseBinary | ❌ ELF-only | ✅ Full PE parsing |
| analyzeCodeAI quality | ❌ Identical boilerplate | 🟡 Context-aware analysis |
| New tools | 0 | 4 (extractStrings, getSections, entropyAnalysis, hexDump) |
| disassemble | 🟡 Wrong offset | ❌ BigInt crash (regression) |
| decompile | ❌ Garbage from offset 0 | ❌ Same bug |
| executeScript | 🟡 No binary access | ❌ TypeError (regression) |
| String extraction | Manual only | ✅ Automated with tags |
| Vulnerability detection | ✅ Works | ✅ Works |
| YARA scanning | ✅ Works | ✅ Works |

---

## Priority Action Plan

### 🔴 P0 — Critical (core functionality broken)

1. **Fix `disassemble` BigInt serialization** — The most impactful fix. Add `BigInt.prototype.toJSON` or use a custom serializer. Without this, 3 tools (disassemble, decompile, analyzeCodeAI) are crippled.

2. **Fix `executeScript` binary data loading** — Pass actual file bytes into the `data` variable. This is the most flexible tool and should be the most powerful.

3. **Fix `decompile` entry point** — After fixing disassemble, ensure decompile starts at the code entry point (from PE Optional Header) rather than offset 0.

### 🟡 P1 — High (usability & completeness)

4. **Add entry point to `parseBinary` output** — Currently missing. Should include `entryPointRVA` and `imageBase`.

5. **Add `data` parameter validation** — Many tools accept `data` but silently fail or produce garbage when given a filename instead of binary content. Add file path → binary content resolution middleware.

6. **Make `emulatorControl` load binaries** — Add a `load` action that reads the PE, maps sections to memory, and sets RIP to the entry point.

### 🟢 P2 — Quality of Life

7. **Add range params to `hexDump`** — `startOffset` and `length` parameters to avoid dumping the entire file.

8. **Add per-section entropy to `entropyAnalysis`** — Currently only gives overall score. Per-section breakdown would identify packed `.text` sections.

9. **Add import risk scoring to `vulnScan`** — Flag dangerous API combinations (e.g., `VirtualAlloc` + `system` = potential shellcode launcher).

10. **Add `disassemble` address/size parameters** — `startVA` and `length` to disassemble specific regions.

---

## Summary

The v2 update is a major step forward: PE support, new string/section analysis tools, and improved AI analysis transform the server from "mostly broken" to "mostly working." The three tools that are still broken (disassemble, decompile, executeScript) share the same root cause — the server can't reliably load binary file content into its analysis pipeline. Fixing this one architectural issue would bring the server to production quality.

**Overall v2 Score: 6.5/10** (up from 3/10 in v1)

---

## 🆕 Feature Wishlist — Proposed New Tools

Based on real-world testing against two CTF binaries (`helloworld.exe` and `password_or_payload.exe`), here are the tools that would make this MCP server genuinely capable of solving reverse engineering challenges without resorting to external command-line utilities.

### 🔴 P0 — Critical Gaps (makes the server actually usable for RE)

#### #1: `loadBinary` (Binary File Loader Middleware)

**This is the one killer feature.** Accept a file path, read the binary into memory, parse the PE/ELF/Mach-O format, and make the raw bytes, sections, entry point, and imports available to ALL other tools.

**Why:** Currently every tool receives a filename string instead of binary content. This single feature fixes `disassemble` (correct start offset), `executeScript` (actual binary bytes), `emulatorControl` (load & run), and `decompile` (correct entry point) — all at once.

**Schema:**
```json
{
  "filePath": "pwp.exe"
}
```
**Output:** Session-scoped binary context loaded. All subsequent tool calls reference the loaded binary by default.

**Priority:** P0 — fixes 3 broken tools simultaneously.

---

#### #2: Cross-Reference (XREF) Finder

"Where is `VirtualAlloc` called from?" "What code references the `"pass is correct!"` string?" Currently impossible without disassembly. `yaraScan` finds strings/patterns but can't tell you what code uses them.

**Schema:**
```json
{
  "target": "VirtualAlloc",           // or RVA like 0x140003288
  "type": "code_to_data"              // code_to_data | data_to_code | code_to_code
}
```

**Output:** List of RVAs where the target is referenced, with instruction context (call, lea, mov, etc.)

**Why this matters for CTFs:** In `password_or_payload.exe`, this would immediately show `0x14000106c` calls `VirtualAlloc` and `0x140001111` calls `*%rdi` (user input buffer) — the two smoking guns.

**Priority:** P0 — no RE is possible without "who uses this?"

---

#### #3: Control Flow Graph (CFG)

"Show me the branching around the `IsDebuggerPresent` check at `0x140001097`." Even as ASCII art or a DOT graph, this would be transformative.

**Schema:**
```json
{
  "startVA": "0x140001000",
  "format": "ascii"                   // ascii | dot | json
}
```

**Output:**
```
0x140001000 (entry)
  ├─ 0x140001097: call IsDebuggerPresent
  │   ├─ [eax=1] → 0x1400010a1 (XOR path + execute)
  │   └─ [eax=0] → 0x1400010ab (direct execute)
  ├─ 0x140001111: call *%rdi
  │   ├─ [al≠0]  → 0x140001125 ("pass is correct!")
  │   └─ [al=0]  → 0x140001115 ("passwort is incorrect")
```

**Priority:** P0 — the single most useful view for understanding program logic.

---

### 🟡 P1 — Makes analysis actually productive

#### #4: Diff Sections

"What changed between version A and version B of this binary?" Currently `diffBinaries` exists but takes raw `dataA`/`dataB` params with unclear schema and was never successfully tested.

**Schema:**
```json
{
  "fileA": "helloworld.exe",
  "fileB": "pwp.exe",
  "sections": [".text", ".rdata"]
}
```

**Output:** Side-by-side diff of the selected sections with changed bytes highlighted.

**Priority:** P1

---

#### #5: Export to IDA/Ghidra

Dump the analyzed binary + metadata in a format importable by proper RE tools. Even just a `.idc` script with renamed functions and annotated strings would bridge the gap between MCP analysis and professional tooling.

**Schema:**
```json
{
  "format": "idc"                     // idc | ghidra_python | radare2
}
```

**Output:** Script file content with:
- Renamed functions based on imported API usage
- String annotations at their xref locations
- Section comments with entropy data
- YARA match annotations

**Priority:** P1

---

#### #6: Patch & Run

"Patch out the `IsDebuggerPresent` check and see what happens." Combine `patchBinary` + `emulatorControl` into an end-to-end workflow. Currently both are broken independently.

**Schema:**
```json
{
  "patches": [
    { "rva": "0x140001097", "original": "ff15...", "patched": "31c090" }
  ],
  "runUntil": "0x140001111"
}
```

**Priority:** P1

---

#### #7: Import Risk Analyzer

Auto-flag dangerous API combinations. Currently `vulnScan` only does basic CVE pattern matching, missing obvious red flags like `VirtualAlloc` + `system` in the same binary.

**Output:**
```
⚠️  HIGH: VirtualAlloc + system → potential shellcode launcher
⚠️  MEDIUM: IsDebuggerPresent + TerminateProcess → anti-debug with kill
✅  LOW: fgets used for input (safe bounded read)
```

**Priority:** P1 — would instantly flag `password_or_payload.exe` as suspicious.

---

### 🟢 P2 — Quality of Life

#### #8: Call Tree

"Show me the call graph: `main → IsDebuggerPresent → VirtualAlloc → shellcode`." Even just listing callees/callers per function would be valuable for understanding program structure at a glance.

**Priority:** P2

---

#### #9: Type/Struct Recovery

The binary's PDB path is embedded: `C:\Users\NaThA\hacks\helloworld\x64\Release\helloworld.pdb`. If the PDB is available, parse it and recover function names, parameter types, and local variable names. Without PDB, use heuristic struct identification from instruction patterns.

**Priority:** P2

---

#### #10: Emulator Hooks (Breakpoints)

Interactive debugging via MCP: "Run until RIP = `0x140001097` (IsDebuggerPresent call), then dump registers and stack." Currently the emulator can only reset — no step/run/breakpoint functionality works.

**Schema:**
```json
{
  "action": "runUntil",
  "breakpoints": ["0x140001097"],
  "dumpOnBreak": ["regs", "stack:32"]
}
```

**Priority:** P2

---

#### #11: Pipeline / Chain Mode

"`extractStrings` → filter for API names → find xrefs → disassemble those functions." Currently every step is a manual tool call. A pipeline DSL would let complex analyses be expressed declaratively.

**Example:**
```json
{
  "pipeline": [
    { "tool": "extractStrings", "filter": { "tag": "api" } },
    { "tool": "findXrefs", "map": "$.strings[].rva" },
    { "tool": "disassemble", "map": "$.xrefs[].callsite" }
  ]
}
```

**Priority:** P2

---

## 🎯 Impact Analysis: What Each Feature Would Unlock for the CTF

Using `password_or_payload.exe` as the test case:

| Without Feature | With Feature |
|-----------------|--------------|
| Can't see code → don't know `call *%rdi` exists | `disassemble` fixed → see user input executed as code |
| Can't find who calls `VirtualAlloc` | `findXrefs` → `0x14000106c` calls it with `PAGE_EXECUTE_READWRITE` |
| Can't find who references `"pass is correct!"` | `findXrefs` → `0x140001125` branches to it after `test al,al` |
| Can't test shellcode inputs | `emulatorControl` patched → send `\xB0\x01\xC3`, see `al=1`, hit success branch |
| Can't auto-flag suspicious imports | `importRiskAnalyzer` → flags `VirtualAlloc+RWX + system` combo |

**Bottom line:** With the P0 features (binary loader + xrefs + CFG), this server could solve the CTF entirely on its own — no `objdump`, no `printf`, no external tools needed.
