# Uret-Server MCP Tools — Comprehensive Review

> **Review Date:** May 31, 2026  
> **Target Binary:** `helloworld.exe` (PE32+ 64-bit Windows console, 225KB)  
> **MCP Server:** `C:/Users/NaThA/hacks/antigravity_things/agy/mcp_server/potato/src/mcp-server.ts`  
> **Tools Tested:** 9 of 11 (2 untested due to inapplicability)  
> **Tools Working Correctly:** 2 of 11

---

## Executive Summary

The uret-server MCP tools provide an ambitious set of binary analysis capabilities — disassembly, decompilation, PE/ELF parsing, emulation, vulnerability scanning, YARA scanning, symbolic execution, binary diffing, patching, and scriptable analysis. 

**However, the implementation quality varies dramatically.** Out of 11 tools, only 2 work correctly (yaraScan, vulnScan). 6 tools have critical bugs that produce wrong or useless output. 3 tools were partially functional. The root causes include hardcoded ELF-only parsing, incorrect offset handling, and data passing bugs where filename strings are passed instead of binary contents.

**Overall Grade: D+** — Ambitious scope, poor execution. Fixable with targeted debugging of ~5 core issues.

---

## Detailed Bug Reports

---

### Bug #1: `parseBinary` — ELF-Only, Fails on PE/Mach-O

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical |
| **Status** | Confirmed |
| **Input** | `{ "data": "helloworld.exe" }` |
| **Expected** | Parsed PE headers: DOS header, NT headers, section table, imports, exports |
| **Actual** | `"Invalid ELF Magic header"` |
| **Root Cause** | The parser assumes ELF format with `\x7fELF` magic bytes. PE files start with `MZ`. The parser does not check the magic bytes to determine format and route to the appropriate parser. |
| **Impact** | The most fundamental tool — binary parsing — is completely unusable for Windows binaries. Since many downstream tools depend on parsed binary information (entry point, sections, etc.), this cascades into failures elsewhere. |

**Code-Level Root Cause (Probable):**
```javascript
// Likely something like this in the parser:
function parseBinary(data) {
  if (data.slice(0, 4).toString() !== '\x7fELF') {
    throw new Error('Invalid ELF Magic header');
  }
  // ... ELF parsing only, no PE/Mach-O support
}
```
The server has PE parser code somewhere (the user mentioned it), but it's not integrated into the `parseBinary` tool.

**Fix Recommendation:**
1. Add magic-byte detection at the top of `parseBinary`
2. Route to PE/ELF/Mach-O parser based on detected format
3. If PE parser exists in the codebase but isn't wired up, wire it up
4. Return a consistent schema regardless of format (or document format-specific fields)

---

### Bug #2: `disassemble` — Disassembles DOS Header, Not Code

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical |
| **Status** | Confirmed |
| **Input** | `{ "data": "helloworld.exe", "address": <entryPointRVA> }` |
| **Expected** | Disassembly of the `.text` section starting at the PE entry point |
| **Actual** | Disassembly starting at file offset 0 (the DOS "MZ" header), producing garbage instructions like `push 0x6f6c6c65` (which is actually the ASCII for "hello" in the data sections) |
| **Root Cause** | The `address` parameter is **silently ignored**. The disassembler always starts at offset 0 of whatever data it receives. For PE files, offset 0 is the DOS header ("MZ"), not executable code. |
| **Impact** | The disassembler produces completely useless output. The "instructions" shown are actually data bytes (strings) being misinterpreted as x86-64 opcodes. This could seriously mislead a reverse engineer. |

**Additional Finding:** Even if the address parameter worked, the tool receives the filename string `"helloworld.exe"` rather than the actual binary bytes (see Bug #8). So even fixing the offset bug wouldn't help unless the data-passing bug is also fixed.

**Fix Recommendation:**
1. Fix the data-passing bug (Bug #8) first — the tool needs actual binary bytes
2. Respect the `address` parameter — if provided, start disassembly from that file offset, not offset 0
3. For PE files, compute the file offset from RVA using section headers automatically
4. If no address is provided, default to the PE entry point (not offset 0)
5. Add informational output noting the format detected and entry point used

---

### Bug #3: `decompile` — Decompiles DOS Header, Not Code (Same Root Cause as Bug #2)

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical |
| **Status** | Confirmed |
| **Input** | `{ "data": "helloworld.exe" }` |
| **Expected** | C-like pseudocode of the actual program logic |
| **Actual** | Garbage pseudocode decompiled from DOS header bytes |
| **Root Cause** | Same as Bug #2 — starts at offset 0, ignores the entry point. The decompiler is downstream of the disassembler, so it inherits all the same bugs. |
| **Impact** | Useless output. The pseudocode shows nonsensical operations on bytes that aren't instructions. |

**Fix Recommendation:**
Same as Bug #2. Fix the disassembler and the decompiler inherits the fix.

---

### Bug #4: `analyzeCodeAI` — Returns Boilerplate, Not Actual Analysis

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical |
| **Status** | Confirmed |
| **Input** | Tested with two different inputs: decompiled pseudocode from helloworld.exe and a completely different program |
| **Expected** | Different analysis output for different inputs, identifying actual patterns, complexity, and pseudocode insights |
| **Actual** | **Identical output** for both inputs. Generic boilerplate about "iterative control loop processing string or buffer data with conditional branching" |
| **Root Cause** | The AI analysis either: (a) returns a hardcoded/template response regardless of input, (b) the API call to the AI model is failing silently and returning a fallback, or (c) the input is not being passed to the AI model correctly |
| **Impact** | This is not "AI-powered analysis" — it's a fake. Users will make security decisions based on misleading generic analysis that doesn't actually examine their code. |

**Fix Recommendation:**
1. Verify that the `code` parameter is actually being sent to the AI model
2. Check for API errors or rate limiting that might cause silent fallback
3. Add a hash/checksum of the input to the output so users can verify the analysis corresponds to their input
4. If the AI API is unavailable, the tool should explicitly error rather than return fake analysis
5. Implement an actual LLM call (OpenAI, Anthropic, local model) with proper prompt engineering for binary analysis

---

### Bug #5: `executeScript` — Receives Filename String, Not Binary Data

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical |
| **Status** | Confirmed |
| **Input** | `{ "data": "helloworld.exe" }` |
| **Expected** | `data` variable in the script sandbox contains the raw binary bytes (Buffer) of helloworld.exe |
| **Actual** | `data` variable contains the **string** `"helloworld.exe"` — literally the filename text, not the file contents |
| **Root Cause** | The tool passes the `data` parameter through to the script sandbox without first reading the file from disk. The filename string is treated as the data. |
| **Impact** | Any script that tries to analyze the binary will operate on the 14-character string `"helloworld.exe"` instead of 225KB of binary. Scripts that check for "MZ" header will fail. Scripts that parse PE structures will crash. This tool is completely non-functional for file-based analysis. |

**Additional Findings from Script Execution:**
- The sandbox does NOT have `require()` — no `fs`, `path`, or other Node.js modules
- `Buffer` exists but is useless when `data` is just a filename string
- Scripts cannot read files from disk themselves due to the sandbox restrictions
- Error messages from scripts are returned but sometimes vague

**Fix Recommendation:**
1. **Read the actual file** from disk before passing to the script sandbox
2. Pass binary data as a `Buffer` (or Uint8Array) to the `data` variable
3. Also expose a `filename` or `path` variable so scripts know the original file
4. Expose `fileSize`, `fileType` (PE/ELF/Mach-O), and other pre-parsed metadata
5. Consider adding `fs.readFileSync` to the sandbox for additional file access
6. Document what globals are available in the sandbox (Buffer, console, etc.)

---

### Bug #6: `emulatorControl` — Cannot Load Binary into Emulator

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **Status** | Confirmed |
| **Sub-tests Performed** | `reset` (✅ works), `readReg` (✅ works — returns 0 for all regs), `writeMem` (✅ appears to succeed), `run` (❌ "No instruction found at address 0x0"), `step` (❌ same error) |
| **Expected** | After calling `writeMem` to load the binary at address 0, `run` or `step` should execute instructions |
| **Actual** | `writeMem` returns success but `run`/`step` find no instructions. The emulator memory and instruction decoder appear disconnected. |
| **Root Cause** | Unclear — possible causes: (a) `writeMem` writes to data memory but the instruction decoder reads from a separate instruction cache, (b) the emulator requires instructions to be loaded via a specific "load binary" API that doesn't exist, (c) x86-64 instruction decoding isn't implemented in the emulator core |
| **Impact** | Cannot run or step through binary code. The emulator is effectively just a register viewer/writer — not an emulator. |

**Fix Recommendation:**
1. Add a dedicated `load` action that accepts binary data and automatically loads it at the correct address
2. Implement x86-64 instruction fetch/decode/execute loop
3. Add a `loadBinary` action that parses the PE/ELF and loads sections at correct addresses
4. Document which architectures and instruction sets the emulator supports
5. If full emulation is out of scope, rename the tool to `registerViewer` or similar to set expectations

---

### Bug #7: `patchBinary` — Parameter Schema Ambiguous / Undocumented

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **Status** | Confirmed |
| **Attempted Schemas** | 1. `{ "offset": 0, "bytes": "4d5a" }` → rejected (wants `patchedBytes` not `bytes`, wants `address` not `offset`) 2. `{ "address": 0, "patchedBytes": "4d5a" }` → rejected (wants `offset` not `address`) |
| **Root Cause** | The tool's Zod/JSON schema validation is checking for mutually exclusive field names. The schema likely wants `offset` (number) + `patchedBytes` (string), but the error messages suggested otherwise on each attempt. The schema is either internally inconsistent or the error messages are misleading. |
| **Impact** | Cannot use the patching tool at all. Users cannot determine the correct parameter names through trial and error. |

**Fix Recommendation:**
1. Document the exact parameter schema clearly (field names, types, hex format)
2. Fix the schema to consistently accept one format
3. In error messages, show the expected schema with example values
4. Accept both hex string (`"4d5a"`) and byte array (`[0x4d, 0x5a]`) formats
5. Support both `offset` and `address` (RVA) mode with a discriminator field

---

### Bug #8: `symbolicExecute` — Deeply Nested Schema, Hard to Use Correctly

| Field | Detail |
|---|---|
| **Severity** | 🟡 Medium |
| **Status** | Partially tested (works with correct schema, hard to discover) |
| **Schema Required** | `instructions: [{ op: string, args: array }]`, `inputs: [{ name: string, ... }]`, `targetAddress: number` |
| **Actual Schema** | Much more complex — `instructions` requires `op` (string) and `args` (array) fields, and `inputs` requires objects with `name` fields, not plain strings |
| **Attempts** | 3 attempts before finding correct schema |
| **Root Cause** | Extremely nested, non-obvious parameter structure. Error messages only show one level of validation failure at a time (e.g., "expected string for op" but not the full schema). |
| **Impact** | Extremely frustrating to use. Each wrong attempt reveals one more field requirement. Users will give up after 2-3 attempts. |

**Fix Recommendation:**
1. Accept simpler input formats (e.g., disassembler output directly, or plain text instructions)
2. Provide a helper to parse disassembler output into the required format
3. Show the full expected schema in error messages, not just the first validation error
4. Add examples in the tool description

---

### Bug #9: `diffBinaries` — Schema Requires Two Data Fields (Untested)

| Field | Detail |
|---|---|
| **Severity** | ⚪ Not Tested (requires two binaries) |
| **Schema** | Requires both `dataA` and `dataB` (two binary data fields) |
| **Issue** | Presumably shares the same data-passing bug as `executeScript` — if `data` is just a filename string, then `dataA` and `dataB` are likely filename strings too |

---

### Bug #10: Cross-Cutting — No File Reading on the Server Side

| Field | Detail |
|---|---|
| **Severity** | 🔴 Critical (affects 6+ tools) |
| **Observation** | When tools receive `{ "data": "helloworld.exe" }`, many of them treat `data` as the literal string `"helloworld.exe"` instead of reading the file from disk. |
| **Affected Tools** | `executeScript` (confirmed), `parseBinary` (confirmed — gets string, tries to parse as ELF), `disassemble` (probable), `decompile` (probable), `emulatorControl` (probable), `patchBinary` (probable) |
| **Root Cause** | The MCP server receives the tool call parameters and passes them directly to the tool implementation without resolving file paths to file contents. There is no file-reading middleware. |
| **Fix Recommendation** | Add a middleware layer in the MCP server that: 1. Detects if `data`/`dataA`/`dataB` is a file path (string ending in known binary extensions or containing path separators) 2. Reads the file from disk using `fs.readFileSync` 3. Passes the actual binary `Buffer` to the tool implementation 4. Also passes metadata: `originalPath`, `fileSize`, `fileType` |

---

## Usability Pain Points

### 1. Error Messages Are Cryptic and Misleading
- Zod validation errors use raw JSON schema terminology (`"expected string, received undefined"`)
- Errors show only the first validation failure, not the full expected schema
- For nested objects (symbolicExecute), it takes 3-4 failed attempts to discover the full schema
- The `patchBinary` error messages contradicted each other across attempts

**Recommendation:** Add human-readable error messages with examples on validation failure.

### 2. No Self-Documentation
- The tool descriptions (visible in `mcp.json`) are one-liners
- There are no usage examples anywhere
- No README or documentation for any tool
- No indication of supported formats (ELF-only vs PE vs Mach-O)

**Recommendation:** Add `description` fields to tool definitions with: supported formats, parameter examples, expected input/output, and links to docs.

### 3. No Input Validation / Format Detection
- `parseBinary` returns "Invalid ELF Magic" instead of detecting PE format and routing appropriately
- No tool tells you what format it detected before trying to process
- Silent failures are common — tools return garbage instead of errors

**Recommendation:** Add format detection as a first step in every binary tool. Return clear errors like `"PE format detected. This tool only supports ELF."` so users know what went wrong.

### 4. No Batch / Workflow Support
- Can't pipe output of `disassemble` into `decompile` or `symbolicExecute` automatically
- Each tool must be called independently with manually reformatted parameters
- The AI assistant has to do all the orchestration

**Recommendation:** Add a `workflow` or `pipeline` tool, or ensure tool outputs are compatible with tool inputs (e.g., disassembler output format matches symbolicExecute input format).

### 5. Silent Degradation Instead of Explicit Errors
- `analyzeCodeAI` returns boilerplate instead of erroring when AI is unavailable
- `emulatorControl.writeMem` returns success but doesn't actually make instructions executable
- The disassembler happily disassembles non-code data without warning

**Recommendation:** Fail loudly when tools can't do what they claim. Return warnings when processing data that doesn't look like code.

### 6. Sandbox Too Restrictive for `executeScript`
- No `require()`, no `fs`, no file I/O
- Can't read additional files for comparison
- Can't use npm packages for analysis
- The only data available is the (broken) `data` variable

**Recommendation:** Either: (a) allow file I/O in the sandbox, or (b) expose rich pre-parsed metadata (sections, imports, strings, etc.) so scripts don't need to parse the binary themselves.

---

## What's Hard / Bad About Using These Tools

1. **Discoverability is zero.** You can't look at a tool and understand what parameters it needs without trial and error. The schemas are hidden in compiled JavaScript.

2. **The tools lie about their capabilities.** `analyzeCodeAI` claims to do AI analysis but returns boilerplate. `emulatorControl` claims to emulate but can't execute instructions. `parseBinary` claims to parse binaries but only does ELF.

3. **Error recovery is impossible.** When a tool produces garbage (disassembler starting at offset 0), there's no way to tell from the output that it's garbage — it "looks" like real disassembly if you don't know better.

4. **The PE/ELF asymmetry is undocumented.** Nothing tells you which tools work with which formats. You discover through cryptic errors like "Invalid ELF Magic header."

5. **No way to verify correctness.** When `analyzeCodeAI` returns analysis, there's no hash, checksum, or reference to the input to confirm it actually analyzed your code.

6. **The emulator is a stub.** It has register read/write and memory write, but no instruction execution. It's less capable than the average CTF emulator.

---

## Recommendations for Improvement

### Priority 1 (Critical — Fix These First)

1. **Add file-reading middleware** to resolve file paths to binary buffers before passing to tools
2. **Add PE support to `parseBinary`** (wire up the existing PE parser code)
3. **Fix `disassemble`/`decompile` offset handling** — respect the `address` parameter and default to the PE entry point
4. **Fix `analyzeCodeAI`** — either implement real AI analysis or remove the tool

### Priority 2 (High Impact)

5. **Fix `emulatorControl`** — implement actual instruction execution or rename/descope the tool
6. **Fix `patchBinary` parameter schema** — make it consistent and document it
7. **Simplify `symbolicExecute` parameter schema** — accept simpler input formats
8. **Add comprehensive error messages** with examples on validation failure

### Priority 3 (Quality of Life)

9. **Add tool descriptions** with examples and supported formats
10. **Add format auto-detection** with clear error messages
11. **Add input/output compatibility** between tools (disassembler → symbolicExecute)
12. **Expose pre-parsed metadata** in `executeScript` (sections, imports, strings, entry point)
13. **Add a `/help` or `/docs` tool** that returns tool documentation

---

## Feature Requests — What I'd Like to See

### 1. Strings Extraction Tool
A simple `extractStrings` tool that pulls ASCII and UTF-16 strings from the binary with configurable minimum length. This is one of the most basic and useful reverse engineering tools and it's completely absent.

### 2. Import/Export Viewer
The PE parser exists — expose imports (which DLLs and functions does this call?) and exports as a standalone tool or as part of `parseBinary` output. This is critical for understanding what a binary does.

### 3. Section Viewer
Show PE sections (.text, .data, .rdata, .rsrc) with their virtual addresses, raw offsets, sizes, and characteristics (read/write/execute). Critical for understanding binary layout.

### 4. Entropy Analysis
Calculate entropy per section to detect packed/encrypted code. This is a standard malware analysis technique.

### 5. Control Flow Graph (CFG) Generator
Given disassembly, generate a basic block / control flow graph. The `analyzeCodeAI` tool hinted at this but didn't deliver.

### 6. Hex Dump Viewer
Simple hex dump of arbitrary offsets. The current tools jump straight to disassembly — sometimes you just want to see the raw bytes.

### 7. Tool Chaining / Pipelines
Allow output of one tool to feed into another automatically. Example: `parseBinary` → get entry point → `disassemble` at entry point → `decompile` → `symbolicExecute`.

### 8. Session State
The emulator has `reset` but no session management. Tools like `parseBinary` should cache parsed info for subsequent tool calls on the same binary.

### 9. Comparison / Baseline Mode
For vulnerability scanning, compare against known-good binaries or baseline scans to reduce false positives.

### 10. Report Generation
Combine results from multiple tools into a single PDF/HTML/JSON report. Useful for security audits.

---

## What Actually Works Well

It's not all bad. Two tools worked correctly:

| Tool | Performance |
|---|---|
| **yaraScan** | ✅ Clean — correctly reported no matches on a clean binary. Schema was straightforward (`data` + `rules`). |
| **vulnScan** | ✅ Clean — correctly reported no vulnerabilities. Schema was straightforward (`data`). |

These two tools demonstrate that the underlying scanning engine is functional when the data is passed correctly.

The `symbolicExecute` tool also works when given the correct, manually constructed input format (not intuitively discoverable, but functional).

---

## Summary Table

| # | Tool | Status | Severity | Root Issue |
|---|---|---|---|---|
| 1 | `parseBinary` | ❌ Broken | Critical | ELF-only, no PE support |
| 2 | `disassemble` | ❌ Broken | Critical | Ignores `address`, starts at offset 0 |
| 3 | `decompile` | ❌ Broken | Critical | Inherits disassembler bug |
| 4 | `yaraScan` | ✅ Works | — | — |
| 5 | `vulnScan` | ✅ Works | — | — |
| 6 | `analyzeCodeAI` | ❌ Broken | Critical | Returns boilerplate, not real analysis |
| 7 | `emulatorControl` | 🟡 Partial | Medium | Can't execute instructions |
| 8 | `executeScript` | ❌ Broken | Critical | Receives filename string, not binary data |
| 9 | `symbolicExecute` | 🟡 Partial | Medium | Overly complex schema, works otherwise |
| 10 | `diffBinaries` | ⚪ Untested | — | Requires two binaries |
| 11 | `patchBinary` | ❌ Broken | Medium | Ambiguous/contradictory schema |

**Final Verdict:** The tools have the right *vision* — a comprehensive binary analysis suite accessible via MCP is a great idea. But the implementation needs serious debugging. The good news: the bugs are fixable. The root causes are clear (file reading middleware, format detection, parameter validation), and the fixes are well-scoped. With ~1-2 weeks of focused debugging, this could be an excellent toolset.
