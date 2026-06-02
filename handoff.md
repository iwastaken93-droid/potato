# URET / DISSECT — Session 21 Handoff

> **Project**: Universal Reverse Engineering Tool (URET / DISSECT)
> **Status**: All 886 tests passing, production bundle builds cleanly.

---

## 1. Project Status
- **Tests**: **886 passed** across 71 test files. Green.
- **Build**: Production build `pnpm build` successful (`tsc && vite build`). No errors.
- **Lint**: ESLint clean.

---

## 2. Completed Tasks & Features

### RISC-V M & A Extensions
- Implemented decoding for M (multiply/divide) and A (atomic) instructions in [riscv.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/riscv.ts).
- Tested instructions like `mul`, `mulh`, `div`, `rem`, `lr.w`, `sc.w`, `amoadd.w` in [riscv.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/riscv.test.ts).

### PE Authenticode Verification
- Added PKCS#7 SignedData ASN.1 DER parser inside [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts).
- Computes Authenticode hashes by skipping PE checksum, Security Directory entry, and certificate table.
- Covered in [pe.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/pe.test.ts).

### DWARF v5 `.debug_loclists`
- Added parser for location lists table and indirection array parsing in [dwarfParser.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dwarfParser.ts).
- Exported from [debugSymbols.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/debugSymbols.ts) and verified via [dwarf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dwarf.test.ts).

### MCP Server & AI Bridge Refactoring
- Added file-reading middleware mapping `data`, `dataA`, `dataB` to automatically read path strings into hex strings in [mcp-server.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/mcp-server.ts).
- Supported entrypoint / offset auto-location for ELF/PE disasm/decompilation in [aiBridge.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/aiBridge.ts).
- Expanded tools: `extractStrings`, `getSections`, `entropyAnalysis`, `hexDump`.
- Implemented BFS queue-based multi-path symbolic solver.
- Simplified `patchBinary` schema (`offset` and `patchedBytes`).
- Upgraded emulator with dynamic disassembly of RAM and handling `nop`.
- Exposed `fs`, `path`, `fileSize`, `fileType` to script runner environment.

---

## 3. Roadmap & Remaining Tasks
- **Java Class Debug Info**: Parse `LineNumberTable` and `LocalVariableTable` in [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts). (Not Started)
- Add more unit/integration test coverage for Java class parser debug info.

---

## 4. Run Guide
- **Install**: `pnpm install`
- **Tests**: `pnpm test`
- **Build**: `pnpm build`
- **Dev**: `pnpm dev`

---

## 5. Next Immediate Action
- Parse Java `LineNumberTable` and `LocalVariableTable` attributes in [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts).

---

## SESSION 22 AGENT: GET STARTED IMMEDIATELY. NO PLANNING. GO!
