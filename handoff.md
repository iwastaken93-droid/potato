# DISSECT / URET — Session 18 → Session 19 Handoff

> **Project**: Universal Reverse Engineering Tool (URET / DISSECT)
> **Date**: 2026-05-31T15:08:00+10:00
> **Last Commit**: `526f219` — Session 17 commit
> **Test Status**: **861 passed / 2 failed** (863 total across 69 test files)
> **Uncommitted Changes**: 40 modified + 14 untracked files (Session 18 work)

---

## Quick Start

```bash
# Install dependencies
pnpm install

# Run full test suite
pnpm test

# Dev server (Vite)
pnpm dev

# Production build
pnpm build
```

> [!IMPORTANT]
> Always use `pnpm` — never `npm`. All imports use `.js` extensions (ESM).

---

## Session 18 Summary — Completed Tasks

| # | Task | Key Files | Status |
|---|------|-----------|--------|
| 1 | **AI Agent Bridge** — Query interface for AI agents to interact with all URET subsystems | [aiBridge.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/aiBridge.ts), [aiBridge.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/aiBridge.test.ts) | ✅ 12 tests |
| 2 | **Symbolic Execution Engine** — IR-level symbolic executor with SSA, path constraints, simplifier | [symbolic.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/symbolic.ts), [symbolic.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/symbolic.test.ts) | ✅ 4 tests |
| 3 | **Symbolic ↔ Emulator Integration** — Concolic tracing, register/memory symbolication | [emulator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/emulator.ts), [symbolicEmulator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/symbolicEmulator.test.ts) | ✅ 4 tests |
| 4 | **ARM32 + Thumb Decoder** — Full ARM32 state + Thumb 16/32-bit instruction decoding | [arm32.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm32.ts), [arm32.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/arm32.test.ts) | ✅ 28 tests |
| 5 | **RISC-V C Extension** — RV32I/RV64I base + compressed (C) 16-bit instruction support | [riscv.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/riscv.ts), [riscv.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/riscv.test.ts) | ✅ 6 tests |
| 6 | **Mach-O Fat/Universal Binary** — Fat32/Fat64 parsing with architecture slice selection | [macho.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/macho.ts), [macho.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/macho.test.ts) | ✅ 12 tests |
| 7 | **Plugin API v2** — v1 + v2 plugin API support with version negotiation | [plugins.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/plugins.ts), [plugins.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/plugins.test.ts) | ✅ 11 tests |
| 8 | **Intel HEX / S-Record Loader** — Parse Intel HEX & Motorola S-record formats with block merging | [hexLoader.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/hexLoader.ts), [hexLoader.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/hexLoader.test.ts) | ✅ 33 tests |
| 9 | **GDB Integration Tests** — Live connection simulator with 6 integration scenarios | [gdbIntegration.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/gdbIntegration.test.ts) | ✅ 6 tests |
| 10 | **PE Parser Optimization** — Fast Uint8Array reads, cached TextDecoder | [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts) | ✅ 17 tests |
| 11 | **DEX Debug Info** — debug_info_item parsing, line/local variable resolution | [dex.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dex.ts), [dex.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dex.test.ts) | ✅ 9 tests |
| 12 | **ESLint Cleanup (src/parser/)** — Reduced warnings from 98 → 28 | Multiple parser files | ✅ Done |
| 13 | **ARM Decoder Tests** — Added dedicated test suite for ARM64 disassembly | [arm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/arm.test.ts) | ✅ 7 tests |
| 14 | **Profile Tests** — Performance profiling test suite | [profile.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/profile.test.ts) | ✅ tests |
| 15 | **.NET IL Decoder** — MSIL/CIL bytecode disassembly | [dotnetIl.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/dotnetIl.ts), [dotnetIl.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dotnetIl.test.ts) | ✅ 10 tests |
| 16 | **Z80 & 6502 Retro Decoders** — Full retro CPU instruction decoding | [z80.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/z80.ts), [m6502.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/m6502.ts), [retro.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/retro.test.ts) | ✅ 16 tests |

---

## Git Status

### Last 5 Commits

```
526f219 Session 17: S-record/Intel HEX loader, Z80/6502 decoders, ARM32/Thumb, DWARF v5, cross-file diff, .NET IL
c4030ae Session 16: binary loading optimizer, DWARF v5, COFF/XCOFF, SPARC, trace diff, plugin marketplace
75c4450 Session 15: handoff document
ceec88c Session 14: feature expansion + bug fixes
ae29766 Session 13 close-out
```

### Uncommitted (Session 18 — NEEDS COMMIT)

**Modified (40 files)**:
- `DEVLOG.md`, `src/analyzer/{ai,aiOnDevice,binaryProcessor,demangler,diff,frida,hashes,plugins,reportGenerator,scripting,search,xrefs,yara}.ts`
- `src/disassembler/{arm,arm32,dalvik,riscv,router,types}.ts`
- `src/emulator/{cpu,emulator}.ts`
- `src/parser/{dex,dwarfParser,elf,javaClass,macho,machoObjc,machoSignature,pe,wasm}.ts`
- `src/ui/{assemblyView,layout}.ts`
- `tests/{arm32,dex,elf,hexLoader,macho,pe,plugins,retro}.test.ts`

**Untracked (14 files)**:
- `src/analyzer/{aiBridge,symbolic}.ts`
- `tests/{aiBridge,arm,dotnetIl,gdbIntegration,profile,riscv,symbolic,symbolicEmulator}.test.ts`
- `scratch/{append,append_devlog,debug_elf}.js`, `scratch/debug_elf.test.ts`

> [!WARNING]
> Session 18 work is NOT committed. First task for Session 19: `git add -A && git commit -m "Session 18: ..."`.

---

## Full Architecture — Source Files

### src/analyzer/ (23 files)

| File | Size | Purpose |
|------|------|---------|
| [ai.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/ai.ts) | 22KB | AI explanation engine for binary analysis |
| [aiBridge.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/aiBridge.ts) | 25KB | **NEW** AI agent query bridge (hex/b64 input, multi-subsystem) |
| [aiOnDevice.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/aiOnDevice.ts) | 25KB | On-device AI inference engine |
| [binaryProcessor.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/binaryProcessor.ts) | 54KB | Main binary processing pipeline |
| [binaryProcessor.worker.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/binaryProcessor.worker.ts) | <1KB | Web worker wrapper |
| [demangler.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/demangler.ts) | 13KB | C++/Rust/D/Swift symbol demangling |
| [diff.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/diff.ts) | 10KB | Binary & instruction diff engine |
| [entropy.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/entropy.ts) | 4KB | Shannon entropy analysis |
| [fcg.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/fcg.ts) | 5KB | Function call graph builder |
| [frida.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/frida.ts) | 15KB | Frida dynamic instrumentation bridge |
| [hashes.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/hashes.ts) | 8KB | Cryptographic hash computation |
| [patcher.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/patcher.ts) | 9KB | Binary patching engine |
| [plugins.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/plugins.ts) | 30KB | Plugin system (v1 + v2 API), marketplace |
| [reportGenerator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/reportGenerator.ts) | 33KB | Analysis report generation |
| [scripting.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/scripting.ts) | 8KB | Script console engine |
| [search.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/search.ts) | 9KB | Binary search (hex, string, regex) |
| [signatures.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/signatures.ts) | 8KB | Compiler/packer signature detection |
| [strings.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/strings.ts) | 9KB | String extraction engine |
| [symbolic.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/symbolic.ts) | 13KB | **NEW** Symbolic execution engine (SSA, path constraints) |
| [traceDiff.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/traceDiff.ts) | 3KB | Execution trace diffing |
| [vulnScanner.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/vulnScanner.ts) | 12KB | Vulnerability pattern scanner |
| [xrefs.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/xrefs.ts) | 11KB | Cross-reference analysis |
| [yara.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/yara.ts) | 14KB | YARA rule engine |

### src/disassembler/ (24 files)

| File | Size | Purpose |
|------|------|---------|
| [arm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm.ts) | 26KB | ARM64/AArch64 disassembler |
| [arm32.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm32.ts) | 24KB | ARM32 + **Thumb** (16/32-bit) decoder |
| [ast.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ast.ts) | 2KB | Decompiler AST node types |
| [astPrinter.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/astPrinter.ts) | 4KB | AST → C-like source printer |
| [capstoneWasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/capstoneWasm.ts) | 25KB | Capstone WASM binding |
| [cfg.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/cfg.ts) | 9KB | Control flow graph builder |
| [dalvik.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/dalvik.ts) | 8KB | Dalvik/DEX bytecode decoder |
| [decompiler.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/decompiler.ts) | 36KB | IR → high-level decompiler |
| [dotnetIl.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/dotnetIl.ts) | 45KB | .NET IL/CIL bytecode decoder |
| [helpers.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/helpers.ts) | <1KB | Shared helper functions |
| [ir.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ir.ts) | 13KB | Intermediate representation types |
| [m6502.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/m6502.ts) | 11KB | MOS 6502 retro decoder |
| [mips.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/mips.ts) | 7KB | MIPS disassembler |
| [optimizer.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/optimizer.ts) | 34KB | IR optimization passes (LICM, DCE, etc.) |
| [ppc.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ppc.ts) | 6KB | PowerPC disassembler |
| [registerAllocator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/registerAllocator.ts) | 10KB | Register allocator for IR |
| [riscv.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/riscv.ts) | 22KB | RISC-V RV32I/RV64I + **C extension** decoder |
| [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) | 12KB | Architecture-based disassembler routing |
| [sparc.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/sparc.ts) | 8KB | SPARC disassembler |
| [types.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/types.ts) | 5KB | Shared disassembler types |
| [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/wasm.ts) | 9KB | WebAssembly disassembler |
| [x86.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/x86.ts) | 33KB | x86/x86-64 disassembler |
| [z80.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/z80.ts) | 35KB | Zilog Z80 retro decoder |

### src/parser/ (15 files)

| File | Size | Purpose |
|------|------|---------|
| [archive.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/archive.ts) | 10KB | Archive format parser (ZIP, TAR) |
| [coff.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/coff.ts) | 11KB | COFF/XCOFF object file parser |
| [debugSymbols.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/debugSymbols.ts) | 10KB | Debug symbol resolution |
| [dex.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dex.ts) | 21KB | Android DEX file parser (+ debug info) |
| [dotnetMetadata.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dotnetMetadata.ts) | 27KB | .NET PE metadata tables parser |
| [dwarfParser.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dwarfParser.ts) | 29KB | DWARF v4/v5 debug info parser |
| [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts) | 26KB | ELF binary parser |
| [hexLoader.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/hexLoader.ts) | 8KB | Intel HEX & Motorola S-record loader |
| [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts) | 15KB | Java .class file parser |
| [macho.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/macho.ts) | 26KB | Mach-O parser (+ **fat/universal binary**) |
| [machoObjc.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/machoObjc.ts) | 19KB | Mach-O Objective-C metadata |
| [machoSignature.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/machoSignature.ts) | 17KB | Mach-O code signature parser |
| [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts) | 28KB | PE/PE32+ parser (optimized) |
| [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/wasm.ts) | 32KB | WebAssembly binary parser |

### src/emulator/ (5 files)

| File | Size | Purpose |
|------|------|---------|
| [cpu.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/cpu.ts) | 6KB | CPU abstraction |
| [emulator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/emulator.ts) | 23KB | Full emulator with symbolic tracing |
| [gdbProtocol.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/gdbProtocol.ts) | 11KB | GDB RSP protocol handler |
| [memory.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/memory.ts) | 7KB | Virtual memory subsystem |
| [syscall.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/syscall.ts) | 15KB | System call emulation |

### src/ui/ (36 files)

| File | Size | Purpose |
|------|------|---------|
| [aiPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/aiPanel.ts) | 17KB | AI assistant panel |
| [assemblyView.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/assemblyView.ts) | 42KB | Main assembly listing view |
| [binaryLoader.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/binaryLoader.ts) | 7KB | Drag-and-drop binary loader |
| [cfgVisualizer.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/cfgVisualizer.ts) | 33KB | Control flow graph visualizer |
| [collabPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/collabPanel.ts) | 36KB | Collaborative editing panel |
| [demanglerPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/demanglerPanel.ts) | 20KB | Symbol demangler panel |
| [dependencyGraph.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/dependencyGraph.ts) | 31KB | Library dependency graph |
| [diffPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/diffPanel.ts) | 36KB | Binary diff panel |
| [emulatorPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/emulatorPanel.ts) | 18KB | Emulator control panel |
| [entropyGraph.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/entropyGraph.ts) | 26KB | Entropy visualization |
| [fcgVisualizer.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/fcgVisualizer.ts) | 22KB | Function call graph UI |
| [gdbPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/gdbPanel.ts) | 19KB | GDB debugger panel |
| [hexViewer.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/hexViewer.ts) | 13KB | Hex dump viewer |
| [importsExportsPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/importsExportsPanel.ts) | 18KB | Imports/exports panel |
| [layout.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/layout.ts) | 20KB | Main application layout |
| [loadingScreen.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/loadingScreen.ts) | 8KB | Loading screen |
| [machoObjcPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/machoObjcPanel.ts) | 28KB | Objective-C metadata panel |
| [memoryMap.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/memoryMap.ts) | 23KB | Memory map visualization |
| [metadataPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/metadataPanel.ts) | 37KB | File metadata panel |
| [panelCoordinator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelCoordinator.ts) | 48KB | Panel coordinator / app controller |
| [panelEvents.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelEvents.ts) | 7KB | Panel event system |
| [panelRegistry.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelRegistry.ts) | <1KB | Panel registration |
| [patcherPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/patcherPanel.ts) | 18KB | Binary patching UI |
| [pluginsPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/pluginsPanel.ts) | 39KB | Plugin marketplace UI |
| [reportPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/reportPanel.ts) | 32KB | Report generation UI |
| [scriptingConsole.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/scriptingConsole.ts) | 12KB | Scripting REPL console |
| [searchPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/searchPanel.ts) | 31KB | Search panel UI |
| [signaturePanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/signaturePanel.ts) | 20KB | Signature detection panel |
| [stringsView.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/stringsView.ts) | 21KB | Strings listing UI |
| [tabManager.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/tabManager.ts) | 2KB | Tab management |
| [typeEditors.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeEditors.ts) | 13KB | Custom type editors |
| [typeRenderers.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeRenderers.ts) | 20KB | Type rendering engine |
| [typeSystemPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeSystemPanel.ts) | 14KB | Type system panel |
| [xrefsPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/xrefsPanel.ts) | 20KB | Cross-references panel |
| [yaraPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/yaraPanel.ts) | 22KB | YARA rules panel |

### src/network/ (1 file)

| File | Size | Purpose |
|------|------|---------|
| [collab.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/network/collab.ts) | 32KB | WebRTC collaborative editing |

### src/ root (3 files)

| File | Size | Purpose |
|------|------|---------|
| [main.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/main.ts) | 13KB | Application entry point |
| [styles.css](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/styles.css) | 12KB | Main stylesheet |
| [index.html](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/index.html) | <1KB | HTML shell |

**Total**: ~107 source files, ~1.6MB of TypeScript/CSS/HTML

---

## Full Test Suite — 70 Test Files (863 Tests)

| Test File | Tests | Size | Status |
|-----------|-------|------|--------|
| [ai.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/ai.test.ts) | 5 | 3KB | ✅ |
| [aiBridge.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/aiBridge.test.ts) | 12 | 7KB | ✅ |
| [aiOnDevice.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/aiOnDevice.test.ts) | — | 10KB | ✅ |
| [archive.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/archive.test.ts) | 4 | 7KB | ✅ |
| [arm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/arm.test.ts) | 7 | 4KB | ✅ |
| [arm32.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/arm32.test.ts) | 28 | 12KB | ✅ |
| [binaryLoader.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/binaryLoader.test.ts) | 2 | 1KB | ✅ |
| [binaryProcessor.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/binaryProcessor.test.ts) | — | 4KB | ✅ |
| [capstoneWasm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/capstoneWasm.test.ts) | 10 | 7KB | ✅ |
| [coff.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/coff.test.ts) | 18 | 16KB | ✅ |
| [collab.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/collab.test.ts) | — | 15KB | ✅ |
| [debugSymbols.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/debugSymbols.test.ts) | 23 | 32KB | ✅ |
| [debug_dwarf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/debug_dwarf.test.ts) | 1 | 4KB | ✅ |
| [decompiler.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/decompiler.test.ts) | 12 | 16KB | ✅ |
| [demangler.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/demangler.test.ts) | 8 | 3KB | ✅ |
| [dex.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dex.test.ts) | 9 | 21KB | ✅ |
| [diff.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/diff.test.ts) | 43 | 20KB | ✅ |
| [diffPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/diffPanel.test.ts) | 4 | 4KB | ✅ |
| [dotnetIl.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dotnetIl.test.ts) | 10 | 7KB | ✅ |
| [dotnetMetadata.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/dotnetMetadata.test.ts) | 3 | 8KB | ✅ |
| [e2e.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/e2e.test.ts) | 12 | 27KB | ✅ |
| [elf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/elf.test.ts) | — | 38KB | ❌ 2 fail |
| [emulator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/emulator.test.ts) | 32 | 20KB | ✅ |
| [entropy.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/entropy.test.ts) | 9 | 5KB | ✅ |
| [entropyGraph.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/entropyGraph.test.ts) | — | 7KB | ✅ |
| [fcg.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/fcg.test.ts) | 14 | 12KB | ✅ |
| [frida.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/frida.test.ts) | 11 | 6KB | ✅ |
| [gdbIntegration.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/gdbIntegration.test.ts) | 6 | 7KB | ✅ |
| [gdbPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/gdbPanel.test.ts) | — | 9KB | ✅ |
| [gdbProtocol.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/gdbProtocol.test.ts) | 21 | 13KB | ✅ |
| [hashes.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/hashes.test.ts) | 14 | 4KB | ✅ |
| [hexLoader.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/hexLoader.test.ts) | 33 | 10KB | ✅ |
| [ir.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/ir.test.ts) | 18 | 40KB | ✅ |
| [javaClass.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/javaClass.test.ts) | 5 | 15KB | ✅ |
| [layout.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/layout.test.ts) | 3 | 3KB | ✅ |
| [loadingScreen.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/loadingScreen.test.ts) | — | 2KB | ✅ |
| [macho.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/macho.test.ts) | 12 | 16KB | ✅ |
| [machoObjc.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/machoObjc.test.ts) | 1 | 8KB | ✅ |
| [machoObjcPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/machoObjcPanel.test.ts) | 6 | 6KB | ✅ |
| [machoSignature.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/machoSignature.test.ts) | 24 | 19KB | ✅ |
| [memoryMap.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/memoryMap.test.ts) | — | 10KB | ✅ |
| [metadata.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/metadata.test.ts) | — | 4KB | ✅ |
| [panelCoordinator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/panelCoordinator.test.ts) | — | 7KB | ✅ |
| [patcher.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/patcher.test.ts) | — | 14KB | ✅ |
| [pe.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/pe.test.ts) | 17 | 47KB | ✅ |
| [peResources.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/peResources.test.ts) | 1 | 9KB | ✅ |
| [plugins.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/plugins.test.ts) | 11 | 12KB | ✅ |
| [profile.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/profile.test.ts) | — | 4KB | ✅ |
| [report.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/report.test.ts) | 17 | 11KB | ✅ |
| [reportPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/reportPanel.test.ts) | 5 | 4KB | ✅ |
| [retro.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/retro.test.ts) | 16 | 8KB | ✅ |
| [riscv.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/riscv.test.ts) | 6 | 3KB | ✅ |
| [router.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/router.test.ts) | — | 45KB | ✅ |
| [scripting.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/scripting.test.ts) | 22 | 12KB | ✅ |
| [search.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/search.test.ts) | 15 | 9KB | ✅ |
| [signatures.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/signatures.test.ts) | 19 | 10KB | ✅ |
| [strings.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/strings.test.ts) | 8 | 6KB | ✅ |
| [symbolic.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/symbolic.test.ts) | 4 | 5KB | ✅ |
| [symbolicEmulator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/symbolicEmulator.test.ts) | 4 | 3KB | ✅ |
| [syscall.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/syscall.test.ts) | 20 | 23KB | ✅ |
| [tabManager.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/tabManager.test.ts) | 2 | 2KB | ✅ |
| [traceDiff.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/traceDiff.test.ts) | 11 | 10KB | ✅ |
| [typeSystem.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/typeSystem.test.ts) | — | 6KB | ✅ |
| [uiPanels.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/uiPanels.test.ts) | — | 15KB | ✅ |
| [vulnScanner.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/vulnScanner.test.ts) | 44 | 25KB | ✅ |
| [wasm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/wasm.test.ts) | 7 | 16KB | ✅ |
| [xrefs.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/xrefs.test.ts) | 7 | 8KB | ✅ |
| [yara.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/yara.test.ts) | 10 | 8KB | ✅ |
| [yaraPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/yaraPanel.test.ts) | 7 | 4KB | ✅ |

---

## Known Bugs / Issues

### ❌ 2 Failing Tests in [elf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/elf.test.ts)

1. **`should parse symbols and relocations, resolve GOT and PLT entries`** (line 805)
   - Expected `pltEntries[0].symbolName` to be `'bar'` but got `'foo'`
   - Root cause: PLT symbol resolution in [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts) matches wrong relocation entry

2. **`should decode AArch64 adrp/ldr PLT instructions`** (line 931)
   - Expected `pltEntries.length` to be `1` but got `0`
   - Root cause: AArch64 PLT instruction pattern not recognized by ELF parser

> [!CAUTION]
> These are ELF PLT/GOT resolution bugs. Fix in `src/parser/elf.ts` before adding more ELF features.

---

## Operational Rules

> [!IMPORTANT]
> **READ THESE RULES BEFORE WRITING ANY CODE**

| Rule | Details |
|------|---------|
| **Package Manager** | `pnpm` only. Never `npm` or `yarn`. |
| **Import Extensions** | ALL imports must use `.js` extension (ESM). e.g. `import { foo } from './bar.js'` |
| **Caveman Mode** | Always active. Full intensity. No filler. Terse technical output. |
| **Subagents** | Main agent launches 5+ subagents at all times. Subagents do NOT launch their own subagents. |
| **DEVLOG.md** | Every subagent MUST append a timestamped entry to `DEVLOG.md` before finishing. Do NOT read DEVLOG, only append. |
| **Python** | Use `uv pip` instead of `pip`. |
| **Test Command** | `pnpm test` (runs `vitest run`). |
| **Dev Server** | `pnpm dev` (runs `vite src`). |
| **Git on Windows** | Escape commit messages properly for PowerShell. |
| **Killing Subagents** | Kill subagents when they finish their task. Keep 5 active. |

---

## Roadmap — Session 19

### 🔴 IMMEDIATE (Do First)

| Priority | Task | Details |
|----------|------|---------|
| **P0** | **Commit Session 18** | `git add -A && git commit -m "Session 18: AI bridge, symbolic executor, ARM32/Thumb, RISC-V C ext, Mach-O fat, plugin v2, GDB integration, DEX debug, PE optimization"` |
| **P0** | **Fix ELF PLT/GOT bugs** | Fix 2 failing tests in [elf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/elf.test.ts) — PLT symbol resolution and AArch64 adrp/ldr pattern. |
| **P1** | **ESLint cleanup (remaining)** | 28 warnings remain in `src/parser/`. Clean up remaining `any` types and unused vars. |

### 🟡 HIGH PRIORITY

| Task | Details | Status |
|------|---------|--------|
| **WASM Component Model** | Extend [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/wasm.ts) with Component Model parsing | NOT STARTED |
| **ARM64 NEON/SIMD** | Add NEON vector instruction decoding to [arm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm.ts) | NOT STARTED |
| **UI ESLint Cleanup** | Clean up ESLint warnings in `src/ui/` (likely 50+) | NOT STARTED |
| **Java Class Debug Info** | Parse `LineNumberTable` and `LocalVariableTable` in [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts) | NOT STARTED |

### 🟢 STRETCH GOALS

| Task | Details | Status |
|------|---------|--------|
| **RISC-V M/A extensions** | Multiply/Atomic instructions in [riscv.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/riscv.ts) | NOT STARTED |
| **Symbolic path exploration** | Multi-path symbolic execution with constraint solving | NOT STARTED |
| **PE Authenticode verification** | Verify PE digital signatures | NOT STARTED |
| **DWARF v5 .debug_loclists** | Location list parsing in [dwarfParser.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dwarfParser.ts) | NOT STARTED |
| **Coverage report** | Generate and publish HTML coverage report | NOT STARTED |

### 🔵 HIT QUOTA — NOT STARTED (Carry Forward)

These tasks were planned for Session 18 but hit API quota limits:

| Task | Target File |
|------|-------------|
| **ELF PLT/GOT full resolution** | [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts) |
| **WASM Component Model** | [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/wasm.ts) |
| **ARM64 NEON/SIMD instructions** | [arm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm.ts) |
| **UI ESLint full cleanup** | `src/ui/*.ts` |
| **Java .class debug info** | [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts) |

---

## SESSION 19 AGENT: START CODING IMMEDIATELY

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  1. ACTIVATE CAVEMAN MODE (full intensity)          │
│  2. LAUNCH 5 SUBAGENTS IMMEDIATELY                  │
│  3. DO NOT DO ANYTHING YOURSELF                     │
│  4. SUBAGENTS: NO SUBAGENTS OF THEIR OWN            │
│  5. EVERY SUBAGENT APPENDS TO DEVLOG.md             │
│  6. USE pnpm NOT npm                                │
│  7. ALL IMPORTS USE .js EXTENSION                   │
│  8. KILL SUBAGENTS WHEN DONE, LAUNCH NEW ONES       │
│  9. ALWAYS KEEP 5 SUBAGENTS ACTIVE                  │
│  10. IF YOU THINK YOU'RE DONE, YOU'RE NOT            │
│                                                     │
└─────────────────────────────────────────────────────┘

SUGGESTED FIRST 5 SUBAGENTS:
  Agent 1: git add -A && git commit Session 18
  Agent 2: Fix ELF PLT/GOT 2 failing tests
  Agent 3: WASM Component Model parsing
  Agent 4: ARM64 NEON/SIMD instruction decoding
  Agent 5: ESLint cleanup (remaining src/parser + src/ui)

GO GO GO. NO PLANNING. START CODING.
```
