# 🔬 DISSECT — Universal Reverse Engineering Tool
## Handoff Document — Session 15 → Session 16

> **Date**: 2026-05-30 20:27 AEST
> **Git HEAD**: `ceec88c` — "Session 14: feature expansion + bug fixes" (Session 15 commit pending)
> **Test Status**: ✅ **669 passed / 0 failed** (53 test files, 669 tests)
> **Project Root**: `C:\Users\NaThA\hacks\antigravity_things\agy\test`

---

## ⚡ Quick Start

```bash
pnpm install          # Install dependencies
pnpm test             # Run all 669 tests (Vitest)
pnpm dev              # Start Vite dev server
pnpm build            # Production build
```

---

## 🚨 PRIORITY 1 — BINARY LOADING OPTIMIZER + LOADING SCREEN

> [!CAUTION]
> **USER BUG REPORT**: Binary uploads use MASSIVE memory and CRASH the browser. This is the #1 user-reported issue. Must be fixed BEFORE anything else in Session 16.

### What's needed:
1. **Loading screen UI** — progress bar, chunk counter, cancel button
2. **Chunked/streaming binary loading** — don't read entire file into memory at once
3. **Web Worker offload** — parse binary in background thread so UI doesn't freeze
4. **Memory management** — release ArrayBuffer chunks after processing, use TypedArray views not copies
5. **Files to modify**: `src/ui/binaryLoader.ts`, `src/analyzer/binaryProcessor.ts`, `src/main.ts`
6. **Add new file**: `src/ui/loadingScreen.ts`

**START HERE. DO THIS FIRST. LAUNCH 5 SUBAGENTS IMMEDIATELY.**

---

## 📋 Session 15 Summary (What Got Done)

### 16 Tasks Completed:

| # | Task | Files Touched |
|---|------|---------------|
| 1 | **Technical debt cleanup** — verified no dangling imports, build passes clean | All `src/` |
| 2 | **Capstone disassembler** — full x86/ARM64/MIPS instruction decoding with operand parsing | `src/disassembler/capstoneWasm.ts` |
| 3 | **IR bug fixes** — BigInt coercion, division semantics, PHI node liveness, spill loads/stores | `src/disassembler/ir.ts`, `optimizer.ts`, `registerAllocator.ts` |
| 4 | **On-device LLM fix** — `totalTokens` bug fixed, test passes | `src/analyzer/aiOnDevice.ts` |
| 5 | **Parser type safety** — `wasm.ts` and `macho.ts` any types replaced, bounds checking added | `src/parser/wasm.ts`, `src/parser/macho.ts` |
| 6 | **Router.ts split** — arch-specific decoders extracted to separate files | `src/disassembler/router.ts`, `x86.ts`, `arm.ts`, `riscv.ts` |
| 7 | **panelCoordinator.ts split** — event bus and registry extracted | `src/ui/panelCoordinator.ts` → `panelRegistry.ts` + `panelEvents.ts` |
| 8 | **typeSystemPanel.ts split** — renderers and editors extracted | `src/ui/typeSystemPanel.ts` → `typeRenderers.ts` + `typeEditors.ts` |
| 9 | **decompiler.ts split** — AST nodes and printer extracted | `src/disassembler/decompiler.ts` → `ast.ts` + `astPrinter.ts` |
| 10 | **ir.ts split** — optimizer and register allocator extracted | `src/disassembler/ir.ts` → `optimizer.ts` + `registerAllocator.ts` |
| 11 | **RISC-V instruction support** — added to router | `src/disassembler/riscv.ts`, `router.ts` |
| 12 | **MIPS instruction decoder** — new file | `src/disassembler/mips.ts` |
| 13 | **PowerPC instruction decoder** — new file | `src/disassembler/ppc.ts` |
| 14 | **ELF PLT/GOT resolution** — dynamic linking support | `src/parser/elf.ts` |
| 15 | **PE TLS callback parsing** — thread local storage | `src/parser/pe.ts` |
| 16 | **Mach-O chained fixups** — `LC_DYLD_CHAINED_FIXUPS` parsing | `src/parser/macho.ts` |

### Tests grew from 655 → 669 (all passing)

---

## 🏗️ Full Architecture — ALL Files

### `src/` Root
| File | Size | Purpose |
|------|------|---------|
| `main.ts` | 12.5 KB | App coordinator, panel wiring, binary load orchestration |
| `styles.css` | 12 KB | Global CSS, dark theme, panel layouts |
| `index.html` | 428 B | Entry HTML |

### `src/parser/` — Binary Format Parsers (12 files)
| File | Size | Purpose |
|------|------|---------|
| `elf.ts` | 23 KB | ELF parser (sections, segments, symbols, dynamic, PLT/GOT resolution) |
| `pe.ts` | 28 KB | PE/PE32+ parser (headers, sections, imports/exports, resources, TLS callbacks) |
| `macho.ts` | 26 KB | Mach-O parser (load commands, segments, chained fixups) |
| `wasm.ts` | 26 KB | WebAssembly parser (sections, types, functions, name section) |
| `dex.ts` | 16 KB | Android DEX parser |
| `javaClass.ts` | 15 KB | Java .class parser |
| `dotnetMetadata.ts` | 27 KB | .NET metadata/CLR parser |
| `debugSymbols.ts` | 35 KB | DWARF v4 debug info parser |
| `machoSignature.ts` | 17 KB | Mach-O code signing parser |
| `machoObjc.ts` | 19 KB | Mach-O Objective-C metadata parser |
| `archive.ts` | 10 KB | Archive format parser (ZIP, TAR, etc.) |

### `src/disassembler/` — Disassembly & Decompilation (19 files)
| File | Size | Purpose |
|------|------|---------|
| `router.ts` | 8.8 KB | Disassembler router — dispatches to arch-specific decoders |
| `x86.ts` | 33 KB | x86/x86_64 instruction decoder (SSE/AVX/BMI) |
| `arm.ts` | 20 KB | ARM64/AArch64 instruction decoder |
| `riscv.ts` | 7.8 KB | **NEW** — RISC-V instruction decoder |
| `mips.ts` | 6.9 KB | **NEW** — MIPS instruction decoder |
| `ppc.ts` | 5.8 KB | **NEW** — PowerPC instruction decoder |
| `dalvik.ts` | 7.4 KB | Dalvik bytecode decoder |
| `wasm.ts` | 9 KB | WebAssembly disassembler |
| `capstoneWasm.ts` | 25 KB | Capstone WASM engine (real instruction decoding) |
| `cfg.ts` | 8.5 KB | Control flow graph builder |
| `decompiler.ts` | 36 KB | Decompiler (SSA → C-like AST output) |
| `ast.ts` | 2.2 KB | **NEW** — AST node type definitions (extracted from decompiler) |
| `astPrinter.ts` | 3.9 KB | **NEW** — AST pretty printer (extracted from decompiler) |
| `ir.ts` | 13 KB | SSA IR builder (PHI nodes, basic blocks) |
| `optimizer.ts` | 34 KB | **NEW** — Constant propagation, DCE, LICM (extracted from ir.ts) |
| `registerAllocator.ts` | 9.9 KB | **NEW** — Graph coloring register allocator (extracted from ir.ts) |
| `types.ts` | 4.4 KB | Shared disassembler type definitions |
| `helpers.ts` | 641 B | Utility helpers |

### `src/analyzer/` — Analysis Engines (19 files)
| File | Size | Purpose |
|------|------|---------|
| `binaryProcessor.ts` | 30 KB | Binary processing pipeline — format detection, high-level parse |
| `ai.ts` | 22 KB | AI analysis panel backend (cloud LLM) |
| `aiOnDevice.ts` | 25 KB | On-device LLM inference (WebGPU/WASM) |
| `plugins.ts` | 26 KB | Plugin system — load/unload/config/execute |
| `reportGenerator.ts` | 33 KB | Report generation engine |
| `yara.ts` | 14 KB | YARA rule engine |
| `frida.ts` | 15 KB | Frida integration |
| `demangler.ts` | 13 KB | C++/Rust/Swift symbol demangler |
| `vulnScanner.ts` | 12 KB | Vulnerability scanner |
| `xrefs.ts` | 11 KB | Cross-reference analysis |
| `diff.ts` | 9.5 KB | Binary diff engine |
| `search.ts` | 8.7 KB | Search engine (hex, string, regex, symbol) |
| `strings.ts` | 8.7 KB | String extraction |
| `signatures.ts` | 8.2 KB | Signature matching |
| `scripting.ts` | 8 KB | Scripting engine |
| `hashes.ts` | 7.7 KB | Hash computation |
| `patcher.ts` | 6.5 KB | Binary patching engine |
| `entropy.ts` | 4.1 KB | Entropy analysis |
| `fcg.ts` | 4.7 KB | Function call graph |

### `src/ui/` — UI Panels (35 files)
| File | Size | Purpose |
|------|------|---------|
| `panelCoordinator.ts` | 43 KB | Master panel coordinator — lifecycle, routing |
| `panelRegistry.ts` | 267 B | **NEW** — Panel type registry (extracted) |
| `panelEvents.ts` | 6.1 KB | **NEW** — Panel event bus (extracted) |
| `assemblyView.ts` | 39 KB | Assembly listing view |
| `cfgVisualizer.ts` | 33 KB | CFG graph visualizer |
| `collabPanel.ts` | 35 KB | Real-time collaboration panel |
| `reportPanel.ts` | 32 KB | Report panel |
| `searchPanel.ts` | 31 KB | Search panel |
| `dependencyGraph.ts` | 31 KB | Dependency graph panel |
| `metadataPanel.ts` | 37 KB | Binary metadata panel |
| `machoObjcPanel.ts` | 28 KB | Mach-O ObjC inspector panel |
| `pluginsPanel.ts` | 28 KB | Plugin marketplace panel |
| `diffPanel.ts` | 27 KB | Binary diff panel |
| `entropyGraph.ts` | 26 KB | Entropy visualization |
| `memoryMap.ts` | 23 KB | Memory map panel |
| `yaraPanel.ts` | 22 KB | YARA rules panel |
| `fcgVisualizer.ts` | 22 KB | Function call graph visualizer |
| `demanglerPanel.ts` | 20 KB | Demangler panel |
| `xrefsPanel.ts` | 20 KB | Cross-references panel |
| `typeRenderers.ts` | 20 KB | **NEW** — Type system renderers (extracted) |
| `stringsView.ts` | 21 KB | Strings view panel |
| `signaturePanel.ts` | 20 KB | Signature panel |
| `gdbPanel.ts` | 19 KB | GDB remote debugger panel |
| `patcherPanel.ts` | 18 KB | Binary patcher panel |
| `importsExportsPanel.ts` | 18 KB | Imports/Exports panel |
| `aiPanel.ts` | 17 KB | AI chat panel |
| `emulatorPanel.ts` | 18 KB | CPU emulator panel |
| `typeSystemPanel.ts` | 14 KB | Type system panel (coordinator) |
| `typeEditors.ts` | 13 KB | **NEW** — Type editor components (extracted) |
| `layout.ts` | 14 KB | Layout manager |
| `hexViewer.ts` | 13 KB | Hex viewer |
| `binaryLoader.ts` | 11 KB | Binary file loader UI |
| `scriptingConsole.ts` | 12 KB | Scripting console |
| `tabManager.ts` | 2.3 KB | Tab management |

### `src/emulator/` — CPU Emulation (5 files)
| File | Size | Purpose |
|------|------|---------|
| `emulator.ts` | 18 KB | Emulator core — CPU loop, breakpoints |
| `cpu.ts` | 6 KB | CPU state (registers, flags) |
| `memory.ts` | 6.9 KB | Virtual memory manager |
| `syscall.ts` | 15 KB | Syscall emulation (Linux + Windows) |
| `gdbProtocol.ts` | 11 KB | GDB Remote Serial Protocol |

### `src/network/` — Networking (1 file)
| File | Size | Purpose |
|------|------|---------|
| `collab.ts` | 32 KB | Real-time collaboration (WebSocket, Yjs, CRDT) |

### `src/coverage/` — Istanbul Coverage Reports
Auto-generated coverage output.

---

## 🧪 Test Suite — 53 Files, 669 Tests

All passing. Key test files and counts:

| Test File | Tests | Area |
|-----------|-------|------|
| `pe.test.ts` | 17 | PE parser |
| `elf.test.ts` | 16 | ELF parser |
| `ir.test.ts` | 18 | SSA IR + optimization |
| `diff.test.ts` | 42 | Binary diff |
| `vulnScanner.test.ts` | 44 | Vulnerability scanning |
| `router.test.ts` | ~40 | Instruction routing (all arches) |
| `machoSignature.test.ts` | 24 | Mach-O signatures |
| `syscall.test.ts` | 20 | Syscall emulation |
| `gdbProtocol.test.ts` | 21 | GDB RSP |
| `e2e.test.ts` | 12 | End-to-end UI integration |
| `capstoneWasm.test.ts` | 10 | Capstone WASM engine |
| `decompiler.test.ts` | 12 | Decompiler |
| `collab.test.ts` | 14 | Collaboration |
| Other 40 files | ~379 | Everything else |

### Known stderr noise (NOT failures):
- `binaryProcessor.test.ts` emits `"High-level parsing failed or incomplete"` on mock PE/WASM — expected fallback behavior
- `machoObjcPanel.test.ts` emits `"Not implemented: Window's alert()"` — jsdom limitation

---

## 🐛 Known Bugs / Issues

1. **Binary loading memory crash** — PRIORITY 1 (see top of document)
2. `panelRegistry.ts` is only 267 bytes — minimal stub, may need expansion
3. `binaryProcessor.ts` stderr noise on malformed inputs — cosmetic, not a bug
4. Coverage report is from a previous session — may be stale

---

## ❌ Quota-Exhausted / NOT Completed (Session 15)

These tasks were planned but **NOT started or NOT finished** due to API quota exhaustion:

| # | Task | Priority | Estimated Effort |
|---|------|----------|------------------|
| 1 | **Binary loading optimizer + loading screen** | 🔴 CRITICAL (user bug) | ~2 hours |
| 2 | **DWARF v5 support** | 🟡 Medium | ~1 hour |
| 3 | **Wasm component model parsing** | 🟡 Medium | ~1 hour |
| 4 | **Plugin marketplace UI** | 🟢 Low | ~1.5 hours |
| 5 | **Collaborative cursors** | 🟢 Low | ~1 hour |
| 6 | **DEVLOG.md PowerPC entry** | 🟢 Low | ~5 min |

---

## 🗺️ Roadmap — What To Do Next (Session 16)

### IMMEDIATE (do first, in this order):
1. **🔴 Binary loading optimizer + loading screen** — chunked streaming, Web Worker, progress UI
2. **DEVLOG.md PPC entry** — quick 5 min fix, just add the entry
3. **DWARF v5 support** — extend `debugSymbols.ts` with v5 line number program, split DWARF

### NEXT (after immediate):
4. **Wasm component model** — extend `parser/wasm.ts` with component model sections
5. **Plugin marketplace UI** — remote plugin discovery, install/update UI in `pluginsPanel.ts`
6. **Collaborative cursors** — real-time cursor position sync in `collabPanel.ts`

### STRETCH (if time permits):
7. **COFF/XCOFF parser** — new file `src/parser/coff.ts`
8. **SPARC instruction decoder** — new file `src/disassembler/sparc.ts`
9. **Differential debugging** — compare emulator traces side-by-side
10. **Binary patching undo/redo** — transaction log in `patcher.ts`
11. **Performance profiling** — bundle size audit, lazy loading panels

---

## ⚙️ Operational Rules — READ THESE

### Package Manager
- **USE `pnpm`** — NOT npm, NOT yarn. The project uses `pnpm-workspace.yaml`.
- `pnpm install`, `pnpm test`, `pnpm dev`, `pnpm build`

### Import Style
- **ALL imports MUST use `.js` extension** — even for `.ts` files
- Example: `import { foo } from './bar.js'` NOT `import { foo } from './bar'`
- This is required for Vite/ESM resolution

### TypeScript
- `tsconfig.json` has `strict: true`
- NO `any` types allowed — use proper types or `unknown` with narrowing
- All `.ts` files compile with `tsc --noEmit`

### Testing
- Framework: **Vitest** with jsdom environment
- Tests in `/tests/*.test.ts`
- Run: `pnpm test`
- Run single: `pnpm vitest run tests/specific.test.ts`

### Git
- Commit after every major milestone
- Format: `"Session N: description"`

### Build
- Vite bundler
- Target: keep main chunk under 350KB
- `vite.config.ts` in project root

### Caveman Skill
- **ACTIVATE CAVEMAN FULL SKILL** — terse, high-density technical output
- No fluff, no verbose explanations, just code and results

### Subagents
- **ALWAYS LAUNCH AT LEAST 5 SUBAGENTS** running in parallel
- Never do work yourself — delegate to subagents
- Kill subagents when they finish, launch new ones
- **SUBAGENTS MUST NOT LAUNCH THEIR OWN SUBAGENTS**
- Tell subagents to activate caveman mode
- Use `pnpm` not `npm`
- Use `uv pip` not `pip`

### DEVLOG.md
- **ONLY APPEND** to DEVLOG.md — never read it, never overwrite
- Add timestamped entries with file links
- Subagents must add to DEVLOG before finishing

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| Total source files | ~92 |
| Total test files | 53 |
| Total tests | 669 |
| Test pass rate | 100% |
| Git commits | ~20 |
| Project size (src/) | ~1.5 MB |
| Supported binary formats | ELF, PE, Mach-O, WASM, DEX, Java .class, .NET, Archives |
| Supported architectures | x86/x64, ARM64, RISC-V, MIPS, PowerPC, Dalvik, WASM |
| UI panels | 35 |
| Analysis engines | 19 |

---

## 🔥 SESSION 16 AGENT: START CODING IMMEDIATELY

> [!IMPORTANT]
> 1. Read this handoff document
> 2. Run `pnpm test` to verify 669 tests pass
> 3. **LAUNCH 5 SUBAGENTS IMMEDIATELY**
> 4. Subagent 1-2: Binary loading optimizer + loading screen (PRIORITY 1)
> 5. Subagent 3: DWARF v5 support
> 6. Subagent 4: DEVLOG.md PPC entry + Wasm component model
> 7. Subagent 5: Plugin marketplace UI
> 8. **DO NOT WASTE TIME READING CODE** — the architecture table above has everything
> 9. **ACTIVATE CAVEMAN FULL SKILL**
> 10. **ALWAYS HAVE 5+ SUBAGENTS RUNNING**

**GO GO GO. SHIP CODE. 🚀**
