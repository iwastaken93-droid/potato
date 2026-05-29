# 🔬 DISSECT — Universal Reverse Engineering Tool: Comprehensive Handoff

> **Last Updated:** 2026-05-29 21:43 AEST (Session 12 close-out)
> **Project Root:** `C:\Users\NaThA\hacks\antigravity_things\agy\test`
> **Long-Term Goal:** 1,000,000+ lines of code — a fully-featured universal RE workbench
> **Current Size:** ~1.54 MB of TypeScript source across 83 source files + 50 test files (~563 KB tests)

---

## 🚨🚨🚨 NEXT SESSION (Session 13): START BUILDING IMMEDIATELY 🚨🚨🚨

# ⚡ LAUNCH 5 SUBAGENTS RIGHT NOW ⚡

> [!CAUTION]
> **DO NOT READ THIS ENTIRE DOCUMENT BEFORE STARTING. Skim the roadmap section, then START CODING. You can reference this document as you go. Every second counts.**

1. **ALL 612 TESTS ARE PASSING** — the codebase is GREEN. No test fixes needed.
2. **Launch 5 subagents IMMEDIATELY** to work in parallel on Priority 0 tasks
3. **Always run `pnpm test` after changes** and update DEVLOG.md
4. **DO NOT WAIT. DO NOT PLAN. DO NOT OVERTHINK. START CODING NOW.**
5. **TELL ALL SUBAGENTS: DO NOT LAUNCH THEIR OWN SUBAGENTS**
6. **Always use `pnpm`, NEVER `npm`**
7. **Always use `.js` extensions in TypeScript imports** (NodeNext module resolution)
8. **`git add -A && git commit` regularly** — don't lose work

---

## 1. 📊 Current Project Status (Session 12 Close-Out)

### Test Results (as of 2026-05-29 21:43 AEST)

```
 Test Files  50 passed (50)
      Tests  612 passed (612)
   Duration  ~43s
```

### ✅ ALL TESTS PASSING — 0 FAILURES

### Git Log (Last 20 Commits)

```
e339d21 feat: session 11 - fix all 4 failing tests, GDB panel, Mach-O signature/ObjC tests, decompiler AST, WASM name parser, E2E expansion, 604/604 tests passing
0f3aafd docs: reduce subagent count from 10 to 5 in handoff
4ecfe14 docs: session 10 final devlog close-out entry
1f4b0b8 docs: session 10 handoff document
4244d0b feat: session 10 - resolve freeze issues, optimize main.ts loops, implement virtual scrolling, add Java/debugSymbols parsers and tests
24a344e feat: session 9 - fix diff/ir tests, plugin system, E2E tests, instruction expansion, code audits
1098907 feat: session 8 - fix capstone/syscall/cfg tests, add IR/SSA framework, expand diff/vuln/hash tests
3ce12ed feat: session 6 - fix AI tests, add patcher/fcg/scripting/entropy tests, wire panels, roadmap proposals, partial new features
1714917 docs: comprehensive handoff document for session continuity
f10bcc5 feat: integrate emulator and emulator panel UI into main.ts, fix self-jump pc advancement bug
bdaf3bd feat: implement report panel, emulator core, and virtual memory systems with full test suite verification
b556635 docs: rewrite devlog with chronological session 1 summary
103538f chore: finalize gitignore, package.json, and lockfile
b21fbe6 feat: final code typecheck fixes and application coordinator integration
5699f2f chore: add ESLint configuration for typescript linting
f0acd25 docs: update final devlog entries
7e30f14 chore: fix dev script to launch vite
f57c580 feat: complete initial reverse engineering core setup, tests, and configuration
d6f75cd chore: setup vitest testing configuration and ci workflows
3ec7053 test: add test suites for ELF, PE, WASM parsers and Decompiler
c7a9f9e feat: initial project structure, parsers, and UI skeleton
```

> [!IMPORTANT]
> **Session 12 changes are NOT YET COMMITTED.** The handoff commit will be the Session 12 commit. See `git diff --stat HEAD` below for what changed.

### Uncommitted Changes (Session 12 Diff)

```
 DEVLOG.md                       |   28 +
 src/analyzer/binaryProcessor.ts |  498 ++++++++++     (NEW — extracted from main.ts)
 src/disassembler/ir.ts          |  252 +++++      (LICM optimization pass added)
 src/disassembler/router.ts      |  255 ++++-      (instruction expansion)
 src/main.ts                     | 1972 ++-----   (decomposed from 72KB → 11.6KB)
 src/ui/layout.ts                |  358 +++++++     (NEW — extracted from main.ts)
 src/ui/panelCoordinator.ts      | 1112 ++++++++++ (NEW — extracted from main.ts)
 src/ui/diffPanel.ts             |    2 +-
 src/ui/gdbPanel.ts              |    2 +-
 src/ui/metadataPanel.ts         |   10 +-
 src/ui/searchPanel.ts           |    2 +-
 src/ui/typeSystemPanel.ts       |    4 +-
 src/analyzer/demangler.ts       |    2 +-
 src/parser/machoSignature.ts    |    2 +-
 tests/e2e.test.ts               |    1 +
 19 files changed, 3008 insertions(+), 2471 deletions(-)
```

---

## 2. 🛠️ What Was Done in Session 12

Session 12 was a **major architecture refactoring + optimization session**. The monolithic 72KB `main.ts` was fully decomposed and an IR/SSA LICM optimization pass was added.

### ✅ main.ts Decomposition (Priority 0 — COMPLETED)

The `main.ts` monolith (72.2 KB, ~2000 lines) was decomposed into **4 focused modules**:

| Extracted Module | File | Size | Purpose |
|------------------|------|------|---------|
| **PanelCoordinator** | [panelCoordinator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelCoordinator.ts) | 39.3 KB (1113 lines) | All UI panel management, lazy loading, event listeners, panel initialization |
| **Layout** | [layout.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/layout.ts) | 13.8 KB (359 lines) | CSS injection, structural HTML generation, layout initialization |
| **BinaryProcessor** | [binaryProcessor.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/binaryProcessor.ts) | 14.8 KB (499 lines) | Binary parsing, disassembly routing, dependency computation |
| **main.ts (slim)** | [main.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/main.ts) | **11.6 KB** (319 lines) | Thin coordinator delegating to extracted modules |

**Result:** main.ts reduced from **72.2 KB → 11.6 KB** (84% reduction, well below the 30KB target).

Backward compatibility was preserved — `ApplicationCoordinator` class still exports getter/method compatibility layers for existing tests. All 612 tests pass.

### ✅ IR/SSA LICM Optimization Pass (Priority 1 — COMPLETED)

Added **Loop Invariant Code Motion (LICM)** to the `IROptimizer` class in [ir.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ir.ts) (grew from 23.6 KB → 31.7 KB):

- **Dominators computation** — iterative data-flow analysis
- **Natural loop detection** — back-edge identification in CFG
- **Invariant expression detection** — recursive check for constants/values defined outside loop body
- **Instruction hoisting** — moves invariant instructions to newly created loop pre-header blocks
- **CFG update** — dynamically patches predecessors and jump targets

Comprehensive tests added in [ir.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/ir.test.ts) — all 14 IR tests pass.

### ✅ Instruction Table Expansion

[router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) expanded from 66.4 KB → **78.4 KB** with additional x86 opcodes and instruction patterns.

### ✅ Minor Fixes

- Fixed import typos in `diffPanel.ts`, `gdbPanel.ts`, `searchPanel.ts`, `typeSystemPanel.ts`
- Fixed metadata rendering in `metadataPanel.ts`
- Reverted unrelated syntax changes in test files to maintain consistency

### Session 12 Summary

- **main.ts decomposed: 72.2 KB → 11.6 KB** (3 new modules extracted)
- **LICM optimization pass** added to IR/SSA framework
- **Instruction tables expanded** in disassembler router
- **Tests went from 604 → 612** (+8 new tests from router expansion)
- **Test files remain at 50**
- **0 failures, all green**

---

## 3. 📐 Full Architecture (Complete File Tree)

```
test/                                          # Project Root
├── .agents/
│   └── skills/
│       ├── Handoff/SKILL.md                   # Handoff skill instructions
│       └── start/SKILL.md                     # Start skill instructions
├── .github/
│   └── workflows/
│       └── ci.yml                             # GitHub Actions CI pipeline
├── src/                                        # ~1.54 MB total source (83 files)
│   ├── index.html                (428 B)      # Vite entry HTML (loads main.ts)
│   ├── main.ts                   (11.6 KB)    # ApplicationCoordinator — thin delegator [DECOMPOSED S12]
│   ├── styles.css                (12.1 KB)    # Premium dark glassmorphic CSS design system
│   │
│   ├── parser/                                # Binary format parsers (12 files, ~208 KB)
│   │   ├── elf.ts                (10.4 KB)    # ELF parser — 32/64-bit, LE/BE, section/program headers
│   │   ├── pe.ts                 (25.6 KB)    # PE/PE32+ parser — DOS, COFF, imports/exports, resources
│   │   ├── wasm.ts               (25.8 KB)    # WebAssembly parser — LEB128, full name section
│   │   ├── macho.ts              (17.3 KB)    # Mach-O parser — fat/universal, 32/64-bit, segments, symbols
│   │   ├── dex.ts                (15.6 KB)    # DEX parser — MUTF-8, classes, methods, try/catch, LEB128
│   │   ├── javaClass.ts          (14.8 KB)    # Java class file parser — 0xCAFEBABE, constant pool, bytecode
│   │   ├── debugSymbols.ts       (24.5 KB)    # DWARF + PDB debug symbols parser
│   │   ├── dotnetMetadata.ts     (27.3 KB)    # .NET ECMA-335 metadata parser
│   │   ├── archive.ts            (10.3 KB)    # ZIP/APK/JAR/IPA archive unpacker
│   │   ├── machoObjc.ts          (18.8 KB)    # Mach-O Objective-C metadata parser
│   │   └── machoSignature.ts     (17.5 KB)    # Mach-O code signature parser
│   │
│   ├── disassembler/                          # Disassembly & decompilation engine (7 files, ~190 KB)
│   │   ├── types.ts              (4.4 KB)     # Core types — Instruction, Section, Symbol, Operand
│   │   ├── router.ts             (78.4 KB)    # DisassemblerRouter — auto-detect, x86/ARM/WASM/Dalvik + Capstone [EXPANDED S12]
│   │   ├── cfg.ts                (8.5 KB)     # CFG builder — basic block splitting, leader detection, edges
│   │   ├── decompiler.ts         (41.7 KB)    # Pseudo-C decompiler — CHK dominators, structured AST, visitor
│   │   ├── capstoneWasm.ts       (4.2 KB)     # Capstone WASM integration — x86/ARM disassembly
│   │   └── ir.ts                 (31.7 KB)    # IR/SSA framework — algebraic simp, PHI simp, LICM [EXPANDED S12]
│   │
│   ├── analyzer/                              # Analysis engines (19 files, ~210 KB)
│   │   ├── entropy.ts            (4.1 KB)     # Shannon entropy — sliding window, high-entropy blocks
│   │   ├── strings.ts            (8.4 KB)     # String extractor — ASCII/Unicode, URL/filepath/API tags
│   │   ├── search.ts             (8.7 KB)     # Pattern search — text, hex wildcard, instruction matching
│   │   ├── signatures.ts         (8.2 KB)     # Signature scanner — compiler/packer/crypto detection rules
│   │   ├── reportGenerator.ts    (8.6 KB)     # Report generator — JSON/Markdown export
│   │   ├── xrefs.ts              (10.8 KB)    # Cross-references — CALL/JUMP/DATA xref tracking
│   │   ├── yara.ts               (12.4 KB)    # YARA engine — rule parsing, hex/text matching, conditions
│   │   ├── ai.ts                 (22.3 KB)    # AI explanation engine — pattern-based code analysis
│   │   ├── aiOnDevice.ts         (19.2 KB)    # On-device LLM via ONNX/WebNN/WebGPU
│   │   ├── patcher.ts            (6.5 KB)     # Binary patcher — patch tracking, undo/redo, export
│   │   ├── fcg.ts                (4.7 KB)     # Function Call Graph builder — call relationship maps
│   │   ├── scripting.ts          (8.1 KB)     # Scripting engine — JS-based scripting console context
│   │   ├── demangler.ts          (12.8 KB)    # Symbol demangler — C++/Rust/Swift name demangling
│   │   ├── diff.ts               (9.5 KB)     # Binary diff engine — side-by-side comparison
│   │   ├── hashes.ts             (7.7 KB)     # Hash calculator — MD5/SHA-1/SHA-256/CRC32
│   │   ├── vulnScanner.ts        (11.5 KB)    # Vulnerability scanner — unsafe API detection
│   │   ├── plugins.ts            (25.7 KB)    # Plugin architecture — discovery, config, lifecycle hooks
│   │   ├── frida.ts              (14.7 KB)    # Frida DBI scripting helper
│   │   └── binaryProcessor.ts    (14.8 KB)    # Binary parsing/disassembly orchestrator [NEW S12]
│   │
│   ├── emulator/                              # x86_64 emulator (5 files, ~49 KB)
│   │   ├── cpu.ts                (6.0 KB)     # CPU state machine — RAX-R15, RIP, RFLAGS, sub-register aliases
│   │   ├── memory.ts             (6.9 KB)     # Virtual memory — page-based, permission checks, section loading
│   │   ├── emulator.ts           (17.9 KB)    # Instruction executor — MOV/ADD/SUB/PUSH/POP/CALL/RET/JMP/etc.
│   │   ├── syscall.ts            (8.2 KB)     # Syscall emulation — Linux syscalls + Windows API stubs
│   │   └── gdbProtocol.ts        (10.5 KB)    # GDB/LLDB RSP protocol handler
│   │
│   ├── network/                               # Networking / collaboration (1 file, ~22 KB)
│   │   └── collab.ts             (22.4 KB)    # Collaborative sync — mock WebRTC/WebSocket, CRDT
│   │
│   └── ui/                                    # Premium UI components (35 files, ~710 KB)
│       ├── hexViewer.ts          (12.7 KB)    # Interactive hex viewer — virtual scrolling
│       ├── assemblyView.ts       (38.8 KB)    # Assembly listing — virtual scrolling
│       ├── cfgVisualizer.ts      (32.8 KB)    # SVG CFG graph — zoom/pan, coverage overlay
│       ├── dependencyGraph.ts    (30.7 KB)    # Import/export dep graph — force-directed canvas renderer
│       ├── dependencyGraphView.ts (11.3 KB)   # Dep graph wrapper — container integration
│       ├── memoryMap.ts          (23.2 KB)    # Memory map overlay — entropy heatmaps, section coloring
│       ├── memoryMapView.ts      (8.2 KB)     # Memory map wrapper
│       ├── stringsView.ts        (19.9 KB)    # Strings viewer — virtual scrolling
│       ├── searchPanel.ts        (31.1 KB)    # Search panel — text/hex/instruction modes
│       ├── searchView.ts         (10.1 KB)    # Search wrapper
│       ├── signaturePanel.ts     (20.1 KB)    # Signature scan panel — grouped results by category
│       ├── reportPanel.ts        (33.6 KB)    # Report panel — JSON/MD download, clipboard, preview
│       ├── emulatorPanel.ts      (17.7 KB)    # Emulator panel — step controls, registers, stack, memory
│       ├── xrefsPanel.ts         (20.4 KB)    # Cross-refs panel — incoming/outgoing xrefs
│       ├── importsExportsPanel.ts (17.9 KB)   # Import/export table — sub-tabs, search, navigation
│       ├── aiPanel.ts            (17.3 KB)    # AI explanation panel — code analysis UI
│       ├── collabPanel.ts        (28.5 KB)    # Collaboration panel — peer list, comments, highlights
│       ├── patcherPanel.ts       (17.7 KB)    # Binary patcher panel — hex editing, patch history
│       ├── yaraPanel.ts          (21.8 KB)    # YARA rules panel — rule editor, scan results
│       ├── entropyGraph.ts       (25.5 KB)    # Entropy visualization — canvas graph
│       ├── fcgVisualizer.ts      (21.7 KB)    # FCG visualizer — destroy() for cleanup
│       ├── scriptingConsole.ts   (11.8 KB)    # Scripting console — JS REPL UI
│       ├── demanglerPanel.ts     (20.4 KB)    # Symbol demangler panel
│       ├── diffPanel.ts          (27.3 KB)    # Binary diff panel — side-by-side comparison
│       ├── metadataPanel.ts      (36.8 KB)    # Metadata panel — file info, hashes, PE resources
│       ├── typeSystemPanel.ts    (35.8 KB)    # Type system panel — struct viewer, C parser
│       ├── vulnPanel.ts          (12.6 KB)    # Vulnerability scanner panel
│       ├── pluginsPanel.ts       (28.1 KB)    # Plugin management panel
│       ├── machoObjcPanel.ts     (28.4 KB)    # Mach-O ObjC panel
│       ├── gdbPanel.ts           (19.0 KB)    # GDB debugger panel
│       ├── tabManager.ts         (2.3 KB)     # Tab management module [EXTRACTED S11]
│       ├── binaryLoader.ts       (5.7 KB)     # Binary loading module [EXTRACTED S11]
│       ├── layout.ts             (13.8 KB)    # Layout/CSS injection [NEW S12]
│       └── panelCoordinator.ts   (39.3 KB)    # Panel lifecycle manager [NEW S12]
│
├── tests/                                     # Test suites (Vitest) — 50 files, 612 total tests
│   ├── ai.test.ts                (2.9 KB)     # AI explanation tests (5 tests) ✅
│   ├── aiOnDevice.test.ts        (8.0 KB)     # On-device LLM tests (15 tests) ✅
│   ├── archive.test.ts           (7.5 KB)     # Archive unpacker tests (4 tests) ✅
│   ├── binaryLoader.test.ts      (1.2 KB)     # Binary loader tests (2 tests) ✅
│   ├── capstoneWasm.test.ts      (5.5 KB)     # Capstone WASM tests (9 tests) ✅
│   ├── collab.test.ts            (7.5 KB)     # Collaboration engine tests (10 tests) ✅
│   ├── debugSymbols.test.ts      (13.3 KB)    # Debug symbols tests (11 tests) ✅
│   ├── decompiler.test.ts        (16.3 KB)    # Decompiler tests (12 tests) ✅
│   ├── demangler.test.ts         (3.5 KB)     # Demangler tests (8 tests) ✅
│   ├── dex.test.ts               (12.9 KB)    # DEX parser tests (8 tests) ✅
│   ├── diff.test.ts              (18.7 KB)    # Diff engine tests (42 tests) ✅
│   ├── dotnetMetadata.test.ts    (8.0 KB)     # .NET metadata tests (3 tests) ✅
│   ├── e2e.test.ts               (23.5 KB)    # E2E integration tests (12 tests) ✅
│   ├── elf.test.ts               (23.3 KB)    # ELF parser tests (15 tests) ✅
│   ├── emulator.test.ts          (19.9 KB)    # Emulator tests (32 tests) ✅
│   ├── entropy.test.ts           (4.9 KB)     # Entropy analyzer tests (9 tests) ✅
│   ├── entropyGraph.test.ts      (7.3 KB)     # Entropy graph UI tests (7 tests) ✅
│   ├── fcg.test.ts               (12.4 KB)    # FCG builder + visualizer tests (14 tests) ✅
│   ├── frida.test.ts             (5.8 KB)     # Frida DBI tests (11 tests) ✅
│   ├── gdbPanel.test.ts          (8.6 KB)     # GDB panel UI tests (5 tests) ✅
│   ├── gdbProtocol.test.ts       (6.8 KB)     # GDB RSP tests (16 tests) ✅
│   ├── hashes.test.ts            (3.7 KB)     # Hash computation tests (14 tests) ✅
│   ├── ir.test.ts                (31.2 KB)    # IR/SSA framework tests (14 tests) ✅ [EXPANDED S12]
│   ├── javaClass.test.ts         (15.3 KB)    # Java class parser tests (5 tests) ✅
│   ├── macho.test.ts             (9.7 KB)     # Mach-O parser tests (9 tests) ✅
│   ├── machoObjc.test.ts         (7.9 KB)     # Mach-O ObjC tests (1 test) ✅
│   ├── machoObjcPanel.test.ts    (6.0 KB)     # Mach-O ObjC panel tests (6 tests) ✅
│   ├── machoSignature.test.ts    (19.1 KB)    # Mach-O signature tests (24 tests) ✅
│   ├── memoryMap.test.ts         (9.9 KB)     # Memory map tests (9 tests) ✅
│   ├── metadata.test.ts          (4.4 KB)     # Metadata panel tests (6 tests) ✅
│   ├── patcher.test.ts           (12.3 KB)    # Patcher engine + panel tests (18 tests) ✅
│   ├── pe.test.ts                (42.0 KB)    # PE parser tests (15 tests) ✅
│   ├── peResources.test.ts       (9.4 KB)     # PE resources tests (1 test) ✅
│   ├── plugins.test.ts           (7.7 KB)     # Plugin system tests (8 tests) ✅
│   ├── report.test.ts            (9.6 KB)     # Report generator tests (15 tests) ✅
│   ├── reportPanel.test.ts       (3.5 KB)     # Report panel UI tests (5 tests) ✅
│   ├── router.test.ts            (27.2 KB)    # Disassembler router tests (41 tests) ✅
│   ├── scripting.test.ts         (12.2 KB)    # Scripting engine + console tests (22 tests) ✅
│   ├── search.test.ts            (8.6 KB)     # Pattern search tests (15 tests) ✅
│   ├── signatures.test.ts        (10.0 KB)    # Signature scanner tests (19 tests) ✅
│   ├── strings.test.ts           (6.3 KB)     # String extraction tests (8 tests) ✅
│   ├── syscall.test.ts           (13.1 KB)    # Syscall emulation tests (14 tests) ✅
│   ├── tabManager.test.ts        (2.0 KB)     # Tab manager tests (2 tests) ✅
│   ├── typeSystem.test.ts        (3.4 KB)     # Type system panel tests (4 tests) ✅
│   ├── uiPanels.test.ts          (14.6 KB)    # UI panel integration tests (15 tests) ✅
│   ├── vulnScanner.test.ts       (24.7 KB)    # Vulnerability scanner tests (44 tests) ✅
│   ├── wasm.test.ts              (14.1 KB)    # WASM parser tests (6 tests) ✅
│   ├── xrefs.test.ts             (7.9 KB)     # Cross-references tests (7 tests) ✅
│   ├── yara.test.ts              (6.2 KB)     # YARA engine tests (9 tests) ✅
│   └── yaraPanel.test.ts         (3.6 KB)     # YARA panel UI tests (6 tests) ✅
│
├── fixtures/
│   └── index.ts                  (6.9 KB)     # Mock binary test data (ELF, PE, WASM)
│
├── docs/                                      # Documentation (8 files, ~41 KB)
│   ├── README.md                 (2.9 KB)     # Table of contents, introduction, design principles
│   ├── architecture.md           (5.4 KB)     # System pipeline, Mermaid diagrams
│   ├── parsers.md                (6.4 KB)     # Binary format parser details (ELF/PE/Mach-O/DEX/WASM)
│   ├── disassembler_router.md    (5.7 KB)     # Routing logic, block splitting, CFG, decompiler
│   ├── emulator.md               (6.7 KB)     # Register structures, virtual memory, instruction loop
│   ├── analyzers.md              (4.4 KB)     # Entropy, signatures, strings, xrefs, report config
│   ├── developer_setup.md        (2.5 KB)     # Setup scripts, linting, formatting
│   └── roadmap_proposals.md      (6.8 KB)     # Strategic research proposals & advanced features
│
├── dist/                                      # Production build output (code-split)
│   ├── index.html                (0.48 KB)
│   └── assets/
│       ├── index-*.css           (8.14 KB)
│       ├── index-*.js            (513.39 KB)  # Main chunk
│       ├── cfgVisualizer-*.js    (17.52 KB)   # Lazy chunk
│       ├── emulatorPanel-*.js    (13.41 KB)   # Lazy chunk
│       ├── collabPanel-*.js      (30.35 KB)   # Lazy chunk
│       └── pluginsPanel-*.js     (29.15 KB)   # Lazy chunk
│
├── scratch/                                   # Scratch/debug scripts
│   ├── brace_checker.cjs         (45 lines)
│   ├── brace_checker.js          (44 lines)
│   └── diff_router.txt           (80 KB)
│
├── package.json                 (656 B)       # Project config (pnpm, type:module, ESM)
├── tsconfig.json                (435 B)       # ES2022, NodeNext, strict, DOM libs
├── vite.config.ts               (439 B)       # Vite + Vitest config (root: src, port 5173, testTimeout: 30000)
├── eslint.config.js             (363 B)       # ESLint flat config with typescript-eslint
├── .prettierrc                  (105 B)       # Prettier: semi, singleQuote, tabWidth:2
├── .gitignore                   (1.1 KB)      # Standard ignores
├── pnpm-workspace.yaml          (35 B)        # pnpm workspace config
├── pnpm-lock.yaml               (163 KB)      # Lock file
├── index.js                     (59 B)        # Placeholder entry
├── AGENTS.md                    (1.6 KB)      # Agent rules (pnpm, subagents, devlog)
├── DEVLOG.md                    (110 KB)       # Development log (1488 lines)
├── README.md                    (7.1 KB)       # Project README with architecture diagram
└── handoff.md                                 # THIS FILE
```

---

## 4. ⚙️ Tech Stack & Configuration

### Versions

| Component | Version | Notes |
|-----------|---------|-------|
| TypeScript | 6.0.3 | Strict mode, ES2022 target |
| Vite | 8.0.14 | Dev server on port 5173, root: `src/` |
| Vitest | 4.1.7 | Test runner, test files in `tests/`, testTimeout: 30000 |
| pnpm | latest | **ALWAYS use pnpm, NEVER npm** |
| Node.js | latest LTS | |
| ESLint | 10.4.0 | Flat config with typescript-eslint |
| Prettier | 3.8.3 | Semi, singleQuote, tabWidth:2, trailingComma:es5 |
| jsdom | 29.1.1 | For UI component testing |
| @vitest/coverage-v8 | 4.1.7 | Coverage reporting |

### Import Rules (CRITICAL)

```typescript
// ✅ CORRECT — always use .js extensions
import { parseELF } from './parser/elf.js';
import { Section } from '../disassembler/types.js';

// ❌ WRONG — will fail at runtime
import { parseELF } from './parser/elf';
import { Section } from '../disassembler/types';
```

### Key Configuration Details

- **Module system**: ESM (`"type": "module"` in package.json)
- **Module resolution**: NodeNext (requires `.js` extensions in imports!)
- **tsconfig**: `target: "ES2022"`, `module: "NodeNext"`, `strict: true`, `lib: ["DOM", "DOM.Iterable", "ES2022"]`
- **Vite**: `root: 'src'`, `build.outDir: '../dist'`, `test.include: ['../tests/**/*.test.ts']`, `server.port: 5173`
- **Test timeout**: 30,000ms (increased in S11 for E2E stability)

---

## 5. 🗺️ Roadmap — Prioritized for Session 13

### 🔴 Priority 0 — IMMEDIATE (Do These FIRST)

1. **Expand code splitting** — Only 4 panels are lazy-loaded. Convert remaining heavy panels (diffPanel, metadataPanel, typeSystemPanel, searchPanel, reportPanel, yaraPanel, machoObjcPanel, gdbPanel) to dynamic `import()`. Target: **main chunk <350KB** (currently 513KB).

2. **Run `pnpm tsc --noEmit`** — TypeScript strict typecheck was not completed in S11 or S12 (subagent hit quota). Fix any type errors.

3. **Run `pnpm eslint src/`** — Lint check was not completed. Fix warnings.

4. **Rebuild production bundle** — The `dist/` is stale (from S11). Run `pnpm build` to verify the decomposition didn't break the bundle and measure new sizes.

5. **Add tests for new extracted modules** — `panelCoordinator.ts`, `layout.ts`, `binaryProcessor.ts` have NO dedicated test files. Add `panelCoordinator.test.ts`, `layout.test.ts`, `binaryProcessor.test.ts`.

### 🟠 Priority 1 — Feature Expansion

6. **Expand instruction tables** — More x86_64 opcodes (SIMD/SSE/AVX), more ARM instructions in [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts)

7. **YARA rule import/export** — File I/O for .yar files in [yara.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/yara.ts)

8. **IR/SSA more optimization passes** — Register allocation, constant folding improvements, dead code elimination in [ir.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ir.ts)

9. **Expand syscall emulation** — More Linux syscalls + Windows API hooks in [syscall.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/syscall.ts)

10. **Expand type system** — More C struct parsing, unions, enums, typedefs in [typeSystemPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeSystemPanel.ts)

11. **GDB panel tests expansion** — Only 5 tests currently. Add RSP packet edge cases, memory reads, breakpoints.

### 🟡 Priority 2 — Polish & Production

12. **Real Capstone.js WASM integration** — Move from mock to real disassembly engine in [capstoneWasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/capstoneWasm.ts)

13. **PDF report generation** — Add PDF export to [reportGenerator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/reportGenerator.ts)

14. **Headless backend offloading** — Node.js/Go remote processing server

15. **Expand coverage** — Target 95%+ on all modules. Current gaps: panelCoordinator.ts, layout.ts, binaryProcessor.ts, some UI panels

16. **Documentation expansion** — Update docs/ to cover new S12 features (decomposition architecture, LICM)

### 🟢 Priority 3 — Advanced Features

17. **Real CRDT collaboration** — Yjs WebSocket real-time sync (replace mock in collab.ts)

18. **On-device LLM production** — WebNN/ONNX for real local AI analysis

19. **Dynamic plugin loading** — Load plugins from external .js files at runtime

20. **Expand E2E tests** — Full workflow scenarios for every panel (currently 12 tests)

21. **Decompiler C output improvements** — if/else/while/for pattern recognition, variable naming

---

## 6. 🔑 Key Audit Findings (Carried Forward)

| Area | Finding | Status |
|------|---------|--------|
| **main.ts** (11.6 KB) | Was monolithic 72KB god class | ✅ **RESOLVED S12** — decomposed into panelCoordinator + layout + binaryProcessor |
| **Bundle size** | Main chunk 513 KB | ⚠️ Code splitting started S11 (4 chunks), needs more panels lazy-loaded |
| **New modules untested** | panelCoordinator/layout/binaryProcessor have no dedicated tests | ⚠️ Need test files |
| **Recursion risk** | decompiler.ts deep AST structuring | ⚠️ Still open |
| **DOM rendering** | Virtual scrolling for hex/assembly/strings | ✅ Resolved S10 |
| **Memory leaks** | CFG/FCG visualizer listeners | ✅ Resolved S10 |
| **Upload freeze** | O(N²) loops in main.ts | ✅ Resolved S10 |
| **tsc --noEmit** | Not run in S11 or S12 | ⚠️ Still pending |
| **ESLint** | Not run in S11 or S12 | ⚠️ Still pending |

### Coverage Achievements (Through Session 12)

| File | Coverage |
|------|----------|
| [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts) | **100%** ✅ |
| [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts) | **99.65%** ✅ |
| [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) | **98.41%** ✅ |
| [memoryMap.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/memoryMap.ts) | **96.13%** ✅ |
| [decompiler.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/decompiler.ts) | **94.08%** ✅ |

---

## 7. 🔧 Quick Reference Commands

```bash
# Install dependencies
pnpm install

# Start dev server (localhost:5173)
pnpm dev

# Run all tests
pnpm test

# Run a single test file
pnpm vitest run tests/<file>.test.ts

# Run tests with coverage
pnpm vitest run --coverage

# Production build
pnpm build

# TypeScript type checking
pnpm tsc --noEmit

# Git commit everything
git add -A && git commit -m "feat: description"

# Check git status
git status --short

# View recent git log
git log --oneline -25

# Check bundle size
pnpm build 2>&1 | Select-String "kB"

# Format code
pnpm prettier --write src/

# Lint code
pnpm eslint src/
```

---

## 8. 📈 Growth Metrics

### Session-by-Session Table

| Metric | S1 | S2 | S3 | S4 | S5 | S6 | S7 | S8 | S9 | S10 | S11 | **S12** |
|--------|----|----|----|----|----|----|----|----|----|-----|-----|---------|
| Test Files | 4 | 10 | 11 | 13 | 18 | 31 | 31 | 33 | 35 | 45 | 50 | **50** |
| Total Tests | 17 | 84 | 97 | 144 | 173 | 297 | 297 | 398 | 423 | 568 | 604 | **612** |
| Passing | 17 | 84 | 97 | 144 | 171 | 292 | 292 | 394 | 422 | 564 | 604 | **612** |
| Failing | 0 | 0 | 0 | 0 | 2 | 5 | 5 | 4 | 1 | 4 | 0 | **0** |
| Source Files | 17 | 30 | 32 | 38 | 55+ | 65+ | 68+ | 70+ | 75+ | 85+ | 90+ | **83*** |
| Bundle (KB) | 91 | ~150 | ~180 | ~250 | 354 | 487 | 487 | 487 | 497 | 558 | 612 | **612†** |
| DEVLOG Lines | ~100 | ~300 | ~400 | ~500 | ~640 | ~736 | 776 | 866 | 906 | 1160 | 1460 | **1488** |

*\* Accurate count via filesystem scan. Prior sessions used approximate counts.*
*† Bundle not rebuilt in S12 — dist/ is stale from S11. Rebuild in S13 to get accurate size.*

### Cumulative Growth

- **Tests:** 17 → 612 (**36x growth**)
- **Test Files:** 4 → 50 (**12.5x growth**)
- **Source Files:** 17 → 83 (**4.9x growth**, precise count)
- **Source Size:** ~50 KB → 1.54 MB (**30x growth**)
- **Test Size:** ~5 KB → 563 KB (**112x growth**)
- **Failures:** 0 → varied → **0** (all green!)
- **DEVLOG Lines:** ~100 → 1488 (**14.9x growth**)

### Session Highlights

| Session | Key Deliverables |
|---------|-----------------|
| **1** | Project init, ELF/PE/WASM parsers, CFG builder, decompiler, hex viewer, assembly view, CFG visualizer, CSS design system, 17 tests |
| **2** | Mach-O/DEX parsers, entropy/strings/search/signatures analyzers, memory map, strings viewer, search panel, dependency graph |
| **3** | Router testing, signature scan panel, report generator, emulator CPU/memory core |
| **4** | Emulator executor, report panel, memory permissions, XRefs engine, YARA engine |
| **5** | Full docs suite, imports/exports panel, XRefs panel, collab sync, AI/patcher/FCG/scripting, entropy graph, FCG visualizer |
| **6** | Demangler, binary diff, vuln scanner, type system, metadata, Capstone WASM, syscall emulation, 297 tests |
| **7** | Tab integration wiring, docs expansion, git commit all files |
| **8** | Fixed 5 test failures. IR/SSA framework. 394/398 tests |
| **9** | Fixed ALL remaining failures. Plugin architecture. E2E tests. Instruction expansion. 422/423 tests (99.8%) |
| **10** | Java/debugSymbols/dotnet/archive parsers, GDB RSP, Frida DBI, on-device AI, virtual scrolling, upload freeze fix, memory leak fixes, PE resources, CHK dominator algorithm, coverage expansion. 564/568 tests (99.3%) |
| **11** | **Fixed ALL 4 failures. GDB debugger panel. Mach-O signature tests (24). ObjC panel integration (6 tests). WASM name parser expansion. Decompiler structured AST (visitor pattern). E2E expansion to 12 tests. Started main.ts decomposition + code splitting. 604/604 tests (100%)** |
| **12** | **Completed main.ts decomposition (72KB→11.6KB). Extracted PanelCoordinator (39KB), Layout (14KB), BinaryProcessor (15KB). Added IR/SSA LICM optimization pass. Expanded instruction tables. 612/612 tests (100%)** |

---

## 9. 🚀🚀🚀 CRITICAL INSTRUCTIONS FOR SESSION 13 🚀🚀🚀

> [!CAUTION]
> **ALL 612 TESTS ARE GREEN. The codebase is healthy. Jump straight into building new features and optimizations.**

### ⚡ STEP 1: Launch 5 Subagents IMMEDIATELY

| # | Subagent Task | Priority |
|---|---------------|----------|
| 1 | **Expand code splitting** — Convert 8+ more panels to dynamic import() chunks, rebuild bundle, target <350KB main chunk | 🔴 P0 |
| 2 | **Run tsc --noEmit + eslint** — Fix any type/lint errors across the codebase | 🔴 P0 |
| 3 | **Add tests for extracted modules** — panelCoordinator.test.ts, layout.test.ts, binaryProcessor.test.ts | 🔴 P0 |
| 4 | **Expand instruction tables** — Add SIMD/SSE/AVX opcodes, more ARM instructions | 🟠 P1 |
| 5 | **IR/SSA optimization passes** — Register allocation, constant folding, dead code elimination | 🟠 P1 |

### ⚡ STEP 2: After subagents complete, run `pnpm test` to verify

### ⚡ STEP 3: `git add -A && git commit -m "feat: session 13 - ..."`

### ⚡ STEP 4: Launch 5 MORE subagents for Priority 1-2 tasks

### ⚡ RULES

- **ALWAYS** use `pnpm`, NEVER `npm`
- **ALWAYS** use `.js` extensions in TypeScript imports
- **ALWAYS** run `pnpm test` after changes
- **ALWAYS** update DEVLOG.md with timestamps and file links
- **ALWAYS** tell subagents: DO NOT LAUNCH THEIR OWN SUBAGENTS
- **ALWAYS** have at least 5 subagents running in parallel
- **ALWAYS** `git add -A && git commit` regularly
