# 🔬 DISSECT — Universal Reverse Engineering Tool

> **Handoff Document — Session 14 Onboarding**
> **Last Updated:** 2026-05-30 18:06 AEST
> **Project Root:** `C:\Users\NaThA\hacks\antigravity_things\agy\test`
> **Long-Term Goal:** 1,000,000+ lines of code — a fully-featured universal RE workbench
> **Current Size:** ~1.56 MB of TypeScript source across 83 source files + 53 test files (~610 KB tests)

---

## ⚡ IMMEDIATE ACTION — READ THIS FIRST ⚡

> [!CAUTION]
> **DO NOT read this entire document before starting. Skim the Quick Start and Roadmap, then START CODING.**

1. **Launch 5 subagents IMMEDIATELY** to work in parallel on Priority 1 tasks.
2. **TELL ALL SUBAGENTS: DO NOT LAUNCH THEIR OWN SUBAGENTS.** (Max 1 level depth.)
3. **ALL 632 TESTS ARE PASSING** — the codebase is completely GREEN. No test fixes needed.
4. **Run `pnpm test` after every change** and update [DEVLOG.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/DEVLOG.md) with timestamps + file links.
5. **`git add -A && git commit` regularly** — don't lose work.
6. **Always use `pnpm`**, NEVER `npm`.
7. **Always use `.js` extensions in TypeScript imports** (NodeNext module resolution).
8. **Always keep at least 5 subagents active.** When one finishes, launch another.

---

## 🚀 Quick Start

```bash
# Navigate to project root
cd C:\Users\NaThA\hacks\antigravity_things\agy\test

# Install dependencies (if needed)
pnpm install

# Run all tests (should see 632 passing)
pnpm test

# Start dev server
pnpm dev

# Production build (verify bundle stays < 350KB main chunk)
pnpm build

# Type check
pnpm tsc --noEmit
```

---

## 📊 Current Project Status (Session 13 Close-Out)

### Test Results

```
 Test Files  53 passed (53)
      Tests  632 passed (632)
   Duration  ~20s
```

### ✅ ALL TESTS PASSING — 0 FAILURES

### Uncommitted Changes from Session 13

The following files were modified/created in Session 13 and may still be uncommitted:

| File | Change |
|------|--------|
| [DEVLOG.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/DEVLOG.md) | Updated |
| [eslint.config.js](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/eslint.config.js) | Updated |
| [yara.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/yara.ts) | New — YARA serialization |
| [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) | Minor fix |
| [syscall.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/syscall.ts) | New — expanded syscall layer |
| [panelCoordinator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelCoordinator.ts) | Major — dynamic imports |
| [typeSystemPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeSystemPanel.ts) | Major — unions/enums/typedefs |
| [yaraPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/yaraPanel.ts) | Updated |
| [e2e.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/e2e.test.ts) | New tests |
| [syscall.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/syscall.test.ts) | New test suite |
| [typeSystem.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/typeSystem.test.ts) | New tests |
| [yara.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/yara.test.ts) | New tests |
| [yaraPanel.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/yaraPanel.test.ts) | New tests |
| [binaryProcessor.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/binaryProcessor.test.ts) | New — untracked |
| [layout.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/layout.test.ts) | New — untracked |
| [panelCoordinator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/panelCoordinator.test.ts) | New — untracked |

> [!IMPORTANT]
> **First action in Session 14:** Run `git add -A && git commit -m "Session 13 close-out"` to lock in all the above work.

---

## ⚙️ Tech Stack & Configuration

| Component | Version | Notes |
|-----------|---------|-------|
| TypeScript | 6.0.3 | Strict mode, ES2022 target |
| Vite | 8.0.14 | Root: `src/`, output: `../dist` |
| Vitest | 4.1.7 | `testTimeout: 30000` |
| ESLint | 10.4.0 | Flat config, warnings mapping |
| pnpm | latest | **ALWAYS use pnpm, NEVER npm** |

### Key Configuration Files

- [package.json](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/package.json) — Scripts: `dev`, `build`, `test`
- [tsconfig.json](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tsconfig.json) — `NodeNext` module resolution, `.js` imports required
- [vite.config.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/vite.config.ts) — Path alias `@` → `./src`
- [eslint.config.js](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/eslint.config.js) — Flat config

> [!WARNING]
> **Known dependency issue:** `jest`, `ts-jest`, and `@types/jest` are still in `devDependencies` but are NOT used (Vitest is the test runner). Remove them when convenient.

---

## 📐 Architecture Overview

```
test/                                          # Project Root
├── src/                                       # ~1.56 MB source (83 files)
│   ├── index.html              (428 B)        # Vite entry HTML
│   ├── main.ts                 (11.6 KB)      # ApplicationCoordinator — thin orchestrator
│   ├── styles.css              (12.1 KB)      # Premium dark glassmorphic CSS
│   │
│   ├── parser/                                # Binary format parsers (12 files)
│   │   ├── elf.ts              (10.4 KB)      # ELF parser
│   │   ├── pe.ts               (25.6 KB)      # PE/PE32+ parser
│   │   ├── wasm.ts             (25.8 KB)      # WebAssembly parser
│   │   ├── macho.ts            (17.3 KB)      # Mach-O parser
│   │   ├── dex.ts              (15.6 KB)      # DEX parser
│   │   ├── javaClass.ts        (14.8 KB)      # Java class file parser
│   │   ├── debugSymbols.ts     (24.5 KB)      # DWARF + PDB debug symbols
│   │   ├── dotnetMetadata.ts   (27.3 KB)      # .NET ECMA-335 metadata
│   │   ├── archive.ts          (10.3 KB)      # ZIP/APK/JAR/IPA unpacker
│   │   ├── machoObjc.ts        (18.8 KB)      # Mach-O Obj-C metadata
│   │   └── machoSignature.ts   (17.5 KB)      # Mach-O code signature
│   │
│   ├── disassembler/                          # Disassembly & decompilation
│   │   ├── types.ts            (4.4 KB)       # Core types
│   │   ├── router.ts           (78.4 KB)      # DisassemblerRouter (⚠️ 2,244 lines — needs split)
│   │   ├── cfg.ts              (8.5 KB)       # CFG builder
│   │   ├── decompiler.ts       (41.7 KB)      # Pseudo-C decompiler (⚠️ 1,460 lines)
│   │   ├── capstoneWasm.ts     (4.2 KB)       # Capstone WASM integration (mock)
│   │   └── ir.ts               (31.7 KB)      # IR/SSA framework (with LICM)
│   │
│   ├── analyzer/                              # Analysis engines (15 files)
│   │   ├── entropy.ts          (4.1 KB)       # Shannon entropy
│   │   ├── strings.ts          (8.4 KB)       # String extractor
│   │   ├── search.ts           (8.7 KB)       # Pattern search
│   │   ├── signatures.ts       (8.2 KB)       # Signature scanner
│   │   ├── reportGenerator.ts  (8.6 KB)       # Report generator
│   │   ├── xrefs.ts            (10.8 KB)      # Cross-references
│   │   ├── yara.ts             (12.4 KB)      # YARA engine
│   │   ├── ai.ts               (22.3 KB)      # AI explanation engine
│   │   ├── aiOnDevice.ts       (19.2 KB)      # On-device LLM (ONNX/WebNN/WebGPU)
│   │   ├── patcher.ts          (6.5 KB)       # Binary patcher
│   │   ├── fcg.ts              (4.7 KB)       # Function Call Graph builder
│   │   ├── scripting.ts        (8.1 KB)       # Scripting engine
│   │   ├── demangler.ts        (12.8 KB)      # Symbol demangler
│   │   ├── diff.ts             (9.5 KB)       # Binary diff engine
│   │   ├── hashes.ts           (7.7 KB)       # Hash calculator
│   │   ├── vulnScanner.ts      (11.5 KB)      # Vulnerability scanner
│   │   ├── plugins.ts          (25.7 KB)      # Plugin architecture
│   │   ├── frida.ts            (14.7 KB)      # Frida DBI scripting helper
│   │   └── binaryProcessor.ts  (14.8 KB)      # Binary parsing orchestrator
│   │
│   ├── emulator/                              # x86_64 emulator
│   │   ├── cpu.ts              (6.0 KB)       # CPU state machine
│   │   ├── memory.ts           (6.9 KB)       # Virtual memory
│   │   ├── emulator.ts         (17.9 KB)      # Instruction executor
│   │   ├── syscall.ts          (8.2 KB)       # Syscall emulation
│   │   └── gdbProtocol.ts      (10.5 KB)      # GDB/LLDB RSP protocol
│   │
│   └── ui/                                    # Premium UI components
│       ├── hexViewer.ts        (12.7 KB)      # Interactive hex viewer
│       ├── assemblyView.ts     (38.8 KB)      # Assembly listing (⚠️ 1,277 lines)
│       ├── cfgVisualizer.ts    (32.8 KB)      # SVG CFG graph (⚠️ 1,092 lines)
│       ├── dependencyGraph.ts  (30.7 KB)      # Import/export dep graph (⚠️ 1,035 lines)
│       ├── typeSystemPanel.ts  (35.8 KB)      # Type system panel (⚠️ 1,392 lines)
│       ├── layout.ts           (13.8 KB)      # Layout/CSS injection
│       └── panelCoordinator.ts (39.3 KB)      # Panel lifecycle coordinator (⚠️ 1,196 lines)
│
├── tests/                                     # 53 test files, 632 tests (Vitest)
└── docs/                                      # Documentation
```

---

## 🛠️ Session 13 Summary (What Was Done)

### ✅ Code Splitting & Bundle Optimization
- Expanded dynamic imports in [panelCoordinator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelCoordinator.ts) — all heavy UI panels now load dynamically via `import()`.
- Maintained synchronous fallback via `globalThis.PANEL_REGISTRY` for test environments.
- **Main chunk dropped from 513 KB → 313 KB** (under the 350 KB limit).

### ✅ Type System Parser Overhaul
- [typeSystemPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeSystemPanel.ts) now parses: unions, enums, typedefs, nested inline structs.
- Comprehensive tests in [typeSystem.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/typeSystem.test.ts).

### ✅ YARA Rules Serialization
- `serializeYaraRules` in [yara.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/yara.ts) — roundtrip-tested in [yara.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/yara.test.ts).
- `exportCompiledRules` in [yaraPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/yaraPanel.ts).

### ✅ Expanded Emulator & Syscall Layer
- [syscall.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/syscall.ts): Linux syscalls (`mprotect`, `nanosleep`, `clone`, `wait4`) + Windows APIs (`VirtualProtect`, `CreateFileA`, `CloseHandle`).
- Tests in [syscall.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/syscall.test.ts).

### ✅ New Test Suites
- [panelCoordinator.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/panelCoordinator.test.ts), [layout.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/layout.test.ts), [binaryProcessor.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/binaryProcessor.test.ts).

### ✅ Type Safety & Linting
- Cleaned `pnpm tsc --noEmit` errors; configured ESLint flat rules in [eslint.config.js](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/eslint.config.js).

---

## 🗺️ Roadmap — Session 14 Priorities

### 🔴 Priority 1 — Feature Expansion (Assign to Subagents Immediately)

| # | Task | Key File(s) | Details |
|---|------|-------------|---------|
| 1 | **Expand x86_64 instruction tables** | [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) | Add SIMD/SSE/AVX opcodes, more ARM & Dalvik instructions |
| 2 | **IR/SSA optimization passes** | [ir.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ir.ts) | Register allocation, constant folding, dead code elimination |
| 3 | **GDB panel test expansion** | [gdbProtocol.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/gdbProtocol.ts) | Only 5 tests — add RSP edge cases, memory reads, breakpoints |
| 4 | **Expand syscall emulation** | [syscall.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/syscall.ts) | More Linux syscalls + Windows APIs |

### 🟠 Priority 2 — Polish & Production

| # | Task | Key File(s) | Details |
|---|------|-------------|---------|
| 5 | **Real Capstone.js WASM** | [capstoneWasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/capstoneWasm.ts) | Replace mock disassembler with real engine |
| 6 | **PDF report generation** | [reportGenerator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/reportGenerator.ts) | Add PDF export support |
| 7 | **Expand test coverage** | All modules | Target 95%+ coverage on UI panels and coordinators |

### 🟡 Priority 3 — Advanced Features

| # | Task | Key File(s) | Details |
|---|------|-------------|---------|
| 8 | **Real CRDT collaboration** | `src/network/collab.ts` | Replace mock with Yjs WebSocket real-time sync |
| 9 | **On-device LLM production** | [aiOnDevice.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/analyzer/aiOnDevice.ts) | Configure WebNN/ONNX for local AI analysis |

---

## 🐛 Known Bugs & Technical Debt

> [!WARNING]
> These were identified during the Session 13 thermo-nuclear code quality review. Address alongside feature work.

### IR & Register Allocator Bugs (in [ir.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/ir.ts))

- [ ] **BigInt fallback coercion bug** — `const val1 = inst.args[0].value ?? 0n;` can cause number/bigint mixing errors. Ensure fallback conversions work correctly.
- [ ] **Division semantics mismatch** — BigInt division (`b1 / b2`) truncates differently than `Math.floor`. Align behavior.
- [ ] **PHI node liveness analysis** — Exclude `IROp.PHI` instructions from `blockUses` in liveness analysis.
- [ ] **Spilled variable rewrites** — Implement proper spill loads/stores instead of naive memory operand conversions.

### Dead Code & Duplication

- [ ] **Remove dead view files** — These are duplicated by newer panel implementations:
  - `src/ui/searchView.ts` → duplicated by `searchPanel.ts`
  - `src/ui/dependencyGraphView.ts` → duplicated by `dependencyGraph.ts`
  - `src/ui/memoryMapView.ts` → duplicated by `memoryMap.ts`
  - `src/ui/vulnPanel.ts` → completely unreferenced
- [ ] **Remove unused test dependencies** — Delete `jest`, `ts-jest`, `@types/jest` from [package.json](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/package.json) `devDependencies`.

### Type Safety

- [ ] **Reduce `any` types** — Especially in parser outputs (`wasm.ts`, `macho.ts`, `dotnetMetadata.ts`).
- [ ] **Fix unchecked assertions/casts** — `as SectionId`, `as ValueType` on raw binary inputs (WASM, Mach-O parsing).
- [ ] **Fix ArrayBuffer `.buffer` casts** — Using `.buffer` directly retrieves the entire underlying buffer, not sliced views.
- [ ] **Add bounds checking** — Buffer-length constraint assertions before offset reads.

### Oversized Files (>1,000 Lines — Need Decomposition)

| File | Lines | Priority |
|------|-------|----------|
| [router.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/router.ts) | 2,244 | High |
| [decompiler.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/decompiler.ts) | 1,460 | High |
| [typeSystemPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/typeSystemPanel.ts) | 1,392 | Medium |
| [assemblyView.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/assemblyView.ts) | 1,277 | Medium |
| [panelCoordinator.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/panelCoordinator.ts) | 1,196 | Medium |
| [metadataPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/metadataPanel.ts) | 1,120 | Low |
| [cfgVisualizer.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/cfgVisualizer.ts) | 1,092 | Low |
| [reportPanel.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/reportPanel.ts) | 1,036 | Low |
| [dependencyGraph.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/ui/dependencyGraph.ts) | 1,035 | Low |

---

## 📋 Operational Rules (Non-Negotiable)

> [!IMPORTANT]
> Every agent in the session MUST follow these rules.

1. **Always launch 5 subagents.** Keep at least 5 active at all times. When one finishes, launch another.
2. **Subagents MUST NOT launch their own subagents.** Max 1 level depth.
3. **Always use `pnpm`**, never `npm`.
4. **Always use `.js` extensions** in TypeScript imports (NodeNext module resolution).
5. **Run `pnpm test` after every change.** All 632+ tests must stay green.
6. **Update [DEVLOG.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/DEVLOG.md)** with timestamps and file links after every meaningful change.
7. **`git add -A && git commit` regularly** — commit early, commit often.
8. **Use `uv pip` instead of `pip`** for any Python tooling.
9. **Zero runtime dependencies** — this project has no production dependencies, keep it that way.
10. **Bundle size limit** — Main chunk must stay **under 350 KB**. Verify with `pnpm build`.

---

## 📚 Key Reference Files

| File | Purpose |
|------|---------|
| [AGENTS.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/AGENTS.md) | Agent configuration rules |
| [DEVLOG.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/DEVLOG.md) | Development log (append-only, do NOT read) |
| [README.md](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/README.md) | Project README |
| [package.json](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/package.json) | Dependencies & scripts |
| [tsconfig.json](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tsconfig.json) | TypeScript configuration |
| [vite.config.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/vite.config.ts) | Build configuration |
| [eslint.config.js](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/eslint.config.js) | Linting rules |

---

*End of handoff. Start building. Launch subagents. Ship code.* 🚀
