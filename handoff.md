# URET / DISSECT — Session 19 → Session 20 Handoff

> **Project**: Universal Reverse Engineering Tool (URET / DISSECT)
> **Date**: 2026-05-31T21:22:05+10:00
> **Last Commit**: Session 19 commit
> **Test Status**: **874 passed / 0 failed** (874 total across 70 test files)
> **Uncommitted Changes**: None (staged and committed)

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

## Session 19 Summary — Completed Tasks

| Task | Key Files | Status |
|------|-----------|--------|
| **WASM Component Model** | [wasm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/wasm.ts), [wasm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/wasm.test.ts) | ✅ Added parsing for core instances, core types, components, instances, aliases, types, canons, starts, and values. |
| **ARM64 NEON SIMD** | [arm.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/arm.ts), [arm.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/arm.test.ts) | ✅ Added decoding for logic, multiply, min/max, and floating-point min/max NEON SIMD instructions. |
| **ESLint Cleanup** | Multiple files in `src/parser/` and `src/ui/` | ✅ Removed `any` type arrays, unused variables/imports, and resolved `any` casts. |
| **ELF GOT/PLT Fixes** | [elf.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/elf.ts), [elf.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/elf.test.ts) | ✅ Fixed ELF test symbol mismatch ('bar' vs 'foo') and verified AArch64 adrp/ldr PLT pattern decoding. |
| **URET MCP Server** | [mcp-server.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/mcp-server.ts), [mcp-server.test.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/tests/mcp-server.test.ts) | ✅ Implemented and tested MCP server protocol bridge for URET engine. |

---

## Full Test Suite — 70 Test Files (874 Tests)

All 874 tests are passing successfully.

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
| **Killing Subagents** | Kill subagents when they finish their task. Keep 5 active. |

---

## Roadmap — Session 20

### 🟡 HIGH PRIORITY

| Task | Details | Status |
|------|---------|--------|
| **Java Class Debug Info** | Parse `LineNumberTable` and `LocalVariableTable` in [javaClass.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/javaClass.ts) | NOT STARTED |
| **RISC-V M/A extensions** | Multiply/Atomic instructions in [riscv.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/disassembler/riscv.ts) | NOT STARTED |

### 🟢 STRETCH GOALS

| Task | Details | Status |
|------|---------|--------|
| **Symbolic path exploration** | Multi-path symbolic execution with constraint solving | NOT STARTED |
| **PE Authenticode verification** | Verify PE digital signatures | NOT STARTED |
| **DWARF v5 .debug_loclists** | Location list parsing in [dwarfParser.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/dwarfParser.ts) | NOT STARTED |

---

## SESSION 20 AGENT: START CODING IMMEDIATELY

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
  Agent 1: Parse Java LineNumberTable and LocalVariableTable
  Agent 2: Implement RISC-V M/A extensions in riscv.ts
  Agent 3: Implement PE Authenticode verification
  Agent 4: Implement DWARF v5 .debug_loclists
  Agent 5: Implement symbolic multi-path constraint solver

GO GO GO. NO PLANNING. START CODING.
```
