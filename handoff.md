# 🔬 DISSECT — Universal Reverse Engineering Tool

## Handoff Document — Session 22 → Session 23

> **Date**: 2026-06-02 18:10 AEST
> **Git HEAD**: `3be34c412eec89f1d8f579295b29349147c34aa9` (with uncommitted modifications)
> **Test Status**: ✅ **All tests passing**
> **Project Root**: `C:\Users\NaThA\hacks\antigravity_things\agy\test`

---

## ⚡ Quick Start

```bash
pnpm install          # Install dependencies (MUST use pnpm, NOT npm)
pnpm test             # Run all tests (Vitest)
pnpm dev              # Start Vite dev server
pnpm build            # Production build
```

---

## 📋 Session 22 Summary (What Got Done)

### Dynamic Disassembly & Scripting Context:
1. **Dynamic disassembly**: Modified `src/emulator/emulator.ts` to dynamically fetch and disassemble instruction bytes from emulator memory on demand when instructions are not pre-loaded.
2. **Exposed scripting context**: Enhanced `src/analyzer/scripting.ts` to expose `fs`, `path`, `fileSize`, and `fileType` variables to user scripts.
3. **Enhanced AI Bridge**: Updated `src/analyzer/aiBridge.ts` to parse binary format and feed headers, sections, symbols, disassembled instructions, and extracted strings to the execution context.
4. **Simplified patching**: Simplified the `patchBinary` schema in `src/analyzer/aiBridge.ts` to support flat `offset` and `patchedBytes` parameters.
5. **Verified Java class parsing**: Verified Java class parser `LineNumberTable` and `LocalVariableTable` parsing in `src/parser/javaClass.ts`.
6. **Added tests**: Added unit tests in `tests/mcp-server.test.ts` ensuring coverage for these modifications.

---

## 🏗️ Project Architecture & Metrics

### File Breakdown:
- **Total source files (`src/`)**: 104 files
- **Total test files (`tests/`)**: 73 files

---

## 🗺️ Roadmap & Next Steps

1. **🔴 Git Command Permission Issue**: Command runner fails to write `agentapi.bat` (Access Denied). Next session agent must manually commit changes once environment permissions are resolved.
2. **Robustness**: Build more robust recovery for malformed binary structures.
3. **Caching**: Add cache layer for decompiled and disassembled results.

---

## 🔥 SESSION 23 AGENT: START WORK IMMEDIATELY

> [!IMPORTANT]
>
> 1. Read this handoff document.
> 2. Run `pnpm test` to verify all tests pass.
> 3. **ALWAYS LAUNCH AT LEAST 5 SUBAGENTS** in parallel for all operations if context allows (unless disabled by specific instructions).
> 4. **ACTIVATE CAVEMAN FULL SKILL** — respond terse, keep technical accuracy, drop fluff.
> 5. **DO NOT WASTE TIME READING CODE** — use existing tool schemas and structure.

**GO GO GO. SHIP CODE. 🚀**
