# 🔍 DISSECT Documentation Hub

Welcome to the official developer and architecture documentation for **DISSECT**, a universal reverse engineering, file parsing, disassembly, and CPU emulation platform.

DISSECT is designed as a modular, high-performance static and dynamic analysis tool written entirely in TypeScript. It supports multi-architecture binary parsing, control-flow graph (CFG) extraction, decompilation, and step-by-step CPU emulation.

---

## 📚 Table of Contents

- [**🏗️ System Architecture & Data Flow**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/architecture.md)
  An overview of the end-to-end pipeline, from file input byte streams to interactive decompiled view and visual control-flow graphs. Contains Mermaid architecture and dataflow diagrams.
- [**🧬 Binary Parsers (ELF, PE, Mach-O, DEX, WASM)**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/parsers.md)
  Deep technical breakdown of how DISSECT parses compiled executables, bytecode formats, and web assemblies into a unified internal representation.
- [**⚙️ Disassembler Router & Control Flow Graphs**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/disassembler_router.md)
  Understand the automatic format detector, opcode decoder routing rules, Basic Block splitting, loop-finding algorithms, and dominator tree building.
- [**🧠 Virtual CPU Emulator State & Memory Model**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/emulator.md)
  Detailed look at the virtual environment, including sub-register aliasing, memory page maps, read/write/execute permissions, step execution, and breakpoint control.
- [**📊 Static Analyzers (Entropy, Signatures, Search)**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/analyzers.md)
  Details on Shannon entropy calculations, sliding-window signatures (compilers/cryptography/packers), string extraction rules, and xref (cross-reference) analysis.
- [**💻 Developer Setup & Engineering Guidelines**](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/docs/developer_setup.md)
  Guide on environment prerequisites (`pnpm`), CLI operations, running the test suites (`vitest`), formatting standards (`prettier`), and production packaging (`vite`).

---

## 🛠️ Core Design Principles

1. **Zero External Dependencies**: Standard analysis libraries are implemented from scratch in pure TypeScript to guarantee portability and run safely in any sandboxed browser or Node environment.
2. **Unified Data Structures**: Regardless of whether a binary is an ELF executable or a WASM file, parsed sections, symbols, and instruction structures map to a common schema.
3. **Responsive Visual Interaction**: Designed with a high-fidelity slate/charcoal dark-mode theme, canvas-drawn jump arrows, SVG-based CFG nodes, and smooth micro-animations.
