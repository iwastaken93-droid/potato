# 🏗️ System Architecture & Data Flow

DISSECT is structured as a unidirectional pipeline that transforms raw binary input (byte streams) into rich, interactive visual representations and an executable virtual emulation state.

---

## 📈 System Architecture Diagram

Below is the high-level architecture of DISSECT showing how files progress from initial upload to UI panels and the virtual emulator.

```mermaid
graph TD
    %% Input Layer
    subgraph Input ["📥 Input Layer"]
        A[Raw File / ArrayBuffer] --> B[FileReader / Binary Stream]
    end

    %% Parsing Layer
    subgraph Parsers ["🧬 Parsing & Normalization Layer"]
        B --> C[Disassembler Router]
        C -->|Detect ELF| D[ELF Parser]
        C -->|Detect PE| E[PE Parser]
        C -->|Detect Mach-O| F[Mach-O Parser]
        C -->|Detect DEX| G[DEX Parser]
        C -->|Detect WASM| H[WASM Parser]
    end

    %% Core Data Model
    subgraph CoreModel ["📦 Unified Metadata & Code Representation"]
        D & E & F & G & H --> I[Unified Executable Representation]
        I -->|Sections / Entropy / Symbols| J[Static Analyzer Engine]
        I -->|Machine Code / Bytecode| K[Disassembler Engine]
        I -->|Raw Headers & Data| L[Hex Viewer Core]
    end

    %% Execution & Control Flow
    subgraph Execution ["⚙️ Flow & Execution Engines"]
        K --> M[Basic Block Builder]
        M --> N[CFG Router / Edge Solver]
        N --> O[Dominator Tree Decompiler]

        I -->|Load Sections & EntryPoint| P[Virtual CPU Emulator]
        P -->|Page Memory Map| Q[Virtual Memory Manager]
        P -->|Register Banks| R[x86_64 Register Aliasing]
    end

    %% UI & Presentation Layer
    subgraph UI ["🎨 Premium Frontend Viewports"]
        L --> S[Hex Viewer Component]
        K --> T[Assembly / Jump-Arrow View]
        N --> U[CFG SVG Visualizer]
        O --> V[Pseudocode View]
        J --> W[Analyzer & Signatures Tab]
        P --> X[Emulator Execution Panel]
    end

    classDef input fill:#1E293B,stroke:#475569,stroke-width:2px,color:#E2E8F0;
    classDef parse fill:#1E1B4B,stroke:#4F46E5,stroke-width:2px,color:#E0E7FF;
    classDef core fill:#311042,stroke:#C084FC,stroke-width:2px,color:#F3E8FF;
    classDef exec fill:#064E3B,stroke:#059669,stroke-width:2px,color:#D1FAE5;
    classDef ui fill:#0F172A,stroke:#3B82F6,stroke-width:2px,color:#EFF6FF;

    class A,B input;
    class C,D,E,F,G,H parse;
    class I,J,K,L core;
    class M,N,O,P,Q,R exec;
    class S,T,U,V,W,X ui;
```

---

## 🔁 Complete Data Pipeline

### 1. File Ingestion & Auto-Detection

The user uploads a binary file (via drag-and-drop or select file). The coordinator ([main.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/main.ts)) reads the data as a `Uint8Array`. The raw array is sent directly to `DisassemblerRouter.detectArchitecture()` which inspects file header magic bytes to resolve the source format:

- **ELF**: `\x7FELF`
- **PE**: `MZ` header (with COFF signature check)
- **Mach-O**: `\xFE\xED\xFA\xCE` or `\xFE\xED\xFA\xCF` (and fat binary headers)
- **DEX**: `dex\n`
- **WASM**: `\x00asm`

### 2. Format Parsing & Section Normalization

Once the format is determined, the corresponding parser (such as [pe.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/pe.ts) or [macho.ts](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/parser/macho.ts)) executes:

- Reads headers, directories, load commands, or bytecode sections.
- Populates a list of section metadata (virtual addresses, file offsets, raw bytes, read/write/execute permissions).
- Extracts import/export dynamic libraries and names, as well as debugging/linker symbols.

### 3. Disassembly & Flow Analysis

For executable code segments, the `DisassemblerRouter` routes bytes to the corresponding architecture-specific disassembler (e.g. x86_64, ARM, DEX bytecode instructions, or WASM virtual stack instructions).

- Outputs structured `Instruction` records containing operands (registers, immediate values, memory expressions).
- The CFG Builder takes instructions, splits them on branches (`JMP`, `Jcc`, `CALL`, `RET`, etc.), creates basic blocks, and links edges.
- The decompiler builds loop maps and dominator structures to output simplified high-level structure pseudocode.

### 4. Static Analysis Core

Concurrently, the raw executable undergoes static analysis in the background:

- **Entropy Map**: Calculates Shannon entropy per section and reports high-entropy byte regions indicating packers/encryption.
- **Signature Scanner**: Scans byte patterns using compiled Yara-like signatures to locate cryptographic constants, compiler labels, and packaging markers.
- **Strings & Xrefs**: Extracts ASCII/Unicode string patterns and registers cross-references pointing to specific memory offsets.

### 5. Virtual Machine Execution (Emulator)

If execution simulation is requested:

- The parser sections are mapped into the virtual CPU's [Memory](file:///C:/Users/NaThA/hacks/antigravity_things/agy/test/src/emulator/memory.ts) pages using configured permissions (R, W, X).
- The registers are initialized, including stack pointer (`rsp`) and program counter (`rip`).
- The emulator executes commands sequentially, translating memory lookups, modifying flag bits (`ZF`, `CF`, `SF`, etc.), and enforcing memory bounds.
