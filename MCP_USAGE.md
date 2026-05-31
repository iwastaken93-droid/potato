# URET Model Context Protocol (MCP) Server Usage Documentation

This document describes how to configure, run, and use the Model Context Protocol (MCP) server for URET (Universal Reverse Engineering Toolkit).

---

## Installation

### Prerequisites
- Node.js (v18 or higher recommended)
- `pnpm` package manager

### Local Build Setup
1. Clone/navigate to the project repository.
2. Install dependencies:
   ```bash
   pnpm install
   ```
3. Build the TypeScript source code:
   ```bash
   pnpm build
   ```

---

## Claude Desktop Configuration

To register the URET MCP server with Claude Desktop, edit your `claude_desktop_config.json` file.

* **Windows Path:** `%APPDATA%\Claude\claude_desktop_config.json`
* **macOS Path:** `~/Library/Application Support/Claude/claude_desktop_config.json`

Add the server configuration under the `mcpServers` key:

### Option A: Using the Compiled JavaScript (Recommended)
Make sure to replace `C:/Users/NaThA/hacks/antigravity_things/agy/test` with the absolute path of your workspace.

```json
{
  "mcpServers": {
    "uret-server": {
      "command": "node",
      "args": [
        "C:/Users/NaThA/hacks/antigravity_things/agy/test/dist/mcp-server.js"
      ]
    }
  }
}
```

### Option B: Running Directly with TypeScript (tsx)
```json
{
  "mcpServers": {
    "uret-server": {
      "command": "npx",
      "args": [
        "-y",
        "tsx",
        "C:/Users/NaThA/hacks/antigravity_things/agy/test/src/mcp-server.ts"
      ]
    }
  }
}
```

---

## Available Tools

The URET MCP server exposes the following tools:

### 1. `disassemble`
Disassemble raw binary data into structured instructions.
* **Arguments:**
  * `data` (string, required): Hex or Base64 encoded binary data.
  * `arch` (string, optional): Architecture (e.g., `x86_64`, `arm`, `riscv`, `thumb`, `wasm`, `dex`, `z80`).
  * `baseAddress` (number, optional): Base virtual address (default 0).

### 2. `decompile`
Decompile structured instructions or raw binary into C-like pseudocode.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data.
  * `entryPoint` (number, optional): Entry point offset/address.
  * `instructions` (array, optional): Array of instruction objects:
    * `address` (number)
    * `op` (string)
    * `args` (array of strings)

### 3. `parseBinary`
Parse ELF, PE, or Mach-O executable binary headers, sections, and symbols.
* **Arguments:**
  * `data` (string, required): Hex or Base64 encoded binary data.
  * `format` (string, optional): Binary format (`elf`, `pe`, `macho`, `auto`, default: `auto`).

### 4. `patchBinary`
Apply patches at specified offsets or virtual addresses to binary data.
* **Arguments:**
  * `data` (string, required): Hex or Base64 encoded binary data.
  * `patches` (array, required): Array of patch objects:
    * `offset` (number, required): Offset in binary to apply patch.
    * `patchedBytes` (string, required): Hex or Base64 encoded replacement bytes.
    * `address` (number, required): Virtual address associated with the patch.
    * `description` (string, optional): Purpose or summary of the patch.

### 5. `executeScript`
Run JavaScript analytics scripts with helper contexts on a binary.
* **Arguments:**
  * `data` (string, required): Hex or Base64 encoded binary data.
  * `script` (string, required): JavaScript code to execute.

### 6. `yaraScan`
Scan binary data using YARA-like text signatures.
* **Arguments:**
  * `data` (string, required): Hex or Base64 encoded binary data.
  * `rules` (string, required): YARA rules source string.

### 7. `vulnScan`
Scan function instructions, imports, strings, or decompiled code for vulnerabilities.
* **Arguments:**
  * `instructions` (array, optional): Array of instructions.
  * `strings` (array, optional): Array of strings extracted from binary.
  * `importNames` (array, optional): Array of imported symbol names.
  * `decompiledText` (string, optional): Decompiled code block.

### 8. `diffBinaries`
Perform diffing analysis between two binaries or instruction sets.
* **Arguments:**
  * `dataA` (string, required): Binary A (Hex or Base64).
  * `dataB` (string, required): Binary B (Hex or Base64).
  * `type` (string, optional): Diff mode (`bytes`, `instructions`, default: `bytes`).

### 9. `analyzeCodeAI`
Use the AI engine to analyze code patterns, suggestions, complexity, and pseudocode.
* **Arguments:**
  * `code` (string, required): Assembly or C code block to explain.
  * `functionName` (string, optional): Name of the function context.
  * `arch` (string, optional): Architecture context.

### 10. `symbolicExecute`
Symbolically execute mock/simplified assembly instructions to find inputs hitting a target.
* **Arguments:**
  * `instructions` (array, required): Array of instructions with `op` and `args`.
  * `inputs` (array, required): Array of input variable objects:
    * `name` (string, required): Variable/Register name.
    * `min` (number, optional)
    * `max` (number, optional)
  * `targetAddress` (number, required): The address to reach.

### 11. `emulatorControl`
Control x86_64 emulator instance, execute instructions, read/write memory and registers.
* **Arguments:**
  * `action` (string, required): Emulator action (`run`, `step`, `reset`, `readReg`, `writeReg`, `readMem`, `writeMem`).
  * `instructions` (array, optional): Array of instructions to load on reset.
  * `registers` (object, optional): Register key-value pairs.
  * `memory` (array, optional): Memory mappings/patches:
    * `address` (string)
    * `value` (string, Hex)
  * `steps` (number, optional): Steps for step/run action.

---

## Examples

### Disassembling a byte sequence
Call the `disassemble` tool:
```json
{
  "data": "90",
  "arch": "x86_64"
}
```
**Output:**
```json
{
  "success": true,
  "instructions": [
    {
      "address": 0,
      "mnemonic": "nop",
      "opStr": "",
      "size": 1,
      "bytes": [144],
      "op": "nop",
      "args": []
    }
  ]
}
```

### Running Symbolic Execution
Call the `symbolicExecute` tool to find inputs where `x` reaches `0x2000`:
```json
{
  "instructions": [
    { "address": 4096, "op": "mov", "args": ["rax", "x"] },
    { "address": 4100, "op": "cmp", "args": ["rax", "0x2a"] },
    { "address": 4104, "op": "je", "args": ["0x2000"] }
  ],
  "inputs": [
    { "name": "x", "min": 0, "max": 100 }
  ],
  "targetAddress": 8192
}
```
**Output:**
```json
{
  "success": true,
  "pathFound": true,
  "constraints": [
    "x === 42"
  ],
  "solutions": {
    "x": 42
  }
}
```
