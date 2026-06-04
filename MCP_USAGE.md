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
Make sure to replace `/home/myname/projects/potato` with the absolute path of your workspace.

```json
{
  "mcpServers": {
    "uret-server": {
      "command": "node",
      "args": [
        "/home/myname/projects/potato/dist/mcp-server.js"
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
        "/home/myname/projects/potato/src/mcp-server.ts"
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

### 12. `loadBinary`
Load an executable binary into the session cache. All subsequent tool calls will use this loaded binary by default if "data" is omitted.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data.
  * `filePath` (string, optional): Local path of binary to load (resolved by server).

### 13. `diffSections`
Compare raw bytes of specific sections between two loaded binaries to find changed offsets and values.
* **Arguments:**
  * `dataA` (string, optional): Hex or Base64 encoded binary A (optional if session binary loaded).
  * `dataB` (string, required): Hex or Base64 encoded binary B.
  * `sections` (array of strings, optional): List of section names to compare. Default: `[".text"]`.

### 14. `exportToIda`
Generate an IDC script containing function renames and string comments for importing into IDA Pro/Ghidra.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data (optional if session binary loaded).

### 15. `patchAndRun`
Apply byte-level patches to a binary and emulate execution starting from entrypoint until hitting target address or step limit.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data (optional if session binary loaded).
  * `patches` (array, required): Array of patch objects:
    * `offset` (number, required): Byte offset in raw binary file.
    * `patchedBytes` (string, required): Hex or Base64 replacement bytes.
  * `runUntil` (number, optional): Virtual address/PC to run emulation until (breakpoint).
  * `maxSteps` (number, optional): Maximum step limit for emulator execution. Default 1000.

### 16. `callTree`
Compute the callers and callees call tree for a specific function name or virtual address in the binary.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data (optional if session binary loaded).
  * `target` (string, required): Function name or virtual address (hex or decimal) to query.
  * `arch` (string, optional): Target CPU architecture. Default is `x86_64`.

### 17. `typeStructRecovery`
Scan binary function instructions to reconstruct struct field layouts based on base registers and offset loads/stores.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data (optional if session binary loaded).
  * `address` (number, required): Virtual address of the function to analyze.
  * `arch` (string, optional): Target CPU architecture. Default is `x86_64`.

### 18. `emulatorHooks`
Manage emulation breakpoints and run emulation with breakpoint hit reporting.
* **Arguments:**
  * `action` (string, required): Emulation action (`run`, `setBreakpoints`, `clearBreakpoints`).
  * `breakpoints` (array of numbers, optional): List of virtual addresses to use as breakpoints.
  * `steps` (number, optional): Maximum steps to execute in "run" (default 1000).

### 19. `pipelineChainMode`
Execute a series of URET tools in sequence, passing outputs from one tool as inputs to subsequent tools using reference placeholders.
* **Arguments:**
  * `pipeline` (array, required): Array of step objects:
    * `tool` (string, required): Name of the tool to execute.
    * `params` (object, required): Parameters for the tool, supporting `$$prev.property$$` placeholder resolution.

### 20. `analyzeExports`
Parse PE/ELF binary and extract all exported symbols (ordinals, names, addresses). Supports PE and ELF formats.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded executable binary. Optional if a binary is loaded in the session.
  * `format` (string, optional): Format of the binary (`elf`, `pe`, `auto`, default: `auto`).

### 21. `analyzeResources`
Parse PE binary resources (.rsrc) and extract manifests, strings, and version headers. Supports PE format only.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded executable binary. Optional if a binary is loaded in the session.

### 22. `importRiskAnalyzer`
Analyze the imported APIs and instructions of a binary for potential security risks and process injection techniques, computing an overall risk score and returning detected risk combinations.
* **Arguments:**
  * `data` (string, optional): Hex or Base64 encoded binary data to analyze. Optional if a binary is loaded in the session.
  * `importNames` (array of strings, optional): Optional list of import names to scan directly.

### 23. `getSessionStatus`
Get the current session status, detailing any loaded binary, its format, architecture, file size, and entry point.
* **Arguments:** None.

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
