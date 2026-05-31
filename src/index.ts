/**
 * DISSECT — Universal Reverse Engineering Toolkit
 * 
 * Main entry point for library usage.
 * Import from 'dissect-re' or 'dissect-re/bridge' for AI Bridge only.
 */

// AI Bridge (primary API for AI agents)
export { AIBridge, TOOL_SCHEMAS, toUint8Array, toHex, SymbolicExecutor } from './analyzer/aiBridge.js';

// Parsers
export { parseElf } from './parser/elf.js';
export { PEParser } from './parser/pe.js';
export { MachoParser } from './parser/macho.js';
export { parseWasm } from './parser/wasm.js';
export { parseDex } from './parser/dex.js';
export { parseJavaClass } from './parser/javaClass.js';
export { CoffParser, ParsedCoff } from './parser/coff.js';
export { parseIntelHex, parseSRecord, detectFormat as detectHexFormat } from './parser/hexLoader.js';

// Disassemblers
export { DisassemblerRouter } from './disassembler/router.js';
export { Decompiler } from './disassembler/decompiler.js';

// Analyzers
export { BinaryPatcher } from './analyzer/patcher.js';
export { ScriptingEngine } from './analyzer/scripting.js';
export { YaraEngine } from './analyzer/yara.js';
export { VulnScanner } from './analyzer/vulnScanner.js';
export { diffBytes, diffInstructions } from './analyzer/diff.js';
export { AIExplanationEngine } from './analyzer/ai.js';

// Emulator
export { Emulator } from './emulator/emulator.js';
