import { describe, it, expect } from 'vitest';
import {
  parseWasm,
  ValueType,
  ExportKind,
  SectionId,
} from '../src/parser/wasm.js';

// Helper functions to generate binary WASM structures for testing
function encodeVarUint(val: number): number[] {
  const bytes: number[] = [];
  let temp = val;
  while (true) {
    const byte = temp & 0x7f;
    temp >>>= 7;
    if (temp === 0) {
      bytes.push(byte);
      break;
    } else {
      bytes.push(byte | 0x80);
    }
  }
  return bytes;
}

function encodeVarInt(val: number): number[] {
  const bytes: number[] = [];
  let temp = val;
  while (true) {
    const byte = temp & 0x7f;
    temp >>= 7;
    if (
      (temp === 0 && (byte & 0x40) === 0) ||
      (temp === -1 && (byte & 0x40) !== 0)
    ) {
      bytes.push(byte);
      break;
    } else {
      bytes.push(byte | 0x80);
    }
  }
  return bytes;
}

function encodeString(str: string): number[] {
  const bytes = Array.from(new TextEncoder().encode(str));
  return [...encodeVarUint(bytes.length), ...bytes];
}

describe('WASM Parser Unit Tests', () => {
  it('should throw an error for invalid magic header', () => {
    const invalidBytes = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00,
    ]);
    expect(() => parseWasm(invalidBytes)).toThrow(
      /Invalid WebAssembly magic number/
    );
  });

  it('should successfully parse a valid WASM header with no sections', () => {
    const emptyWasm = new Uint8Array([
      0x00,
      0x61,
      0x73,
      0x6d, // Magic: "\0asm"
      0x01,
      0x00,
      0x00,
      0x00, // Version: 1
    ]);
    const module = parseWasm(emptyWasm);
    expect(module.magic).toEqual([0x00, 0x61, 0x73, 0x6d]);
    expect(module.version).toBe(1);
    expect(module.types).toHaveLength(0);
    expect(module.imports).toHaveLength(0);
    expect(module.functions).toHaveLength(0);
    expect(module.exports).toHaveLength(0);
    expect(module.code).toHaveLength(0);
  });

  it('should parse custom sections correctly', () => {
    const customSectionName = 'test_custom';
    const nameBytes = encodeString(customSectionName);
    const customPayload = [0x01, 0x02, 0x03];
    const sectionLength = nameBytes.length + customPayload.length;

    const wasmBytes = new Uint8Array([
      0x00,
      0x61,
      0x73,
      0x6d,
      0x01,
      0x00,
      0x00,
      0x00,
      SectionId.Custom,
      ...encodeVarUint(sectionLength),
      ...nameBytes,
      ...customPayload,
    ]);

    const module = parseWasm(wasmBytes);
    expect(module.customSections).toHaveLength(1);
    expect(module.customSections[0].name).toBe(customSectionName);
    expect(module.customSections[0].size).toBe(customPayload.length);
  });

  it('should decode types, functions, exports, imports, and bytecode', () => {
    // 1. Type Section: 1 function type: (i32, i32) -> i32
    const typePayload = [
      ...encodeVarUint(1), // number of types
      0x60, // type form (func)
      ...encodeVarUint(2), // param count
      ValueType.I32,
      ValueType.I32,
      ...encodeVarUint(1), // result count
      ValueType.I32,
    ];

    // 2. Import Section: import "env" "print" as func index 0 (using type index 0)
    const importPayload = [
      ...encodeVarUint(1), // number of imports
      ...encodeString('env'),
      ...encodeString('print'),
      ExportKind.Func,
      ...encodeVarUint(0), // type index
    ];

    // 3. Function Section: defines 1 function using type index 0 (this will be func index 1 since import is 0)
    const funcPayload = [
      ...encodeVarUint(1), // number of functions
      ...encodeVarUint(0), // type index 0
    ];

    // 4. Export Section: export function index 1 as "add"
    const exportPayload = [
      ...encodeVarUint(1), // number of exports
      ...encodeString('add'),
      ExportKind.Func,
      ...encodeVarUint(1), // function index 1
    ];

    // 5. Code Section: body for function 1
    // Let's create locals: 1 local of type i32
    const locals = [
      ...encodeVarUint(1), // number of local declarations
      ...encodeVarUint(1), // count of locals in this decl
      ValueType.I32, // type
    ];

    // Instructions: local.get 0, local.get 1, i32.add, end (0x0b)
    const instructions = [
      0x20,
      ...encodeVarUint(0), // local.get 0
      0x20,
      ...encodeVarUint(1), // local.get 1
      0x6a, // i32.add
      0x0b, // end
    ];

    const funcBody = [...locals, ...instructions];
    const codePayload = [
      ...encodeVarUint(1), // number of code bodies
      ...encodeVarUint(funcBody.length),
      ...funcBody,
    ];

    // Combine all sections
    const wasmBytes = new Uint8Array([
      0x00,
      0x61,
      0x73,
      0x6d,
      0x01,
      0x00,
      0x00,
      0x00,

      SectionId.Type,
      ...encodeVarUint(typePayload.length),
      ...typePayload,

      SectionId.Import,
      ...encodeVarUint(importPayload.length),
      ...importPayload,

      SectionId.Function,
      ...encodeVarUint(funcPayload.length),
      ...funcPayload,

      SectionId.Export,
      ...encodeVarUint(exportPayload.length),
      ...exportPayload,

      SectionId.Code,
      ...encodeVarUint(codePayload.length),
      ...codePayload,
    ]);

    const module = parseWasm(wasmBytes);

    // Verify Types
    expect(module.types).toHaveLength(1);
    expect(module.types[0].params).toEqual([ValueType.I32, ValueType.I32]);
    expect(module.types[0].results).toEqual([ValueType.I32]);

    // Verify Imports
    expect(module.imports).toHaveLength(1);
    expect(module.imports[0].module).toBe('env');
    expect(module.imports[0].field).toBe('print');
    expect(module.imports[0].kind).toBe(ExportKind.Func);
    expect(module.imports[0].typeIndexOrDesc).toBe(0);

    // Verify Functions
    expect(module.functions).toHaveLength(1);
    expect(module.functions[0]).toBe(0);

    // Verify Exports
    expect(module.exports).toHaveLength(1);
    expect(module.exports[0].name).toBe('add');
    expect(module.exports[0].kind).toBe(ExportKind.Func);
    expect(module.exports[0].index).toBe(1);

    // Verify Code and Bytecode parsing
    expect(module.code).toHaveLength(1);
    expect(module.code[0].locals).toHaveLength(1);
    expect(module.code[0].locals[0].count).toBe(1);
    expect(module.code[0].locals[0].type).toBe(ValueType.I32);

    const parsedInstructions = module.code[0].instructions;
    expect(parsedInstructions).toHaveLength(4);

    expect(parsedInstructions[0].mnemonic).toBe('local.get');
    expect(parsedInstructions[0].args).toBe(0);

    expect(parsedInstructions[1].mnemonic).toBe('local.get');
    expect(parsedInstructions[1].args).toBe(1);

    expect(parsedInstructions[2].mnemonic).toBe('i32.add');
    expect(parsedInstructions[2].args).toBeUndefined();

    expect(parsedInstructions[3].mnemonic).toBe('end');
    expect(parsedInstructions[3].args).toBeUndefined();
  });
});
