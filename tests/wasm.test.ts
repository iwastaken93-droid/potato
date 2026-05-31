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

  it('should parse the name custom section (module, function, local, type names)', () => {
    // Subsection 0: Module Name "MyModule"
    const sub0 = [
      0x00, // Sub ID 0
      ...encodeVarUint(encodeString('MyModule').length),
      ...encodeString('MyModule'),
    ];

    // Subsection 1: Function Names (index 0 -> "func_zero", index 1 -> "func_one")
    const funcNamesMap = [
      ...encodeVarUint(2), // count
      ...encodeVarUint(0),
      ...encodeString('func_zero'),
      ...encodeVarUint(1),
      ...encodeString('func_one'),
    ];
    const sub1 = [
      0x01, // Sub ID 1
      ...encodeVarUint(funcNamesMap.length),
      ...funcNamesMap,
    ];

    // Subsection 2: Local Names (func 1 -> local 0 -> "loc_zero", local 1 -> "loc_one")
    const localMap = [
      ...encodeVarUint(0), // local 0
      ...encodeString('loc_zero'),
      ...encodeVarUint(1),
      ...encodeString('loc_one'),
    ];
    const localFuncs = [
      ...encodeVarUint(1), // func count
      ...encodeVarUint(1), // func index 1
      ...encodeVarUint(2), // local count
      ...localMap,
    ];
    const sub2 = [
      0x02, // Sub ID 2
      ...encodeVarUint(localFuncs.length),
      ...localFuncs,
    ];

    // Subsection 3: Label Names (func 1 -> label 0 -> "lbl_zero")
    const labelMap = [
      ...encodeVarUint(0), // label 0
      ...encodeString('lbl_zero'),
    ];
    const labelFuncs = [
      ...encodeVarUint(1), // func count
      ...encodeVarUint(1), // func index 1
      ...encodeVarUint(1), // label count
      ...labelMap,
    ];
    const sub3 = [
      0x03, // Sub ID 3
      ...encodeVarUint(labelFuncs.length),
      ...labelFuncs,
    ];

    // Subsection 4: Type Names (index 0 -> "type_zero")
    const typeNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('type_zero'),
    ];
    const sub4 = [
      0x04, // Sub ID 4
      ...encodeVarUint(typeNamesMap.length),
      ...typeNamesMap,
    ];

    // Subsection 5: Table Names (index 0 -> "tab_zero")
    const tableNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('tab_zero'),
    ];
    const sub5 = [
      0x05, // Sub ID 5
      ...encodeVarUint(tableNamesMap.length),
      ...tableNamesMap,
    ];

    // Subsection 6: Memory Names (index 0 -> "mem_zero")
    const memoryNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('mem_zero'),
    ];
    const sub6 = [
      0x06, // Sub ID 6
      ...encodeVarUint(memoryNamesMap.length),
      ...memoryNamesMap,
    ];

    // Subsection 7: Global Names (index 0 -> "glob_zero")
    const globalNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('glob_zero'),
    ];
    const sub7 = [
      0x07, // Sub ID 7
      ...encodeVarUint(globalNamesMap.length),
      ...globalNamesMap,
    ];

    // Subsection 8: Element Names (index 0 -> "elem_zero")
    const elemNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('elem_zero'),
    ];
    const sub8 = [
      0x08, // Sub ID 8
      ...encodeVarUint(elemNamesMap.length),
      ...elemNamesMap,
    ];

    // Subsection 9: Data Names (index 0 -> "dat_zero")
    const dataNamesMap = [
      ...encodeVarUint(1), // count
      ...encodeVarUint(0),
      ...encodeString('dat_zero'),
    ];
    const sub9 = [
      0x09, // Sub ID 9
      ...encodeVarUint(dataNamesMap.length),
      ...dataNamesMap,
    ];

    const namePayload = [
      ...sub0,
      ...sub1,
      ...sub2,
      ...sub3,
      ...sub4,
      ...sub5,
      ...sub6,
      ...sub7,
      ...sub8,
      ...sub9,
    ];
    const nameSectionBytes = encodeString('name');
    const customSectionLength = nameSectionBytes.length + namePayload.length;

    const wasmBytes = new Uint8Array([
      0x00,
      0x61,
      0x73,
      0x6d,
      0x01,
      0x00,
      0x00,
      0x00, // Header
      SectionId.Custom,
      ...encodeVarUint(customSectionLength),
      ...nameSectionBytes,
      ...namePayload,
    ]);

    const module = parseWasm(wasmBytes);
    expect(module.names).toBeDefined();
    expect(module.names?.module).toBe('MyModule');
    expect(module.names?.functions?.[0]).toBe('func_zero');
    expect(module.names?.functions?.[1]).toBe('func_one');
    expect(module.names?.locals?.[1]?.[0]).toBe('loc_zero');
    expect(module.names?.locals?.[1]?.[1]).toBe('loc_one');
    expect(module.names?.labels?.[1]?.[0]).toBe('lbl_zero');
    expect(module.names?.types?.[0]).toBe('type_zero');
    expect(module.names?.tables?.[0]).toBe('tab_zero');
    expect(module.names?.memories?.[0]).toBe('mem_zero');
    expect(module.names?.globals?.[0]).toBe('glob_zero');
    expect(module.names?.elements?.[0]).toBe('elem_zero');
    expect(module.names?.data?.[0]).toBe('dat_zero');
  });

  it('should parse other custom metadata sections (producers, target_features, sourceMappingURL)', () => {
    // 1. producers section
    const producersPayload = [
      ...encodeVarUint(2), // 2 fields
      ...encodeString('language'),
      ...encodeVarUint(1), // 1 value
      ...encodeString('Rust'),
      ...encodeString('1.60.0'),
      ...encodeString('processed-by'),
      ...encodeVarUint(1), // 1 value
      ...encodeString('rustc'),
      ...encodeString('1.60.0'),
    ];
    const producersSectionBytes = encodeString('producers');
    const producersLength =
      producersSectionBytes.length + producersPayload.length;

    // 2. target_features section
    const featuresPayload = [
      ...encodeVarUint(2), // 2 features
      0x2b, // '+'
      ...encodeString('atomics'),
      0x2d, // '-'
      ...encodeString('bulk-memory'),
    ];
    const featuresSectionBytes = encodeString('target_features');
    const featuresLength = featuresSectionBytes.length + featuresPayload.length;

    // 3. sourceMappingURL section
    const sourceMapPayload = [
      ...new TextEncoder().encode('http://example.com/map'),
    ];
    const sourceMapSectionBytes = encodeString('sourceMappingURL');
    const sourceMapLength =
      sourceMapSectionBytes.length + sourceMapPayload.length;

    const wasmBytes = new Uint8Array([
      0x00,
      0x61,
      0x73,
      0x6d,
      0x01,
      0x00,
      0x00,
      0x00, // Header
      SectionId.Custom,
      ...encodeVarUint(producersLength),
      ...producersSectionBytes,
      ...producersPayload,
      SectionId.Custom,
      ...encodeVarUint(featuresLength),
      ...featuresSectionBytes,
      ...featuresPayload,
      SectionId.Custom,
      ...encodeVarUint(sourceMapLength),
      ...sourceMapSectionBytes,
      ...sourceMapPayload,
    ]);

    const module = parseWasm(wasmBytes);
    expect(module.metadata).toBeDefined();
    expect(module.metadata?.producers).toEqual({
      language: { Rust: '1.60.0' },
      'processed-by': { rustc: '1.60.0' },
    });
    expect(module.metadata?.target_features).toEqual([
      '+atomics',
      '-bulk-memory',
    ]);
    expect(module.metadata?.sourceMappingURL).toBe('http://example.com/map');
  });

  it('should parse Wasm component model binaries with imports, exports, and nested core modules', () => {
    const importPayload = [
      ...encodeVarUint(1), // count = 1
      0x00, // tag = 0x00 (simple string)
      ...encodeString('hello_import'),
      0x01, // descTag = 0x01
      ...encodeVarUint(5), // descVal = 5
    ];

    const exportPayload = [
      ...encodeVarUint(1), // count = 1
      0x01, // tag = 0x01 (two strings)
      ...encodeString('pkg'),
      ...encodeString('hello_export'),
      0x00, // sort = 0x00 (func)
      ...encodeVarUint(2), // index = 2
    ];

    const customPayload = [
      ...encodeString('custom_comp'),
      0xaa,
      0xbb,
    ];

    const embeddedWasm = [
      0x00, 0x61, 0x73, 0x6d, // magic
      0x01, 0x00, 0x00, 0x00, // version = 1
    ];

    const wasmBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, // magic
      0x0d, 0x00, 0x01, 0x00, // version = 13, layer = 1 (component)

      10, // Section 10: Import
      ...encodeVarUint(importPayload.length),
      ...importPayload,

      11, // Section 11: Export
      ...encodeVarUint(exportPayload.length),
      ...exportPayload,

      1, // Section 1: Core Module
      ...encodeVarUint(embeddedWasm.length),
      ...embeddedWasm,

      0, // Section 0: Custom
      ...encodeVarUint(customPayload.length),
      ...customPayload,
    ]);

    const module = parseWasm(wasmBytes);
    expect(module.isComponent).toBe(true);
    expect(module.version).toBe(13);
    expect(module.layer).toBe(1);

    expect(module.imports).toHaveLength(1);
    expect(module.imports[0].field).toBe('hello_import');

    expect(module.exports).toHaveLength(1);
    expect(module.exports[0].name).toBe('pkg:hello_export');

    expect(module.componentSections).toHaveLength(4);
    const coreModSection = module.componentSections?.find(s => s.id === 1);
    expect(coreModSection).toBeDefined();
    expect(coreModSection?.modules).toHaveLength(1);
    expect(coreModSection?.modules?.[0].version).toBe(1);

    const customSection = module.customSections.find(s => s.name === 'custom_comp');
    expect(customSection).toBeDefined();
    expect(customSection?.size).toBe(2);
  });

  it('should parse Wasm component model binaries with new component model sections', () => {
    // Section 2: core-instance
    const coreInstPayload = [
      ...encodeVarUint(1), // count = 1
      0x00, // tag = instantiate
      ...encodeVarUint(0), // moduleIdx = 0
      ...encodeVarUint(0), // args count = 0
    ];

    // Section 3: core-type
    const coreTypePayload = [
      ...encodeVarUint(1), // count = 1
      0x60, // tag = func type
      ...encodeVarUint(0), // params = 0
      ...encodeVarUint(0), // results = 0
    ];

    // Section 4: nested component (empty header)
    const compPayload = [
      0x00, 0x61, 0x73, 0x6d,
      0x0d, 0x00, 0x01, 0x00,
    ];

    // Section 5: instance
    const instPayload = [
      ...encodeVarUint(1), // count = 1
      0x00, // tag = instantiate
      ...encodeVarUint(0), // componentIdx = 0
      ...encodeVarUint(0), // args count = 0
    ];

    // Section 6: alias
    const aliasPayload = [
      ...encodeVarUint(1), // count = 1
      0x00, // tag = export
      ...encodeVarUint(0), // instanceIdx = 0
      0x00, // tag = 0x00 (simple string)
      ...encodeString('foo'),
      0x00, // sort = 0
    ];

    // Section 7: type
    const typePayload = [
      ...encodeVarUint(1), // count = 1
      0x72, // tag = record
    ];

    // Section 8: canon
    const canonPayload = [
      ...encodeVarUint(1), // count = 1
      0x00, // tag = lift
      ...encodeVarUint(0), // coreFuncIdx = 0
      ...encodeVarUint(0), // options = 0
    ];

    // Section 9: start
    const startPayload = [
      ...encodeVarUint(0), // funcIdx = 0
      ...encodeVarUint(0), // args = 0
      ...encodeVarUint(0), // results = 0
    ];

    // Section 12: value
    const valuePayload = [
      ...encodeVarUint(1), // count = 1
      0x7f, // valType = 0x7f
    ];

    const wasmBytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, // magic
      0x0d, 0x00, 0x01, 0x00, // version = 13, layer = 1 (component)

      2, // Section 2
      ...encodeVarUint(coreInstPayload.length),
      ...coreInstPayload,

      3, // Section 3
      ...encodeVarUint(coreTypePayload.length),
      ...coreTypePayload,

      4, // Section 4
      ...encodeVarUint(compPayload.length),
      ...compPayload,

      5, // Section 5
      ...encodeVarUint(instPayload.length),
      ...instPayload,

      6, // Section 6
      ...encodeVarUint(aliasPayload.length),
      ...aliasPayload,

      7, // Section 7
      ...encodeVarUint(typePayload.length),
      ...typePayload,

      8, // Section 8
      ...encodeVarUint(canonPayload.length),
      ...canonPayload,

      9, // Section 9
      ...encodeVarUint(startPayload.length),
      ...startPayload,

      12, // Section 12
      ...encodeVarUint(valuePayload.length),
      ...valuePayload,
    ]);

    const module = parseWasm(wasmBytes);
    expect(module.isComponent).toBe(true);

    const s2 = module.componentSections?.find(s => s.id === 2);
    expect(s2).toBeDefined();
    expect(s2?.coreInstances).toHaveLength(1);
    expect(s2?.coreInstances?.[0].type).toBe('instantiate');

    const s3 = module.componentSections?.find(s => s.id === 3);
    expect(s3).toBeDefined();
    expect(s3?.coreTypes).toHaveLength(1);
    expect(s3?.coreTypes?.[0].type).toBe('func');

    const s4 = module.componentSections?.find(s => s.id === 4);
    expect(s4).toBeDefined();
    expect(s4?.modules).toHaveLength(1);
    expect(s4?.modules?.[0].isComponent).toBe(true);

    const s5 = module.componentSections?.find(s => s.id === 5);
    expect(s5).toBeDefined();
    expect(s5?.instances).toHaveLength(1);
    expect(s5?.instances?.[0].type).toBe('instantiate');

    const s6 = module.componentSections?.find(s => s.id === 6);
    expect(s6).toBeDefined();
    expect(s6?.aliases).toHaveLength(1);
    expect(s6?.aliases?.[0].name).toBe('foo');

    const s7 = module.componentSections?.find(s => s.id === 7);
    expect(s7).toBeDefined();
    expect(s7?.types).toHaveLength(1);
    expect(s7?.types?.[0].tag).toBe(0x72);

    const s8 = module.componentSections?.find(s => s.id === 8);
    expect(s8).toBeDefined();
    expect(s8?.canons).toHaveLength(1);
    expect(s8?.canons?.[0].type).toBe('lift');

    const s9 = module.componentSections?.find(s => s.id === 9);
    expect(s9).toBeDefined();
    expect(s9?.starts).toHaveLength(1);
    expect(s9?.starts?.[0].funcIdx).toBe(0);

    const s12 = module.componentSections?.find(s => s.id === 12);
    expect(s12).toBeDefined();
    expect(s12?.values).toHaveLength(1);
    expect(s12?.values?.[0].valType).toBe(0x7f);
  });
});

