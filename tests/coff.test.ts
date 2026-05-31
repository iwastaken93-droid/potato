import { describe, it, expect } from 'vitest';
import { CoffParser } from '../src/parser/coff.js';

describe('COFF/XCOFF Parser Unit Tests', () => {
  it('should successfully parse a standard COFF (PE-like) little-endian header', () => {
    // 20 bytes file header + 40 bytes section header + 18 bytes symbol + string table
    const buffer = new ArrayBuffer(100);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. File Header
    view.setUint16(0, 0x14c, true); // Machine: Intel 386
    view.setUint16(2, 1, true); // Number of Sections: 1
    view.setUint32(4, 12345678, true); // TimeDateStamp
    view.setUint32(8, 60, true); // PointerToSymbolTable
    view.setUint32(12, 1, true); // NumberOfSymbols: 1
    view.setUint16(16, 0, true); // SizeOfOptionalHeader: 0
    view.setUint16(18, 0x0102, true); // Characteristics

    // 2. Section Header (offset 20)
    // Section Name: ".text"
    bytes[20] = 0x2e; bytes[21] = 0x74; bytes[22] = 0x65; bytes[23] = 0x78; bytes[24] = 0x74;
    view.setUint32(28, 0x1000, true); // PhysicalAddress / VirtualSize
    view.setUint32(32, 0x1000, true); // VirtualAddress
    view.setUint32(36, 0x200, true); // Size
    view.setUint32(40, 0x400, true); // PointerToRawData
    view.setUint32(44, 0, true); // PointerToRelocations
    view.setUint32(48, 0, true); // PointerToLinenumbers
    view.setUint16(52, 0, true); // NumberOfRelocations
    view.setUint16(54, 0, true); // NumberOfLinenumbers
    view.setUint32(56, 0x60000020, true); // Characteristics

    // 3. Symbol Table (offset 60)
    // Inline Name: "main"
    bytes[60] = 0x6d; bytes[61] = 0x61; bytes[62] = 0x69; bytes[63] = 0x6e;
    view.setUint32(68, 0x1000, true); // Value
    view.setInt16(72, 1, true); // Section Number: 1
    view.setUint16(74, 0x20, true); // Type
    bytes[76] = 2; // Storage Class: External
    bytes[77] = 0; // Number of Aux Symbols: 0

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();

    expect(parsed.is64Bit).toBe(false);
    expect(parsed.isBigEndian).toBe(false);
    expect(parsed.header.machineName).toBe('Intel 386');
    expect(parsed.sections).toHaveLength(1);
    expect(parsed.sections[0].name).toBe('.text');
    expect(parsed.symbols).toHaveLength(1);
    expect(parsed.symbols[0].name).toBe('main');
    expect(parsed.symbols[0].value).toBe(0x1000);
  });

  it('should successfully parse a standard COFF with string table references', () => {
    // 20 bytes file header + 40 bytes section header + 18 bytes symbol + string table (8 bytes: length 8, "longsym\0")
    const buffer = new ArrayBuffer(20 + 40 + 18 + 8);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. File Header
    view.setUint16(0, 0x14c, true);
    view.setUint16(2, 1, true);
    view.setUint32(4, 12345678, true);
    view.setUint32(8, 60, true);
    view.setUint32(12, 1, true);
    view.setUint16(16, 0, true);
    view.setUint16(18, 0, true);

    // 2. Section Header (offset 20)
    // String table name reference: "/4" (meaning offset 4 in string table)
    bytes[20] = 0x2f; bytes[21] = 0x34; // '/' and '4'
    view.setUint32(28, 0x1000, true);
    view.setUint32(32, 0x1000, true);
    view.setUint32(36, 0x200, true);
    view.setUint32(40, 0x400, true);
    view.setUint32(44, 0, true);
    view.setUint32(48, 0, true);
    view.setUint16(52, 0, true);
    view.setUint16(54, 0, true);
    view.setUint32(56, 0x60000020, true);

    // 3. Symbol Table (offset 60)
    // String table reference: zero-magic (first 4 bytes 0) + offset 4
    view.setUint32(60, 0, true);
    view.setUint32(64, 4, true); // Offset 4
    view.setUint32(68, 0x1000, true);
    view.setInt16(72, 1, true);
    view.setUint16(74, 0x20, true);
    bytes[76] = 2;
    bytes[77] = 0;

    // 4. String Table (offset 78)
    view.setUint32(78, 8, true); // Length of string table (4 bytes size + 4 bytes string)
    // String at offset 4: "sym\0"
    bytes[82] = 0x73; bytes[83] = 0x79; bytes[84] = 0x6d; bytes[85] = 0;

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();

    expect(parsed.sections[0].name).toBe('sym');
    expect(parsed.symbols[0].name).toBe('sym');
  });

  it('should successfully parse a big-endian XCOFF32 binary header and symbols', () => {
    // 20 bytes file header + 40 bytes section header + 18 bytes symbol
    const buffer = new ArrayBuffer(20 + 40 + 18);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Big-endian magic U802TOCMAGIC = 0x01df
    view.setUint16(0, 0x01df, false);
    view.setUint16(2, 1, false);
    view.setUint32(4, 12345678, false);
    view.setUint32(8, 60, false);
    view.setUint32(12, 1, false);
    view.setUint16(16, 0, false);
    view.setUint16(18, 0, false);

    // Section Header (offset 20)
    bytes[20] = 0x2e; bytes[21] = 0x74; bytes[22] = 0x65; bytes[23] = 0x78; bytes[24] = 0x74;
    view.setUint32(28, 0x1000, false);
    view.setUint32(32, 0x1000, false);
    view.setUint32(36, 0x200, false);
    view.setUint32(40, 0x400, false);
    view.setUint32(44, 0, false);
    view.setUint32(48, 0, false);
    view.setUint16(52, 0, false);
    view.setUint16(54, 0, false);
    view.setUint32(56, 0x60000020, false);

    // Symbol Table (offset 60)
    bytes[60] = 0x6d; bytes[61] = 0x61; bytes[62] = 0x69; bytes[63] = 0x6e;
    view.setUint32(68, 0x1000, false);
    view.setInt16(72, 1, false);
    view.setUint16(74, 0x20, false);
    bytes[76] = 2;
    bytes[77] = 0;

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();

    expect(parsed.is64Bit).toBe(false);
    expect(parsed.isBigEndian).toBe(true);
    expect(parsed.header.machineName).toBe('PowerPC (XCOFF32)');
    expect(parsed.sections[0].name).toBe('.text');
    expect(parsed.symbols[0].name).toBe('main');
  });

  it('should successfully parse a big-endian XCOFF64 binary header, sections, and symbols', () => {
    // 24 bytes file header + 72 bytes section header + 18 bytes symbol + string table (8 bytes)
    const buffer = new ArrayBuffer(24 + 72 + 18 + 8);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // Big-endian magic XCOFF64 = 0x01f6
    view.setUint16(0, 0x01f6, false);
    view.setUint16(2, 1, false);
    view.setUint32(4, 12345678, false);
    view.setBigUint64(8, 96n, false); // pointerToSymbolTable: 96
    view.setUint32(16, 1, false);
    view.setUint16(20, 0, false);
    view.setUint16(22, 0, false);

    // Section Header (offset 24)
    bytes[24] = 0x2e; bytes[25] = 0x64; bytes[26] = 0x61; bytes[27] = 0x74; bytes[28] = 0x61; // ".data"
    view.setBigUint64(32, 0x2000n, false); // physical address
    view.setBigUint64(40, 0x2000n, false); // virtual address
    view.setBigUint64(48, 0x400n, false); // size
    view.setBigUint64(56, 0x800n, false); // pointer to raw data
    view.setBigUint64(64, 0n, false);
    view.setBigUint64(72, 0n, false);
    view.setUint32(80, 0, false);
    view.setUint32(84, 0, false);
    view.setUint32(88, 0x40, false); // flags/characteristics

    // Symbol Table (offset 96)
    view.setBigUint64(96, 0x2000n, false); // value
    view.setUint32(104, 4, false); // nameOffset = 4
    view.setInt16(108, 1, false);
    view.setUint16(110, 0x20, false);
    bytes[112] = 2;
    bytes[113] = 0;

    // String Table (offset 114)
    view.setUint32(114, 8, false); // size = 8
    bytes[118] = 0x66; bytes[119] = 0x6f; bytes[120] = 0x6f; bytes[121] = 0; // "foo\0"

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();

    expect(parsed.is64Bit).toBe(true);
    expect(parsed.isBigEndian).toBe(true);
    expect(parsed.header.machineName).toBe('PowerPC (XCOFF64)');
    expect(parsed.sections[0].name).toBe('.data');
    expect(parsed.sections[0].size).toBe(0x400n);
    expect(parsed.symbols[0].name).toBe('foo');
    expect(parsed.symbols[0].value).toBe(0x2000n);
  });

  it('should throw an error if buffer is too small for standard COFF header', () => {
    const buffer = new ArrayBuffer(15);
    const parser = new CoffParser(buffer);
    expect(() => parser.parse()).toThrow('File too small to contain a COFF header');
  });

  it('should throw an error if buffer is too small for XCOFF64 header', () => {
    const buffer = new ArrayBuffer(22);
    const view = new DataView(buffer);
    // Write XCOFF64 magic
    view.setUint16(0, 0x01f6, false);
    const parser = new CoffParser(buffer);
    expect(() => parser.parse()).toThrow('File too small to contain an XCOFF64 header');
  });

  it('should return Unknown for unrecognized machine types', () => {
    const buffer = new ArrayBuffer(20);
    const view = new DataView(buffer);
    view.setUint16(0, 0x9999, true); // Unknown magic / machine
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.header.machineName).toBe('Unknown');
  });

  it('should handle zero symbol table pointer or zero symbols count', () => {
    const buffer = new ArrayBuffer(20);
    const view = new DataView(buffer);
    view.setUint16(0, 0x14c, true); // Intel 386
    view.setUint32(8, 0, true); // pointerToSymbolTable = 0
    view.setUint32(12, 0, true); // numberOfSymbols = 0
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols).toHaveLength(0);
  });

  it('should handle out of bounds string table offset', () => {
    const buffer = new ArrayBuffer(20 + 18);
    const view = new DataView(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint32(8, 20, true); // pointerToSymbolTable = 20
    view.setUint32(12, 1, true); // numberOfSymbols = 1 (ends at 38, so string table starts at 38)
    // but the buffer size is only 38, so stringTableOffset + 4 is out of bounds
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols).toHaveLength(1);
    expect(parsed.symbols[0].name).toBe('');
  });

  it('should handle out of bounds section headers', () => {
    // 20 bytes file header, expects 2 sections (requires 20 + 2 * 40 = 100 bytes)
    // but we only provide 40 bytes
    const buffer = new ArrayBuffer(40);
    const view = new DataView(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint16(2, 2, true); // numberOfSections = 2
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    // Should parse only the first section and break on the second
    expect(parsed.sections).toHaveLength(0);
  });

  it('should parse section name with slash but invalid offset', () => {
    // '/' followed by non-numeric 'abc'
    const buffer = new ArrayBuffer(20 + 40);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint16(2, 1, true); // 1 section

    bytes[20] = 0x2f; // '/'
    bytes[21] = 0x61; bytes[22] = 0x62; bytes[23] = 0x63; // 'abc'
    
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.sections[0].name).toBe('abc');
  });

  it('should parse section name without null terminator within 8 bytes', () => {
    const buffer = new ArrayBuffer(20 + 40);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint16(2, 1, true);

    // Section name: "12345678" (exactly 8 bytes)
    for (let i = 0; i < 8; i++) {
      bytes[20 + i] = 0x31 + i;
    }

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.sections[0].name).toBe('12345678');
  });

  it('should handle out-of-bounds nameOffset in 64-bit symbols', () => {
    const buffer = new ArrayBuffer(24 + 18);
    const view = new DataView(buffer);
    // XCOFF64 magic
    view.setUint16(0, 0x01f6, false);
    view.setUint16(2, 0, false);
    view.setBigUint64(8, 24n, false); // pointerToSymbolTable = 24
    view.setUint32(16, 1, false); // numberOfSymbols = 1

    // Symbol: value (8 bytes), nameOffset = 9999 (4 bytes, out of bounds)
    view.setBigUint64(24, 0x1000n, false);
    view.setUint32(32, 9999, false); // nameOffset
    
    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols[0].name).toBe('');
  });

  it('should skip auxiliary symbols during symbol parsing', () => {
    // 20 bytes header + 18 bytes main sym + 18 bytes aux sym 1 + 18 bytes aux sym 2
    const buffer = new ArrayBuffer(20 + 18 + 18 + 18);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true); // Intel 386
    view.setUint32(8, 20, true); // pointerToSymbolTable = 20
    view.setUint32(12, 3, true); // numberOfSymbols = 3

    // Symbol 0 (main symbol)
    bytes[20] = 0x73; bytes[21] = 0x79; bytes[22] = 0x6d; bytes[23] = 0x00; // "sym"
    view.setUint32(28, 0x1000, true); // value
    view.setInt16(32, 1, true); // section
    bytes[36] = 2; // Storage Class
    bytes[37] = 2; // Number of Aux Symbols = 2 (so symbol 1 and symbol 2 are aux, skipped)

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols).toHaveLength(1);
    expect(parsed.symbols[0].name).toBe('sym');
  });

  it('should handle non-null-terminated string table at buffer end', () => {
    // 20 bytes header + 18 bytes symbol + string table (8 bytes, no null terminator at end)
    const buffer = new ArrayBuffer(20 + 18 + 8);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint32(8, 20, true); // pointerToSymbolTable = 20
    view.setUint32(12, 1, true); // numberOfSymbols = 1

    // Symbol 0
    view.setUint32(20, 0, true); // nameZero = 0
    view.setUint32(24, 4, true); // nameOffset = 4

    // String table (starts at 38)
    view.setUint32(38, 8, true); // size = 8
    bytes[42] = 0x61; bytes[43] = 0x62; bytes[44] = 0x63; bytes[45] = 0x64; // "abcd" without null terminator

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols[0].name).toBe('abcd');
  });

  it('should return empty string table if size is invalid or out of bounds', () => {
    // String table offset is 38. If we set size of string table to 100, but buffer is only 46 bytes.
    const buffer = new ArrayBuffer(20 + 18 + 8);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint32(8, 20, true);
    view.setUint32(12, 1, true);

    // String table size = 100 (out of bounds)
    view.setUint32(38, 100, true);

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols[0].name).toBe('');
  });

  it('should return empty string table if size is less than 4', () => {
    const buffer = new ArrayBuffer(20 + 18 + 8);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    view.setUint16(0, 0x14c, true);
    view.setUint32(8, 20, true);
    view.setUint32(12, 1, true);

    // String table size = 2 (less than 4)
    view.setUint32(38, 2, true);

    const parser = new CoffParser(buffer);
    const parsed = parser.parse();
    expect(parsed.symbols[0].name).toBe('');
  });

  it('should lookup machine names correctly for all known types', () => {
    const machines = [
      { code: 0x8664, name: 'AMD64 (x64)' },
      { code: 0x01f7, name: 'PowerPC 64-bit (XCOFF32)' },
      { code: 0xaa64, name: 'ARM64' },
      { code: 0x5064, name: 'RISCV64' }
    ];
    for (const mach of machines) {
      const buffer = new ArrayBuffer(20);
      const view = new DataView(buffer);
      view.setUint16(0, mach.code, true);
      const parser = new CoffParser(buffer);
      const parsed = parser.parse();
      expect(parsed.header.machineName).toBe(mach.name);
    }
  });
});

