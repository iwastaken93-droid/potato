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
});
