import { describe, it, expect } from 'vitest';
import { PEParser } from '../src/parser/pe.js';

describe('PE Parser Unit Tests', () => {
  it('should successfully parse a valid 32-bit PE (PE32) binary header', () => {
    // Allocate buffer: DOS header (64) + PE signature (4) + COFF header (20) + Optional header (224) + 1 Section (40) = 352 bytes
    const buffer = new ArrayBuffer(352);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. DOS Header
    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);

    // 2. PE Signature
    view.setUint32(e_lfanew, 0x00004550, true); // "PE\0\0"

    // 3. COFF File Header
    const coffOffset = e_lfanew + 4; // 68
    view.setUint16(coffOffset, 0x14c, true); // Machine: Intel 386
    view.setUint16(coffOffset + 2, 1, true); // Number of Sections: 1
    view.setUint32(coffOffset + 4, 1234567890, true); // TimeDateStamp
    view.setUint32(coffOffset + 8, 0, true); // PointerToSymbolTable
    view.setUint32(coffOffset + 12, 0, true); // NumberOfSymbols
    const sizeOfOptionalHeader = 224;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true); // SizeOfOptionalHeader
    view.setUint16(coffOffset + 18, 0x0102, true); // Characteristics

    // 4. Optional Header (PE32: Magic = 0x10b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x10b, true); // Magic (PE32)
    view.setUint8(optionalOffset + 2, 2); // MajorLinkerVersion
    view.setUint8(optionalOffset + 3, 25); // MinorLinkerVersion
    view.setUint32(optionalOffset + 4, 0x1000, true); // SizeOfCode
    view.setUint32(optionalOffset + 8, 0x2000, true); // SizeOfInitializedData
    view.setUint32(optionalOffset + 12, 0, true); // SizeOfUninitializedData
    view.setUint32(optionalOffset + 16, 0x1000, true); // AddressOfEntryPoint
    view.setUint32(optionalOffset + 20, 0x1000, true); // BaseOfCode
    view.setUint32(optionalOffset + 24, 0x2000, true); // BaseOfData

    // Windows-Specific Fields (from optionalOffset + 28 for PE32)
    const winOffset = optionalOffset + 28; // 116
    view.setUint32(winOffset, 0x400000, true); // ImageBase (32-bit: 0x400000)
    view.setUint32(winOffset + 4, 0x1000, true); // SectionAlignment
    view.setUint32(winOffset + 8, 0x200, true); // FileAlignment
    view.setUint16(winOffset + 12, 4, true); // MajorOperatingSystemVersion
    view.setUint16(winOffset + 14, 0, true); // MinorOperatingSystemVersion
    view.setUint16(winOffset + 16, 1, true); // MajorImageVersion
    view.setUint16(winOffset + 18, 0, true); // MinorImageVersion
    view.setUint16(winOffset + 20, 4, true); // MajorSubsystemVersion
    view.setUint16(winOffset + 22, 0, true); // MinorSubsystemVersion
    view.setUint32(winOffset + 24, 0, true); // Win32VersionValue
    view.setUint32(winOffset + 28, 0x8000, true); // SizeOfImage
    view.setUint32(winOffset + 32, 0x400, true); // SizeOfHeaders
    view.setUint32(winOffset + 36, 0, true); // CheckSum
    view.setUint16(winOffset + 40, 3, true); // Subsystem (Console)
    view.setUint16(winOffset + 42, 0x8140, true); // DllCharacteristics

    // Stack and Heap (PE32: 16 bytes starting at winOffset + 44)
    const stackHeapOffset = winOffset + 44; // 160
    view.setUint32(stackHeapOffset, 0x100000, true); // SizeOfStackReserve
    view.setUint32(stackHeapOffset + 4, 0x1000, true); // SizeOfStackCommit
    view.setUint32(stackHeapOffset + 8, 0x100000, true); // SizeOfHeapReserve
    view.setUint32(stackHeapOffset + 12, 0x1000, true); // SizeOfHeapCommit

    const afterStackHeapOffset = stackHeapOffset + 16; // 176
    view.setUint32(afterStackHeapOffset, 0, true); // LoaderFlags
    view.setUint32(afterStackHeapOffset + 4, 2, true); // NumberOfRvaAndSizes (we'll test with 2 directories)

    // Data Directories starting at afterStackHeapOffset + 8 (184)
    const dirOffset = afterStackHeapOffset + 8; // 184
    // Export Directory
    view.setUint32(dirOffset, 0, true); // Export VirtualAddress
    view.setUint32(dirOffset + 4, 0, true); // Export Size
    // Import Directory
    view.setUint32(dirOffset + 8, 0, true); // Import VirtualAddress
    view.setUint32(dirOffset + 12, 0, true); // Import Size

    // 5. Section Headers (offset = optionalOffset + sizeOfOptionalHeader = 88 + 224 = 312)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 312
    // Section Name: ".text"
    bytes[sectionOffset] = 0x2e; // '.'
    bytes[sectionOffset + 1] = 0x74; // 't'
    bytes[sectionOffset + 2] = 0x65; // 'e'
    bytes[sectionOffset + 3] = 0x78; // 'x'
    bytes[sectionOffset + 4] = 0x74; // 't'
    // Other fields
    view.setUint32(sectionOffset + 8, 0x1000, true); // VirtualSize
    view.setUint32(sectionOffset + 12, 0x1000, true); // VirtualAddress
    view.setUint32(sectionOffset + 16, 0x200, true); // SizeOfRawData
    view.setUint32(sectionOffset + 20, 0x400, true); // PointerToRawData
    view.setUint32(sectionOffset + 24, 0, true); // PointerToRelocations
    view.setUint32(sectionOffset + 28, 0, true); // PointerToLinenumbers
    view.setUint16(sectionOffset + 32, 0, true); // NumberOfRelocations
    view.setUint16(sectionOffset + 34, 0, true); // NumberOfLinenumbers
    view.setUint32(sectionOffset + 36, 0x60000020, true); // Characteristics (CODE, EXECUTE, READ)

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    // Verify DOS Header
    expect(parsed.is32Bit).toBe(true);
    expect(parsed.dosHeader.magic).toBe('MZ');
    expect(parsed.dosHeader.e_lfanew).toBe(64);

    // Verify COFF Header
    expect(parsed.coffHeader.machine).toBe(0x14c);
    expect(parsed.coffHeader.numberOfSections).toBe(1);
    expect(parsed.coffHeader.timeDateStamp).toBe(1234567890);
    expect(parsed.coffHeader.sizeOfOptionalHeader).toBe(224);

    // Verify Optional Header
    expect(parsed.optionalHeader.magic).toBe(0x10b);
    expect(parsed.optionalHeader.majorLinkerVersion).toBe(2);
    expect(parsed.optionalHeader.minorLinkerVersion).toBe(25);
    expect(parsed.optionalHeader.imageBase).toBe(0x400000);
    expect(parsed.optionalHeader.subsystem).toBe(3);
    expect(parsed.optionalHeader.numberOfRvaAndSizes).toBe(2);
    expect(parsed.optionalHeader.dataDirectories.length).toBe(2);

    // Verify Sections
    expect(parsed.sections.length).toBe(1);
    expect(parsed.sections[0].name).toBe('.text');
    expect(parsed.sections[0].virtualAddress).toBe(0x1000);
    expect(parsed.sections[0].characteristics).toBe(0x60000020);
  });

  it('should successfully parse a valid 64-bit PE (PE32+) binary header', () => {
    // Allocate buffer: DOS header (64) + PE signature (4) + COFF header (20) + Optional header (240) + 1 Section (40) = 368 bytes
    const buffer = new ArrayBuffer(368);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. DOS Header
    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);

    // 2. PE Signature
    view.setUint32(e_lfanew, 0x00004550, true);

    // 3. COFF File Header
    const coffOffset = e_lfanew + 4; // 68
    view.setUint16(coffOffset, 0x8664, true); // Machine: AMD64
    view.setUint16(coffOffset + 2, 1, true); // Number of Sections: 1
    view.setUint32(coffOffset + 4, 1111111111, true);
    const sizeOfOptionalHeader = 240;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);
    view.setUint16(coffOffset + 18, 0x0022, true);

    // 4. Optional Header (PE32+: Magic = 0x20b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x20b, true); // Magic (PE32+)
    view.setUint8(optionalOffset + 2, 14);
    view.setUint8(optionalOffset + 3, 0);
    view.setUint32(optionalOffset + 4, 0x1000, true);
    view.setUint32(optionalOffset + 8, 0x1000, true);
    view.setUint32(optionalOffset + 12, 0, true);
    view.setUint32(optionalOffset + 16, 0x1200, true);
    view.setUint32(optionalOffset + 20, 0x1000, true);

    // Windows-Specific Fields (from optionalOffset + 24 for PE32+)
    const winOffset = optionalOffset + 24; // 112
    view.setBigUint64(winOffset, 0x140000000n, true); // ImageBase (64-bit)
    view.setUint32(winOffset + 8, 0x1000, true);
    view.setUint32(winOffset + 12, 0x200, true);
    view.setUint16(winOffset + 16, 6, true); // OS Major
    view.setUint16(winOffset + 18, 0, true); // OS Minor
    view.setUint16(winOffset + 20, 0, true);
    view.setUint16(winOffset + 22, 0, true);
    view.setUint16(winOffset + 24, 6, true); // Subsystem Major
    view.setUint16(winOffset + 26, 0, true); // Subsystem Minor
    view.setUint32(winOffset + 28, 0, true);
    view.setUint32(winOffset + 32, 0xa000, true); // SizeOfImage
    view.setUint32(winOffset + 36, 0x400, true); // SizeOfHeaders
    view.setUint32(winOffset + 40, 0, true);
    view.setUint16(winOffset + 44, 2, true); // Subsystem (Windows GUI)
    view.setUint16(winOffset + 46, 0x8140, true);

    // Stack and Heap (PE32+: 32 bytes starting at winOffset + 48)
    const stackHeapOffset = winOffset + 48; // 160
    view.setBigUint64(stackHeapOffset, 0x100000n, true); // SizeOfStackReserve
    view.setBigUint64(stackHeapOffset + 8, 0x1000n, true); // SizeOfStackCommit
    view.setBigUint64(stackHeapOffset + 16, 0x100000n, true); // SizeOfHeapReserve
    view.setBigUint64(stackHeapOffset + 24, 0x1000n, true); // SizeOfHeapCommit

    const afterStackHeapOffset = stackHeapOffset + 32; // 192
    view.setUint32(afterStackHeapOffset, 0, true);
    view.setUint32(afterStackHeapOffset + 4, 1, true); // NumberOfRvaAndSizes

    // Data Directories starting at afterStackHeapOffset + 8 (200)
    const dirOffset = afterStackHeapOffset + 8; // 200
    view.setUint32(dirOffset, 0, true);
    view.setUint32(dirOffset + 4, 0, true);

    // 5. Section Headers (offset = optionalOffset + sizeOfOptionalHeader = 88 + 240 = 328)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 328
    // Section Name: ".data"
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x64;
    bytes[sectionOffset + 2] = 0x61;
    bytes[sectionOffset + 3] = 0x74;
    bytes[sectionOffset + 4] = 0x61;
    // Other fields
    view.setUint32(sectionOffset + 8, 0x2000, true);
    view.setUint32(sectionOffset + 12, 0x2000, true);
    view.setUint32(sectionOffset + 16, 0x400, true);
    view.setUint32(sectionOffset + 20, 0x600, true);
    view.setUint32(sectionOffset + 24, 0, true);
    view.setUint32(sectionOffset + 28, 0, true);
    view.setUint16(sectionOffset + 32, 0, true);
    view.setUint16(sectionOffset + 34, 0, true);
    view.setUint32(sectionOffset + 36, 0xc0000040, true); // Characteristics (INITIALIZED_DATA, READ, WRITE)

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    expect(parsed.is32Bit).toBe(false);
    expect(parsed.dosHeader.magic).toBe('MZ');
    expect(parsed.optionalHeader.magic).toBe(0x20b);
    expect(parsed.optionalHeader.imageBase).toBe(0x140000000n);
    expect(parsed.sections[0].name).toBe('.data');
  });

  it('should throw an error if the buffer is too small to contain a valid DOS header', () => {
    const buffer = new ArrayBuffer(32);
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow(
      'File too small to contain a valid DOS header'
    );
  });

  it('should throw an error for invalid DOS MZ signature', () => {
    const buffer = new ArrayBuffer(64);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x41; // 'A'
    bytes[1] = 0x42; // 'B'
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow('Invalid DOS MZ header signature');
  });

  it('should throw an error if PE header offset points outside of file limits', () => {
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 100, true); // Points past the end of the buffer (64)
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow(
      'PE header offset points outside of file limits'
    );
  });

  it('should throw an error if PE signature is invalid', () => {
    const buffer = new ArrayBuffer(128);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    view.setUint32(60, 64, true);
    view.setUint32(64, 0x12345678, true); // Invalid PE signature
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow('Invalid PE signature');
  });
});
