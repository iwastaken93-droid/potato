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

  it('should parse exports and imports for a 32-bit PE binary', () => {
    const buffer = new ArrayBuffer(16384);
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
    view.setUint16(coffOffset, 0x14c, true); // Machine
    view.setUint16(coffOffset + 2, 3, true); // 3 Sections
    view.setUint32(coffOffset + 4, 1234567890, true);
    const sizeOfOptionalHeader = 224;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);
    view.setUint16(coffOffset + 18, 0x0102, true);

    // 4. Optional Header (PE32: Magic = 0x10b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x10b, true); // Magic

    const stackHeapOffset = optionalOffset + 28 + 44; // 160
    view.setUint32(stackHeapOffset + 16 + 4, 2, true); // NumberOfRvaAndSizes = 2

    const dirOffset = stackHeapOffset + 16 + 8; // 184
    // Export directory
    view.setUint32(dirOffset, 0x3000, true); // Export VirtualAddress
    view.setUint32(dirOffset + 4, 0x200, true); // Export Size
    // Import directory
    view.setUint32(dirOffset + 8, 0x4000, true); // Import VirtualAddress
    view.setUint32(dirOffset + 12, 0x200, true); // Import Size

    // 5. Section Headers (offset = optionalOffset + sizeOfOptionalHeader = 88 + 224 = 312)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 312

    // Section 1: .text
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x74;
    bytes[sectionOffset + 2] = 0x65;
    bytes[sectionOffset + 3] = 0x78;
    bytes[sectionOffset + 4] = 0x74;
    view.setUint32(sectionOffset + 8, 0x1000, true); // VirtualSize
    view.setUint32(sectionOffset + 12, 0x1000, true); // VirtualAddress
    view.setUint32(sectionOffset + 16, 0x200, true); // SizeOfRawData
    view.setUint32(sectionOffset + 20, 0x400, true); // PointerToRawData

    // Section 2: .edata (Export data)
    const sec2Offset = sectionOffset + 40; // 352
    bytes[sec2Offset] = 0x2e;
    bytes[sec2Offset + 1] = 0x65;
    bytes[sec2Offset + 2] = 0x64;
    bytes[sec2Offset + 3] = 0x61;
    bytes[sec2Offset + 4] = 0x74;
    bytes[sec2Offset + 5] = 0x61;
    view.setUint32(sec2Offset + 8, 0x1000, true);
    view.setUint32(sec2Offset + 12, 0x3000, true);
    view.setUint32(sec2Offset + 16, 0x1000, true);
    view.setUint32(sec2Offset + 20, 0x1000, true);

    // Section 3: .idata (Import data)
    const sec3Offset = sectionOffset + 80; // 392
    bytes[sec3Offset] = 0x2e;
    bytes[sec3Offset + 1] = 0x69;
    bytes[sec3Offset + 2] = 0x69;
    bytes[sec3Offset + 3] = 0x64;
    bytes[sec3Offset + 4] = 0x74;
    bytes[sec3Offset + 5] = 0x61; // typo? let's make it ".idata"
    // Wait, bytes[sec3Offset] is '.', 'i', 'd', 'a', 't', 'a'. Let's correct it:
    bytes[sec3Offset] = 0x2e;
    bytes[sec3Offset + 1] = 0x69;
    bytes[sec3Offset + 2] = 0x64;
    bytes[sec3Offset + 3] = 0x61;
    bytes[sec3Offset + 4] = 0x74;
    bytes[sec3Offset + 5] = 0x61;
    view.setUint32(sec3Offset + 8, 0x1000, true);
    view.setUint32(sec3Offset + 12, 0x4000, true);
    view.setUint32(sec3Offset + 16, 0x1000, true);
    view.setUint32(sec3Offset + 20, 0x2000, true);

    // Write Export Directory at 0x3000 (file offset 0x1000)
    const expOffset = 0x1000;
    view.setUint32(expOffset, 0, true); // Characteristics
    view.setUint32(expOffset + 4, 987654321, true); // TimeDateStamp
    view.setUint16(expOffset + 8, 1, true); // Major
    view.setUint16(expOffset + 10, 0, true); // Minor
    view.setUint32(expOffset + 12, 0x3030, true); // nameRva (points to 0x3030, file offset 0x1030)
    view.setUint32(expOffset + 16, 1, true); // ordinalBase
    view.setUint32(expOffset + 20, 3, true); // numberOfFunctions
    view.setUint32(expOffset + 24, 2, true); // numberOfNames
    view.setUint32(expOffset + 28, 0x3060, true); // addressOfFunctions (points to 0x3060, file offset 0x1060)
    view.setUint32(expOffset + 32, 0x3070, true); // addressOfNames (points to 0x3070, file offset 0x1070)
    view.setUint32(expOffset + 36, 0x3080, true); // addressOfNameOrdinals (points to 0x3080, file offset 0x1080)

    // Write DLL name at 0x3030 (file offset 0x1030)
    const dllName = 'my_dll.dll';
    for (let i = 0; i < dllName.length; i++) {
      bytes[0x1030 + i] = dllName.charCodeAt(i);
    }
    bytes[0x1030 + dllName.length] = 0;

    // Write addressOfFunctions at 0x3060 (file offset 0x1060)
    // Function 1 (ordinal 1): funcRva = 0x1500 (normal function, not inside export dir)
    // Function 2 (ordinal 2): funcRva = 0x3040 (within export dir 0x3000-0x3200 -> forwarder)
    // Function 3 (ordinal 3): funcRva = 0 (skipped)
    view.setUint32(0x1060, 0x1500, true);
    view.setUint32(0x1064, 0x3040, true);
    view.setUint32(0x1068, 0x0000, true);

    // Write forwarder string at 0x3040 (file offset 0x1040)
    const forwarder = 'other_dll.other_func';
    for (let i = 0; i < forwarder.length; i++) {
      bytes[0x1040 + i] = forwarder.charCodeAt(i);
    }
    bytes[0x1040 + forwarder.length] = 0;

    // Write addressOfNames at 0x3070 (file offset 0x1070)
    // Name 1: nameStringRva = 0x3090 -> "func_one" (file offset 0x1090)
    // Name 2: nameStringRva = 0x30a0 -> "func_two" (file offset 0x10a0)
    view.setUint32(0x1070, 0x3090, true);
    view.setUint32(0x1074, 0x30a0, true);

    const name1 = 'func_one';
    for (let i = 0; i < name1.length; i++)
      bytes[0x1090 + i] = name1.charCodeAt(i);
    bytes[0x1090 + name1.length] = 0;

    const name2 = 'func_two';
    for (let i = 0; i < name2.length; i++)
      bytes[0x10a0 + i] = name2.charCodeAt(i);
    bytes[0x10a0 + name2.length] = 0;

    // Write addressOfNameOrdinals at 0x3080 (file offset 0x1080)
    // Ordinal 1 maps to Function 1 (idx 0)
    // Ordinal 2 maps to Function 2 (idx 1)
    view.setUint16(0x1080, 0, true);
    view.setUint16(0x1082, 1, true);

    // Write Import Directory at 0x4000 (file offset 0x2000)
    const impOffset = 0x2000;
    view.setUint32(impOffset, 0x4030, true); // originalFirstThunk (ILT) -> points to 0x4030 (file offset 0x2030)
    view.setUint32(impOffset + 4, 0, true);
    view.setUint32(impOffset + 8, 0, true);
    view.setUint32(impOffset + 12, 0x4050, true); // nameRva -> "kernel32.dll" at 0x4050 (file offset 0x2050)
    view.setUint32(impOffset + 16, 0x4040, true); // firstThunk (IAT)

    // Write dll name "kernel32.dll" at 0x4050 (file offset 0x2050)
    const impDllName = 'kernel32.dll';
    for (let i = 0; i < impDllName.length; i++) {
      bytes[0x2050 + i] = impDllName.charCodeAt(i);
    }
    bytes[0x2050 + impDllName.length] = 0;

    // Write ILT at 0x4030 (file offset 0x2030)
    // Entry 1: Name import, val = 0x4060 -> points to name descriptor at 0x4060 (file offset 0x2060)
    // Entry 2: Ordinal import, val = 0x80000005 (bit 31 set) -> ordinal 5
    // Entry 3: val = 0 (end)
    view.setUint32(0x2030, 0x4060, true);
    view.setUint32(0x2034, 0x80000005, true);
    view.setUint32(0x2038, 0, true);

    // Write name descriptor at 0x4060 (file offset 0x2060)
    // hint = 12 (uint16), name = "CreateFileA"
    view.setUint16(0x2060, 12, true);
    const impFuncName = 'CreateFileA';
    for (let i = 0; i < impFuncName.length; i++) {
      bytes[0x2062 + i] = impFuncName.charCodeAt(i);
    }
    bytes[0x2062 + impFuncName.length] = 0;

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    // Verify exports
    expect(parsed.exports).toBeDefined();
    expect(parsed.exports!.dllName).toBe('my_dll.dll');
    expect(parsed.exports!.exports.length).toBe(2);
    expect(parsed.exports!.exports[0].ordinal).toBe(1);
    expect(parsed.exports!.exports[0].address).toBe(0x1500);
    expect(parsed.exports!.exports[0].name).toBe('func_one');
    expect(parsed.exports!.exports[0].forwarder).toBeUndefined();

    expect(parsed.exports!.exports[1].ordinal).toBe(2);
    expect(parsed.exports!.exports[1].address).toBe(0x3040);
    expect(parsed.exports!.exports[1].name).toBe('func_two');
    expect(parsed.exports!.exports[1].forwarder).toBe('other_dll.other_func');

    // Verify imports
    expect(parsed.imports.length).toBe(1);
    expect(parsed.imports[0].dllName).toBe('kernel32.dll');
    expect(parsed.imports[0].imports.length).toBe(2);
    expect(parsed.imports[0].imports[0].name).toBe('CreateFileA');
    expect(parsed.imports[0].imports[0].hint).toBe(12);
    expect(parsed.imports[0].imports[1].ordinal).toBe(5);
  });

  it('should parse 64-bit imports', () => {
    const buffer = new ArrayBuffer(16384);
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
    view.setUint16(coffOffset, 0x8664, true); // AMD64
    view.setUint16(coffOffset + 2, 2, true); // 2 Sections
    const sizeOfOptionalHeader = 240;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);

    // 4. Optional Header (PE32+: Magic = 0x20b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x20b, true); // Magic (PE32+)

    const stackHeapOffset = optionalOffset + 24 + 48; // 160
    view.setUint32(stackHeapOffset + 32 + 4, 2, true); // NumberOfRvaAndSizes = 2

    const dirOffset = stackHeapOffset + 32 + 8; // 200
    // Export directory
    view.setUint32(dirOffset, 0, true);
    view.setUint32(dirOffset + 4, 0, true);
    // Import directory
    view.setUint32(dirOffset + 8, 0x4000, true); // Import VirtualAddress
    view.setUint32(dirOffset + 12, 0x200, true); // Import Size

    // 5. Section Headers (offset = optionalOffset + sizeOfOptionalHeader = 88 + 240 = 328)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 328

    // Section 1: .text
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x74;
    bytes[sectionOffset + 2] = 0x65;
    bytes[sectionOffset + 3] = 0x78;
    bytes[sectionOffset + 4] = 0x74;
    view.setUint32(sectionOffset + 8, 0x1000, true);
    view.setUint32(sectionOffset + 12, 0x1000, true);
    view.setUint32(sectionOffset + 16, 0x200, true);
    view.setUint32(sectionOffset + 20, 0x400, true);

    // Section 2: .idata (Import data)
    const sec2Offset = sectionOffset + 40; // 368
    bytes[sec2Offset] = 0x2e;
    bytes[sec2Offset + 1] = 0x69;
    bytes[sec2Offset + 2] = 0x64;
    bytes[sec2Offset + 3] = 0x61;
    bytes[sec2Offset + 4] = 0x74;
    bytes[sec2Offset + 5] = 0x61;
    view.setUint32(sec2Offset + 8, 0x1000, true);
    view.setUint32(sec2Offset + 12, 0x4000, true);
    view.setUint32(sec2Offset + 16, 0x1000, true);
    view.setUint32(sec2Offset + 20, 0x2000, true);

    // Write Import Directory at 0x4000 (file offset 0x2000)
    const impOffset = 0x2000;
    view.setUint32(impOffset, 0x4030, true); // originalFirstThunk (ILT) -> points to 0x4030 (file offset 0x2030)
    view.setUint32(impOffset + 12, 0x4050, true); // nameRva -> "kernel32.dll" at 0x4050 (file offset 0x2050)
    view.setUint32(impOffset + 16, 0x4040, true); // firstThunk (IAT)

    // Write dll name "kernel32.dll" at 0x4050 (file offset 0x2050)
    const impDllName = 'kernel32.dll';
    for (let i = 0; i < impDllName.length; i++) {
      bytes[0x2050 + i] = impDllName.charCodeAt(i);
    }
    bytes[0x2050 + impDllName.length] = 0;

    // Write ILT at 0x4030 (file offset 0x2030) - 8-byte entries for 64-bit
    // Entry 1: Name import, val = 0x4060 -> points to name descriptor at 0x4060 (file offset 0x2060)
    // Entry 2: Ordinal import, val = 0x8000000000000005n (bit 63 set) -> ordinal 5
    // Entry 3: val = 0 (end)
    view.setBigUint64(0x2030, 0x4060n, true);
    view.setBigUint64(0x2038, 0x8000000000000005n, true);
    view.setBigUint64(0x2040, 0n, true);

    // Write name descriptor at 0x4060 (file offset 0x2060)
    // hint = 12 (uint16), name = "CreateFileA"
    view.setUint16(0x2060, 12, true);
    const impFuncName = 'CreateFileA';
    for (let i = 0; i < impFuncName.length; i++) {
      bytes[0x2062 + i] = impFuncName.charCodeAt(i);
    }
    bytes[0x2062 + impFuncName.length] = 0;

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    // Verify imports
    expect(parsed.imports.length).toBe(1);
    expect(parsed.imports[0].dllName).toBe('kernel32.dll');
    expect(parsed.imports[0].imports.length).toBe(2);
    expect(parsed.imports[0].imports[0].name).toBe('CreateFileA');
    expect(parsed.imports[0].imports[0].hint).toBe(12);
    expect(parsed.imports[0].imports[1].ordinal).toBe(5);
  });

  it('should throw an error if COFF file header points outside of file limits', () => {
    const buffer = new ArrayBuffer(72);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 64, true); // e_lfanew points to 64
    view.setUint32(64, 0x00004550, true); // PE signature
    // Coff Offset = 68. coffOffset + 20 = 88. But buffer is 72.
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow(
      'COFF file header points outside of file limits'
    );
  });

  it('should throw an error if Optional header magic points outside of file limits', () => {
    const buffer = new ArrayBuffer(88);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    view.setUint32(60, 64, true);
    view.setUint32(64, 0x00004550, true);
    // Coff Offset = 68.
    // optionalOffset = 88. optionalOffset + 2 = 90. But buffer is 88.
    view.setUint16(68 + 16, 224, true);
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow(
      'Optional header magic points outside of file limits'
    );
  });

  it('should throw an error for unsupported PE optional header magic', () => {
    const buffer = new ArrayBuffer(120);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    view.setUint32(60, 64, true);
    view.setUint32(64, 0x00004550, true);
    view.setUint16(68 + 16, 224, true);
    view.setUint16(88, 0x999, true); // Unsupported magic 0x999
    const parser = new PEParser(buffer);
    expect(() => parser.parse()).toThrow(
      'Unsupported PE optional header magic: 0x999'
    );
  });

  it('should handle data directory parsing truncation (optional header size limit)', () => {
    const buffer = new ArrayBuffer(500);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    view.setUint32(60, 64, true);
    view.setUint32(64, 0x00004550, true);
    view.setUint16(68 + 16, 120, true); // sizeOfOptionalHeader = 120
    view.setUint16(88, 0x10b, true); // PE32
    const stackHeapOffset = 88 + 28 + 44; // 160
    view.setUint32(stackHeapOffset + 16 + 4, 10, true); // NumberOfRvaAndSizes = 10

    const parser = new PEParser(buffer);
    const parsed = parser.parse();
    expect(parsed.optionalHeader.dataDirectories.length).toBeLessThan(10);
  });

  it('should break early if section header offset is out of bounds', () => {
    const buffer = new ArrayBuffer(320); // Not large enough for all section headers
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    view.setUint32(60, 64, true);
    view.setUint32(64, 0x00004550, true);
    view.setUint16(68, 0x14c, true); // Machine
    view.setUint16(68 + 2, 5, true); // Number of Sections: 5
    view.setUint16(68 + 16, 224, true); // sizeOfOptionalHeader: 224
    view.setUint16(88, 0x10b, true); // PE32

    const parser = new PEParser(buffer);
    const parsed = parser.parse();
    expect(parsed.sections.length).toBe(0);
  });

  it('should parse resources from a 32-bit PE binary', () => {
    const buffer = new ArrayBuffer(16384);
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
    view.setUint16(coffOffset, 0x14c, true); // Machine
    view.setUint16(coffOffset + 2, 2, true); // 2 Sections
    view.setUint32(coffOffset + 4, 1234567890, true);
    const sizeOfOptionalHeader = 224;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);
    view.setUint16(coffOffset + 18, 0x0102, true);

    // 4. Optional Header (PE32: Magic = 0x10b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x10b, true); // Magic

    const stackHeapOffset = optionalOffset + 28 + 44; // 160
    view.setUint32(stackHeapOffset + 16 + 4, 3, true); // NumberOfRvaAndSizes = 3

    const dirOffset = stackHeapOffset + 16 + 8; // 184
    // Export directory
    view.setUint32(dirOffset, 0, true);
    view.setUint32(dirOffset + 4, 0, true);
    // Import directory
    view.setUint32(dirOffset + 8, 0, true);
    view.setUint32(dirOffset + 12, 0, true);
    // Resource directory
    view.setUint32(dirOffset + 16, 0x5000, true); // Resource VirtualAddress
    view.setUint32(dirOffset + 20, 0x1000, true); // Resource Size

    // 5. Section Headers (offset = optionalOffset + sizeOfOptionalHeader = 88 + 224 = 312)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 312

    // Section 1: .text
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x74;
    bytes[sectionOffset + 2] = 0x65;
    bytes[sectionOffset + 3] = 0x78;
    bytes[sectionOffset + 4] = 0x74;
    view.setUint32(sectionOffset + 8, 0x1000, true);
    view.setUint32(sectionOffset + 12, 0x1000, true);
    view.setUint32(sectionOffset + 16, 0x200, true);
    view.setUint32(sectionOffset + 20, 0x400, true);

    // Section 2: .rsrc (Resource data)
    const sec2Offset = sectionOffset + 40; // 352
    bytes[sec2Offset] = 0x2e;
    bytes[sec2Offset + 1] = 0x72;
    bytes[sec2Offset + 2] = 0x73;
    bytes[sec2Offset + 3] = 0x72;
    bytes[sec2Offset + 4] = 0x63;
    view.setUint32(sec2Offset + 8, 0x1000, true);
    view.setUint32(sec2Offset + 12, 0x5000, true);
    view.setUint32(sec2Offset + 16, 0x1000, true);
    view.setUint32(sec2Offset + 20, 0x3000, true);

    // Write Resource Directory Root at 0x3000
    const rsrcRoot = 0x3000;
    view.setUint16(rsrcRoot + 12, 0, true); // Named entries
    view.setUint16(rsrcRoot + 14, 3, true); // ID entries: Manifest (24), String Table (6), Icon (3)

    // Entries start at rsrcRoot + 16 (0x3010)
    // Entry 1: Type 24 (Manifest)
    view.setUint32(0x3010, 24, true);
    view.setUint32(0x3014, 0x80000030, true); // Subdirectory offset 0x30
    // Entry 2: Type 6 (String Table)
    view.setUint32(0x3018, 6, true);
    view.setUint32(0x301c, 0x80000060, true); // Subdirectory offset 0x60
    // Entry 3: Type 3 (Icon)
    view.setUint32(0x3020, 3, true);
    view.setUint32(0x3024, 0x80000090, true); // Subdirectory offset 0x90

    // Write Subdirectory at 0x3030 (Type 24 - Manifest)
    const rsrcSub24 = 0x3030;
    view.setUint16(rsrcSub24 + 12, 1, true); // 1 Named entry
    view.setUint16(rsrcSub24 + 14, 0, true); // 0 ID entries
    // Entry: Named "MANIFEST" (points to string at 0xc0)
    view.setUint32(0x3040, 0x800000c0, true); // nameOffsetOrId
    view.setUint32(0x3044, 0x800000e0, true); // offsetToDataOrDirectory (subdir at 0xe0)

    // Write String at 0x30c0
    view.setUint16(0x30c0, 8, true); // Length 8
    const manifestStr = 'MANIFEST';
    for (let i = 0; i < manifestStr.length; i++) {
      view.setUint16(0x30c2 + i * 2, manifestStr.charCodeAt(i), true);
    }

    // Write Subdirectory at 0x30e0 (Manifest language level)
    const rsrcSub24Lang = 0x30e0;
    view.setUint16(rsrcSub24Lang + 12, 0, true);
    view.setUint16(rsrcSub24Lang + 14, 1, true);
    view.setUint32(0x30f0, 1033, true); // Lang ID 1033
    view.setUint32(0x30f4, 0x100, true); // dataEntryOffset = 0x100

    // Write Data Entry at 0x3100
    view.setUint32(0x3100, 0x5120, true); // dataRva (0x5120 -> file offset 0x3120)
    view.setUint32(0x3104, 21, true); // Size

    // Write Manifest Data at 0x3120
    const manifestXml = '<assembly></assembly>';
    for (let i = 0; i < manifestXml.length; i++) {
      bytes[0x3120 + i] = manifestXml.charCodeAt(i);
    }

    // Write Subdirectory at 0x3060 (Type 6 - String Table)
    const rsrcSub6 = 0x3060;
    view.setUint16(rsrcSub6 + 12, 0, true);
    view.setUint16(rsrcSub6 + 14, 1, true);
    view.setUint32(0x3070, 1, true); // String Block ID 1
    view.setUint32(0x3074, 0x80000140, true); // subdir at 0x140

    // Write Subdirectory at 0x3140 (String Table language level)
    const rsrcSub6Lang = 0x3140;
    view.setUint16(rsrcSub6Lang + 12, 0, true);
    view.setUint16(rsrcSub6Lang + 14, 1, true);
    view.setUint32(0x3150, 1033, true);
    view.setUint32(0x3154, 0x160, true); // dataEntryOffset = 0x160

    // Write Data Entry at 0x3160
    view.setUint32(0x3160, 0x5180, true); // dataRva (0x5180 -> file offset 0x3180)
    view.setUint32(0x3164, 40, true); // Size

    // Write String Block at 0x3180
    // String 0: "hello"
    view.setUint16(0x3180, 5, true); // Length 5
    const helloStr = 'hello';
    for (let i = 0; i < helloStr.length; i++) {
      view.setUint16(0x3182 + i * 2, helloStr.charCodeAt(i), true);
    }

    // Write Subdirectory at 0x3090 (Type 3 - Icon)
    const rsrcSub3 = 0x3090;
    view.setUint16(rsrcSub3 + 12, 0, true);
    view.setUint16(rsrcSub3 + 14, 1, true);
    view.setUint32(0x30a0, 1, true); // ID 1
    view.setUint32(0x30a4, 0x80000200, true); // subdir at 0x200

    // Write Subdirectory at 0x3200 (Icon language level)
    const rsrcSub3Lang = 0x3200;
    view.setUint16(rsrcSub3Lang + 12, 0, true);
    view.setUint16(rsrcSub3Lang + 14, 1, true);
    view.setUint32(0x3210, 1033, true);
    view.setUint32(0x3214, 0x220, true); // dataEntryOffset = 0x220

    // Write Data Entry at 0x3220
    view.setUint32(0x3220, 0x5240, true); // dataRva (0x5240 -> file offset 0x3240)
    view.setUint32(0x3224, 64, true); // Size

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    expect(parsed.resources).toBeDefined();
    expect(parsed.resources!.manifests.length).toBe(1);
    expect(parsed.resources!.manifests[0]).toBe('<assembly></assembly>');
    expect(parsed.resources!.strings[0]).toBe('hello');
    expect(parsed.resources!.icons.length).toBe(1);
    expect(parsed.resources!.icons[0].type).toBe('Icon');
    expect(parsed.resources!.icons[0].size).toBe(64);
  });

  it('should handle resource parsing edge cases, named types, truncation, and decode error fallback', () => {
    const buffer = new ArrayBuffer(16384);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // DOS Header
    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);
    // PE Signature
    view.setUint32(e_lfanew, 0x00004550, true);
    // COFF
    const coffOffset = e_lfanew + 4;
    view.setUint16(coffOffset, 0x14c, true);
    view.setUint16(coffOffset + 2, 2, true); // 2 Sections
    const sizeOfOptionalHeader = 224;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);
    // Optional Header
    const optionalOffset = coffOffset + 20;
    view.setUint16(optionalOffset, 0x10b, true); // PE32
    const stackHeapOffset = optionalOffset + 28 + 44; // 160
    view.setUint32(stackHeapOffset + 16 + 4, 3, true); // NumberOfRvaAndSizes = 3
    const dirOffset = stackHeapOffset + 16 + 8; // 184
    view.setUint32(dirOffset + 16, 0x5000, true); // Resource VirtualAddress
    view.setUint32(dirOffset + 20, 0x1000, true); // Resource Size

    // Section Headers
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 312
    // .text
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x74;
    view.setUint32(sectionOffset + 12, 0x1000, true);
    view.setUint32(sectionOffset + 16, 0x200, true);
    view.setUint32(sectionOffset + 20, 0x400, true);
    // .rsrc
    const sec2Offset = sectionOffset + 40;
    bytes[sec2Offset] = 0x2e;
    bytes[sec2Offset + 1] = 0x72;
    bytes[sec2Offset + 2] = 0x73;
    bytes[sec2Offset + 3] = 0x72;
    bytes[sec2Offset + 4] = 0x63;
    view.setUint32(sec2Offset + 8, 0x1000, true);
    view.setUint32(sec2Offset + 12, 0x5000, true);
    view.setUint32(sec2Offset + 16, 0x1000, true);
    view.setUint32(sec2Offset + 20, 0x3000, true);

    // Root directory at 0x3000
    const rsrcRoot = 0x3000;
    view.setUint16(rsrcRoot + 12, 1, true); // 1 Named entry
    view.setUint16(rsrcRoot + 14, 1, true); // 1 ID entry (Manifest Type 24)

    // Entry 1: Named type (name at 0x800000a0, points to subdirectory at 0x80000050)
    view.setUint32(0x3010, 0x800000a0, true);
    view.setUint32(0x3014, 0x80000050, true);

    // Entry 2: ID type 24 (points to subdirectory at 0x80000070)
    view.setUint32(0x3018, 24, true);
    view.setUint32(0x301c, 0x80000070, true);

    // Write String for Named Type name at 0x30a0
    view.setUint16(0x30a0, 4, true); // length = 4
    const customTypeName = 'MYTY';
    for (let i = 0; i < customTypeName.length; i++) {
      view.setUint16(0x30a2 + i * 2, customTypeName.charCodeAt(i), true);
    }

    // Write Subdirectory for Named Type at 0x3050
    const rsrcSubCustom = 0x3050;
    view.setUint16(rsrcSubCustom + 12, 0, true);
    view.setUint16(rsrcSubCustom + 14, 1, true);
    view.setUint32(0x3060, 1, true); // ID 1
    view.setUint32(0x3064, 0x80000120, true); // points to language subdir at 0x120

    // Write language level subdirectory at 0x3120
    view.setUint16(0x3120 + 12, 0, true);
    view.setUint16(0x3120 + 14, 1, true); // 1 ID entry
    view.setUint32(0x3130, 1033, true); // Lang ID 1033
    view.setUint32(0x3134, 0x180, true); // dataEntryOffset = 0x180

    // Write Data Entry at 0x3180
    view.setUint32(0x3180, 0x51c0, true); // dataRva = 0x51c0 -> file 0x31c0
    view.setUint32(0x3184, 10, true); // size = 10

    // Write Subdirectory for Manifest at 0x3070
    view.setUint16(0x3070 + 12, 0, true);
    view.setUint16(0x3070 + 14, 1, true);
    view.setUint32(0x3080, 1, true); // ID 1
    view.setUint32(0x3084, 0x80000150, true); // subdir at 0x150

    // Write language level subdirectory for Manifest at 0x3150
    view.setUint16(0x3150 + 12, 0, true);
    view.setUint16(0x3150 + 14, 1, true);
    view.setUint32(0x3160, 1033, true);
    view.setUint32(0x3164, 0x200, true); // data entry at 0x200

    // Write Data Entry for Manifest at 0x3200
    view.setUint32(0x3200, 0x5220, true); // dataRva = 0x5220 -> file 0x3220
    view.setUint32(0x3204, 4, true); // size = 4

    // Write Manifest data: "xml5"
    bytes[0x3220] = 120;
    bytes[0x3221] = 109;
    bytes[0x3222] = 108;
    bytes[0x3223] = 53;
    bytes[0x3224] = 0;

    // Test named type parsing
    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    expect(parsed.resources).toBeDefined();
    expect(parsed.resources!.manifests.length).toBe(1);
    expect(parsed.resources!.manifests[0]).toBe('xml5');
    const customRes = parsed.resources!.all.find((r) => r.type === 'MYTY');
    expect(customRes).toBeDefined();
    expect(customRes!.typeName).toBe('MYTY');

    // Override TextDecoder to hit TextDecoder catch block
    const originalTextDecoder = globalThis.TextDecoder;
    globalThis.TextDecoder = class {
      decode() {
        throw new Error('TextDecoder failed');
      }
    } as any;

    try {
      const parser2 = new PEParser(buffer);
      const parsed2 = parser2.parse();
      expect(parsed2.resources!.manifests[0]).toBe('xml5');
    } finally {
      globalThis.TextDecoder = originalTextDecoder;
    }

    // Now test resource directory offset truncation logic:
    // 1. absoluteDirOffset + 16 > byteLength
    view.setUint32(0x3134, 0x80003ffd, true); // Point to subdirectory near end of buffer
    const parser3 = new PEParser(buffer);
    const parsed3 = parser3.parse();
    expect(
      parsed3.resources!.all.find((r) => r.type === 'MYTY')
    ).toBeUndefined();

    // 2. absoluteEntryOffset + 8 > byteLength
    view.setUint32(0x3134, 0x180, true);
    view.setUint16(0x3120 + 12, 500, true);
    view.setUint16(0x3120 + 14, 500, true);
    const parser4 = new PEParser(buffer);
    const parsed4 = parser4.parse();
    expect(parsed4.resources).toBeDefined();

    // 3. absoluteStrOffset + 2 > byteLength
    view.setUint32(0x3010, 0x80003ffe, true);
    const parser5 = new PEParser(buffer);
    const parsed5 = parser5.parse();
    const truncatedTypeRes = parsed5.resources!.all.find(
      (r) => typeof r.type === 'string' && r.type.startsWith('Offset_0x')
    );
    expect(truncatedTypeRes).toBeDefined();
  });

  it('should successfully parse TLS directory and callbacks for 32-bit PE', () => {
    const buffer = new ArrayBuffer(512);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);

    view.setUint32(e_lfanew, 0x00004550, true);

    const coffOffset = e_lfanew + 4;
    view.setUint16(coffOffset, 0x14c, true);
    view.setUint16(coffOffset + 2, 1, true);
    const sizeOfOptionalHeader = 224;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);

    const optionalOffset = coffOffset + 20;
    view.setUint16(optionalOffset, 0x10b, true);
    
    const winOffset = optionalOffset + 28;
    view.setUint32(winOffset, 0x400000, true);
    
    const stackHeapOffset = winOffset + 44;
    const afterStackHeapOffset = stackHeapOffset + 16;
    view.setUint32(afterStackHeapOffset + 4, 10, true);

    const dirOffset = afterStackHeapOffset + 8;
    view.setUint32(dirOffset + 9 * 8, 0x2000, true);
    view.setUint32(dirOffset + 9 * 8 + 4, 24, true);

    const sectionOffset = optionalOffset + sizeOfOptionalHeader;
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x64;
    bytes[sectionOffset + 2] = 0x61;
    bytes[sectionOffset + 3] = 0x74;
    bytes[sectionOffset + 4] = 0x61;
    view.setUint32(sectionOffset + 8, 0x1000, true);
    view.setUint32(sectionOffset + 12, 0x2000, true);
    view.setUint32(sectionOffset + 16, 0x200, true);
    view.setUint32(sectionOffset + 20, 0x180, true);
    view.setUint32(sectionOffset + 36, 0xc0000040, true);

    view.setUint32(0x180 + 12, 0x402050, true);

    view.setUint32(0x1d0, 0x401010, true);
    view.setUint32(0x1d4, 0x401020, true);
    view.setUint32(0x1d8, 0, true);

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    expect(parsed.tls).toBeDefined();
    expect(parsed.tls!.rawAddressOfCallbacks).toBe(0x402050);
    expect(parsed.tls!.callbacks).toEqual([0x1010, 0x1020]);
  });

  it('should successfully parse TLS directory and callbacks for 64-bit PE', () => {
    const buffer = new ArrayBuffer(512);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d;
    bytes[1] = 0x5a;
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);

    view.setUint32(e_lfanew, 0x00004550, true);

    const coffOffset = e_lfanew + 4;
    view.setUint16(coffOffset, 0x8664, true);
    view.setUint16(coffOffset + 2, 1, true);
    const sizeOfOptionalHeader = 240;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);

    const optionalOffset = coffOffset + 20;
    view.setUint16(optionalOffset, 0x20b, true);
    
    const winOffset = optionalOffset + 24;
    view.setBigUint64(winOffset, 0x140000000n, true);
    
    const stackHeapOffset = winOffset + 48;
    const afterStackHeapOffset = stackHeapOffset + 32;
    view.setUint32(afterStackHeapOffset + 4, 10, true);

    const dirOffset = afterStackHeapOffset + 8;
    view.setUint32(dirOffset + 9 * 8, 0x2000, true);
    view.setUint32(dirOffset + 9 * 8 + 4, 40, true);

    const sectionOffset = optionalOffset + sizeOfOptionalHeader;
    bytes[sectionOffset] = 0x2e;
    bytes[sectionOffset + 1] = 0x64;
    bytes[sectionOffset + 2] = 0x61;
    bytes[sectionOffset + 3] = 0x74;
    bytes[sectionOffset + 4] = 0x61;
    view.setUint32(sectionOffset + 8, 0x1000, true);
    view.setUint32(sectionOffset + 12, 0x2000, true);
    view.setUint32(sectionOffset + 16, 0x200, true);
    view.setUint32(sectionOffset + 20, 0x180, true);
    view.setUint32(sectionOffset + 36, 0xc0000040, true);

    view.setBigUint64(0x180 + 24, 0x140002050n, true);

    view.setBigUint64(0x1d0, 0x140001010n, true);
    view.setBigUint64(0x1d8, 0x140001020n, true);
    view.setBigUint64(0x1e0, 0n, true);

    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    expect(parsed.tls).toBeDefined();
    expect(parsed.tls!.rawAddressOfCallbacks).toBe(0x140002050n);
    expect(parsed.tls!.callbacks).toEqual([0x1010, 0x1020]);
  });
});
