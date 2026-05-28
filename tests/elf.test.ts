import { describe, it, expect } from 'vitest';
import { parseElf } from '../src/parser/elf.js';

describe('ELF Parser Unit Tests', () => {
  it('should successfully parse a valid 64-bit Little Endian ELF header', () => {
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // ELF Magic: 0x7F, 'E', 'L', 'F'
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;

    // ELF Class: 2 = 64-bit
    bytes[4] = 2;

    // ELF Data: 1 = Little Endian
    bytes[5] = 1;

    // OS/ABI: 0 = System V
    bytes[7] = 0;

    // Type: 2 = EXEC (Executable file), Little Endian
    view.setUint16(16, 2, true);

    // Machine: 62 = AMD64, Little Endian
    view.setUint16(18, 62, true);

    // Entry point: 0x1000, 64-bit Little Endian
    view.setBigUint64(24, 0x1000n, true);

    // Program header offset: 0
    view.setBigUint64(32, 0n, true);

    // Section header offset: 0
    view.setBigUint64(40, 0n, true);

    // Flags: 0
    view.setUint32(48, 0, true);

    // ELF Header size: 64
    view.setUint16(52, 64, true);

    const parsed = parseElf(buffer);

    expect(parsed.header.class).toBe('64-bit');
    expect(parsed.header.endianness).toBe('Little Endian');
    expect(parsed.header.osAbi).toBe('System V');
    expect(parsed.header.type).toBe('EXEC (Executable file)');
    expect(parsed.header.machine).toBe('AMD64 (x86-64)');
    expect(parsed.header.entryPoint).toBe(0x1000n);
    expect(parsed.programHeaders.length).toBe(0);
    expect(parsed.sectionHeaders.length).toBe(0);
  });

  it('should successfully parse a valid 32-bit Big Endian ELF header', () => {
    const buffer = new ArrayBuffer(52);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // ELF Magic: 0x7F, 'E', 'L', 'F'
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;

    // ELF Class: 1 = 32-bit
    bytes[4] = 1;

    // ELF Data: 2 = Big Endian
    bytes[5] = 2;

    // OS/ABI: 3 = Linux
    bytes[7] = 3;

    // Type: 3 = DYN (Shared object file), Big Endian
    view.setUint16(16, 3, false);

    // Machine: 40 = ARM, Big Endian
    view.setUint16(18, 40, false);

    // Entry point: 0x2000, 32-bit Big Endian
    view.setUint32(24, 0x2000, false);

    // Program header offset: 0
    view.setUint32(28, 0, false);

    // Section header offset: 0
    view.setUint32(32, 0, false);

    // Flags: 0
    view.setUint32(36, 0, false);

    // ELF Header size: 52
    view.setUint16(40, 52, false);

    const parsed = parseElf(buffer);

    expect(parsed.header.class).toBe('32-bit');
    expect(parsed.header.endianness).toBe('Big Endian');
    expect(parsed.header.osAbi).toBe('Linux');
    expect(parsed.header.type).toBe('DYN (Shared object file)');
    expect(parsed.header.machine).toBe('ARM');
    expect(parsed.header.entryPoint).toBe(0x2000);
    expect(parsed.programHeaders.length).toBe(0);
    expect(parsed.sectionHeaders.length).toBe(0);
  });

  it('should throw an error for invalid ELF magic bytes', () => {
    const buffer = new ArrayBuffer(64);
    const bytes = new Uint8Array(buffer);
    // Invalid magic bytes
    bytes[0] = 0x88;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;

    expect(() => parseElf(buffer)).toThrow('Invalid ELF Magic header');
  });

  it('should throw an error for unsupported/unknown ELF class', () => {
    const buffer = new ArrayBuffer(64);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;
    bytes[4] = 3; // Invalid class (only 1 and 2 are valid)

    expect(() => parseElf(buffer)).toThrow(
      'Unsupported or unknown ELF class: 3'
    );
  });

  it('should throw an error for unsupported/unknown endianness', () => {
    const buffer = new ArrayBuffer(64);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 3; // Invalid endianness (only 1 and 2 are valid)

    expect(() => parseElf(buffer)).toThrow(
      'Unsupported or unknown endianness: 3'
    );
  });

  it('should successfully parse a 64-bit Little Endian ELF with program and section headers', () => {
    // 64-bit ELF header is 64 bytes.
    // Let's add 1 program header of 56 bytes.
    // Let's add 3 section headers of 64 bytes each:
    // Index 0: SHT_NULL
    // Index 1: SHT_STRTAB (for section names)
    // Index 2: SHT_PROGBITS (.text)
    // And some space for the string table content.
    const phOff = 64;
    const phNum = 1;
    const phentSize = 56;
    const shOff = phOff + phNum * phentSize; // 64 + 56 = 120
    const shNum = 3;
    const shentSize = 64;
    const shstrtabContentOffset = shOff + shNum * shentSize; // 120 + 192 = 312
    const shstrtabSize = 32;

    const buffer = new ArrayBuffer(shstrtabContentOffset + shstrtabSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // ELF Magic
    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0x01; // HP-UX OSABI
    view.setUint16(16, 2, true); // EXEC
    view.setUint16(18, 62, true); // AMD64
    view.setBigUint64(24, 0x1000n, true); // Entrypoint
    view.setBigUint64(32, BigInt(phOff), true); // phOff
    view.setBigUint64(40, BigInt(shOff), true); // shOff
    view.setUint32(48, 0x1234, true); // flags
    view.setUint16(52, 64, true); // ehSize
    view.setUint16(54, phentSize, true); // phentSize
    view.setUint16(56, phNum, true); // phNum
    view.setUint16(58, shentSize, true); // shentSize
    view.setUint16(60, shNum, true); // shNum
    view.setUint16(62, 1, true); // shStrNdX (1 is the string table section index)

    // Write Program Header at phOff (120)
    // pType = PT_LOAD (1)
    view.setUint32(phOff, 1, true);
    // pFlags = PF_X | PF_R (5)
    view.setUint32(phOff + 4, 5, true);
    // pOffset = 0x100
    view.setBigUint64(phOff + 8, 0x100n, true);
    // pVaddr = 0x1000
    view.setBigUint64(phOff + 16, 0x1000n, true);
    // pPaddr = 0x1000
    view.setBigUint64(phOff + 24, 0x1000n, true);
    // pFilesz = 0x200
    view.setBigUint64(phOff + 32, 0x200n, true);
    // pMemsz = 0x200
    view.setBigUint64(phOff + 40, 0x200n, true);
    // pAlign = 0x1000
    view.setBigUint64(phOff + 48, 0x1000n, true);

    // Write Section Header Index 0 (SHT_NULL) - typically all zeroes
    // Write Section Header Index 1 (SHT_STRTAB)
    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 1, true); // shName = offset 1 in shstrtab
    view.setUint32(sh1 + 4, 3, true); // shType = SHT_STRTAB (3)
    view.setBigUint64(sh1 + 8, 0n, true); // shFlags
    view.setBigUint64(sh1 + 16, 0n, true); // shAddr
    view.setBigUint64(sh1 + 24, BigInt(shstrtabContentOffset), true); // shOffset
    view.setBigUint64(sh1 + 32, BigInt(shstrtabSize), true); // shSize
    view.setUint32(sh1 + 40, 0, true); // shLink
    view.setUint32(sh1 + 44, 0, true); // shInfo
    view.setBigUint64(sh1 + 48, 1n, true); // shAddralign
    view.setBigUint64(sh1 + 56, 0n, true); // shEntsize

    // Write Section Header Index 2 (SHT_PROGBITS)
    const sh2 = shOff + 2 * shentSize;
    view.setUint32(sh2, 11, true); // shName = offset 11 in shstrtab
    view.setUint32(sh2 + 4, 1, true); // shType = SHT_PROGBITS (1)
    view.setBigUint64(sh2 + 8, 6n, true); // shFlags = SHF_ALLOC | SHF_EXECINSTR
    view.setBigUint64(sh2 + 16, 0x1000n, true); // shAddr
    view.setBigUint64(sh2 + 24, 0x100n, true); // shOffset
    view.setBigUint64(sh2 + 32, 0x200n, true); // shSize
    view.setUint32(sh2 + 40, 0, true); // shLink
    view.setUint32(sh2 + 44, 0, true); // shInfo
    view.setBigUint64(sh2 + 48, 16n, true); // shAddralign
    view.setBigUint64(sh2 + 56, 0n, true); // shEntsize

    // Write String Table contents
    // shstrtabContentOffset + 1 = ".shstrtab"
    // shstrtabContentOffset + 11 = ".text"
    const shstrtabBytes = new Uint8Array(buffer, shstrtabContentOffset, shstrtabSize);
    shstrtabBytes[0] = 0; // null byte
    const name1 = '.shstrtab';
    for (let i = 0; i < name1.length; i++) shstrtabBytes[1 + i] = name1.charCodeAt(i);
    shstrtabBytes[1 + name1.length] = 0;
    const name2 = '.text';
    for (let i = 0; i < name2.length; i++) shstrtabBytes[11 + i] = name2.charCodeAt(i);
    shstrtabBytes[11 + name2.length] = 0;

    const parsed = parseElf(buffer);

    expect(parsed.header.class).toBe('64-bit');
    expect(parsed.header.endianness).toBe('Little Endian');
    expect(parsed.header.osAbi).toBe('HP-UX');
    expect(parsed.programHeaders.length).toBe(1);
    expect(parsed.programHeaders[0].typeName).toBe('PT_LOAD');
    expect(parsed.programHeaders[0].flags).toBe(5);
    expect(parsed.programHeaders[0].offset).toBe(0x100n);
    expect(parsed.programHeaders[0].vaddr).toBe(0x1000n);
    expect(parsed.programHeaders[0].paddr).toBe(0x1000n);
    expect(parsed.programHeaders[0].filesz).toBe(0x200n);
    expect(parsed.programHeaders[0].memsz).toBe(0x200n);
    expect(parsed.programHeaders[0].align).toBe(0x1000n);

    expect(parsed.sectionHeaders.length).toBe(3);
    expect(parsed.sectionHeaders[1].name).toBe('.shstrtab');
    expect(parsed.sectionHeaders[1].typeName).toBe('SHT_STRTAB');
    expect(parsed.sectionHeaders[2].name).toBe('.text');
    expect(parsed.sectionHeaders[2].typeName).toBe('SHT_PROGBITS');
  });

  it('should successfully parse a 32-bit Little Endian ELF with program and section headers', () => {
    // 32-bit ELF header is 52 bytes.
    // Let's add 1 program header of 32 bytes.
    // Let's add 2 section headers of 40 bytes each:
    // Index 0: SHT_NULL
    // Index 1: SHT_STRTAB (for section names)
    const phOff = 52;
    const phNum = 1;
    const phentSize = 32;
    const shOff = phOff + phNum * phentSize; // 52 + 32 = 84
    const shNum = 2;
    const shentSize = 40;
    const shstrtabContentOffset = shOff + shNum * shentSize; // 84 + 80 = 164
    const shstrtabSize = 20;

    const buffer = new ArrayBuffer(shstrtabContentOffset + shstrtabSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // ELF Magic
    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 1; // 32-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0x09; // FreeBSD
    view.setUint16(16, 1, true); // REL
    view.setUint16(18, 3, true); // x86
    view.setUint32(24, 0x5000, true); // Entrypoint
    view.setUint32(28, phOff, true); // phOff
    view.setUint32(32, shOff, true); // shOff
    view.setUint32(36, 0, true); // flags
    view.setUint16(40, 52, true); // ehSize
    view.setUint16(42, phentSize, true); // phentSize
    view.setUint16(44, phNum, true); // phNum
    view.setUint16(46, shentSize, true); // shentSize
    view.setUint16(48, shNum, true); // shNum
    view.setUint16(50, 1, true); // shStrNdX

    // Write Program Header at phOff (52)
    // pType = PT_NOTE (4)
    view.setUint32(phOff, 4, true);
    // pOffset = 0x50
    view.setUint32(phOff + 4, 0x50, true);
    // pVaddr = 0x5000
    view.setUint32(phOff + 8, 0x5000, true);
    // pPaddr = 0x5000
    view.setUint32(phOff + 12, 0x5000, true);
    // pFilesz = 0x10
    view.setUint32(phOff + 16, 0x10, true);
    // pMemsz = 0x10
    view.setUint32(phOff + 20, 0x10, true);
    // pFlags = 4 (R)
    view.setUint32(phOff + 24, 4, true);
    // pAlign = 4
    view.setUint32(phOff + 28, 4, true);

    // Write Section Header Index 0 (SHT_NULL)
    // Write Section Header Index 1 (SHT_STRTAB)
    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 1, true); // shName
    view.setUint32(sh1 + 4, 3, true); // shType (SHT_STRTAB)
    view.setUint32(sh1 + 8, 0, true); // shFlags
    view.setUint32(sh1 + 12, 0, true); // shAddr
    view.setUint32(sh1 + 16, shstrtabContentOffset, true); // shOffset
    view.setUint32(sh1 + 20, shstrtabSize, true); // shSize
    view.setUint32(sh1 + 24, 0, true); // shLink
    view.setUint32(sh1 + 28, 0, true); // shInfo
    view.setUint32(sh1 + 32, 1, true); // shAddralign
    view.setUint32(sh1 + 36, 0, true); // shEntsize

    // Write String Table
    const shstrtabBytes = new Uint8Array(buffer, shstrtabContentOffset, shstrtabSize);
    shstrtabBytes[0] = 0;
    const name1 = '.shstrtab';
    for (let i = 0; i < name1.length; i++) shstrtabBytes[1 + i] = name1.charCodeAt(i);
    shstrtabBytes[1 + name1.length] = 0;

    const parsed = parseElf(buffer);

    expect(parsed.header.class).toBe('32-bit');
    expect(parsed.header.endianness).toBe('Little Endian');
    expect(parsed.header.osAbi).toBe('FreeBSD');
    expect(parsed.header.type).toBe('REL (Relocatable file)');
    expect(parsed.header.machine).toBe('x86');
    expect(parsed.programHeaders.length).toBe(1);
    expect(parsed.programHeaders[0].typeName).toBe('PT_NOTE');
    expect(parsed.programHeaders[0].flags).toBe(4);
    expect(parsed.sectionHeaders.length).toBe(2);
    expect(parsed.sectionHeaders[1].name).toBe('.shstrtab');
  });

  it('should successfully parse a 64-bit Big Endian ELF with program and section headers', () => {
    const phOff = 64;
    const phNum = 1;
    const phentSize = 56;
    const shOff = phOff + phNum * phentSize;
    const shNum = 2;
    const shentSize = 64;
    const shstrtabContentOffset = shOff + shNum * shentSize;
    const shstrtabSize = 20;

    const buffer = new ArrayBuffer(shstrtabContentOffset + shstrtabSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 2; // Big Endian
    bytes[7] = 0x03; // Linux
    view.setUint16(16, 2, false); // EXEC
    view.setUint16(18, 62, false); // AMD64
    view.setBigUint64(24, 0x1000n, false);
    view.setBigUint64(32, BigInt(phOff), false);
    view.setBigUint64(40, BigInt(shOff), false);
    view.setUint32(48, 0, false);
    view.setUint16(52, 64, false);
    view.setUint16(54, phentSize, false);
    view.setUint16(56, phNum, false);
    view.setUint16(58, shentSize, false);
    view.setUint16(60, shNum, false);
    view.setUint16(62, 1, false);

    // Program header (PT_LOAD = 1)
    view.setUint32(phOff, 1, false);
    view.setUint32(phOff + 4, 5, false);
    view.setBigUint64(phOff + 8, 0x100n, false);

    // Section header (SHT_STRTAB = 3)
    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 1, false);
    view.setUint32(sh1 + 4, 3, false);
    view.setBigUint64(sh1 + 24, BigInt(shstrtabContentOffset), false);
    view.setBigUint64(sh1 + 32, BigInt(shstrtabSize), false);

    // String table
    const shstrtabBytes = new Uint8Array(buffer, shstrtabContentOffset, shstrtabSize);
    shstrtabBytes[0] = 0;
    const name1 = '.shstrtab';
    for (let i = 0; i < name1.length; i++) shstrtabBytes[1 + i] = name1.charCodeAt(i);

    const parsed = parseElf(buffer);
    expect(parsed.header.class).toBe('64-bit');
    expect(parsed.header.endianness).toBe('Big Endian');
    expect(parsed.programHeaders[0].typeName).toBe('PT_LOAD');
    expect(parsed.sectionHeaders[1].name).toBe('.shstrtab');
  });

  it('should successfully parse a 32-bit Big Endian ELF with program and section headers', () => {
    const phOff = 52;
    const phNum = 1;
    const phentSize = 32;
    const shOff = phOff + phNum * phentSize;
    const shNum = 2;
    const shentSize = 40;
    const shstrtabContentOffset = shOff + shNum * shentSize;
    const shstrtabSize = 20;

    const buffer = new ArrayBuffer(shstrtabContentOffset + shstrtabSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 1; // 32-bit
    bytes[5] = 2; // Big Endian
    bytes[7] = 0x03; // Linux
    view.setUint16(16, 2, false);
    view.setUint16(18, 40, false); // ARM
    view.setUint32(24, 0x1000, false);
    view.setUint32(28, phOff, false);
    view.setUint32(32, shOff, false);
    view.setUint32(36, 0, false);
    view.setUint16(40, 52, false);
    view.setUint16(42, phentSize, false);
    view.setUint16(44, phNum, false);
    view.setUint16(46, shentSize, false);
    view.setUint16(48, shNum, false);
    view.setUint16(50, 1, false);

    // Program header (PT_LOAD = 1)
    view.setUint32(phOff, 1, false);
    view.setUint32(phOff + 4, 0x100, false);

    // Section header (SHT_STRTAB = 3)
    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 1, false);
    view.setUint32(sh1 + 4, 3, false);
    view.setUint32(sh1 + 16, shstrtabContentOffset, false);
    view.setUint32(sh1 + 20, shstrtabSize, false);

    // String table
    const shstrtabBytes = new Uint8Array(buffer, shstrtabContentOffset, shstrtabSize);
    shstrtabBytes[0] = 0;
    const name1 = '.shstrtab';
    for (let i = 0; i < name1.length; i++) shstrtabBytes[1 + i] = name1.charCodeAt(i);

    const parsed = parseElf(buffer);
    expect(parsed.header.class).toBe('32-bit');
    expect(parsed.header.endianness).toBe('Big Endian');
    expect(parsed.programHeaders[0].typeName).toBe('PT_LOAD');
    expect(parsed.sectionHeaders[1].name).toBe('.shstrtab');
  });

  it('should fall back to fallback strings for unknown OSABI, machine, and types', () => {
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0x99; // Unknown OSABI
    view.setUint16(16, 0x9999, true); // Unknown type
    view.setUint16(18, 0x8888, true); // Unknown machine

    const parsed = parseElf(buffer);
    expect(parsed.header.osAbi).toBe('Unknown (153)');
    expect(parsed.header.type).toBe('Unknown (39321)');
    expect(parsed.header.machine).toBe('Unknown (34952)');
  });

  it('should handle out of bounds safely when program or section headers exceed buffer', () => {
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little
    view.setBigUint64(32, 1000n, true); // Program header offset out of bounds
    view.setUint16(54, 56, true);
    view.setUint16(56, 1, true); // phNum = 1

    view.setBigUint64(40, 2000n, true); // Section header offset out of bounds
    view.setUint16(58, 64, true);
    view.setUint16(60, 1, true); // shNum = 1

    const parsed = parseElf(buffer);
    expect(parsed.programHeaders.length).toBe(0);
    expect(parsed.sectionHeaders.length).toBe(0);
  });

  it('should handle out of bounds or missing string table gracefully when resolving section names', () => {
    // 64-bit header with 2 sections but string table index is pointing to out of bounds index or offset
    const phOff = 64;
    const phNum = 0;
    const shOff = 64;
    const shNum = 2;
    const shentSize = 64;
    const buffer = new ArrayBuffer(64 + shNum * shentSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little
    view.setBigUint64(40, BigInt(shOff), true);
    view.setUint16(58, shentSize, true);
    view.setUint16(60, shNum, true);
    view.setUint16(62, 5, true); // shStrNdX = 5, but shNum = 2. So shStrNdX is invalid/out of bounds.

    const parsed = parseElf(buffer);
    expect(parsed.sectionHeaders.length).toBe(2);
    expect(parsed.sectionHeaders[0].name).toBe('');
    expect(parsed.sectionHeaders[1].name).toBe('');
  });

  it('should handle cases where string table offset + size exceeds array buffer length', () => {
    const shOff = 64;
    const shNum = 2;
    const shentSize = 64;
    const buffer = new ArrayBuffer(64 + shNum * shentSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2;
    bytes[5] = 1;
    view.setBigUint64(40, BigInt(shOff), true);
    view.setUint16(58, shentSize, true);
    view.setUint16(60, shNum, true);
    view.setUint16(62, 1, true); // shStrNdX = 1

    // Section 1: String table, but we set offset + size to exceed arrayBuffer.byteLength
    const sh1 = shOff + shentSize;
    view.setBigUint64(sh1 + 24, 1000n, true); // offset = 1000 (exceeds buffer size)
    view.setBigUint64(sh1 + 32, 10n, true); // size = 10

    const parsed = parseElf(buffer);
    expect(parsed.sectionHeaders[0].name).toBe('');
  });

  it('should handle cases where section name offset exceeds string table bounds', () => {
    const shOff = 64;
    const shNum = 2;
    const shentSize = 64;
    const shstrtabContentOffset = shOff + shNum * shentSize;
    const shstrtabSize = 10;
    const buffer = new ArrayBuffer(shstrtabContentOffset + shstrtabSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2;
    bytes[5] = 1;
    view.setBigUint64(40, BigInt(shOff), true);
    view.setUint16(58, shentSize, true);
    view.setUint16(60, shNum, true);
    view.setUint16(62, 1, true); // shStrNdX = 1

    // Section 0: Name offset is 50 (exceeds shstrtabSize = 10)
    view.setUint32(shOff, 50, true);

    // Section 1: String table
    const sh1 = shOff + shentSize;
    view.setUint32(sh1, 0, true);
    view.setBigUint64(sh1 + 24, BigInt(shstrtabContentOffset), true);
    view.setBigUint64(sh1 + 32, BigInt(shstrtabSize), true);

    const parsed = parseElf(buffer);
    expect(parsed.sectionHeaders[0].name).toBe('');
  });

  it('should map unknown program and section header types to unknown representations', () => {
    const phOff = 64;
    const phNum = 1;
    const phentSize = 56;
    const shOff = phOff + phNum * phentSize;
    const shNum = 1;
    const shentSize = 64;
    const buffer = new ArrayBuffer(shOff + shNum * shentSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x7f; bytes[1] = 0x45; bytes[2] = 0x4c; bytes[3] = 0x46;
    bytes[4] = 2;
    bytes[5] = 1;
    view.setBigUint64(32, BigInt(phOff), true);
    view.setUint16(54, phentSize, true);
    view.setUint16(56, phNum, true);

    view.setBigUint64(40, BigInt(shOff), true);
    view.setUint16(58, shentSize, true);
    view.setUint16(60, shNum, true);

    // Program header: unknown type 0x9999
    view.setUint32(phOff, 0x9999, true);

    // Section header: unknown type 0x8888
    view.setUint32(shOff + 4, 0x8888, true);

    const parsed = parseElf(buffer);
    expect(parsed.programHeaders[0].typeName).toBe('PT_UNKNOWN (39321)');
    expect(parsed.sectionHeaders[0].typeName).toBe('SHT_UNKNOWN (34952)');
  });
});

