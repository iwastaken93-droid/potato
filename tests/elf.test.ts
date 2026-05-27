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
});
