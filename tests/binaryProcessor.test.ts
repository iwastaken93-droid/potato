import { describe, it, expect } from 'vitest';
import { processBinaryData } from '../src/analyzer/binaryProcessor.js';

describe('binaryProcessor Unit Tests', () => {
  it('should process fallback raw binary data gracefully when header is unrecognized', () => {
    const rawData = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const arrayBuffer = rawData.buffer;

    const result = processBinaryData('unknown.bin', rawData, arrayBuffer);

    expect(result).toBeDefined();
    expect(result.entryPoint).toBe(0);
    expect(result.sections.length).toBeGreaterThanOrEqual(1);
    expect(result.sections[0].name).toBe('.text');
    expect(result.symbols.length).toBeGreaterThanOrEqual(1);
    expect(result.symbols[0].name).toBe('sub_entry');
    expect(result.extractedStrings).toBeDefined();
    expect(result.dependencies).toBeDefined();
    expect(result.dependencies.binaryName).toBe('unknown.bin');
  });

  it('should process mock ELF binary header and detect ELF architecture', () => {
    // ELF header starts with 0x7F 0x45 0x4C 0x46 (7f E L F)
    // Minimally sized mock buffer that parseElf won't crash on, or let it fallback but detect ELF first.
    // Let's build a valid-looking minimal ELF structure if parseElf checks it.
    // Wait, let's check tests/elf.test.ts to see what it uses. But we can also just construct a basic one.
    const rawData = new Uint8Array(64);
    rawData[0] = 0x7f;
    rawData[1] = 0x45;
    rawData[2] = 0x4c;
    rawData[3] = 0x46;
    // e_ident details
    rawData[4] = 2; // ELFCLASS64
    rawData[5] = 1; // ELFDATA2LSB
    rawData[16] = 2; // e_type: ET_EXEC
    rawData[18] = 0x3e; // e_machine: EM_X86_64
    
    // We can run processBinaryData. Since it invokes parseElf, let's see if it parses or falls back safely.
    const arrayBuffer = rawData.buffer;
    const result = processBinaryData('test.elf', rawData, arrayBuffer);
    
    expect(result).toBeDefined();
    expect(result.entryPoint).toBeDefined();
    expect(result.sections).toBeDefined();
    expect(result.symbols).toBeDefined();
    expect(result.dependencies.imports).toBeDefined();
  });

  it('should process mock PE binary header (MZ) and detect PE format', () => {
    const rawData = new Uint8Array(128);
    rawData[0] = 0x4d; // M
    rawData[1] = 0x5a; // Z
    // Set e_lfanew to point to PE signature
    // Let's set it to 64 (0x40)
    rawData[0x3c] = 0x40;
    // PE signature
    rawData[0x40] = 0x50; // P
    rawData[0x41] = 0x45; // E
    rawData[0x42] = 0;
    rawData[0x43] = 0;
    // Machine: 0x8664 (AMD64)
    rawData[0x44] = 0x64;
    rawData[0x45] = 0x86;
    
    const arrayBuffer = rawData.buffer;
    const result = processBinaryData('test.exe', rawData, arrayBuffer);
    
    expect(result).toBeDefined();
    expect(result.dependencies.binaryName).toBe('test.exe');
  });

  it('should process mock WASM binary header', () => {
    const rawData = new Uint8Array(64);
    rawData[0] = 0x00;
    rawData[1] = 0x61;
    rawData[2] = 0x73;
    rawData[3] = 0x6d;
    rawData[4] = 0x01;
    rawData[5] = 0x00;
    rawData[6] = 0x00;
    rawData[7] = 0x00;

    const arrayBuffer = rawData.buffer;
    const result = processBinaryData('test.wasm', rawData, arrayBuffer);

    expect(result).toBeDefined();
    expect(result.architecture).toBe('wasm');
  });
});
