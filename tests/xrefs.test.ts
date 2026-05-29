import { describe, it, expect } from 'vitest';
import { XRefEngine, XRef } from '../src/analyzer/xrefs.js';
import { Instruction, Section } from '../src/disassembler/types.js';

describe('Cross-References (XRefs) Engine Tests', () => {
  it('should allow manually adding and querying XRefs', () => {
    const engine = new XRefEngine();

    const ref1: XRef = {
      from: 0x1000,
      to: 0x2000,
      type: 'CALL',
      context: 'call 0x2000',
    };
    const ref2: XRef = {
      from: 0x1005,
      to: 0x2000,
      type: 'CALL',
      context: 'call 0x2000',
    };
    const ref3: XRef = {
      from: 0x1010,
      to: 0x3000,
      type: 'JUMP',
      context: 'jmp 0x3000',
    };

    engine.addXRef(ref1);
    engine.addXRef(ref2);
    engine.addXRef(ref3);

    // Query pointing TO an address
    const to2000 = engine.getXRefsTo(0x2000);
    expect(to2000).toHaveLength(2);
    expect(to2000.map((r) => r.from)).toContain(0x1000);
    expect(to2000.map((r) => r.from)).toContain(0x1005);

    // Query originating FROM an address
    const from1010 = engine.getXRefsFrom(0x1010);
    expect(from1010).toHaveLength(1);
    expect(from1010[0].to).toBe(0x3000);

    // Query all XRefs
    const all = engine.getAllXRefs();
    expect(all).toHaveLength(3);
  });

  it('should filter callers and callees correctly', () => {
    const engine = new XRefEngine();

    engine.addXRef({
      from: 0x1000,
      to: 0x2000,
      type: 'CALL',
      context: 'call 0x2000',
    });
    engine.addXRef({
      from: 0x1005,
      to: 0x2000,
      type: 'JUMP',
      context: 'jmp 0x2000',
    }); // JUMP should be filtered out
    engine.addXRef({
      from: 0x2000,
      to: 0x3000,
      type: 'CALL',
      context: 'call 0x3000',
    });

    const callers = engine.getCallersOf(0x2000);
    expect(callers).toHaveLength(1);
    expect(callers[0].from).toBe(0x1000);

    const callees = engine.getCalleesOf(0x2000);
    expect(callees).toHaveLength(1);
    expect(callees[0].to).toBe(0x3000);
  });

  it('should validate address boundaries against sections', () => {
    const engine = new XRefEngine();
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 0x1000,
        fileOffset: 0,
        fileSize: 0x1000,
        flags: { read: true, write: false, execute: true },
      },
      {
        name: '.data',
        virtualAddress: 0x8000,
        virtualSize: 0x500,
        fileOffset: 0x1000,
        fileSize: 0x500,
        flags: { read: true, write: true, execute: false },
      },
    ];

    expect(engine.isValidAddress(0x1500, sections)).toBe(true);
    expect(engine.isValidAddress(0x8100, sections)).toBe(true);
    expect(engine.isValidAddress(0x0500, sections)).toBe(false);
    expect(engine.isValidAddress(0x9000, sections)).toBe(false);

    // If no sections are provided, all positive addresses under max uint64 are valid
    expect(engine.isValidAddress(0x500, [])).toBe(true);
  });

  it('should analyze control flow instructions (CALL and JUMP) correctly', () => {
    const engine = new XRefEngine();

    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0xe8, 0x00, 0x10, 0x00, 0x00]),
        mnemonic: 'call',
        opStr: '0x2000',
        operands: [{ type: 'imm', imm: 0x2000 }],
        size: 5,
      },
      {
        address: 0x1005,
        bytes: new Uint8Array([0xeb, 0x05]),
        mnemonic: 'jmp',
        opStr: '0x100c',
        operands: [{ type: 'imm', imm: 0x100c }],
        size: 2,
      },
      {
        address: 0x1007,
        bytes: new Uint8Array([0x74, 0x03]),
        mnemonic: 'je',
        opStr: '0x100c',
        operands: [{ type: 'imm', imm: 0x100c }],
        size: 2,
      },
    ];

    engine.analyze(instructions);

    const to2000 = engine.getXRefsTo(0x2000);
    expect(to2000).toHaveLength(1);
    expect(to2000[0].type).toBe('CALL');
    expect(to2000[0].from).toBe(0x1000);

    const to100c = engine.getXRefsTo(0x100c);
    expect(to100c).toHaveLength(2);
    expect(to100c.every((r) => r.type === 'JUMP')).toBe(true);
  });

  it('should analyze memory operands and RIP-relative data references', () => {
    const engine = new XRefEngine();
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 0x1000,
        fileOffset: 0,
        fileSize: 0x1000,
        flags: { read: true, write: false, execute: true },
      },
      {
        name: '.data',
        virtualAddress: 0x8000,
        virtualSize: 0x1000,
        fileOffset: 0x1000,
        fileSize: 0x1000,
        flags: { read: true, write: true, execute: false },
      },
    ];

    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x48, 0x8d, 0x05, 0x00, 0x70, 0x00, 0x00]),
        mnemonic: 'lea',
        opStr: 'rax, [rip + 0x7000]',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'mem', mem: { base: 'rip', disp: 0x7000 }, access: 'r' },
        ],
        size: 7,
      },
    ];

    engine.analyze(instructions, sections);

    // Target = Address of next instruction (0x1007) + displacement (0x7000) = 0x8007
    const to8007 = engine.getXRefsTo(0x8007);
    expect(to8007).toHaveLength(1);
    expect(to8007[0].type).toBe('DATA_READ');
    expect(to8007[0].from).toBe(0x1000);
  });

  it('should fallback to parsing absolute hex addresses in opStr if operands are empty', () => {
    const engine = new XRefEngine();

    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([]),
        mnemonic: 'call',
        opStr: '0x3000',
        operands: [],
        size: 5,
      },
      {
        address: 0x1005,
        bytes: new Uint8Array([]),
        mnemonic: 'mov',
        opStr: 'rax, [0x4000]',
        operands: [],
        size: 6,
      },
    ];

    engine.analyze(instructions);

    const to3000 = engine.getXRefsTo(0x3000);
    expect(to3000).toHaveLength(1);
    expect(to3000[0].type).toBe('CALL');

    const to4000 = engine.getXRefsTo(0x4000);
    expect(to4000).toHaveLength(1);
    expect(to4000[0].type).toBe('DATA');
  });

  it('should scan data/buffer for 32-bit and 64-bit pointer references', () => {
    const engine = new XRefEngine();

    // Set up a mock text/data structure
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 0x100,
        fileOffset: 0,
        fileSize: 0x100,
        flags: { read: true, write: false, execute: true },
      },
      {
        name: '.data',
        virtualAddress: 0x8000,
        virtualSize: 0x100,
        fileOffset: 0x100,
        fileSize: 0x100,
        flags: { read: true, write: true, execute: false },
      },
    ];

    // Build a buffer for the .data section (starting at file offset 0x100)
    // We'll write pointers pointing to .text section (e.g. 0x1024)
    const buffer = new Uint8Array(0x200); // 0x200 total size
    const view = new DataView(buffer.buffer);

    // Place a 32-bit pointer at file offset 0x110 (which is virtualAddress 0x8010)
    // Pointer value: 0x1020 (which is in .text)
    view.setUint32(0x110, 0x1020, true);

    // Place a 64-bit pointer at file offset 0x120 (which is virtualAddress 0x8020)
    // Pointer value: 0x1040 (which is in .text)
    view.setBigUint64(0x120, 0x1040n, true);

    engine.analyze([], sections, [], buffer);

    const to1020 = engine.getXRefsTo(0x1020);
    expect(to1020).toHaveLength(1);
    expect(to1020[0].from).toBe(0x8010);
    expect(to1020[0].type).toBe('DATA');

    const to1040 = engine.getXRefsTo(0x1040);
    expect(to1040).toHaveLength(1);
    expect(to1040[0].from).toBe(0x8020);
    expect(to1040[0].type).toBe('DATA');
  });
});
