import { describe, it, expect } from 'vitest';
import { CPU, RFlag } from '../src/emulator/cpu.js';
import { Memory, MemoryAccessError } from '../src/emulator/memory.js';
import { Section } from '../src/disassembler/types.js';

describe('CPU State Management Tests', () => {
  it('should initialize all registers to 0', () => {
    const cpu = new CPU();
    const state = cpu.getState();
    expect(state.rax).toBe(0n);
    expect(state.rbx).toBe(0n);
    expect(state.rip).toBe(0n);
    expect(state.rflags).toBe(0n);
  });

  it('should read and write 64-bit GPRs', () => {
    const cpu = new CPU();
    cpu.write('rax', 0x1122334455667788n);
    expect(cpu.read('rax')).toBe(0x1122334455667788n);
    expect(cpu.readGPR('rax')).toBe(0x1122334455667788n);

    cpu.writeGPR('rbx', 0xffffffffffffffffn);
    expect(cpu.read('rbx')).toBe(0xffffffffffffffffn);
  });

  it('should mask 64-bit writes to 64-bit boundaries', () => {
    const cpu = new CPU();
    cpu.write('rax', 0x111222333444555666777888999n);
    expect(cpu.read('rax')).toBe(0x4555666777888999n); // low 64 bits of that large number
  });

  it('should handle zero-extension for 32-bit registers (e.g. eax)', () => {
    const cpu = new CPU();
    cpu.write('rax', 0xffffffffffffffffn);
    cpu.write('eax', 0x12345678n);
    // Writing to eax (32-bit subregister) must zero-extend to RAX
    expect(cpu.read('rax')).toBe(0x12345678n);
    expect(cpu.read('eax')).toBe(0x12345678n);
  });

  it('should preserve upper bits for 16-bit registers (e.g. ax)', () => {
    const cpu = new CPU();
    cpu.write('rax', 0xffffffffffffffffn);
    cpu.write('ax', 0x1234n);
    // Writing to ax (16-bit subregister) does not zero-extend
    expect(cpu.read('rax')).toBe(0xffffffffffff1234n);
    expect(cpu.read('ax')).toBe(0x1234n);
  });

  it('should preserve upper bits for 8-bit low registers (e.g. al)', () => {
    const cpu = new CPU();
    cpu.write('rax', 0xffffffffffffffffn);
    cpu.write('al', 0x12n);
    expect(cpu.read('rax')).toBe(0xffffffffffffff12n);
    expect(cpu.read('al')).toBe(0x12n);
  });

  it('should preserve upper and lower bits for 8-bit high registers (e.g. ah)', () => {
    const cpu = new CPU();
    cpu.write('rax', 0xffffffffffffffffn);
    cpu.write('ah', 0x12n);
    // RAX is 0xffffffffffff12ffn because ah is bits 8-15
    expect(cpu.read('rax')).toBe(0xffffffffffff12ffn);
    expect(cpu.read('ah')).toBe(0x12n);
  });

  it('should handle flags get/set in RFLAGS', () => {
    const cpu = new CPU();
    expect(cpu.getFlag(RFlag.ZF)).toBe(false);
    expect(cpu.getFlag(RFlag.CF)).toBe(false);

    cpu.setFlag(RFlag.ZF, true);
    expect(cpu.getFlag(RFlag.ZF)).toBe(true);
    expect(cpu.read('rflags')).toBe(BigInt(RFlag.ZF));

    cpu.setFlag(RFlag.CF, true);
    expect(cpu.getFlag(RFlag.CF)).toBe(true);
    expect(cpu.read('rflags')).toBe(BigInt(RFlag.ZF | RFlag.CF));

    cpu.setFlag(RFlag.ZF, false);
    expect(cpu.getFlag(RFlag.ZF)).toBe(false);
    expect(cpu.getFlag(RFlag.CF)).toBe(true);
  });

  it('should reset all registers to 0', () => {
    const cpu = new CPU();
    cpu.write('rax', 1234n);
    cpu.setFlag(RFlag.ZF, true);
    cpu.reset();
    expect(cpu.read('rax')).toBe(0n);
    expect(cpu.read('rflags')).toBe(0n);
  });
});

import { Emulator } from '../src/emulator/emulator.js';

describe('Emulator Instruction Execution Tests', () => {
  it('should run MOV and ADD instructions', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rax, 0x100',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 0x100n },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'add',
        opStr: 'rax, 0x50',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 0x50n },
        ],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);
    expect(emu.cpu.read('rax')).toBe(0n);
    expect(emu.cpu.read('rip')).toBe(0x1000n);

    // Step 1: MOV rax, 0x100
    let res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x100n);
    expect(emu.cpu.read('rip')).toBe(0x1004n);

    // Step 2: ADD rax, 0x50
    res = emu.step();
    expect(res.success).toBe(true);
    expect(emu.cpu.read('rax')).toBe(0x150n);
    expect(emu.cpu.read('rip')).toBe(0x1008n);
  });

  it('should support memory operands and LEA', () => {
    const emu = new Emulator();
    emu.reset(0x1000);
    // Write 0xdeadbeef to memory
    emu.memory.write32(0x2000n, 0xdeadbeef);
    emu.cpu.write('rbx', 0x2000n);

    // mov rax, [rbx]
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rax, [rbx]',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'mem', mem: { base: 'rbx' } },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'lea',
        opStr: 'rcx, [rbx + 0x10]',
        operands: [
          { type: 'reg', reg: 'rcx' },
          { type: 'mem', mem: { base: 'rbx', disp: 0x10n } },
        ],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);

    emu.step(); // mov rax, [rbx]
    expect(emu.cpu.read('rax')).toBe(0xdeadbeefn);

    emu.step(); // lea rcx, [rbx + 0x10]
    expect(emu.cpu.read('rcx')).toBe(0x2010n);
  });

  it('should support PUSH and POP', () => {
    const emu = new Emulator();
    emu.reset(0x1000);
    emu.cpu.write('rax', 0xabcdefn);

    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'push',
        opStr: 'rax',
        operands: [{ type: 'reg', reg: 'rax' }],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'pop',
        opStr: 'rbx',
        operands: [{ type: 'reg', reg: 'rbx' }],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);

    const initialRsp = emu.cpu.read('rsp');
    emu.step(); // push rax
    expect(emu.cpu.read('rsp')).toBe(initialRsp - 8n);
    expect(emu.memory.read64(initialRsp - 8n)).toBe(0xabcdefn);

    emu.step(); // pop rbx
    expect(emu.cpu.read('rsp')).toBe(initialRsp);
    expect(emu.cpu.read('rbx')).toBe(0xabcdefn);
  });

  it('should support CALL and RET', () => {
    const emu = new Emulator();
    emu.reset(0x1000);

    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'call',
        opStr: '0x2000',
        operands: [{ type: 'imm', imm: 0x2000n }],
        size: 4,
      },
      {
        address: 0x2000,
        bytes: new Uint8Array([0]),
        mnemonic: 'ret',
        opStr: '',
        operands: [],
        size: 1,
      },
    ];
    emu.loadInstructions(insts);

    emu.step(); // call 0x2000
    expect(emu.cpu.read('rip')).toBe(0x2000n);
    expect(emu.memory.read64(emu.cpu.read('rsp'))).toBe(0x1004n); // pushed return address

    emu.step(); // ret
    expect(emu.cpu.read('rip')).toBe(0x1004n);
  });

  it('should handle jumps and conditional jumps', () => {
    const emu = new Emulator();
    emu.reset(0x1000);

    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'cmp',
        opStr: 'rax, rbx',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'je',
        opStr: '0x1010',
        operands: [{ type: 'imm', imm: 0x1010n }],
        size: 4,
      },
      {
        address: 0x1008,
        bytes: new Uint8Array([0]),
        mnemonic: 'jmp',
        opStr: '0x1020',
        operands: [{ type: 'imm', imm: 0x1020n }],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);

    // Case 1: rax == rbx (0 == 0)
    emu.step(); // cmp rax, rbx -> ZF = 1
    expect(emu.cpu.getFlag(RFlag.ZF)).toBe(true);

    emu.step(); // je 0x1010 -> jumps because ZF = 1
    expect(emu.cpu.read('rip')).toBe(0x1010n);

    // Case 2: rax != rbx
    emu.reset(0x1000);
    emu.cpu.write('rax', 1n);
    emu.step(); // cmp rax, rbx -> ZF = 0
    expect(emu.cpu.getFlag(RFlag.ZF)).toBe(false);

    emu.step(); // je 0x1010 -> no jump
    expect(emu.cpu.read('rip')).toBe(0x1008n);

    emu.step(); // jmp 0x1020
    expect(emu.cpu.read('rip')).toBe(0x1020n);
  });

  it('should run until breakpoint is hit', () => {
    const emu = new Emulator();
    emu.reset(0x1000);

    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rax, 1',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 1n },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rbx, 2',
        operands: [
          { type: 'reg', reg: 'rbx' },
          { type: 'imm', imm: 2n },
        ],
        size: 4,
      },
      {
        address: 0x1008,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rcx, 3',
        operands: [
          { type: 'reg', reg: 'rcx' },
          { type: 'imm', imm: 3n },
        ],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.addBreakpoint(0x1008);

    const res = emu.run();
    expect(res.success).toBe(true);
    expect(res.hitBreakpoint).toBe(true);
    expect(emu.cpu.read('rip')).toBe(0x1008n);
    expect(emu.cpu.read('rax')).toBe(1n);
    expect(emu.cpu.read('rbx')).toBe(2n);
    expect(emu.cpu.read('rcx')).toBe(0n);
  });
});

describe('Memory State Management & Permissions Tests', () => {
  it('should initialize empty and allow mapping regions', () => {
    const mem = new Memory();
    expect(mem.getMemoryMap().length).toBe(0);

    mem.map(0x1000n, 0x100, '.text', {
      read: true,
      write: false,
      execute: true,
    });
    const map = mem.getMemoryMap();
    expect(map.length).toBe(1);
    expect(map[0].name).toBe('.text');
    expect(map[0].address).toBe(0x1000n);
    expect(map[0].size).toBe(0x100);
    expect(map[0].permissions.read).toBe(true);
    expect(map[0].permissions.write).toBe(false);
    expect(map[0].permissions.execute).toBe(true);
  });

  it('should read/write values with correct endianness', () => {
    const mem = new Memory();
    mem.map(0x2000n, 0x100, '.data', {
      read: true,
      write: true,
      execute: false,
    });

    // 8-bit
    mem.write8(0x2000n, 0xef);
    expect(mem.read8(0x2000n)).toBe(0xef);

    // 16-bit
    mem.write16(0x2002n, 0xabcd);
    expect(mem.read16(0x2002n)).toBe(0xabcd);
    expect(mem.read8(0x2002n)).toBe(0xcd);
    expect(mem.read8(0x2003n)).toBe(0xab);

    // 32-bit
    mem.write32(0x2010n, 0x12345678);
    expect(mem.read32(0x2010n)).toBe(0x12345678);

    // 64-bit
    mem.write64(0x2020n, 0x1122334455667788n);
    expect(mem.read64(0x2020n)).toBe(0x1122334455667788n);
  });

  it('should enforce write permissions', () => {
    const mem = new Memory();
    mem.map(0x1000n, 0x100, '.rodata', {
      read: true,
      write: false,
      execute: false,
    });

    // Read should succeed
    expect(mem.read8(0x1000n)).toBe(0);

    // Write should throw MemoryAccessError
    expect(() => mem.write8(0x1000n, 0xff)).toThrow(MemoryAccessError);
  });

  it('should enforce strict mode for unmapped addresses', () => {
    const mem = new Memory();
    mem.strictMode = true;

    expect(() => mem.read8(0x5000n)).toThrow(MemoryAccessError);
    expect(() => mem.write8(0x5000n, 0xff)).toThrow(MemoryAccessError);
  });

  it('should load sections from a parsed binary', () => {
    const mem = new Memory();
    const mockBinary = new Uint8Array([
      0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    ]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 0x100,
        fileOffset: 2,
        fileSize: 4,
        flags: { read: true, write: false, execute: true },
      },
    ];

    mem.loadSections(mockBinary, sections);

    const map = mem.getMemoryMap();
    expect(map.length).toBe(1);
    expect(map[0].name).toBe('.text');
    expect(map[0].permissions.write).toBe(false);

    // Loaded data should be [0x30, 0x40, 0x50, 0x60] at 0x1000
    expect(mem.read8(0x1000n)).toBe(0x30);
    expect(mem.read8(0x1001n)).toBe(0x40);
    expect(mem.read8(0x1002n)).toBe(0x50);
    expect(mem.read8(0x1003n)).toBe(0x60);
    expect(mem.read8(0x1004n)).toBe(0); // padded/virtual size remainder
  });
});

describe('Additional Emulator & Memory Edge Cases', () => {
  it('should handle unmapped accesses when strictMode is false', () => {
    const mem = new Memory();
    mem.strictMode = false;
    expect(mem.read8(0x9999n)).toBe(0);
    // Write shouldn't throw
    expect(() => mem.write8(0x9999n, 0x55)).not.toThrow();
  });

  it('should resolve regions correctly using getRegionAt', () => {
    const mem = new Memory();
    mem.map(0x1000n, 0x100, '.text', {
      read: true,
      write: false,
      execute: true,
    });
    expect(mem.getRegionAt(0x1050n)?.name).toBe('.text');
    expect(mem.getRegionAt(0x2000n)).toBeNull();
  });

  it('should handle read/write across page boundaries', () => {
    const mem = new Memory();
    mem.map(0xff0n, 0x20, '.boundary', {
      read: true,
      write: true,
      execute: false,
    });
    // Write 32 bits spanning across page boundary if page size is 4096 (0x1000)
    // 0xffe, 0xfff, 0x1000, 0x1001
    mem.write32(0xffen, 0x11223344);
    expect(mem.read32(0xffen)).toBe(0x11223344);
    expect(mem.read8(0xffen)).toBe(0x44);
    expect(mem.read8(0xfffn)).toBe(0x33);
    expect(mem.read8(0x1000n)).toBe(0x22);
    expect(mem.read8(0x1001n)).toBe(0x11);
  });

  it('should handle XOR instruction and flags correctly', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'xor',
        opStr: 'rax, rax',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'reg', reg: 'rax' },
        ],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);
    emu.cpu.write('rax', 0x5555n);
    emu.step();
    expect(emu.cpu.read('rax')).toBe(0n);
    expect(emu.cpu.getFlag(RFlag.ZF)).toBe(true);
    expect(emu.cpu.getFlag(RFlag.CF)).toBe(false);
    expect(emu.cpu.getFlag(RFlag.OF)).toBe(false);
  });

  it('should handle various conditional jumps', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'jg',
        opStr: '0x2000',
        operands: [{ type: 'imm', imm: 0x2000n }],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'jl',
        opStr: '0x3000',
        operands: [{ type: 'imm', imm: 0x3000n }],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);

    // Case 1: jg (ZF=0, SF=OF) -> jump
    emu.reset(0x1000);
    emu.cpu.setFlag(RFlag.ZF, false);
    emu.cpu.setFlag(RFlag.SF, true);
    emu.cpu.setFlag(RFlag.OF, true);
    emu.step();
    expect(emu.cpu.read('rip')).toBe(0x2000n);

    // Case 2: jl (SF != OF) -> jump
    emu.reset(0x1004);
    emu.cpu.setFlag(RFlag.SF, true);
    emu.cpu.setFlag(RFlag.OF, false);
    emu.step();
    expect(emu.cpu.read('rip')).toBe(0x3000n);
  });

  it('should handle emulator pause and max instruction limit', () => {
    const emu = new Emulator();
    // infinite loop using two alternating jumps
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'jmp',
        opStr: '0x1004',
        operands: [{ type: 'imm', imm: 0x1004n }],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'jmp',
        opStr: '0x1000',
        operands: [{ type: 'imm', imm: 0x1000n }],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);

    // Set max instruction count low
    emu['maxInstructions'] = 10;
    const res = emu.run();
    expect(res.success).toBe(false);
    expect(res.error).toContain('Maximum instruction execution limit');
  });

  it('should throw error for unsupported instructions', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'invalid_op',
        opStr: 'rax, rbx',
        operands: [],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);
    const res = emu.step();
    expect(res.success).toBe(false);
    expect(res.error).toContain('Unsupported emulator instruction');
  });

  it('should clear all mappings and regions using clear()', () => {
    const mem = new Memory();
    mem.map(0x1000n, 0x100, '.text');
    expect(mem.getMemoryMap().length).toBe(1);
    mem.clear();
    expect(mem.getMemoryMap().length).toBe(0);
    expect(mem.getRegionAt(0x1000n)).toBeNull();
  });

  it('should mask 64-bit addresses in read/write functions', () => {
    const mem = new Memory();
    mem.map(0n, 0x100, '.zero');
    // passing an address that overflows 64-bit space (e.g. 2^64 + 5)
    // it should mask it to 5 and write/read successfully
    const overflowAddr = (1n << 64n) + 5n;
    mem.write8(overflowAddr, 0x55);
    expect(mem.read8(overflowAddr)).toBe(0x55);
    expect(mem.read8(5n)).toBe(0x55);
  });

  it('should enforce read permissions and bypass write permissions when requested', () => {
    const mem = new Memory();
    // Map a region that has write: true but read: false
    mem.map(0x1000n, 0x100, '.writeonly', {
      read: false,
      write: true,
      execute: false,
    });

    // Write should succeed
    mem.write8(0x1000n, 0xaa);
    // Read should throw MemoryAccessError
    expect(() => mem.read8(0x1000n)).toThrow(MemoryAccessError);

    // Map a region that has read: true but write: false
    mem.map(0x2000n, 0x100, '.readonly', {
      read: true,
      write: false,
      execute: false,
    });
    // Write without bypass should throw
    expect(() => mem.write8(0x2000n, 0xbb)).toThrow(MemoryAccessError);
    // Write with bypass should succeed
    mem.write8(0x2000n, 0xbb, true);
    expect(mem.read8(0x2000n)).toBe(0xbb);
  });

  it('should verify execute permissions using checkPermission', () => {
    const mem = new Memory();
    mem.map(0x1000n, 0x100, '.noexec', {
      read: true,
      write: true,
      execute: false,
    });
    // Accessing internal private checkPermission method using casting
    expect(() => (mem as any).checkPermission(0x1000n, 'execute')).toThrow(
      MemoryAccessError
    );

    // Map executable region
    mem.map(0x2000n, 0x100, '.exec', {
      read: true,
      write: true,
      execute: true,
    });
    expect(() =>
      (mem as any).checkPermission(0x2000n, 'execute')
    ).not.toThrow();
  });

  it('should support writeBuffer and readBuffer with bypass permissions', () => {
    const mem = new Memory();
    mem.map(0x1000n, 0x100, '.readonly', {
      read: true,
      write: false,
      execute: false,
    });

    const data = new Uint8Array([1, 2, 3, 4]);
    // Normal writeBuffer on readonly region should throw
    expect(() => mem.writeBuffer(0x1000n, data, false)).toThrow(
      MemoryAccessError
    );

    // Write with bypass should succeed
    mem.writeBuffer(0x1000n, data, true);
    expect(mem.readBuffer(0x1000n, 4)).toEqual(data);
  });
});
