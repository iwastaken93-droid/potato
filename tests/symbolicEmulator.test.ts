import { describe, it, expect } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';
import { stringifyExpr } from '../src/analyzer/symbolic.js';

describe('Symbolic Emulator Integration Tests', () => {
  it('should symbolicate registers and perform symbolic propagation', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
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

    // Concretely rax is 0, but symbolically it is 'x'
    emu.symbolicateRegister('rax', 'x');
    expect(emu.symbolicState.registers.get('rax')).toEqual({ type: 'variable', name: 'x' });

    emu.step();

    const symbolicRax = emu.symbolicState.registers.get('rax');
    expect(symbolicRax).toBeDefined();
    expect(stringifyExpr(symbolicRax!)).toBe('(x ADD 80)');
  });

  it('should handle subregisters during symbolic propagation', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'eax, ebx',
        operands: [
          { type: 'reg', reg: 'eax' },
          { type: 'reg', reg: 'ebx' },
        ],
        size: 4,
      },
    ];

    emu.loadInstructions(insts);
    emu.reset(0x1000);

    emu.symbolicateRegister('rbx', 'y');
    emu.step();

    const symbolicRax = emu.symbolicState.registers.get('rax');
    expect(symbolicRax).toEqual({ type: 'variable', name: 'y' });
  });

  it('should propagate symbolic memory to registers', () => {
    const emu = new Emulator();
    emu.reset(0x1000);
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
    ];

    emu.loadInstructions(insts);
    emu.symbolicateMemory(0x2000n, 'mem_val');

    emu.step();

    const symbolicRax = emu.symbolicState.registers.get('rax');
    expect(symbolicRax).toEqual({ type: 'variable', name: 'mem_val' });
  });

  it('should track branch constraints dynamically', () => {
    const emu = new Emulator();
    emu.reset(0x1000);
    emu.cpu.write('rax', 10n);

    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'cmp',
        opStr: 'rax, 10',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 10n },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'je',
        opStr: '0x1010',
        operands: [
          { type: 'imm', imm: 0x1010n },
        ],
        size: 4,
      },
    ];

    emu.loadInstructions(insts);
    emu.symbolicateRegister('rax', 'input_val');

    emu.step(); // cmp
    emu.step(); // je (taken because rax is concretely 10)

    expect(emu.cpu.read('rip')).toBe(0x1010n);
    expect(emu.symbolicState.constraints.length).toBe(1);
    expect(stringifyExpr(emu.symbolicState.constraints[0])).toBe('(input_val == 10)');
  });
});
