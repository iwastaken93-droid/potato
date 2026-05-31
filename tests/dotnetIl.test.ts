import { describe, it, expect } from 'vitest';
import { disassembleCil } from '../src/disassembler/dotnetIl.js';
import { DisassemblerRouter } from '../src/disassembler/router.js';

describe('.NET IL (CIL) Disassembler Unit Tests', () => {
  it('should decode basic instructions without operands', () => {
    // 0x58 = add
    const data = new Uint8Array([0x58]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].address).toBe(0x1000);
    expect(insts[0].mnemonic).toBe('add');
    expect(insts[0].size).toBe(1);
    expect(insts[0].opStr).toBe('');
    expect(insts[0].operands).toEqual([]);
  });

  it('should decode 2-byte opcodes like ldarg', () => {
    // 0xfe 0x09 = ldarg, followed by uint16 variable (index 5)
    const data = new Uint8Array([0xfe, 0x09, 0x05, 0x00]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].address).toBe(0x1000);
    expect(insts[0].mnemonic).toBe('ldarg');
    expect(insts[0].size).toBe(4);
    expect(insts[0].opStr).toBe('5');
    expect(insts[0].operands).toEqual([{ type: 'imm', imm: 5 }]);
  });

  it('should decode short branch targets (brtarget_s)', () => {
    // 0x2e = beq.s, followed by offset +5 (signed int8)
    const data = new Uint8Array([0x2e, 0x05]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('beq.s');
    expect(insts[0].size).toBe(2);
    // target = 0x1000 (addr) + 1 (opSize) + 1 (i1 offset size) + 5 = 0x1007
    expect(insts[0].opStr).toBe('0x00001007');
    expect(insts[0].operands).toEqual([{ type: 'imm', imm: 0x1007 }]);

    // negative offset: -5 (0xfb)
    const dataNeg = new Uint8Array([0x2e, 0xfb]);
    const instsNeg = disassembleCil(dataNeg, 0x1000);
    expect(instsNeg.length).toBe(1);
    // target = 0x1000 + 1 + 1 - 5 = 0x0ffd
    expect(instsNeg[0].opStr).toBe('0x00000ffd');
    expect(instsNeg[0].operands).toEqual([{ type: 'imm', imm: 0x0ffd }]);
  });

  it('should decode 32-bit branch targets (brtarget)', () => {
    // 0x3b = beq, followed by offset 1000 (0x3e8)
    const data = new Uint8Array([0x3b, 0xe8, 0x03, 0x00, 0x00]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('beq');
    expect(insts[0].size).toBe(5);
    // target = 0x1000 + 1 + 4 + 1000 = 0x13ed
    expect(insts[0].opStr).toBe('0x000013ed');
    expect(insts[0].operands).toEqual([{ type: 'imm', imm: 0x13ed }]);
  });

  it('should decode various integer and float operands', () => {
    // 1. i1: ldc.i4.s (0x1f) with value 127
    const dataI1 = new Uint8Array([0x1f, 0x7f]);
    const instsI1 = disassembleCil(dataI1, 0x1000);
    expect(instsI1[0].mnemonic).toBe('ldc.i4.s');
    expect(instsI1[0].opStr).toBe('127');
    expect(instsI1[0].operands).toEqual([{ type: 'imm', imm: 127 }]);

    // 2. i4: ldc.i4 (0x20) with value 0x12345678 (LE)
    const dataI4 = new Uint8Array([0x20, 0x78, 0x56, 0x34, 0x12]);
    const instsI4 = disassembleCil(dataI4, 0x1000);
    expect(instsI4[0].mnemonic).toBe('ldc.i4');
    expect(instsI4[0].opStr).toBe('305419896');

    // 3. i8: ldc.i8 (0x21) with value 0x1234567890abcdefn (LE)
    const dataI8 = new Uint8Array([0x21, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12]);
    const instsI8 = disassembleCil(dataI8, 0x1000);
    expect(instsI8[0].mnemonic).toBe('ldc.i8');
    expect(instsI8[0].opStr).toBe('1311768467294899695n');
    expect(instsI8[0].operands[0].imm).toBe(1311768467294899695n);

    // 4. r4: ldc.r4 (0x22) with value 1.5 (0x3fc00000 LE)
    const dataR4 = new Uint8Array([0x22, 0x00, 0x00, 0xc0, 0x3f]);
    const instsR4 = disassembleCil(dataR4, 0x1000);
    expect(instsR4[0].mnemonic).toBe('ldc.r4');
    expect(instsR4[0].opStr).toBe('1.5');

    // 5. r8: ldc.r8 (0x23) with value 1.5 (0x3ff8000000000000 LE)
    const dataR8 = new Uint8Array([0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f]);
    const instsR8 = disassembleCil(dataR8, 0x1000);
    expect(instsR8[0].mnemonic).toBe('ldc.r8');
    expect(instsR8[0].opStr).toBe('1.5');
  });

  it('should decode tok and var_s operands', () => {
    // tok: ldtoken (0xd0) with token 0x04030201
    const dataTok = new Uint8Array([0xd0, 0x01, 0x02, 0x03, 0x04]);
    const instsTok = disassembleCil(dataTok, 0x1000);
    expect(instsTok[0].mnemonic).toBe('ldtoken');
    expect(instsTok[0].opStr).toBe('0x04030201');

    // var_s: ldarg.s (0x0e) with value 10
    const dataVarS = new Uint8Array([0x0e, 0x0a]);
    const instsVarS = disassembleCil(dataVarS, 0x1000);
    expect(instsVarS[0].mnemonic).toBe('ldarg.s');
    expect(instsVarS[0].opStr).toBe('10');
  });

  it('should decode switch instructions', () => {
    // 0x45 = switch, count = 2, target1_offset = 10, target2_offset = -10
    const data = new Uint8Array([
      0x45,
      0x02, 0x00, 0x00, 0x00, // count = 2
      0x0a, 0x00, 0x00, 0x00, // target 1: 10
      0xf6, 0xff, 0xff, 0xff, // target 2: -10
    ]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('switch');
    expect(insts[0].size).toBe(13); // 1 (opcode) + 4 (count) + 8 (offsets)
    // instrAfterSwitch = 0x1000 + 1 + 4 + 8 = 0x100d
    // target 1 = 0x100d + 10 = 0x1017
    // target 2 = 0x100d - 10 = 0x1003
    expect(insts[0].opStr).toBe('(0x00001017, 0x00001003)');
    expect(insts[0].operands).toEqual([
      { type: 'imm', imm: 0x1017 },
      { type: 'imm', imm: 0x1003 },
    ]);
  });

  it('should fallback to db on unknown opcode', () => {
    const data = new Uint8Array([0xff]); // 0xff is not a valid 1-byte opcode in CIL
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('db');
    expect(insts[0].opStr).toBe('0xff');
    expect(insts[0].size).toBe(1);
  });

  it('should fallback/roll back to db if there are not enough bytes for operands', () => {
    // beq.s requires 1 operand byte, but we only give it the opcode
    const data = new Uint8Array([0x2e]);
    const insts = disassembleCil(data, 0x1000);

    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('db');
    expect(insts[0].opStr).toBe('0x2e');
    expect(insts[0].size).toBe(1);
  });

  it('should route via DisassemblerRouter', () => {
    const router = new DisassemblerRouter();
    // 0x58 = add
    const data = new Uint8Array([0x58]);

    const instsCil = router.disassemble(data, { arch: 'cil', baseAddress: 0x2000 });
    expect(instsCil.length).toBe(1);
    expect(instsCil[0].mnemonic).toBe('add');
    expect(instsCil[0].address).toBe(0x2000);

    const instsDotnet = router.disassemble(data, { arch: 'dotnetIl', baseAddress: 0x3000 });
    expect(instsDotnet.length).toBe(1);
    expect(instsDotnet[0].mnemonic).toBe('add');
    expect(instsDotnet[0].address).toBe(0x3000);
  });
});
