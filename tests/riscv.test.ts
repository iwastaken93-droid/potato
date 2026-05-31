import { describe, it, expect } from 'vitest';
import { disassembleRiscv } from '../src/disassembler/riscv.js';

describe('RISC-V Disassembler Unit Tests', () => {
  it('should disassemble 32-bit instructions correctly', () => {
    // addi x1, x2, 10
    // opcode: 0x13, rd: 1, funct3: 0, rs1: 2, imm: 10
    // val: 0x00a10093
    const data = new Uint8Array([0x93, 0x00, 0xa1, 0x00]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('addi');
    expect(insts[0].opStr).toBe('x1, x2, 10');
    expect(insts[0].size).toBe(4);
  });

  it('should disassemble compressed c.nop correctly', () => {
    // c.nop: 0x0001
    const data = new Uint8Array([0x01, 0x00]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('c.nop');
    expect(insts[0].size).toBe(2);
  });

  it('should disassemble compressed c.addi correctly', () => {
    // c.addi x1, 5 -> 0x0095
    const data = new Uint8Array([0x95, 0x00]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('c.addi');
    expect(insts[0].opStr).toBe('x1, 5');
    expect(insts[0].size).toBe(2);
  });

  it('should disassemble compressed c.li correctly', () => {
    // c.li x3, -2 -> 0x51f9
    const data = new Uint8Array([0xf9, 0x51]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('c.li');
    expect(insts[0].opStr).toBe('x3, -2');
    expect(insts[0].size).toBe(2);
  });

  it('should disassemble compressed c.lw correctly', () => {
    // c.lw x8, 4(x9) -> 0x40c0
    const data = new Uint8Array([0xc0, 0x40]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('c.lw');
    expect(insts[0].opStr).toBe('x8, 4(x9)');
    expect(insts[0].size).toBe(2);
  });

  it('should disassemble a mix of 16-bit and 32-bit instructions', () => {
    const data = new Uint8Array([
      0x01, 0x00,             // c.nop (2 bytes)
      0x93, 0x00, 0xa1, 0x00, // addi x1, x2, 10 (4 bytes)
      0x95, 0x00              // c.addi x1, 5 (2 bytes)
    ]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(3);
    expect(insts[0].mnemonic).toBe('c.nop');
    expect(insts[0].size).toBe(2);
    expect(insts[1].mnemonic).toBe('addi');
    expect(insts[1].size).toBe(4);
    expect(insts[2].mnemonic).toBe('c.addi');
    expect(insts[2].size).toBe(2);
  });
});
