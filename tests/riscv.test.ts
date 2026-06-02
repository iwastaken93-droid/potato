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

  it('should disassemble M extension mul correctly', () => {
    // mul x1, x2, x3 -> opcode: 0x33, funct7: 0x01, funct3: 0, rd: 1, rs1: 2, rs2: 3
    // val: 023100b3 -> [0xb3, 0x00, 0x31, 0x02]
    const data = new Uint8Array([0xb3, 0x00, 0x31, 0x02]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('mul');
    expect(insts[0].opStr).toBe('x1, x2, x3');
    expect(insts[0].size).toBe(4);
  });

  it('should disassemble A extension amoadd.w correctly', () => {
    // amoadd.w x1, x2, (x3) -> opcode: 0x2f, funct3: 2, funct5: 0, rd: 1, rs1: 3, rs2: 2
    // val: 000120af -> opcode: 0x2f, rd: 1, funct3: 2, rs1: 3, rs2: 2, funct5: 0
    // Binary:
    // funct5 (5b): 00000
    // aq (1b): 0
    // rl (1b): 0
    // rs2 (5b): 00010 (2)
    // rs1 (5b): 00011 (3)
    // funct3 (3b): 010 (2)
    // rd (5b): 00001 (1)
    // opcode (7b): 0101111 (0x2f)
    // 0000000 00010 00011 010 00001 0101111
    // Hex: 0021a0af -> [0xaf, 0xa0, 0x21, 0x00]
    const data = new Uint8Array([0xaf, 0xa0, 0x21, 0x00]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('amoadd.w');
    expect(insts[0].opStr).toBe('x1, x2, (x3)');
    expect(insts[0].size).toBe(4);
  });

  it('should disassemble A extension lr.w correctly', () => {
    // lr.w x1, (x2) -> opcode: 0x2f, funct3: 2, funct5: 2, rd: 1, rs1: 2, rs2: 0
    // val: 010120af -> [0xaf, 0x20, 0x01, 0x10]
    const data = new Uint8Array([0xaf, 0x20, 0x01, 0x10]);
    const insts = disassembleRiscv(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('lr.w');
    expect(insts[0].opStr).toBe('x1, (x2)');
    expect(insts[0].size).toBe(4);
  });
});
