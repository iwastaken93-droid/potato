import { describe, it, expect } from 'vitest';
import { disassembleArm } from '../src/disassembler/arm.js';

describe('ARM64 Disassembler Neon/SIMD/FP Unit Tests', () => {
  it('should disassemble FMOV immediate correctly', () => {
    // fmov s0, #1.0
    // imm8 = 0x70, rd = 0, sz = 0
    const val = 0x1e201000 | (0x70 << 13) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fmov');
    expect(insts[0].opStr).toBe('s0, #1.0');
  });

  it('should disassemble FMOV register to register correctly', () => {
    // fmov d0, d1
    // sz = 1 (bit 22), rd = 0, rn = 1
    const val = 0x1e204000 | (1 << 22) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fmov');
    expect(insts[0].opStr).toBe('d0, d1');
  });

  it('should disassemble FMOV GPR to FP register correctly', () => {
    // fmov s0, w1
    // sf = 0, sz = 0, rd = 0, rn = 1
    const val = 0x1e270000 | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fmov');
    expect(insts[0].opStr).toBe('s0, w1');
  });

  it('should disassemble Vector ADD (SIMD integer) correctly', () => {
    // add v0.4s, v1.4s, v2.4s
    // q = 1, size = 2, rm = 2, opcode = 0x10, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (2 << 22) | (1 << 21) | (2 << 16) | (0x10 << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('add');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble Vector FADD (SIMD FP) correctly', () => {
    // fadd v0.4s, v1.4s, v2.4s
    // q = 1, size = 0, rm = 2, opcode = 0x1a, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (0 << 22) | (1 << 21) | (2 << 16) | (0x1a << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fadd');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble DUP GPR correctly', () => {
    // dup v0.4s, w1
    // q = 1, imm5 = 4, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (4 << 16) | (3 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('dup');
    expect(insts[0].opStr).toBe('v0.4s, w1');
  });

  it('should disassemble DUP element correctly', () => {
    // dup v0.4s, v1.s[1]
    // q = 1, imm5 = 12 (element size 32-bit (4), index = 1 -> 1 << 3 | 4 = 12), rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (12 << 16) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('dup');
    expect(insts[0].opStr).toBe('v0.4s, v1.s[1]');
  });

  it('should disassemble Vector AND (SIMD logical) correctly', () => {
    // and v0.16b, v1.16b, v2.16b
    // q = 1, u = 0, size = 0, rm = 2, opcode = 0x03, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (0 << 22) | (1 << 21) | (2 << 16) | (0x03 << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('and');
    expect(insts[0].opStr).toBe('v0.16b, v1.16b, v2.16b');
  });

  it('should disassemble Vector ORR (SIMD logical) correctly', () => {
    // orr v0.8b, v1.8b, v2.8b
    // q = 0, u = 0, size = 1, rm = 2, opcode = 0x03, rn = 1, rd = 0
    const val = 0x00000000 | 0x0e000000 | (1 << 22) | (1 << 21) | (2 << 16) | (0x03 << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('orr');
    expect(insts[0].opStr).toBe('v0.8b, v1.8b, v2.8b');
  });

  it('should disassemble Vector MUL (SIMD integer mul) correctly', () => {
    // mul v0.4s, v1.4s, v2.4s
    // q = 1, u = 0, size = 2, rm = 2, opcode = 0x19, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (2 << 22) | (1 << 21) | (2 << 16) | (0x19 << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('mul');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble Vector SMAX (SIMD integer max) correctly', () => {
    // smax v0.4s, v1.4s, v2.4s
    // q = 1, u = 0, size = 2, rm = 2, opcode = 0x0c, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (2 << 22) | (1 << 21) | (2 << 16) | (0x0c << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('smax');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble Vector UMIN (SIMD integer min) correctly', () => {
    // umin v0.4s, v1.4s, v2.4s
    // q = 1, u = 1, size = 2, rm = 2, opcode = 0x0d, rn = 1, rd = 0
    const val = 0x40000000 | 0x20000000 | 0x0e000000 | (2 << 22) | (1 << 21) | (2 << 16) | (0x0d << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('umin');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble Vector FMAX (SIMD float max) correctly', () => {
    // fmax v0.4s, v1.4s, v2.4s
    // q = 1, u = 0, size = 0, rm = 2, opcode = 0x1e, rn = 1, rd = 0
    const val = 0x40000000 | 0x0e000000 | (0 << 22) | (1 << 21) | (2 << 16) | (0x1e << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fmax');
    expect(insts[0].opStr).toBe('v0.4s, v1.4s, v2.4s');
  });

  it('should disassemble Vector FMINNM (SIMD float min num) correctly', () => {
    // fminnm v0.2d, v1.2d, v2.2d
    // q = 1, u = 1, size = 1, rm = 2, opcode = 0x1c, rn = 1, rd = 0
    const val = 0x40000000 | 0x20000000 | 0x0e000000 | (1 << 22) | (1 << 21) | (2 << 16) | (0x1c << 11) | (1 << 10) | (1 << 5) | 0;
    const data = new Uint8Array([
      val & 0xff,
      (val >> 8) & 0xff,
      (val >> 16) & 0xff,
      (val >> 24) & 0xff,
    ]);
    const insts = disassembleArm(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('fminnm');
    expect(insts[0].opStr).toBe('v0.2d, v1.2d, v2.2d');
  });
});
