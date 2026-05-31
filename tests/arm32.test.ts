import { describe, it, expect } from 'vitest';
import { disassembleArm32, disassembleThumb } from '../src/disassembler/arm32.js';
import { DisassemblerRouter } from '../src/disassembler/router.js';

describe('ARM32 Disassembler Unit Tests', () => {
  it('should disassemble NOP correctly', () => {
    const data = new Uint8Array([0x00, 0x00, 0xa0, 0xe1]); // mov r0, r0
    const insts = disassembleArm32(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('nop');
    expect(insts[0].opStr).toBe('');
  });

  it('should disassemble ADD reg, reg, reg correctly', () => {
    const data = new Uint8Array([0x02, 0x00, 0x81, 0xe0]); // add r0, r1, r2
    const insts = disassembleArm32(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('add');
    expect(insts[0].opStr).toBe('r0, r1, r2');
    expect(insts[0].operands[0]).toEqual({ type: 'reg', reg: 'r0', access: 'w' });
    expect(insts[0].operands[1]).toEqual({ type: 'reg', reg: 'r1', access: 'r' });
    expect(insts[0].operands[2]).toEqual({ type: 'reg', reg: 'r2', access: 'r' });
  });

  it('should disassemble SUB reg, reg, imm correctly', () => {
    const data = new Uint8Array([0x05, 0x00, 0x41, 0xe2]); // sub r0, r1, #5
    const insts = disassembleArm32(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('sub');
    expect(insts[0].opStr).toBe('r0, r1, #0x5');
  });

  it('should disassemble LDR and STR correctly', () => {
    const dataLdr = new Uint8Array([0x04, 0x00, 0x91, 0xe5]); // ldr r0, [r1, #4]
    const instsLdr = disassembleArm32(dataLdr, 0x1000);
    expect(instsLdr.length).toBe(1);
    expect(instsLdr[0].mnemonic).toBe('ldr');
    expect(instsLdr[0].opStr).toBe('r0, [r1, #0x4]');

    const dataStr = new Uint8Array([0x04, 0x00, 0x81, 0xe5]); // str r0, [r1, #4]
    const instsStr = disassembleArm32(dataStr, 0x1000);
    expect(instsStr.length).toBe(1);
    expect(instsStr[0].mnemonic).toBe('str');
    expect(instsStr[0].opStr).toBe('r0, [r1, #0x4]');
  });

  it('should disassemble B and BL correctly', () => {
    const dataB = new Uint8Array([0x02, 0x00, 0x00, 0xea]); // b +8 (dest = pc + 8 + 8 = 0x1010)
    const instsB = disassembleArm32(dataB, 0x1000);
    expect(instsB.length).toBe(1);
    expect(instsB[0].mnemonic).toBe('b');
    expect(instsB[0].opStr).toBe('0x1010');
  });

  it('should disassemble PUSH and POP correctly', () => {
    const dataPush = new Uint8Array([0x07, 0x40, 0x2d, 0xe9]); // push {r0, r1, r2, lr}
    const instsPush = disassembleArm32(dataPush, 0x1000);
    expect(instsPush.length).toBe(1);
    expect(instsPush[0].mnemonic).toBe('push');
    expect(instsPush[0].opStr).toBe('{r0, r1, r2, lr}');

    const dataPop = new Uint8Array([0x07, 0x80, 0xbd, 0xe8]); // pop {r0, r1, r2, pc}
    const instsPop = disassembleArm32(dataPop, 0x1000);
    expect(instsPop.length).toBe(1);
    expect(instsPop[0].mnemonic).toBe('pop');
    expect(instsPop[0].opStr).toBe('{r0, r1, r2, pc}');
  });

  it('should disassemble BX and BLX correctly', () => {
    const dataBx = new Uint8Array([0x1e, 0xff, 0x2f, 0xe1]); // bx lr
    const instsBx = disassembleArm32(dataBx, 0x1000);
    expect(instsBx.length).toBe(1);
    expect(instsBx[0].mnemonic).toBe('bx');
    expect(instsBx[0].opStr).toBe('lr');
  });

  it('should support condition suffixes', () => {
    const dataAddEq = new Uint8Array([0x02, 0x00, 0x81, 0x00]); // addeq r0, r1, r2
    const insts = disassembleArm32(dataAddEq, 0x1000);
    expect(insts[0].mnemonic).toBe('addeq');
  });
});

describe('Thumb Disassembler Unit Tests', () => {
  it('should disassemble 16-bit shifts', () => {
    const data = new Uint8Array([0x48, 0x00]); // lsl r0, r1, #1
    const insts = disassembleThumb(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].mnemonic).toBe('lsl');
    expect(insts[0].opStr).toBe('r0, r1, #0x1');
  });

  it('should disassemble 16-bit add/sub imm and reg', () => {
    const dataAddReg = new Uint8Array([0x48, 0x18]); // add r0, r1, r1
    const instsAddReg = disassembleThumb(dataAddReg, 0x1000);
    expect(instsAddReg[0].mnemonic).toBe('add');
    expect(instsAddReg[0].opStr).toBe('r0, r1, r1');

    const dataAddImm = new Uint8Array([0x48, 0x1c]); // add r0, r1, #1
    const instsAddImm = disassembleThumb(dataAddImm, 0x1000);
    expect(instsAddImm[0].mnemonic).toBe('add');
    expect(instsAddImm[0].opStr).toBe('r0, r1, #0x1');
  });

  it('should disassemble 16-bit mov and cmp', () => {
    const data = new Uint8Array([0x05, 0x20]); // mov r0, #5
    const insts = disassembleThumb(data, 0x1000);
    expect(insts[0].mnemonic).toBe('mov');
    expect(insts[0].opStr).toBe('r0, #0x5');
  });

  it('should disassemble 16-bit push and pop', () => {
    const dataPush = new Uint8Array([0x07, 0xb4]); // push {r0, r1, r2}
    const instsPush = disassembleThumb(dataPush, 0x1000);
    expect(instsPush[0].mnemonic).toBe('push');
    expect(instsPush[0].opStr).toBe('{r0, r1, r2}');

    const dataPushLr = new Uint8Array([0x07, 0xb5]); // push {r0, r1, r2, lr}
    const instsPushLr = disassembleThumb(dataPushLr, 0x1000);
    expect(instsPushLr[0].mnemonic).toBe('push');
    expect(instsPushLr[0].opStr).toBe('{r0, r1, r2, lr}');

    const dataPop = new Uint8Array([0x07, 0xbd]); // pop {r0, r1, r2, pc}
    const instsPop = disassembleThumb(dataPop, 0x1000);
    expect(instsPop[0].mnemonic).toBe('pop');
    expect(instsPop[0].opStr).toBe('{r0, r1, r2, pc}');
  });

  it('should disassemble 16-bit conditional and unconditional branch', () => {
    const dataCond = new Uint8Array([0x01, 0xd0]); // beq +2 (dest = pc + 4 + 2 = 0x1006)
    const instsCond = disassembleThumb(dataCond, 0x1000);
    expect(instsCond[0].mnemonic).toBe('beq');
    expect(instsCond[0].opStr).toBe('0x1006');

    const dataUncond = new Uint8Array([0x01, 0xe0]); // b +2 (dest = pc + 4 + 2 = 0x1006)
    const instsUncond = disassembleThumb(dataUncond, 0x1000);
    expect(instsUncond[0].mnemonic).toBe('b');
    expect(instsUncond[0].opStr).toBe('0x1006');
  });

  it('should disassemble 32-bit Thumb BL instruction', () => {
    // hw1 = 0xf000, hw2 = 0xf801. In little endian: 00 f0 01 f8
    const data = new Uint8Array([0x00, 0xf0, 0x01, 0xf8]);
    const insts = disassembleThumb(data, 0x1000);
    expect(insts.length).toBe(1);
    expect(insts[0].size).toBe(4);
    expect(insts[0].mnemonic).toBe('bl');
  });

  it('should disassemble 32-bit Thumb MOV.W and ADD.W', () => {
    // mov.w r0, #5 -> hw1 = 0xf04f, hw2 = 0x0005 => 4f f0 05 00
    const dataMov = new Uint8Array([0x4f, 0xf0, 0x05, 0x00]);
    const instsMov = disassembleThumb(dataMov, 0x1000);
    expect(instsMov[0].mnemonic).toBe('mov.w');
    expect(instsMov[0].opStr).toBe('r0, #0x5');

    // add.w r0, r1, #5 -> hw1 = 0xf101, hw2 = 0x0005 => 01 f1 05 00
    const dataAdd = new Uint8Array([0x01, 0xf1, 0x05, 0x00]);
    const instsAdd = disassembleThumb(dataAdd, 0x1000);
    expect(instsAdd[0].mnemonic).toBe('add.w');
    expect(instsAdd[0].opStr).toBe('r0, r1, #0x5');
  });
});

describe('Router Integration tests', () => {
  const router = new DisassemblerRouter();

  it('should route explicitly requested arm32 and thumb', () => {
    const dataAdd = new Uint8Array([0x02, 0x00, 0x81, 0xe0]); // add r0, r1, r2
    const instsArm32 = router.disassemble(dataAdd, { arch: 'arm32' });
    expect(instsArm32[0].mnemonic).toBe('add');
    expect(instsArm32[0].opStr).toBe('r0, r1, r2');

    const dataThumb = new Uint8Array([0x48, 0x00]); // lsl r0, r1, #1
    const instsThumb = router.disassemble(dataThumb, { arch: 'thumb' });
    expect(instsThumb[0].mnemonic).toBe('lsl');
    expect(instsThumb[0].opStr).toBe('r0, r1, #0x1');
  });

  it('should auto-detect 32-bit ELF ARM and route to arm32', () => {
    // 32-bit ELF, Machine 40 (EM_ARM)
    const data = new Uint8Array(64);
    data[0] = 0x7f;
    data[1] = 0x45;
    data[2] = 0x4c;
    data[3] = 0x46; // ELF
    data[4] = 1; // 32-bit
    data[18] = 40; // EM_ARM
    // Append an ARM32 instruction: add r0, r1, r2
    data[20] = 0x02;
    data[21] = 0x00;
    data[22] = 0x81;
    data[23] = 0xe0;

    const insts = router.disassemble(data);
    // Should run arm32 decoder and find the instruction
    const hasAdd = insts.some(i => i.mnemonic === 'add');
    expect(hasAdd).toBe(true);
  });
});
