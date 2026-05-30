import { Instruction, Operand } from './types.js';
import { signExtend8 } from './helpers.js';

/**
 * Lightweight mock Dalvik bytecode disassembler.
 * Decodes DEX bytecode.
 */
export function disassembleDalvik(
  data: Uint8Array,
  baseAddress: number
): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;
  while (i < data.length) {
    const addr = baseAddress + i;
    const opcode = data[i];
    let mnemonic = 'nop';
    let opStr = '';
    let operands: Operand[] = [];
    let size = 1;

    if (opcode === 0x00) {
      mnemonic = 'nop';
      size = 1;
    } else if (opcode === 0x01) {
      mnemonic = 'move';
      const vA = data[i + 1] & 0xf;
      const vB = (data[i + 1] >> 4) & 0xf;
      opStr = `v${vA}, v${vB}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
      ];
      size = 2;
    } else if (opcode === 0x02) {
      mnemonic = 'move/from16';
      const vA = data[i + 1];
      const vB = data[i + 2] | (data[i + 3] << 8);
      opStr = `v${vA}, v${vB}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
      ];
      size = 4;
    } else if (opcode === 0x03) {
      mnemonic = 'move/16';
      const vA = data[i + 2] | (data[i + 3] << 8);
      const vB = data[i + 4] | (data[i + 5] << 8);
      opStr = `v${vA}, v${vB}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
      ];
      size = 6;
    } else if (opcode === 0x07) {
      mnemonic = 'move-object';
      const vA = data[i + 1] & 0xf;
      const vB = (data[i + 1] >> 4) & 0xf;
      opStr = `v${vA}, v${vB}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
      ];
      size = 2;
    } else if (opcode === 0x0f) {
      mnemonic = 'return';
      const vA = data[i + 1];
      opStr = `v${vA}`;
      operands = [{ type: 'reg', reg: `v${vA}` }];
      size = 2;
    } else if (opcode === 0x10) {
      mnemonic = 'return-wide';
      const vA = data[i + 1];
      opStr = `v${vA}`;
      operands = [{ type: 'reg', reg: `v${vA}` }];
      size = 2;
    } else if (opcode === 0x11) {
      mnemonic = 'return-object';
      const vA = data[i + 1];
      opStr = `v${vA}`;
      operands = [{ type: 'reg', reg: `v${vA}` }];
      size = 2;
    } else if (opcode === 0x14) {
      mnemonic = 'const';
      const vA = data[i + 1];
      const val = data[i + 2] | (data[i + 3] << 8) | (data[i + 4] << 16) | (data[i + 5] << 24);
      const signedVal = val > 0x7fffffff ? val - 0x100000000 : val;
      opStr = `v${vA}, #0x${signedVal.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: signedVal },
      ];
      size = 6;
    } else if (opcode === 0x1a) {
      mnemonic = 'const-string';
      const vA = data[i + 1];
      const stringIdx = data[i + 2] | (data[i + 3] << 8);
      opStr = `v${vA}, string@0x${stringIdx.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: stringIdx },
      ];
      size = 4;
    } else if (opcode === 0x1c) {
      mnemonic = 'const-class';
      const vA = data[i + 1];
      const typeIdx = data[i + 2] | (data[i + 3] << 8);
      opStr = `v${vA}, class@0x${typeIdx.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: typeIdx },
      ];
      size = 4;
    } else if (opcode === 0x1d) {
      mnemonic = 'monitor-enter';
      const vA = data[i + 1];
      opStr = `v${vA}`;
      operands = [{ type: 'reg', reg: `v${vA}` }];
      size = 2;
    } else if (opcode === 0x1e) {
      mnemonic = 'monitor-exit';
      const vA = data[i + 1];
      opStr = `v${vA}`;
      operands = [{ type: 'reg', reg: `v${vA}` }];
      size = 2;
    } else if (opcode === 0x22) {
      mnemonic = 'new-instance';
      const vA = data[i + 1];
      const typeIdx = data[i + 2] | (data[i + 3] << 8);
      opStr = `v${vA}, type@0x${typeIdx.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: typeIdx },
      ];
      size = 4;
    } else if (opcode === 0x90) {
      mnemonic = 'add-int';
      const vA = data[i + 1];
      const vB = data[i + 2];
      const vC = data[i + 3];
      opStr = `v${vA}, v${vB}, v${vC}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
        { type: 'reg', reg: `v${vC}` },
      ];
      size = 4;
    } else if (opcode === 0x12) {
      mnemonic = 'const/4';
      const vA = data[i + 1] & 0xf;
      const B = (data[i + 1] >> 4) & 0xf;
      const val = B > 7 ? B - 16 : B;
      opStr = `v${vA}, #0x${val.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: val },
      ];
      size = 2;
    } else if (opcode === 0x26) {
      mnemonic = 'fill-array-data';
      const vA = data[i + 1];
      const offset =
        data[i + 2] |
        (data[i + 3] << 8) |
        (data[i + 4] << 16) |
        (data[i + 5] << 24);
      opStr = `v${vA}, +0x${offset.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: offset },
      ];
      size = 6;
    } else if (opcode === 0x28) {
      mnemonic = 'goto';
      const offset = signExtend8(data[i + 1]);
      opStr = `+0x${offset.toString(16)}`;
      operands = [{ type: 'imm', imm: addr + offset * 2 }];
      size = 2;
    } else if (opcode === 0x32) {
      mnemonic = 'if-eq';
      const vA = data[i + 1] & 0xf;
      const vB = (data[i + 1] >> 4) & 0xf;
      const offset = data[i + 2] | (data[i + 3] << 8);
      const signedOffset = offset > 0x7fff ? offset - 0x10000 : offset;
      opStr = `v${vA}, v${vB}, +0x${signedOffset.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'reg', reg: `v${vB}` },
        { type: 'imm', imm: addr + signedOffset * 2 },
      ];
      size = 4;
    } else if (opcode === 0x71 || opcode === 0x6e) {
      mnemonic = opcode === 0x71 ? 'invoke-static' : 'invoke-virtual';
      const count = (data[i + 1] >> 4) & 0xf;
      const methIdx = data[i + 2] | (data[i + 3] << 8);
      opStr = `{v0..v${Math.max(0, count - 1)}}, meth@0x${methIdx.toString(16)}`;
      operands = [{ type: 'imm', imm: methIdx }];
      size = 6;
    } else if (opcode === 0x0e) {
      mnemonic = 'return-void';
      size = 1;
    } else if (opcode === 0x13) {
      mnemonic = 'const/16';
      const vA = data[i + 1];
      const val = data[i + 2] | (data[i + 3] << 8);
      const signedVal = val > 0x7fff ? val - 0x10000 : val;
      opStr = `v${vA}, #0x${signedVal.toString(16)}`;
      operands = [
        { type: 'reg', reg: `v${vA}` },
        { type: 'imm', imm: signedVal },
      ];
      size = 4;
    } else {
      mnemonic = `db`;
      opStr = `0x${opcode.toString(16).padStart(2, '0')}`;
      operands = [];
      size = 1;
    }

    if (i + size > data.length) {
      size = data.length - i;
      mnemonic = 'db';
      opStr = Array.from(data.subarray(i, i + size))
        .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
        .join(', ');
    }

    instructions.push({
      address: addr,
      bytes: data.slice(i, i + size),
      mnemonic,
      opStr,
      operands,
      size,
    });

    i += size;
  }

  return instructions;
}
