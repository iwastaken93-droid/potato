import { Instruction, Operand } from './types.js';

const MIPS_REGISTERS = [
  '$zero', '$at', '$v0', '$v1', '$a0', '$a1', '$a2', '$a3',
  '$t0', '$t1', '$t2', '$t3', '$t4', '$t5', '$t6', '$t7',
  '$s0', '$s1', '$s2', '$s3', '$s4', '$s5', '$s6', '$s7',
  '$t8', '$t9', '$k0', '$k1', '$gp', '$sp', '$fp', '$ra'
];

/**
 * Disassembles a buffer of MIPS instructions.
 */
export function disassembleMips(
  data: Uint8Array,
  baseAddress = 0,
  isLittleEndian = false
): Instruction[] {
  const instructions: Instruction[] = [];

  for (let offset = 0; offset + 4 <= data.length; offset += 4) {
    const pc = baseAddress + offset;
    const bytes = data.slice(offset, offset + 4);

    let instr = 0;
    if (isLittleEndian) {
      instr = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
    } else {
      instr = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    }
    instr = instr >>> 0;

    const opcode = (instr >>> 26) & 0x3f;
    const rs = (instr >>> 21) & 0x1f;
    const rt = (instr >>> 16) & 0x1f;
    const rd = (instr >>> 11) & 0x1f;
    const shamt = (instr >>> 6) & 0x1f;
    const funct = instr & 0x3f;
    const immediate = instr & 0xffff;
    const signedImmediate =
      immediate & 0x8000 ? immediate | ~0xffff : immediate;
    const target26 = instr & 0x3ffffff;

    let mnemonic = 'unknown';
    let opStr = '';
    const operands: Operand[] = [];

    const regS = MIPS_REGISTERS[rs];
    const regT = MIPS_REGISTERS[rt];
    const regD = MIPS_REGISTERS[rd];

    if (opcode === 0) {
      // R-type
      switch (funct) {
        case 0x20:
          mnemonic = 'add';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x21:
          mnemonic = 'addu';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x22:
          mnemonic = 'sub';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x23:
          mnemonic = 'subu';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x24:
          mnemonic = 'and';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x25:
          mnemonic = 'or';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x26:
          mnemonic = 'xor';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x27:
          mnemonic = 'nor';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        case 0x2a:
          mnemonic = 'slt';
          opStr = `${regD}, ${regS}, ${regT}`;
          operands.push(
            { type: 'reg', reg: regD, access: 'w' },
            { type: 'reg', reg: regS, access: 'r' },
            { type: 'reg', reg: regT, access: 'r' }
          );
          break;
        default:
          mnemonic = `r_type_0x${funct.toString(16)}`;
          opStr = `${regD}, ${regS}, ${regT}`;
          break;
      }
    } else {
      switch (opcode) {
        case 0x23: // LW
          mnemonic = 'lw';
          opStr = `${regT}, ${signedImmediate}(${regS})`;
          operands.push(
            { type: 'reg', reg: regT, access: 'w' },
            {
              type: 'mem',
              mem: { base: regS, disp: signedImmediate },
              access: 'r',
            }
          );
          break;
        case 0x2b: // SW
          mnemonic = 'sw';
          opStr = `${regT}, ${signedImmediate}(${regS})`;
          operands.push(
            { type: 'reg', reg: regT, access: 'r' },
            {
              type: 'mem',
              mem: { base: regS, disp: signedImmediate },
              access: 'w',
            }
          );
          break;
        case 0x04: // BEQ
          {
            mnemonic = 'beq';
            const target = pc + 4 + signedImmediate * 4;
            opStr = `${regS}, ${regT}, 0x${target.toString(16)}`;
            operands.push(
              { type: 'reg', reg: regS, access: 'r' },
              { type: 'reg', reg: regT, access: 'r' },
              { type: 'imm', imm: target }
            );
          }
          break;
        case 0x05: // BNE
          {
            mnemonic = 'bne';
            const target = pc + 4 + signedImmediate * 4;
            opStr = `${regS}, ${regT}, 0x${target.toString(16)}`;
            operands.push(
              { type: 'reg', reg: regS, access: 'r' },
              { type: 'reg', reg: regT, access: 'r' },
              { type: 'imm', imm: target }
            );
          }
          break;
        case 0x02: // J
          {
            mnemonic = 'j';
            const target = (((pc + 4) & 0xf0000000) | (target26 * 4)) >>> 0;
            opStr = `0x${target.toString(16)}`;
            operands.push({ type: 'imm', imm: target });
          }
          break;
        case 0x03: // JAL
          {
            mnemonic = 'jal';
            const target = (((pc + 4) & 0xf0000000) | (target26 * 4)) >>> 0;
            opStr = `0x${target.toString(16)}`;
            operands.push({ type: 'imm', imm: target });
          }
          break;
        default:
          mnemonic = `opcode_0x${opcode.toString(16)}`;
          opStr = `0x${instr.toString(16)}`;
          break;
      }
    }

    instructions.push({
      address: pc,
      bytes,
      mnemonic,
      opStr,
      operands,
      size: 4,
    });
  }

  return instructions;
}
