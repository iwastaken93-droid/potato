import { Instruction, Operand } from './types.js';

function signExtend(value: number, bits: number): number {
  const shift = 32 - bits;
  return (value << shift) >> shift;
}

/**
 * Lightweight RISC-V (RV32I/RV64I base) disassembler.
 */
export function disassembleRiscv(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  const regs = [
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31'
  ];

  let i = 0;
  while (i + 3 < data.length) {
    const addr = baseAddress + i;
    const val =
      (data[i] |
        (data[i + 1] << 8) |
        (data[i + 2] << 16) |
        (data[i + 3] << 24)) >>>
      0;
    
    let mnemonic = 'db';
    let opStr = `0x${val.toString(16).padStart(8, '0')}`;
    let operands: Operand[] = [];
    const size = 4;

    const opcode = val & 0x7f;
    const rd = (val >> 7) & 0x1f;
    const funct3 = (val >> 12) & 0x7;
    const rs1 = (val >> 15) & 0x1f;
    const rs2 = (val >> 20) & 0x1f;
    const funct7 = (val >> 25) & 0x7f;

    const rdName = regs[rd];
    const rs1Name = regs[rs1];
    const rs2Name = regs[rs2];

    switch (opcode) {
      case 0x13: { // OP-IMM
        const imm = signExtend(val >>> 20, 12);
        if (funct3 === 0x0) {
          mnemonic = 'addi';
          opStr = `${rdName}, ${rs1Name}, ${imm}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm }
          ];
        } else if (funct3 === 0x4) {
          mnemonic = 'xori';
          opStr = `${rdName}, ${rs1Name}, ${imm}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm }
          ];
        } else if (funct3 === 0x6) {
          mnemonic = 'ori';
          opStr = `${rdName}, ${rs1Name}, ${imm}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm }
          ];
        } else if (funct3 === 0x7) {
          mnemonic = 'andi';
          opStr = `${rdName}, ${rs1Name}, ${imm}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm }
          ];
        } else if (funct3 === 0x1) {
          const shamt = rs2; // imm[5:0] for RV64I, rs2 for RV32I (imm[4:0])
          mnemonic = 'slli';
          opStr = `${rdName}, ${rs1Name}, ${shamt}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm: shamt }
          ];
        } else if (funct3 === 0x5) {
          const shamt = rs2;
          const isSra = (funct7 & 0x20) !== 0;
          mnemonic = isSra ? 'srai' : 'srli';
          opStr = `${rdName}, ${rs1Name}, ${shamt}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'imm', imm: shamt }
          ];
        }
        break;
      }
      case 0x33: { // OP
        if (funct3 === 0x0) {
          if (funct7 === 0x00) {
            mnemonic = 'add';
          } else if (funct7 === 0x20) {
            mnemonic = 'sub';
          }
        } else if (funct3 === 0x1 && funct7 === 0x00) {
          mnemonic = 'sll';
        } else if (funct3 === 0x4 && funct7 === 0x00) {
          mnemonic = 'xor';
        } else if (funct3 === 0x5) {
          if (funct7 === 0x00) mnemonic = 'srl';
          else if (funct7 === 0x20) mnemonic = 'sra';
        } else if (funct3 === 0x6 && funct7 === 0x00) {
          mnemonic = 'or';
        } else if (funct3 === 0x7 && funct7 === 0x00) {
          mnemonic = 'and';
        }

        if (mnemonic !== 'db') {
          opStr = `${rdName}, ${rs1Name}, ${rs2Name}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rs1Name },
            { type: 'reg', reg: rs2Name }
          ];
        }
        break;
      }
      case 0x37: { // LUI
        const imm = val & 0xfffff000;
        const signExtImm = signExtend(imm, 32);
        opStr = `${rdName}, 0x${((val >>> 12) & 0xfffff).toString(16)}`;
        mnemonic = 'lui';
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'imm', imm: signExtImm }
        ];
        break;
      }
      case 0x17: { // AUIPC
        const imm = val & 0xfffff000;
        const offset = signExtend(imm, 32);
        const dest = addr + offset;
        opStr = `${rdName}, 0x${((val >>> 12) & 0xfffff).toString(16)}`;
        mnemonic = 'auipc';
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'imm', imm: dest }
        ];
        break;
      }
      case 0x6f: { // JAL
        const bit20 = (val >>> 31) & 1;
        const bits10_1 = (val >>> 21) & 0x3ff;
        const bit11 = (val >>> 20) & 1;
        const bits19_12 = (val >>> 12) & 0xff;
        const offset = signExtend((bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1), 21);
        const dest = addr + offset;
        mnemonic = 'jal';
        opStr = `${rdName}, 0x${dest.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'imm', imm: dest }
        ];
        break;
      }
      case 0x67: { // JALR
        if (funct3 === 0x0) {
          const imm = signExtend(val >>> 20, 12);
          mnemonic = 'jalr';
          opStr = `${rdName}, ${imm}(${rs1Name})`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'mem', mem: { base: rs1Name, disp: imm } }
          ];
        }
        break;
      }
      case 0x63: { // Branch (BEQ, BNE, etc.)
        const bit12 = (val >>> 31) & 1;
        const bit11 = (val >>> 7) & 1;
        const bits10_5 = (val >>> 25) & 0x3f;
        const bits4_1 = (val >>> 8) & 0xf;
        const offset = signExtend((bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1), 13);
        const dest = addr + offset;

        if (funct3 === 0x0) mnemonic = 'beq';
        else if (funct3 === 0x1) mnemonic = 'bne';
        else if (funct3 === 0x4) mnemonic = 'blt';
        else if (funct3 === 0x5) mnemonic = 'bge';
        else if (funct3 === 0x6) mnemonic = 'bltu';
        else if (funct3 === 0x7) mnemonic = 'bgeu';

        if (mnemonic !== 'db') {
          opStr = `${rs1Name}, ${rs2Name}, 0x${dest.toString(16)}`;
          operands = [
            { type: 'reg', reg: rs1Name },
            { type: 'reg', reg: rs2Name },
            { type: 'imm', imm: dest }
          ];
        }
        break;
      }
      case 0x03: { // Load (LW, etc.)
        if (funct3 === 0x2) {
          const imm = signExtend(val >>> 20, 12);
          mnemonic = 'lw';
          opStr = `${rdName}, ${imm}(${rs1Name})`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'mem', mem: { base: rs1Name, disp: imm } }
          ];
        }
        break;
      }
      case 0x23: { // Store (SW, etc.)
        if (funct3 === 0x2) {
          const imm = signExtend(((val >> 7) & 0x1f) | (((val >> 25) & 0x7f) << 5), 12);
          mnemonic = 'sw';
          opStr = `${rs2Name}, ${imm}(${rs1Name})`;
          operands = [
            { type: 'reg', reg: rs2Name },
            { type: 'mem', mem: { base: rs1Name, disp: imm } }
          ];
        }
        break;
      }
    }

    instructions.push({
      address: addr,
      bytes: data.slice(i, i + 4),
      mnemonic,
      opStr,
      operands,
      size
    });

    i += 4;
  }

  return instructions;
}
