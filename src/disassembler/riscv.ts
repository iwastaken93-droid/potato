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
  while (i + 1 < data.length) {
    const addr = baseAddress + i;
    const lowHalf = data[i] | (data[i + 1] << 8);
    const isCompressed = (lowHalf & 3) !== 3;

    let mnemonic = 'db';
    let opStr = '';
    let operands: Operand[] = [];
    let size = 4;
    let bytes: Uint8Array;
    let val = 0;

    if (isCompressed) {
      size = 2;
      val = lowHalf;
      bytes = data.slice(i, i + 2);
      opStr = `0x${val.toString(16).padStart(4, '0')}`;

      const op = val & 3;
      const funct3 = (val >> 13) & 7;
      const rdPrime = regs[8 + ((val >> 2) & 7)];
      const rs1Prime = regs[8 + ((val >> 7) & 7)];
      const rs2Prime = regs[8 + ((val >> 2) & 7)];
      const rd = regs[(val >> 7) & 0x1f];
      const rs2 = regs[(val >> 2) & 0x1f];

      if (op === 0) { // Quadrant 0
        if (funct3 === 0x0) { // c.addi4spn
          const imm =
            (((val >> 5) & 1) << 3) |
            (((val >> 6) & 1) << 2) |
            (((val >> 7) & 1) << 6) |
            (((val >> 8) & 1) << 7) |
            (((val >> 9) & 1) << 8) |
            (((val >> 10) & 1) << 9) |
            (((val >> 11) & 1) << 4) |
            (((val >> 12) & 1) << 5);
          if (imm !== 0) {
            mnemonic = 'c.addi4spn';
            opStr = `${rdPrime}, x2, ${imm}`;
            operands = [
              { type: 'reg', reg: rdPrime },
              { type: 'reg', reg: 'x2' },
              { type: 'imm', imm }
            ];
          }
        } else if (funct3 === 0x2) { // c.lw
          const offset =
            (((val >> 6) & 1) << 2) |
            (((val >> 10) & 7) << 3) |
            (((val >> 5) & 1) << 6);
          mnemonic = 'c.lw';
          opStr = `${rdPrime}, ${offset}(${rs1Prime})`;
          operands = [
            { type: 'reg', reg: rdPrime },
            { type: 'mem', mem: { base: rs1Prime, disp: offset } }
          ];
        } else if (funct3 === 0x3) { // c.ld
          const offset =
            (((val >> 10) & 7) << 3) |
            (((val >> 5) & 3) << 6);
          mnemonic = 'c.ld';
          opStr = `${rdPrime}, ${offset}(${rs1Prime})`;
          operands = [
            { type: 'reg', reg: rdPrime },
            { type: 'mem', mem: { base: rs1Prime, disp: offset } }
          ];
        } else if (funct3 === 0x6) { // c.sw
          const offset =
            (((val >> 6) & 1) << 2) |
            (((val >> 10) & 7) << 3) |
            (((val >> 5) & 1) << 6);
          mnemonic = 'c.sw';
          opStr = `${rs2Prime}, ${offset}(${rs1Prime})`;
          operands = [
            { type: 'reg', reg: rs2Prime },
            { type: 'mem', mem: { base: rs1Prime, disp: offset } }
          ];
        } else if (funct3 === 0x7) { // c.sd
          const offset =
            (((val >> 10) & 7) << 3) |
            (((val >> 5) & 3) << 6);
          mnemonic = 'c.sd';
          opStr = `${rs2Prime}, ${offset}(${rs1Prime})`;
          operands = [
            { type: 'reg', reg: rs2Prime },
            { type: 'mem', mem: { base: rs1Prime, disp: offset } }
          ];
        }
      } else if (op === 1) { // Quadrant 1
        if (funct3 === 0x0) { // c.addi or c.nop
          const imm = signExtend(((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5), 6);
          const rdIdx = (val >> 7) & 0x1f;
          if (rdIdx === 0 && imm === 0) {
            mnemonic = 'c.nop';
            opStr = '';
            operands = [];
          } else {
            mnemonic = 'c.addi';
            opStr = `${rd}, ${imm}`;
            operands = [
              { type: 'reg', reg: rd },
              { type: 'imm', imm }
            ];
          }
        } else if (funct3 === 0x1) { // c.jal (RV32C)
          const bit11 = (val >>> 12) & 1;
          const bit4 = (val >>> 11) & 1;
          const bits9_8 = (val >>> 9) & 3;
          const bit10 = (val >>> 8) & 1;
          const bit6 = (val >>> 7) & 1;
          const bit7 = (val >>> 6) & 1;
          const bits3_1 = (val >>> 3) & 7;
          const bit5 = (val >>> 2) & 1;
          const offset = signExtend(
            (bit11 << 11) |
            (bit10 << 10) |
            (bits9_8 << 8) |
            (bit7 << 7) |
            (bit6 << 6) |
            (bit5 << 5) |
            (bit4 << 4) |
            (bits3_1 << 1),
            12
          );
          const dest = addr + offset;
          mnemonic = 'c.jal';
          opStr = `0x${dest.toString(16)}`;
          operands = [
            { type: 'imm', imm: dest }
          ];
        } else if (funct3 === 0x2) { // c.li
          const imm = signExtend(((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5), 6);
          mnemonic = 'c.li';
          opStr = `${rd}, ${imm}`;
          operands = [
            { type: 'reg', reg: rd },
            { type: 'imm', imm }
          ];
        } else if (funct3 === 0x3) { // c.addi16sp or c.lui
          const rdIdx = (val >> 7) & 0x1f;
          if (rdIdx === 2) { // c.addi16sp
            const imm = signExtend((((val >> 12) & 1) << 9) | (((val >> 4) & 1) << 8) | (((val >> 3) & 1) << 7) | (((val >> 5) & 1) << 6) | (((val >> 2) & 1) << 5) | (((val >> 6) & 1) << 4), 10) * 16;
            mnemonic = 'c.addi16sp';
            opStr = `x2, ${imm}`;
            operands = [
              { type: 'reg', reg: 'x2' },
              { type: 'imm', imm }
            ];
          } else if (rdIdx !== 0) { // c.lui
            const imm = signExtend((((val >> 12) & 1) << 17) | (((val >> 2) & 0x1f) << 12), 18);
            mnemonic = 'c.lui';
            opStr = `${rd}, 0x${((imm >>> 12) & 0xfffff).toString(16)}`;
            operands = [
              { type: 'reg', reg: rd },
              { type: 'imm', imm }
            ];
          }
        } else if (funct3 === 0x4) {
          const subop = (val >> 10) & 3;
          if (subop === 0) { // c.srli
            const shamt = ((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5);
            mnemonic = 'c.srli';
            opStr = `${rs1Prime}, ${shamt}`;
            operands = [
              { type: 'reg', reg: rs1Prime },
              { type: 'imm', imm: shamt }
            ];
          } else if (subop === 0x1) { // c.srai
            const shamt = ((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5);
            mnemonic = 'c.srai';
            opStr = `${rs1Prime}, ${shamt}`;
            operands = [
              { type: 'reg', reg: rs1Prime },
              { type: 'imm', imm: shamt }
            ];
          } else if (subop === 0x2) { // c.andi
            const imm = signExtend(((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5), 6);
            mnemonic = 'c.andi';
            opStr = `${rs1Prime}, ${imm}`;
            operands = [
              { type: 'reg', reg: rs1Prime },
              { type: 'imm', imm }
            ];
          } else if (subop === 0x3) {
            const bit12 = (val >> 12) & 1;
            const bits6_5 = (val >> 5) & 3;
            if (bit12 === 0) {
              if (bits6_5 === 0) mnemonic = 'c.sub';
              else if (bits6_5 === 1) mnemonic = 'c.xor';
              else if (bits6_5 === 2) mnemonic = 'c.or';
              else if (bits6_5 === 3) mnemonic = 'c.and';
              opStr = `${rs1Prime}, ${rs2Prime}`;
              operands = [
                { type: 'reg', reg: rs1Prime },
                { type: 'reg', reg: rs2Prime }
              ];
            } else {
              if (bits6_5 === 0) mnemonic = 'c.subw';
              else if (bits6_5 === 1) mnemonic = 'c.addw';
              if (mnemonic !== 'db') {
                opStr = `${rs1Prime}, ${rs2Prime}`;
                operands = [
                  { type: 'reg', reg: rs1Prime },
                  { type: 'reg', reg: rs2Prime }
                ];
              }
            }
          }
        } else if (funct3 === 0x5) { // c.j
          const bit11 = (val >>> 12) & 1;
          const bit4 = (val >>> 11) & 1;
          const bits9_8 = (val >>> 9) & 3;
          const bit10 = (val >>> 8) & 1;
          const bit6 = (val >>> 7) & 1;
          const bit7 = (val >>> 6) & 1;
          const bits3_1 = (val >>> 3) & 7;
          const bit5 = (val >>> 2) & 1;
          const offset = signExtend(
            (bit11 << 11) |
            (bit10 << 10) |
            (bits9_8 << 8) |
            (bit7 << 7) |
            (bit6 << 6) |
            (bit5 << 5) |
            (bit4 << 4) |
            (bits3_1 << 1),
            12
          );
          const dest = addr + offset;
          mnemonic = 'c.j';
          opStr = `0x${dest.toString(16)}`;
          operands = [
            { type: 'imm', imm: dest }
          ];
        } else if (funct3 === 0x6) { // c.beqz
          const bit8 = (val >>> 12) & 1;
          const bits4_3 = (val >>> 10) & 3;
          const bits7_6 = (val >>> 5) & 3;
          const bits2_1 = (val >>> 3) & 3;
          const bit5 = (val >>> 2) & 1;
          const offset = signExtend(
            (bit8 << 8) |
            (bits7_6 << 6) |
            (bit5 << 5) |
            (bits4_3 << 3) |
            (bits2_1 << 1),
            9
          );
          const dest = addr + offset;
          mnemonic = 'c.beqz';
          opStr = `${rs1Prime}, 0x${dest.toString(16)}`;
          operands = [
            { type: 'reg', reg: rs1Prime },
            { type: 'imm', imm: dest }
          ];
        } else if (funct3 === 0x7) { // c.bnez
          const bit8 = (val >>> 12) & 1;
          const bits4_3 = (val >>> 10) & 3;
          const bits7_6 = (val >>> 5) & 3;
          const bits2_1 = (val >>> 3) & 3;
          const bit5 = (val >>> 2) & 1;
          const offset = signExtend(
            (bit8 << 8) |
            (bits7_6 << 6) |
            (bit5 << 5) |
            (bits4_3 << 3) |
            (bits2_1 << 1),
            9
          );
          const dest = addr + offset;
          mnemonic = 'c.bnez';
          opStr = `${rs1Prime}, 0x${dest.toString(16)}`;
          operands = [
            { type: 'reg', reg: rs1Prime },
            { type: 'imm', imm: dest }
          ];
        }
      } else if (op === 2) { // Quadrant 2
        if (funct3 === 0x0) { // c.slli
          const shamt = ((val >> 2) & 0x1f) | (((val >> 12) & 1) << 5);
          mnemonic = 'c.slli';
          opStr = `${rd}, ${shamt}`;
          operands = [
            { type: 'reg', reg: rd },
            { type: 'imm', imm: shamt }
          ];
        } else if (funct3 === 0x2) { // c.lwsp
          const offset =
            (((val >> 12) & 1) << 5) |
            (((val >> 2) & 3) << 6) |
            (((val >> 4) & 7) << 2);
          mnemonic = 'c.lwsp';
          opStr = `${rd}, ${offset}(x2)`;
          operands = [
            { type: 'reg', reg: rd },
            { type: 'mem', mem: { base: 'x2', disp: offset } }
          ];
        } else if (funct3 === 0x3) { // c.ldsp
          const offset =
            (((val >> 12) & 1) << 5) |
            (((val >> 2) & 7) << 6) |
            (((val >> 5) & 3) << 3);
          mnemonic = 'c.ldsp';
          opStr = `${rd}, ${offset}(x2)`;
          operands = [
            { type: 'reg', reg: rd },
            { type: 'mem', mem: { base: 'x2', disp: offset } }
          ];
        } else if (funct3 === 0x4) {
          const bit12 = (val >> 12) & 1;
          const rs2Idx = (val >> 2) & 0x1f;
          if (bit12 === 0) {
            if (rs2Idx === 0) { // c.jr
              mnemonic = 'c.jr';
              opStr = `${rd}`;
              operands = [{ type: 'reg', reg: rd }];
            } else { // c.mv
              mnemonic = 'c.mv';
              opStr = `${rd}, ${rs2}`;
              operands = [
                { type: 'reg', reg: rd },
                { type: 'reg', reg: rs2 }
              ];
            }
          } else {
            if (rs2Idx === 0) {
              const rdIdx = (val >> 7) & 0x1f;
              if (rdIdx === 0) { // c.ebreak
                mnemonic = 'c.ebreak';
                opStr = '';
                operands = [];
              } else { // c.jalr
                mnemonic = 'c.jalr';
                opStr = `${rd}`;
                operands = [{ type: 'reg', reg: rd }];
              }
            } else { // c.add
              mnemonic = 'c.add';
              opStr = `${rd}, ${rs2}`;
              operands = [
                { type: 'reg', reg: rd },
                { type: 'reg', reg: rs2 }
              ];
            }
          }
        } else if (funct3 === 0x6) { // c.swsp
          const offset =
            (((val >> 9) & 0xf) << 2) |
            (((val >> 7) & 3) << 6);
          mnemonic = 'c.swsp';
          opStr = `${rs2}, ${offset}(x2)`;
          operands = [
            { type: 'reg', reg: rs2 },
            { type: 'mem', mem: { base: 'x2', disp: offset } }
          ];
        } else if (funct3 === 0x7) { // c.sdsp
          const offset =
            (((val >> 10) & 7) << 3) |
            (((val >> 7) & 7) << 6);
          mnemonic = 'c.sdsp';
          opStr = `${rs2}, ${offset}(x2)`;
          operands = [
            { type: 'reg', reg: rs2 },
            { type: 'mem', mem: { base: 'x2', disp: offset } }
          ];
        }
      }
    } else {
      if (i + 3 >= data.length) {
        // Fallback for incomplete 32-bit instruction at the end of the buffer
        size = 2;
        val = lowHalf;
        bytes = data.slice(i, i + 2);
        mnemonic = 'db';
        opStr = `0x${val.toString(16).padStart(4, '0')}`;
        instructions.push({
          address: addr,
          bytes,
          mnemonic,
          opStr,
          operands,
          size
        });
        i += 2;
        continue;
      }

      size = 4;
      val =
        (data[i] |
          (data[i + 1] << 8) |
          (data[i + 2] << 16) |
          (data[i + 3] << 24)) >>>
        0;
      bytes = data.slice(i, i + 4);
      opStr = `0x${val.toString(16).padStart(8, '0')}`;

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
          if (funct7 === 0x01) { // M extension
            if (funct3 === 0x0) mnemonic = 'mul';
            else if (funct3 === 0x1) mnemonic = 'mulh';
            else if (funct3 === 0x2) mnemonic = 'mulhsu';
            else if (funct3 === 0x3) mnemonic = 'mulhu';
            else if (funct3 === 0x4) mnemonic = 'div';
            else if (funct3 === 0x5) mnemonic = 'divu';
            else if (funct3 === 0x6) mnemonic = 'rem';
            else if (funct3 === 0x7) mnemonic = 'remu';
          } else { // Standard OP RV32I
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
        case 0x2f: { // OP-AMO (A extension)
          if (funct3 === 0x2) {
            const funct5 = (val >>> 27) & 0x1f;
            if (funct5 === 0x02) mnemonic = 'lr.w';
            else if (funct5 === 0x03) mnemonic = 'sc.w';
            else if (funct5 === 0x01) mnemonic = 'amoswap.w';
            else if (funct5 === 0x00) mnemonic = 'amoadd.w';
            else if (funct5 === 0x04) mnemonic = 'amoxor.w';
            else if (funct5 === 0x0c) mnemonic = 'amoand.w';
            else if (funct5 === 0x08) mnemonic = 'amoor.w';
            else if (funct5 === 0x10) mnemonic = 'amomin.w';
            else if (funct5 === 0x14) mnemonic = 'amomax.w';
            else if (funct5 === 0x18) mnemonic = 'amominu.w';
            else if (funct5 === 0x1c) mnemonic = 'amomaxu.w';

            if (mnemonic !== 'db') {
              if (mnemonic === 'lr.w') {
                opStr = `${rdName}, (${rs1Name})`;
                operands = [
                  { type: 'reg', reg: rdName },
                  { type: 'mem', mem: { base: rs1Name, disp: 0 } }
                ];
              } else {
                opStr = `${rdName}, ${rs2Name}, (${rs1Name})`;
                operands = [
                  { type: 'reg', reg: rdName },
                  { type: 'reg', reg: rs2Name },
                  { type: 'mem', mem: { base: rs1Name, disp: 0 } }
                ];
              }
            }
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
    }

    instructions.push({
      address: addr,
      bytes,
      mnemonic,
      opStr,
      operands,
      size
    });

    i += size;
  }

  return instructions;
}
