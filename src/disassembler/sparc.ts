import { Instruction, Operand } from './types.js';

function signExtend(value: number, bits: number): number {
  const shift = 32 - bits;
  return (value << shift) >> shift;
}

const regs = [
  '%g0', '%g1', '%g2', '%g3', '%g4', '%g5', '%g6', '%g7',
  '%o0', '%o1', '%o2', '%o3', '%o4', '%o5', '%o6', '%o7',
  '%l0', '%l1', '%l2', '%l3', '%l4', '%l5', '%l6', '%l7',
  '%i0', '%i1', '%i2', '%i3', '%i4', '%i5', '%i6', '%i7'
];

/**
 * Lightweight SPARC / SPARC V9 disassembler.
 */
export function disassembleSparc(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  while (i + 3 < data.length) {
    const addr = baseAddress + i;
    // SPARC instructions are 4 bytes, Big Endian
    const val =
      ((data[i] << 24) |
        (data[i + 1] << 16) |
        (data[i + 2] << 8) |
        data[i + 3]) >>>
      0;

    let mnemonic = 'db';
    let opStr = `0x${val.toString(16).padStart(8, '0')}`;
    let operands: Operand[] = [];
    const size = 4;

    const op = (val >>> 30) & 3;

    if (op === 1) {
      // CALL
      const disp30 = signExtend(val & 0x3fffffff, 30);
      const target = addr + disp30 * 4;
      mnemonic = 'call';
      opStr = `0x${target.toString(16)}`;
      operands = [{ type: 'imm', imm: target }];
    } else if (op === 0) {
      // Format 2: Branches, SETHI
      const rd = (val >>> 25) & 0x1f;
      const op2 = (val >>> 22) & 7;
      const rdName = regs[rd];

      if (op2 === 4) {
        // sethi
        const imm22 = val & 0x3fffff;
        mnemonic = 'sethi';
        opStr = `0x${(imm22 << 10).toString(16)}, ${rdName}`;
        operands = [
          { type: 'imm', imm: imm22 << 10 },
          { type: 'reg', reg: rdName }
        ];
      } else if (op2 === 2 || op2 === 6) {
        // bicc (op2=2) or fbcc (op2=6)
        const cond = (val >>> 25) & 0xf;
        const disp22 = signExtend(val & 0x3fffff, 22);
        const target = addr + disp22 * 4;
        
        let condName = 'unknown';
        if (op2 === 2) {
          // Bicc integer branch
          switch (cond) {
            case 8: condName = 'ba'; break; // branch always
            case 0: condName = 'bn'; break; // branch never
            case 9: condName = 'bne'; break;
            case 1: condName = 'be'; break;
            case 5: condName = 'bg'; break;
            case 13: condName = 'bge'; break;
            case 3: condName = 'bl'; break;
            case 2: condName = 'ble'; break;
            case 11: condName = 'bgu'; break;
            case 4: condName = 'bleu'; break;
            case 12: condName = 'bcc'; break; // bgeu
            case 6: condName = 'bcs'; break; // blu
            case 14: condName = 'bpos'; break;
            case 7: condName = 'bneg'; break;
            case 15: condName = 'bvc'; break;
            case 10: condName = 'bvs'; break;
          }
          mnemonic = condName;
        } else {
          // Fbcc floating branch
          mnemonic = `fb_${cond}`;
        }
        opStr = `0x${target.toString(16)}`;
        operands = [{ type: 'imm', imm: target }];
      }
    } else if (op === 2 || op === 3) {
      // Format 3: Arithmetic/Logical (op=2) or Load/Store (op=3)
      const rd = (val >>> 25) & 0x1f;
      const op3 = (val >>> 19) & 0x3f;
      const rs1 = (val >>> 14) & 0x1f;
      const i = (val >>> 13) & 1;

      const rdName = regs[rd];
      const rs1Name = regs[rs1];

      let src2Str = '';
      let src2Operand: Operand;

      if (i === 0) {
        const rs2 = val & 0x1f;
        const rs2Name = regs[rs2];
        src2Str = rs2Name;
        src2Operand = { type: 'reg', reg: rs2Name };
      } else {
        const simm13 = signExtend(val & 0x1fff, 13);
        src2Str = simm13 >= 0 ? `0x${simm13.toString(16)}` : `-0x${Math.abs(simm13).toString(16)}`;
        src2Operand = { type: 'imm', imm: simm13 };
      }

      if (op === 2) {
        // Arithmetic / Logical / Miscellaneous
        let isKnown = true;
        switch (op3) {
          case 0x00: mnemonic = 'add'; break;
          case 0x10: mnemonic = 'addcc'; break;
          case 0x08: mnemonic = 'addx'; break;
          case 0x18: mnemonic = 'addxcc'; break;
          case 0x04: mnemonic = 'sub'; break;
          case 0x14: mnemonic = 'subcc'; break;
          case 0x0c: mnemonic = 'subx'; break;
          case 0x1c: mnemonic = 'subxcc'; break;
          case 0x01: mnemonic = 'and'; break;
          case 0x11: mnemonic = 'andcc'; break;
          case 0x02: mnemonic = 'or'; break;
          case 0x12: mnemonic = 'orcc'; break;
          case 0x03: mnemonic = 'xor'; break;
          case 0x13: mnemonic = 'xorcc'; break;
          case 0x05: mnemonic = 'andn'; break;
          case 0x15: mnemonic = 'andncc'; break;
          case 0x06: mnemonic = 'orn'; break;
          case 0x16: mnemonic = 'orncc'; break;
          case 0x07: mnemonic = 'xnor'; break;
          case 0x17: mnemonic = 'xnorcc'; break;
          case 0x25: mnemonic = 'sll'; break;
          case 0x26: mnemonic = 'srl'; break;
          case 0x27: mnemonic = 'sra'; break;
          case 0x0a: mnemonic = 'umul'; break;
          case 0x0b: mnemonic = 'smul'; break;
          case 0x1a: mnemonic = 'umulcc'; break;
          case 0x1b: mnemonic = 'smulcc'; break;
          case 0x0e: mnemonic = 'udiv'; break;
          case 0x0f: mnemonic = 'sdiv'; break;
          case 0x1e: mnemonic = 'udivcc'; break;
          case 0x1f: mnemonic = 'sdivcc'; break;
          case 0x3c: mnemonic = 'save'; break;
          case 0x3d: mnemonic = 'restore'; break;
          case 0x38: mnemonic = 'jmpl'; break;
          default:
            mnemonic = `op3_0x${op3.toString(16)}`;
            isKnown = false;
            break;
        }

        if (isKnown) {
          if (mnemonic === 'jmpl') {
            opStr = `${rs1Name} + ${src2Str}, ${rdName}`;
            operands = [
              { type: 'mem', mem: { base: rs1Name, disp: i === 1 ? (src2Operand.imm as number) : undefined, index: i === 0 ? (src2Operand.reg as string) : undefined } },
              { type: 'reg', reg: rdName }
            ];
          } else {
            opStr = `${rs1Name}, ${src2Str}, ${rdName}`;
            operands = [
              { type: 'reg', reg: rs1Name },
              src2Operand,
              { type: 'reg', reg: rdName }
            ];
          }
        }
      } else {
        // Load / Store instructions (op=3)
        let isStore = false;
        let isKnown = true;
        switch (op3) {
          case 0x00: mnemonic = 'ld'; break;
          case 0x01: mnemonic = 'ldub'; break;
          case 0x02: mnemonic = 'lduh'; break;
          case 0x03: mnemonic = 'ldd'; break;
          case 0x04: mnemonic = 'st'; isStore = true; break;
          case 0x05: mnemonic = 'stb'; isStore = true; break;
          case 0x06: mnemonic = 'sth'; isStore = true; break;
          case 0x07: mnemonic = 'std'; isStore = true; break;
          case 0x09: mnemonic = 'ldsb'; break;
          case 0x0a: mnemonic = 'ldsh'; break;
          default:
            mnemonic = `ldst_0x${op3.toString(16)}`;
            isKnown = false;
            break;
        }

        if (isKnown) {
          const dispVal = i === 1 ? (src2Operand.imm as number) : undefined;
          const indexVal = i === 0 ? (src2Operand.reg as string) : undefined;
          const memOp: Operand = {
            type: 'mem',
            mem: {
              base: rs1Name,
              disp: dispVal,
              index: indexVal
            }
          };

          if (isStore) {
            opStr = `${rdName}, [${rs1Name} + ${src2Str}]`;
            operands = [
              { type: 'reg', reg: rdName },
              memOp
            ];
          } else {
            opStr = `[${rs1Name} + ${src2Str}], ${rdName}`;
            operands = [
              memOp,
              { type: 'reg', reg: rdName }
            ];
          }
        }
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

  if (i < data.length) {
    const remaining = data.slice(i);
    instructions.push({
      address: baseAddress + i,
      bytes: remaining,
      mnemonic: 'db',
      opStr: Array.from(remaining)
        .map(b => `0x${b.toString(16).padStart(2, '0')}`)
        .join(', '),
      operands: [],
      size: remaining.length
    });
  }

  return instructions;
}
