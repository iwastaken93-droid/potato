import { Instruction, Operand } from './types.js';

const COND_CODES = [
  'eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
  'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', ''
];

const REG_NAMES = [
  'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
  'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'
];

function getRegName(idx: number): string {
  if (idx >= 0 && idx < 16) {
    return REG_NAMES[idx];
  }
  return 'r' + idx;
}

/**
 * Disassembles ARM32 (ARM state, 32-bit instructions).
 */
export function disassembleArm32(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  while (i + 3 < data.length) {
    const addr = baseAddress + i;
    const val = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) >>> 0;
    const bytes = data.slice(i, i + 4);

    let mnemonic = 'db';
    let opStr = `0x${val.toString(16).padStart(8, '0')}`;
    let operands: Operand[] = [];

    const cond = (val >>> 28) & 0xf;
    const condSuffix = cond < 14 ? COND_CODES[cond] : '';

    // NOP (mov r0, r0)
    if (val === 0xe1a00000) {
      mnemonic = 'nop';
      opStr = '';
    }
    // BX / BLX
    else if ((val & 0x0ffffff0) === 0x012fff10) {
      const rm = val & 0xf;
      const rmName = getRegName(rm);
      mnemonic = 'bx' + condSuffix;
      opStr = rmName;
      operands = [{ type: 'reg', reg: rmName, access: 'r' }];
    } else if ((val & 0x0ffffff0) === 0x012fff30) {
      const rm = val & 0xf;
      const rmName = getRegName(rm);
      mnemonic = 'blx' + condSuffix;
      opStr = rmName;
      operands = [{ type: 'reg', reg: rmName, access: 'r' }];
    }
    // Branch / Branch with Link (B / BL)
    else if ((val & 0x0e000000) === 0x0a000000) {
      const isLink = (val & (1 << 24)) !== 0;
      let imm24 = val & 0xffffff;
      if (imm24 & 0x800000) {
        imm24 |= ~0xffffff;
      }
      const dest = (addr + 8 + imm24 * 4) >>> 0;
      mnemonic = (isLink ? 'bl' : 'b') + condSuffix;
      opStr = `0x${dest.toString(16)}`;
      operands = [{ type: 'imm', imm: dest }];
    }
    // LDM / STM (Stack / Multi-load/store)
    else if ((val & 0x0e000000) === 0x08000000) {
      const isLoad = (val & (1 << 20)) !== 0;
      const w = (val & (1 << 21)) !== 0;
      const u = (val & (1 << 23)) !== 0;
      const p = (val & (1 << 24)) !== 0;
      const rn = (val >>> 16) & 0xf;
      const rnName = getRegName(rn);

      const regListMask = val & 0xffff;
      const regsList: string[] = [];
      for (let r = 0; r < 16; r++) {
        if (regListMask & (1 << r)) {
          regsList.push(getRegName(r));
        }
      }
      const regListStr = `{${regsList.join(', ')}}`;

      if (rn === 13 && w) {
        // PUSH/POP
        mnemonic = (isLoad ? 'pop' : 'push') + condSuffix;
        opStr = regListStr;
        operands = regsList.map(r => ({ type: 'reg', reg: r, access: isLoad ? 'w' : 'r' }));
      } else {
        const mode = p ? (u ? 'ib' : 'db') : (u ? 'ia' : 'da');
        mnemonic = (isLoad ? 'ldm' : 'stm') + mode + condSuffix;
        opStr = `${rnName}${w ? '!' : ''}, ${regListStr}`;
        operands = [
          { type: 'reg', reg: rnName, access: w ? 'rw' : 'r' },
          ...regsList.map(r => ({ type: 'reg', reg: r, access: isLoad ? 'w' : 'r' } as Operand))
        ];
      }
    }
    // LDR / STR (Load / Store immediate/register offset)
    else if ((val & 0x0c000000) === 0x04000000) {
      const isLoad = (val & (1 << 20)) !== 0;
      const w = (val & (1 << 21)) !== 0;
      const isByte = (val & (1 << 22)) !== 0;
      const u = (val & (1 << 23)) !== 0;
      const p = (val & (1 << 24)) !== 0;
      const isRegOffset = (val & (1 << 25)) !== 0;

      const rn = (val >>> 16) & 0xf;
      const rd = (val >>> 12) & 0xf;
      const rnName = getRegName(rn);
      const rdName = getRegName(rd);

      mnemonic = (isLoad ? (isByte ? 'ldrb' : 'ldr') : (isByte ? 'strb' : 'str')) + condSuffix;

      let offsetStr = '';
      let dispVal: number | undefined;
      if (!isRegOffset) {
        const offset = val & 0xfff;
        const sign = u ? 1 : -1;
        dispVal = offset * sign;
        offsetStr = `#${dispVal >= 0 ? '' : '-' }0x${Math.abs(dispVal).toString(16)}`;
      } else {
        const rm = val & 0xf;
        const rmName = getRegName(rm);
        offsetStr = (u ? '' : '-') + rmName;
      }

      if (p) {
        if (dispVal === 0) {
          opStr = `${rdName}, [${rnName}]`;
          operands = [
            { type: 'reg', reg: rdName, access: isLoad ? 'w' : 'r' },
            { type: 'mem', mem: { base: rnName }, access: isLoad ? 'r' : 'w' }
          ];
        } else {
          opStr = `${rdName}, [${rnName}, ${offsetStr}]${w ? '!' : ''}`;
          operands = [
            { type: 'reg', reg: rdName, access: isLoad ? 'w' : 'r' },
            { type: 'mem', mem: { base: rnName, disp: dispVal }, access: isLoad ? 'r' : 'w' }
          ];
        }
      } else {
        opStr = `${rdName}, [${rnName}], ${offsetStr}`;
        operands = [
          { type: 'reg', reg: rdName, access: isLoad ? 'w' : 'r' },
          { type: 'mem', mem: { base: rnName, disp: dispVal }, access: isLoad ? 'r' : 'w' }
        ];
      }
    }
    // Data Processing (ADD, SUB, MOV, etc.)
    else if ((val & 0x0c000000) === 0x00000000) {
      const isImm = (val & (1 << 25)) !== 0;
      const opc = (val >>> 21) & 0xf;
      const s = (val & (1 << 20)) !== 0;
      const rn = (val >>> 16) & 0xf;
      const rd = (val >>> 12) & 0xf;

      const rnName = getRegName(rn);
      const rdName = getRegName(rd);

      const opNames = [
        'and', 'eor', 'sub', 'rsb', 'add', 'adc', 'sbc', 'rsc',
        'tst', 'teq', 'cmp', 'cmn', 'orr', 'mov', 'bic', 'mvn'
      ];
      const opName = opNames[opc];
      mnemonic = opName + condSuffix + (s && !['tst', 'teq', 'cmp', 'cmn'].includes(opName) ? 's' : '');

      let op2Str = '';
      let op2Operand: Operand;
      if (isImm) {
        const rotate = ((val >>> 8) & 0xf) * 2;
        const imm8 = val & 0xff;
        const immVal = rotate === 0 ? imm8 : ((imm8 >>> rotate) | (imm8 << (32 - rotate))) >>> 0;
        op2Str = `#0x${immVal.toString(16)}`;
        op2Operand = { type: 'imm', imm: immVal };
      } else {
        const rm = val & 0xf;
        const rmName = getRegName(rm);
        op2Str = rmName;
        op2Operand = { type: 'reg', reg: rmName, access: 'r' };
        
        const shiftType = (val >>> 5) & 3;
        const shiftTypes = ['lsl', 'lsr', 'asr', 'ror'];
        const shiftImm = (val >>> 7) & 0x1f;
        if (shiftImm > 0) {
          op2Str += `, ${shiftTypes[shiftType]} #${shiftImm}`;
        }
      }

      if (['mov', 'mvn'].includes(opName)) {
        opStr = `${rdName}, ${op2Str}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          op2Operand
        ];
      } else if (['cmp', 'cmn', 'tst', 'teq'].includes(opName)) {
        opStr = `${rnName}, ${op2Str}`;
        operands = [
          { type: 'reg', reg: rnName, access: 'r' },
          op2Operand
        ];
      } else {
        opStr = `${rdName}, ${rnName}, ${op2Str}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          { type: 'reg', reg: rnName, access: 'r' },
          op2Operand
        ];
      }
    }
    // SVC (Supervisor Call)
    else if ((val & 0x0f000000) === 0x0f000000) {
      const imm24 = val & 0xffffff;
      mnemonic = 'svc' + condSuffix;
      opStr = `0x${imm24.toString(16)}`;
      operands = [{ type: 'imm', imm: imm24 }];
    }

    instructions.push({
      address: addr,
      bytes,
      mnemonic,
      opStr,
      operands,
      size: 4
    });

    i += 4;
  }

  // Handle trailing bytes
  while (i < data.length) {
    instructions.push({
      address: baseAddress + i,
      bytes: data.slice(i, i + 1),
      mnemonic: 'db',
      opStr: `0x${data[i].toString(16).padStart(2, '0')}`,
      operands: [],
      size: 1
    });
    i++;
  }

  return instructions;
}

/**
 * Disassembles ARM Thumb (Thumb state, 16-bit / 32-bit instructions).
 */
export function disassembleThumb(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  while (i < data.length) {
    const addr = baseAddress + i;
    
    if (i + 1 >= data.length) {
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: `0x${data[i].toString(16).padStart(2, '0')}`,
        operands: [],
        size: 1
      });
      break;
    }

    const hw1 = data[i] | (data[i + 1] << 8);
    const is32Bit = ((hw1 & 0xf800) === 0xe800 || (hw1 & 0xf800) === 0xf000 || (hw1 & 0xf800) === 0xf800);

    if (is32Bit) {
      if (i + 3 >= data.length) {
        instructions.push({
          address: addr,
          bytes: data.slice(i, i + 2),
          mnemonic: 'db',
          opStr: `0x${hw1.toString(16).padStart(4, '0')}`,
          operands: [],
          size: 2
        });
        i += 2;
        continue;
      }

      const hw2 = data[i + 2] | (data[i + 3] << 8);
      const val = ((hw1 << 16) | hw2) >>> 0;
      const bytes = data.slice(i, i + 4);

      let mnemonic = 'db';
      let opStr = `0x${val.toString(16).padStart(8, '0')}`;
      let operands: Operand[] = [];

      // 32-bit BL / BLX (Branch with link / link and exchange)
      if ((hw1 & 0xf800) === 0xf000 && (hw2 & 0xd000) === 0xd000) {
        const s = (hw1 >>> 10) & 1;
        const j1 = (hw2 >>> 13) & 1;
        const j2 = (hw2 >>> 11) & 1;
        const imm10 = hw1 & 0x3ff;
        const imm11 = hw2 & 0x7ff;
        const i1 = ~(j1 ^ s) & 1;
        const i2 = ~(j2 ^ s) & 1;
        const offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
        const signedOffset = (offset & 0x1000000) ? (offset | ~0x1ffffff) : offset;
        const dest = (addr + 4 + signedOffset) >>> 0;
        const isBlx = (hw2 & (1 << 12)) === 0;
        mnemonic = isBlx ? 'blx' : 'bl';
        opStr = `0x${dest.toString(16)}`;
        operands = [{ type: 'imm', imm: dest }];
      }
      // 32-bit MOV.W (immediate)
      else if ((hw1 & 0xffef) === 0xf04f) {
        const rd = (hw2 >>> 8) & 0xf;
        const imm8 = hw2 & 0xff;
        const imm3 = (hw2 >>> 12) & 7;
        const iVal = (hw1 >>> 10) & 1;
        const imm = (iVal << 11) | (imm3 << 8) | imm8;
        mnemonic = 'mov.w';
        const rdName = getRegName(rd);
        opStr = `${rdName}, #0x${imm.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          { type: 'imm', imm }
        ];
      }
      // 32-bit ADD.W (immediate)
      else if ((hw1 & 0xfbe0) === 0xf100) {
        const rn = hw1 & 0xf;
        const rd = (hw2 >>> 8) & 0xf;
        const imm8 = hw2 & 0xff;
        const imm3 = (hw2 >>> 12) & 7;
        const iVal = (hw1 >>> 10) & 1;
        const imm = (iVal << 11) | (imm3 << 8) | imm8;
        mnemonic = 'add.w';
        const rdName = getRegName(rd);
        const rnName = getRegName(rn);
        opStr = `${rdName}, ${rnName}, #0x${imm.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          { type: 'reg', reg: rnName, access: 'r' },
          { type: 'imm', imm }
        ];
      }
      // 32-bit SUB.W (immediate)
      else if ((hw1 & 0xfbe0) === 0xf1a0) {
        const rn = hw1 & 0xf;
        const rd = (hw2 >>> 8) & 0xf;
        const imm8 = hw2 & 0xff;
        const imm3 = (hw2 >>> 12) & 7;
        const iVal = (hw1 >>> 10) & 1;
        const imm = (iVal << 11) | (imm3 << 8) | imm8;
        mnemonic = 'sub.w';
        const rdName = getRegName(rd);
        const rnName = getRegName(rn);
        opStr = `${rdName}, ${rnName}, #0x${imm.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          { type: 'reg', reg: rnName, access: 'r' },
          { type: 'imm', imm }
        ];
      }

      instructions.push({
        address: addr,
        bytes,
        mnemonic,
        opStr,
        operands,
        size: 4
      });

      i += 4;
    } else {
      // 16-bit Thumb instruction
      const bytes = data.slice(i, i + 2);
      let mnemonic = 'db';
      let opStr = `0x${hw1.toString(16).padStart(4, '0')}`;
      let operands: Operand[] = [];

      const op5 = (hw1 >>> 11) & 0x1f;

      // 1. Shift by Immediate (LSL, LSR, ASR)
      if (op5 >= 0 && op5 <= 2) {
        const imm5 = (hw1 >>> 6) & 0x1f;
        const rm = (hw1 >>> 3) & 7;
        const rd = hw1 & 7;
        const opNames = ['lsl', 'lsr', 'asr'];
        mnemonic = opNames[op5];
        const rdName = getRegName(rd);
        const rmName = getRegName(rm);
        opStr = `${rdName}, ${rmName}, #0x${imm5.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName, access: 'w' },
          { type: 'reg', reg: rmName, access: 'r' },
          { type: 'imm', imm: imm5 }
        ];
      }
      // 2. Add / Subtract register or 3-bit immediate
      else if (op5 === 3) {
        const op3 = (hw1 >>> 9) & 3;
        const rnImm3 = (hw1 >>> 6) & 7;
        const rm = (hw1 >>> 3) & 7;
        const rd = hw1 & 7;
        const rdName = getRegName(rd);
        const rmName = getRegName(rm);

        const isSub = (op3 & 1) !== 0;
        const isImm = (op3 & 2) !== 0;
        mnemonic = isSub ? 'sub' : 'add';

        if (isImm) {
          opStr = `${rdName}, ${rmName}, #0x${rnImm3.toString(16)}`;
          operands = [
            { type: 'reg', reg: rdName, access: 'w' },
            { type: 'reg', reg: rmName, access: 'r' },
            { type: 'imm', imm: rnImm3 }
          ];
        } else {
          const rnName = getRegName(rnImm3);
          opStr = `${rdName}, ${rmName}, ${rnName}`;
          operands = [
            { type: 'reg', reg: rdName, access: 'w' },
            { type: 'reg', reg: rmName, access: 'r' },
            { type: 'reg', reg: rnName, access: 'r' }
          ];
        }
      }
      // 3. Move / Compare / Add / Subtract 8-bit immediate
      else if (op5 >= 4 && op5 <= 7) {
        const rd = (hw1 >>> 8) & 7;
        const imm8 = hw1 & 0xff;
        const opNames = ['mov', 'cmp', 'add', 'sub'];
        mnemonic = opNames[op5 - 4];
        const rdName = getRegName(rd);
        opStr = `${rdName}, #0x${imm8.toString(16)}`;
        
        if (mnemonic === 'cmp') {
          operands = [
            { type: 'reg', reg: rdName, access: 'r' },
            { type: 'imm', imm: imm8 }
          ];
        } else {
          operands = [
            { type: 'reg', reg: rdName, access: 'w' },
            { type: 'imm', imm: imm8 }
          ];
        }
      }
      // 4. Data Processing (Format 4)
      else if ((hw1 & 0xfc00) === 0x4000) {
        const aluOp = (hw1 >>> 6) & 0xf;
        const rm = (hw1 >>> 3) & 7;
        const rdn = hw1 & 7;
        const opNames = [
          'and', 'eor', 'lsl', 'lsr', 'asr', 'adc', 'sbc', 'ror',
          'tst', 'rsb', 'cmp', 'cmn', 'orr', 'mul', 'bic', 'mvn'
        ];
        mnemonic = opNames[aluOp];
        const rdnName = getRegName(rdn);
        const rmName = getRegName(rm);
        opStr = `${rdnName}, ${rmName}`;

        if (['tst', 'cmp', 'cmn'].includes(mnemonic)) {
          operands = [
            { type: 'reg', reg: rdnName, access: 'r' },
            { type: 'reg', reg: rmName, access: 'r' }
          ];
        } else {
          operands = [
            { type: 'reg', reg: rdnName, access: 'rw' },
            { type: 'reg', reg: rmName, access: 'r' }
          ];
        }
      }
      // 5. Special Data / BX / BLX (Format 5)
      else if ((hw1 & 0xfc00) === 0x4400) {
        const aluOp = (hw1 >>> 8) & 3;
        const h1 = (hw1 >>> 7) & 1;
        const h2 = (hw1 >>> 6) & 1;
        const rm = ((hw1 >>> 3) & 7) + (h2 << 3);
        const rdn = (hw1 & 7) + (h1 << 3);

        const rdnName = getRegName(rdn);
        const rmName = getRegName(rm);

        if (aluOp === 0) {
          mnemonic = 'add';
          opStr = `${rdnName}, ${rmName}`;
          operands = [
            { type: 'reg', reg: rdnName, access: 'rw' },
            { type: 'reg', reg: rmName, access: 'r' }
          ];
        } else if (aluOp === 1) {
          mnemonic = 'cmp';
          opStr = `${rdnName}, ${rmName}`;
          operands = [
            { type: 'reg', reg: rdnName, access: 'r' },
            { type: 'reg', reg: rmName, access: 'r' }
          ];
        } else if (aluOp === 2) {
          mnemonic = 'mov';
          opStr = `${rdnName}, ${rmName}`;
          operands = [
            { type: 'reg', reg: rdnName, access: 'w' },
            { type: 'reg', reg: rmName, access: 'r' }
          ];
        } else if (aluOp === 3) {
          const isLink = (hw1 & (1 << 7)) !== 0;
          mnemonic = isLink ? 'blx' : 'bx';
          opStr = rmName;
          operands = [{ type: 'reg', reg: rmName, access: 'r' }];
        }
      }
      // 6. LDR / STR (imm offset) (Format 9/10/11/12)
      else if (op5 >= 0xc && op5 <= 0x11) {
        const imm5 = (hw1 >>> 6) & 0x1f;
        const rn = (hw1 >>> 3) & 7;
        const rt = hw1 & 7;
        let scale = 1;
        if (op5 === 0xc) { mnemonic = 'str'; scale = 4; }
        else if (op5 === 0xd) { mnemonic = 'ldr'; scale = 4; }
        else if (op5 === 0xe) { mnemonic = 'strb'; scale = 1; }
        else if (op5 === 0xf) { mnemonic = 'ldrb'; scale = 1; }
        else if (op5 === 0x10) { mnemonic = 'strh'; scale = 2; }
        else if (op5 === 0x11) { mnemonic = 'ldrh'; scale = 2; }

        const offset = imm5 * scale;
        const rtName = getRegName(rt);
        const rnName = getRegName(rn);

        if (offset === 0) {
          opStr = `${rtName}, [${rnName}]`;
          operands = [
            { type: 'reg', reg: rtName, access: mnemonic.startsWith('ldr') ? 'w' : 'r' },
            { type: 'mem', mem: { base: rnName }, access: mnemonic.startsWith('ldr') ? 'r' : 'w' }
          ];
        } else {
          opStr = `${rtName}, [${rnName}, #0x${offset.toString(16)}]`;
          operands = [
            { type: 'reg', reg: rtName, access: mnemonic.startsWith('ldr') ? 'w' : 'r' },
            { type: 'mem', mem: { base: rnName, disp: offset }, access: mnemonic.startsWith('ldr') ? 'r' : 'w' }
          ];
        }
      }
      // 7. LDR / STR SP-relative (Format 13/14)
      else if (op5 === 0x12 || op5 === 0x13) {
        const rt = (hw1 >>> 8) & 7;
        const imm8 = hw1 & 0xff;
        mnemonic = (op5 === 0x12) ? 'str' : 'ldr';
        const offset = imm8 * 4;
        const rtName = getRegName(rt);

        if (offset === 0) {
          opStr = `${rtName}, [sp]`;
          operands = [
            { type: 'reg', reg: rtName, access: mnemonic === 'ldr' ? 'w' : 'r' },
            { type: 'mem', mem: { base: 'sp' }, access: mnemonic === 'ldr' ? 'r' : 'w' }
          ];
        } else {
          opStr = `${rtName}, [sp, #0x${offset.toString(16)}]`;
          operands = [
            { type: 'reg', reg: rtName, access: mnemonic === 'ldr' ? 'w' : 'r' },
            { type: 'mem', mem: { base: 'sp', disp: offset }, access: mnemonic === 'ldr' ? 'r' : 'w' }
          ];
        }
      }
      // 8. PUSH / POP (Format 15)
      else if ((hw1 & 0xf600) === 0xb400) {
        const isPop = (hw1 & (1 << 11)) !== 0;
        const regMask = hw1 & 0xff;
        const list: string[] = [];
        for (let r = 0; r < 8; r++) {
          if (regMask & (1 << r)) {
            list.push(getRegName(r));
          }
        }
        const hasExtra = (hw1 & (1 << 8)) !== 0;
        if (hasExtra) {
          list.push(isPop ? 'pc' : 'lr');
        }
        mnemonic = isPop ? 'pop' : 'push';
        opStr = `{${list.join(', ')}}`;
        operands = list.map(r => ({ type: 'reg', reg: r, access: isPop ? 'w' : 'r' }));
      }
      // 9. Conditional branch & SVC (Format 16/17)
      else if ((hw1 & 0xf000) === 0xd000) {
        const cond = (hw1 >>> 8) & 0xf;
        if (cond === 0xf) {
          const svcImm = hw1 & 0xff;
          mnemonic = 'svc';
          opStr = `0x${svcImm.toString(16)}`;
          operands = [{ type: 'imm', imm: svcImm }];
        } else if (cond === 0xe) {
          // Undefined
        } else {
          const condName = COND_CODES[cond];
          mnemonic = `b${condName}`;
          let imm8 = hw1 & 0xff;
          if (imm8 & 0x80) {
            imm8 |= ~0xff;
          }
          const dest = (addr + 4 + imm8 * 2) >>> 0;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
        }
      }
      // 10. Unconditional branch (Format 18)
      else if ((hw1 & 0xf800) === 0xe000) {
        mnemonic = 'b';
        let imm11 = hw1 & 0x7ff;
        if (imm11 & 0x400) {
          imm11 |= ~0x7ff;
        }
        const dest = (addr + 4 + imm11 * 2) >>> 0;
        opStr = `0x${dest.toString(16)}`;
        operands = [{ type: 'imm', imm: dest }];
      }

      instructions.push({
        address: addr,
        bytes,
        mnemonic,
        opStr,
        operands,
        size: 2
      });

      i += 2;
    }
  }

  return instructions;
}
