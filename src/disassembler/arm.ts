import { Instruction, Operand } from './types.js';
import { signExtend7, signExtend19, signExtend26 } from './helpers.js';

/**
 * Lightweight mock ARM64 disassembler.
 */
export function disassembleArm(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  const regs = Array.from({ length: 31 }, (_, idx) => `x${idx}`).concat([
    'xzr',
    'sp',
  ]);

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

    // NOP (0xd503201f)
    if (val === 0xd503201f) {
      mnemonic = 'nop';
      opStr = '';
    }
    // ADR / ADRP
    else if ((val & 0x9f000000) === 0x90000000) {
      mnemonic = (val & 0x80000000) !== 0 ? 'adrp' : 'adr';
      const rd = val & 0x1f;
      const rdName = regs[rd] || 'x0';
      const immhi = (val >> 5) & 0x7ffff;
      const immlo = (val >> 29) & 3;
      const imm = (immhi << 2) | immlo;
      const signExt = imm & 0x100000 ? imm | ~0x1fffff : imm;
      const dest = mnemonic === 'adrp' ? ((addr & ~0xfff) + signExt * 4096) : (addr + signExt);
      opStr = `${rdName}, 0x${dest.toString(16)}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'imm', imm: dest },
      ];
    }
    // Vector SIMD Three-Same instructions (both Integer and Float)
    else if ((val & 0x1e200400) === 0x0e200400) {
      const q = (val >> 30) & 1;
      const u = (val >> 29) & 1;
      const size = (val >> 22) & 3;
      const rm = (val >> 16) & 0x1f;
      const opcode = (val >> 11) & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rd = val & 0x1f;

      let valid = false;
      let isFloat = false;

      if (opcode === 0x10) {
        mnemonic = u ? 'sub' : 'add';
        valid = true;
      } else if (opcode === 0x1a || opcode === 0x1b) {
        isFloat = true;
        if (u === 0) {
          mnemonic = opcode === 0x1a ? 'fadd' : 'fsub';
        } else {
          mnemonic = opcode === 0x1a ? 'fmul' : 'fdiv';
        }
        valid = true;
      } else if (opcode === 0x03) {
        valid = true;
        if (u === 0) {
          if (size === 0) mnemonic = 'and';
          else if (size === 1) mnemonic = 'orr';
          else if (size === 2) mnemonic = 'eor';
          else if (size === 3) mnemonic = 'bsl';
        } else {
          if (size === 0) mnemonic = 'bic';
          else if (size === 1) mnemonic = 'bif';
          else if (size === 2) mnemonic = 'bit';
          else if (size === 3) mnemonic = 'orn';
        }
      } else if (opcode === 0x19) {
        mnemonic = u ? 'pmul' : 'mul';
        valid = true;
      } else if (opcode === 0x0c) {
        mnemonic = u ? 'umax' : 'smax';
        valid = true;
      } else if (opcode === 0x0d) {
        mnemonic = u ? 'umin' : 'smin';
        valid = true;
      } else if (opcode === 0x1e) {
        isFloat = true;
        mnemonic = u ? 'fmin' : 'fmax';
        valid = true;
      } else if (opcode === 0x1c) {
        isFloat = true;
        mnemonic = u ? 'fminnm' : 'fmaxnm';
        valid = true;
      }

      if (valid) {
        let suffix = '';
        if (opcode === 0x03) {
          suffix = q ? '16b' : '8b';
        } else if (isFloat) {
          const sz = (val >> 22) & 1;
          suffix = sz === 0 ? (q ? '4s' : '2s') : (q ? '2d' : '2d');
        } else {
          if (size === 0) suffix = q ? '16b' : '8b';
          else if (size === 1) suffix = q ? '8h' : '4h';
          else if (size === 2) suffix = q ? '4s' : '2s';
          else if (size === 3) suffix = q ? '2d' : '1d';
        }

        const rdName = `v${rd}.${suffix}`;
        const rnName = `v${rn}.${suffix}`;
        const rmName = `v${rm}.${suffix}`;
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      }
    }
    // DUP (general-purpose register)
    else if ((val & 0xbfc00c00) === 0x0e000c00) {
      const q = (val >> 30) & 1;
      const imm5 = (val >> 16) & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rd = val & 0x1f;

      let suffix = '';
      let srcReg = '';
      if (imm5 & 1) {
        suffix = q ? '16b' : '8b';
        srcReg = 'w' + rn;
      } else if (imm5 & 2) {
        suffix = q ? '8h' : '4h';
        srcReg = 'w' + rn;
      } else if (imm5 & 4) {
        suffix = q ? '4s' : '2s';
        srcReg = 'w' + rn;
      } else if (imm5 & 8) {
        suffix = q ? '2d' : '2d';
        srcReg = 'x' + rn;
      }

      if (suffix) {
        mnemonic = 'dup';
        const srcRegName = rn === 31 ? (srcReg.startsWith('x') ? 'xzr' : 'wzr') : srcReg;
        const rdName = `v${rd}.${suffix}`;
        opStr = `${rdName}, ${srcRegName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: srcRegName },
        ];
      }
    }
    // DUP (element)
    else if ((val & 0xbfc00c00) === 0x0e000400) {
      const q = (val >> 30) & 1;
      const imm5 = (val >> 16) & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rd = val & 0x1f;

      let suffix = '';
      let elemSize = '';
      let index = 0;
      if (imm5 & 1) {
        suffix = q ? '16b' : '8b';
        elemSize = 'b';
        index = imm5 >> 1;
      } else if (imm5 & 2) {
        suffix = q ? '8h' : '4h';
        elemSize = 'h';
        index = imm5 >> 2;
      } else if (imm5 & 4) {
        suffix = q ? '4s' : '2s';
        elemSize = 's';
        index = imm5 >> 3;
      } else if (imm5 & 8) {
        suffix = q ? '2d' : '2d';
        elemSize = 'd';
        index = imm5 >> 4;
      }

      if (suffix) {
        mnemonic = 'dup';
        const rdName = `v${rd}.${suffix}`;
        const srcName = `v${rn}.${elemSize}[${index}]`;
        opStr = `${rdName}, ${srcName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: srcName },
        ];
      }
    }
    // FMOV (immediate)
    else if ((val & 0xffa0fc00) === 0x1e201000) {
      mnemonic = 'fmov';
      const sz = (val >> 22) & 1;
      const rd = val & 0x1f;
      const imm8 = (val >> 13) & 0xff;
      const rdName = (sz ? 'd' : 's') + rd;

      const a = (imm8 >> 7) & 1;
      const b = (imm8 >> 6) & 1;
      const c = (imm8 >> 5) & 1;
      const d = (imm8 >> 4) & 1;
      const e = (imm8 >> 3) & 1;
      const f = (imm8 >> 2) & 1;
      const g = (imm8 >> 1) & 1;
      const h = imm8 & 1;
      const signVal = a ? -1.0 : 1.0;
      const expVal = ((b ^ 1) << 2) | (c << 1) | d;
      const mantVal = (e << 3) | (f << 2) | (g << 1) | h;
      const floatVal = signVal * ((16 + mantVal) / 16) * Math.pow(2, expVal - 3);

      opStr = `${rdName}, #${floatVal.toFixed(1)}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'imm', imm: floatVal as any },
      ];
    }
    // FMOV (register to register)
    else if ((val & 0xffa0fc00) === 0x1e204000) {
      mnemonic = 'fmov';
      const sz = (val >> 22) & 1;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rdName = (sz ? 'd' : 's') + rd;
      const rnName = (sz ? 'd' : 's') + rn;
      opStr = `${rdName}, ${rnName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
      ];
    }
    // FMOV (GPR to FP register)
    else if ((val & 0xfffffc00) === 0x1e270000) {
      mnemonic = 'fmov';
      const sf = (val >> 31) & 1;
      const sz = (val >> 22) & 1;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rdName = (sz ? 'd' : 's') + rd;
      const rnName = (sf ? 'x' : 'w') + (rn === 31 ? 'zr' : rn);
      opStr = `${rdName}, ${rnName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
      ];
    }
    // FMOV (FP register to GPR)
    else if ((val & 0xfffffc00) === 0x1e260000) {
      mnemonic = 'fmov';
      const sf = (val >> 31) & 1;
      const sz = (val >> 22) & 1;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rdName = (sf ? 'x' : 'w') + (rd === 31 ? 'zr' : rd);
      const rnName = (sz ? 'd' : 's') + rn;
      opStr = `${rdName}, ${rnName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
      ];
    }
    // FADD / FSUB / FMUL / FDIV / FCMP (scalar floating point)
    else if (
      (val & 0xffa0fc00) === 0x1e202800 ||
      (val & 0xffa0fc00) === 0x1e203800 ||
      (val & 0xffa0fc00) === 0x1e200800 ||
      (val & 0xffa0fc00) === 0x1e201800 ||
      (val & 0xffa0fc1f) === 0x1e202000
    ) {
      const sz = (val >> 22) & 1;
      const regPrefix = sz === 1 ? 'd' : 's';
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      
      const rnName = regPrefix + rn;
      const rmName = regPrefix + rm;

      if ((val & 0xffa0fc1f) === 0x1e202000) {
        mnemonic = 'fcmp';
        opStr = `${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      } else {
        const rd = val & 0x1f;
        const rdName = regPrefix + rd;
        const fOps: Record<number, string> = {
          0x1e202800: 'fadd',
          0x1e203800: 'fsub',
          0x1e200800: 'fmul',
          0x1e201800: 'fdiv',
        };
        mnemonic = fOps[val & 0xffa0fc00];
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      }
    }
    // CSEL (Conditional Select)
    else if ((val & 0xffe00c00) === 0x1a800000) {
      mnemonic = 'csel';
      const condNames = [
        'eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
        'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'
      ];
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const cond = (val >> 12) & 0xf;
      const sf = (val >> 31) & 1;

      const getArmReg = (id: number, is64: number) => {
        if (id === 31) return is64 ? 'xzr' : 'wzr';
        return (is64 ? 'x' : 'w') + id;
      };

      const rdName = getArmReg(rd, sf);
      const rnName = getArmReg(rn, sf);
      const rmName = getArmReg(rm, sf);
      const condName = condNames[cond] || 'al';

      opStr = `${rdName}, ${rnName}, ${rmName}, ${condName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
        { type: 'reg', reg: rmName },
      ];
    }
    // RET (typically 0xd65f03c0 for x30)
    else if ((val & 0xfffffc1f) >>> 0 === 0xd65f0000) {
      mnemonic = 'ret';
      const regId = (val >> 5) & 0x1f;
      const regName = regId === 30 ? '' : regs[regId];
      opStr = regName;
      operands = regName ? [{ type: 'reg', reg: regName }] : [];
    }
    // Branch / unconditional jump: b <offset> (0x14000000)
    else if ((val & 0xfc000000) >>> 0 === 0x14000000) {
      mnemonic = 'b';
      const offset = signExtend26(val & 0x03ffffff) * 4;
      const dest = addr + offset;
      opStr = `0x${dest.toString(16)}`;
      operands = [{ type: 'imm', imm: dest }];
    }
    // Branch with link / call: bl <offset> (0x94000000)
    else if ((val & 0xfc000000) >>> 0 === 0x94000000) {
      mnemonic = 'bl';
      const offset = signExtend26(val & 0x03ffffff) * 4;
      const dest = addr + offset;
      opStr = `0x${dest.toString(16)}`;
      operands = [{ type: 'imm', imm: dest }];
    }
    // Branch to register / indirect call
    else if ((val & 0xfffffc1f) >>> 0 === 0xd61f0000) {
      mnemonic = 'br';
      const regId = (val >> 5) & 0x1f;
      opStr = regs[regId];
      operands = [{ type: 'reg', reg: regs[regId] }];
    } else if ((val & 0xfffffc1f) >>> 0 === 0xd63f0000) {
      mnemonic = 'blr';
      const regId = (val >> 5) & 0x1f;
      opStr = regs[regId];
      operands = [{ type: 'reg', reg: regs[regId] }];
    }
    // Conditional Branch: b.cond (0x54000000)
    else if ((val & 0xff000010) === 0x54000000) {
      const cond = val & 0xf;
      const condNames = [
        'eq',
        'ne',
        'cs',
        'cc',
        'mi',
        'pl',
        'vs',
        'vc',
        'hi',
        'ls',
        'ge',
        'lt',
        'gt',
        'le',
        'al',
        'nv',
      ];
      mnemonic = `b.${condNames[cond] || 'cond'}`;
      const offset = signExtend19((val >> 5) & 0x7ffff) * 4;
      const dest = addr + offset;
      opStr = `0x${dest.toString(16)}`;
      operands = [{ type: 'imm', imm: dest }];
    }
    // CBZ (0x34000000) / CBNZ (0x35000000)
    else if (
      (val & 0xfe000000) === 0x34000000 ||
      (val & 0xfe000000) === 0x35000000
    ) {
      mnemonic = val & 0x01000000 ? 'cbnz' : 'cbz';
      const rd = val & 0x1f;
      const offset = signExtend19((val >> 5) & 0x7ffff) * 4;
      const dest = addr + offset;
      const rdName = regs[rd] || 'x0';
      opStr = `${rdName}, 0x${dest.toString(16)}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'imm', imm: dest },
      ];
    }
    // ADD / SUB (immediate)
    else if (
      (val & 0xff000000) >>> 0 === 0x91000000 ||
      (val & 0xff000000) >>> 0 === 0xd1000000
    ) {
      mnemonic = val & 0x40000000 ? 'sub' : 'add';
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const imm = (val >> 10) & 0xfff;
      const rdName = regs[rd] || 'x0';
      const rnName = rn === 31 ? 'sp' : regs[rn];
      opStr = `${rdName}, ${rnName}, #0x${imm.toString(16)}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
        { type: 'imm', imm },
      ];
    }
    // ADD / SUB (shifted register)
    else if (
      (val & 0xff200000) >>> 0 === 0x8b000000 ||
      (val & 0xff200000) >>> 0 === 0xcb000000
    ) {
      mnemonic = val & 0x40000000 ? 'sub' : 'add';
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const rdName = regs[rd] || 'x0';
      const rnName = regs[rn] || 'x0';
      const rmName = regs[rm] || 'x0';
      opStr = `${rdName}, ${rnName}, ${rmName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
        { type: 'reg', reg: rmName },
      ];
    }
    // CMP (subs immediate or register - mapped to cmp)
    else if ((val & 0xff000000) >>> 0 === 0xf1000000) {
      // subs immediate
      mnemonic = 'cmp';
      const rn = (val >> 5) & 0x1f;
      const imm = (val >> 10) & 0xfff;
      const rnName = rn === 31 ? 'sp' : regs[rn];
      opStr = `${rnName}, #0x${imm.toString(16)}`;
      operands = [
        { type: 'reg', reg: rnName },
        { type: 'imm', imm },
      ];
    }
    // CMP (subs register / shifted register) / SUBS (shifted register)
    else if ((val & 0xff200000) >>> 0 === 0xeb000000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const rnName = rn === 31 ? 'sp' : regs[rn];
      const rmName = regs[rm] || 'x0';
      if (rd === 31) {
        mnemonic = 'cmp';
        opStr = `${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      } else {
        mnemonic = 'subs';
        const rdName = regs[rd] || 'x0';
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      }
    }
    // TST (ands shifted register) / ANDS (shifted register)
    else if ((val & 0xffc00000) >>> 0 === 0xea000000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const rnName = regs[rn];
      const rmName = regs[rm];
      if (rd === 31) {
        mnemonic = 'tst';
        opStr = `${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      } else {
        mnemonic = 'ands';
        const rdName = regs[rd];
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      }
    }
    // TST (ands immediate) / ANDS (immediate)
    else if ((val & 0xffc00000) >>> 0 === 0xf2000000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const imm = (val >> 10) & 0xfff;
      const rnName = regs[rn];
      if (rd === 31) {
        mnemonic = 'tst';
        opStr = `${rnName}, #0x${imm.toString(16)}`;
        operands = [
          { type: 'reg', reg: rnName },
          { type: 'imm', imm },
        ];
      } else {
        mnemonic = 'ands';
        const rdName = regs[rd];
        opStr = `${rdName}, ${rnName}, #0x${imm.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm },
        ];
      }
    }
    // UBFM (LSR / LSL / UBFX immediate)
    else if ((val & 0xffc00000) >>> 0 === 0xd3400000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const immr = (val >> 16) & 0x3f;
      const imms = (val >> 10) & 0x3f;
      const rdName = regs[rd];
      const rnName = regs[rn];
      if (imms === 63) {
        mnemonic = 'lsr';
        opStr = `${rdName}, ${rnName}, #0x${immr.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm: immr },
        ];
      } else if (imms < immr) {
        mnemonic = 'lsl';
        const shift = 64 - immr;
        opStr = `${rdName}, ${rnName}, #0x${shift.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm: shift },
        ];
      } else {
        mnemonic = 'ubfx';
        opStr = `${rdName}, ${rnName}, #0x${immr.toString(16)}, #0x${(imms - immr + 1).toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm: immr },
          { type: 'imm', imm: imms - immr + 1 },
        ];
      }
    }
    // SBFM (ASR / SBFX immediate)
    else if ((val & 0xffc00000) >>> 0 === 0x93400000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const immr = (val >> 16) & 0x3f;
      const imms = (val >> 10) & 0x3f;
      const rdName = regs[rd];
      const rnName = regs[rn];
      if (imms === 63) {
        mnemonic = 'asr';
        opStr = `${rdName}, ${rnName}, #0x${immr.toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm: immr },
        ];
      } else {
        mnemonic = 'sbfx';
        opStr = `${rdName}, ${rnName}, #0x${immr.toString(16)}, #0x${(imms - immr + 1).toString(16)}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'imm', imm: immr },
          { type: 'imm', imm: imms - immr + 1 },
        ];
      }
    }
    // AArch64 Shift Register: LSLV, LSRV, ASRV, RORV
    else if (
      (val & 0xffc0fc00) >>> 0 === 0x1ac02000 ||
      (val & 0xffc0fc00) >>> 0 === 0x1ac02400 ||
      (val & 0xffc0fc00) >>> 0 === 0x1ac02800 ||
      (val & 0xffc0fc00) >>> 0 === 0x1ac02c00
    ) {
      const op = (val >> 10) & 3;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const opNames = ['lsl', 'lsr', 'asr', 'ror'];
      mnemonic = opNames[op];
      const rdName = regs[rd];
      const rnName = regs[rn];
      const rmName = regs[rm];
      opStr = `${rdName}, ${rnName}, ${rmName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
        { type: 'reg', reg: rmName },
      ];
    }
    // NZCV Flags / System instructions
    else if ((val & 0xffffffe0) >>> 0 === 0xd53b4200) {
      mnemonic = 'mrs';
      const rt = val & 0x1f;
      const rtName = regs[rt];
      opStr = `${rtName}, nzcv`;
      operands = [
        { type: 'reg', reg: rtName },
        { type: 'reg', reg: 'nzcv' },
      ];
    } else if ((val & 0xffffffe0) >>> 0 === 0xd51b4200) {
      mnemonic = 'msr';
      const rt = val & 0x1f;
      const rtName = regs[rt];
      opStr = `nzcv, ${rtName}`;
      operands = [
        { type: 'reg', reg: 'nzcv' },
        { type: 'reg', reg: rtName },
      ];
    }
    // CLZ (Count Leading Zeros)
    else if ((val & 0x7ffffc00) === 0x5ac01000) {
      mnemonic = 'clz';
      const sf = (val >> 31) & 1;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rdName = (sf ? 'x' : 'w') + rd;
      const rnName = (sf ? 'x' : 'w') + rn;
      opStr = `${rdName}, ${rnName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
      ];
    }
    // MOVZ / MOVK / MOVN (Move immediate)
    else if (
      (val & 0xff800000) >>> 0 === 0xd2800000 ||
      (val & 0xff800000) >>> 0 === 0xf2800000 ||
      (val & 0xff800000) >>> 0 === 0x92800000
    ) {
      const op = (val >> 29) & 3;
      mnemonic = op === 2 ? 'mov' : op === 3 ? 'movk' : 'movn';
      const rd = val & 0x1f;
      const imm = (val >> 5) & 0xffff;
      const hw = (val >> 21) & 3;
      const rdName = regs[rd] || 'x0';
      const shiftStr = hw > 0 ? `, lsl #${hw * 16}` : '';
      opStr = `${rdName}, #0x${imm.toString(16)}${shiftStr}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'imm', imm },
      ];
    }
    // ORR / AND / EOR / ORN / BIC / EON / MVN (register/logical)
    else if ((val & 0x1f000000) >>> 0 === 0x0a000000) {
      const op = (val >> 29) & 3;
      const neg = (val & 0x00200000) !== 0;
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const rdName = regs[rd] || 'x0';
      const rnName = regs[rn] || 'x0';
      const rmName = regs[rm] || 'x0';

      if (op === 1 && rnName === 'xzr') {
        mnemonic = neg ? 'mvn' : 'mov';
        opStr = `${rdName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rmName },
        ];
      } else {
        const names = [
          neg ? 'bic' : 'and',
          neg ? 'orn' : 'orr',
          neg ? 'eon' : 'eor',
          neg ? 'bics' : 'ands',
        ];
        mnemonic = names[op];
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      }
    }
    // SDIV / UDIV (Signed / Unsigned Division)
    else if (
      (val & 0xffc0fc00) >>> 0 === 0x1ac00c00 ||
      (val & 0xffc0fc00) >>> 0 === 0x1ac00800
    ) {
      mnemonic = val & 0x00000400 ? 'sdiv' : 'udiv';
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const rdName = regs[rd] || 'x0';
      const rnName = regs[rn] || 'x0';
      const rmName = regs[rm] || 'x0';
      opStr = `${rdName}, ${rnName}, ${rmName}`;
      operands = [
        { type: 'reg', reg: rdName },
        { type: 'reg', reg: rnName },
        { type: 'reg', reg: rmName },
      ];
    }
    // MADD / MSUB / MUL / MNEG (Multiply instructions)
    else if ((val & 0xff200000) >>> 0 === 0x9b000000) {
      const rd = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const ra = (val >> 10) & 0x1f;
      const rm = (val >> 16) & 0x1f;
      const isSub = (val & 0x00008000) !== 0;

      const rdName = regs[rd] || 'x0';
      const rnName = regs[rn] || 'x0';
      const rmName = regs[rm] || 'x0';
      const raName = regs[ra] || 'xzr';

      if (raName === 'xzr') {
        mnemonic = isSub ? 'mneg' : 'mul';
        opStr = `${rdName}, ${rnName}, ${rmName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
        ];
      } else {
        mnemonic = isSub ? 'msub' : 'madd';
        opStr = `${rdName}, ${rnName}, ${rmName}, ${raName}`;
        operands = [
          { type: 'reg', reg: rdName },
          { type: 'reg', reg: rnName },
          { type: 'reg', reg: rmName },
          { type: 'reg', reg: raName },
        ];
      }
    }
    // LDR / STR (immediate offset / register offset)
    else if (
      (val & 0xffc00000) >>> 0 === 0xf9400000 ||
      (val & 0xffc00000) >>> 0 === 0xf9000000
    ) {
      mnemonic = val & 0x00400000 ? 'ldr' : 'str';
      const rt = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const imm = ((val >> 10) & 0xfff) * 8; // scaled by 8 for 64-bit load/store
      const rtName = regs[rt];
      const rnName = rn === 31 ? 'sp' : regs[rn];
      opStr = `${rtName}, [${rnName}, #0x${imm.toString(16)}]`;
      operands = [
        { type: 'reg', reg: rtName },
        { type: 'mem', mem: { base: rnName, disp: imm } },
      ];
    }
    // LDP / STP (register pair)
    else if (
      (val & 0xffc00000) >>> 0 === 0x29400000 ||
      (val & 0xffc00000) >>> 0 === 0x29000000
    ) {
      mnemonic = val & 0x00400000 ? 'ldp' : 'stp';
      const rt1 = val & 0x1f;
      const rn = (val >> 5) & 0x1f;
      const rt2 = (val >> 10) & 0x1f;
      const imm = signExtend7((val >> 15) & 0x7f) * 8;
      const rt1Name = regs[rt1];
      const rt2Name = regs[rt2];
      const rnName = rn === 31 ? 'sp' : regs[rn];
      opStr = `${rt1Name}, ${rt2Name}, [${rnName}, #0x${imm.toString(16)}]`;
      operands = [
        { type: 'reg', reg: rt1Name },
        { type: 'reg', reg: rt2Name },
        { type: 'mem', mem: { base: rnName, disp: imm } },
      ];
    }
    // Stack simulation patterns: str reg, [sp, #-16]! / ldr reg, [sp], #16
    else if ((val & 0xffc003e0) >>> 0 === 0xf81f0ffe) {
      mnemonic = 'push';
      const rt = val & 0x1f;
      opStr = regs[rt];
      operands = [{ type: 'reg', reg: regs[rt] }];
    } else if ((val & 0xffc003e0) >>> 0 === 0xf84007fe) {
      mnemonic = 'pop';
      const rt = val & 0x1f;
      opStr = regs[rt];
      operands = [{ type: 'reg', reg: regs[rt] }];
    }

    const bytes = data.slice(i, i + size);
    instructions.push({
      address: addr,
      bytes,
      mnemonic,
      opStr,
      operands,
      size,
    });

    i += size;
  }

  // Capture any remaining bytes at the end
  while (i < data.length) {
    instructions.push({
      address: baseAddress + i,
      bytes: data.slice(i, i + 1),
      mnemonic: 'db',
      opStr: `0x${data[i].toString(16).padStart(2, '0')}`,
      operands: [],
      size: 1,
    });
    i++;
  }

  return instructions;
}
