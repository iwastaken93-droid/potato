import { Instruction, Operand } from './types.js';

/**
 * Lightweight Z80 disassembler.
 */
export function disassembleZ80(
  data: Uint8Array,
  baseAddress: number
): Instruction[] {
  const instructions: Instruction[] = [];
  const r8 = ['b', 'c', 'd', 'e', 'h', 'l', '(hl)', 'a'];
  let i = 0;

  function getSigned(val: number): number {
    return val >= 128 ? val - 256 : val;
  }

  while (i < data.length) {
    const addr = baseAddress + i;
    let prefixReg: 'ix' | 'iy' | null = null;
    let startIdx = i;

    // Check DD/FD prefixes
    while (i < data.length) {
      if (data[i] === 0xdd) {
        prefixReg = 'ix';
        i++;
      } else if (data[i] === 0xfd) {
        prefixReg = 'iy';
        i++;
      } else {
        break;
      }
    }

    if (i >= data.length) {
      // Reached end with just prefixes
      const remaining = data.slice(startIdx);
      instructions.push({
        address: baseAddress + startIdx,
        bytes: remaining,
        mnemonic: 'db',
        opStr: Array.from(remaining)
          .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
          .join(', '),
        operands: [],
        size: remaining.length,
      });
      break;
    }

    const op = data[i];

    // Helper to check if opcode is affected by DD/FD prefix
    const isPrefixedOp = (o: number) => {
      if (o === 0x09 || o === 0x19 || o === 0x29 || o === 0x39) return true; // add ix, ss
      if (
        o === 0x21 ||
        o === 0x22 ||
        o === 0x23 ||
        o === 0x2a ||
        o === 0x2b
      )
        return true; // ld ix, nn; ld (nn), ix; inc ix; ld ix, (nn); dec ix
      if (o === 0x34 || o === 0x35 || o === 0x36) return true; // inc (ix+d); dec (ix+d); ld (ix+d), n
      if ((o & 0xf8) === 0x70 && o !== 0x76) return true; // ld (ix+d), r
      if ((o & 0xc0) === 0x40 && (o & 0x07) === 0x06) return true; // ld r, (ix+d)
      if ((o & 0xc0) === 0x80 && (o & 0x07) === 0x06) return true; // alu a, (ix+d)
      if (
        o === 0xe1 ||
        o === 0xe5 ||
        o === 0xe9 ||
        o === 0xf9
      )
        return true; // pop ix; push ix; jp (ix); ld sp, ix
      if (o === 0xcb) return true; // DD CB d opcode
      return false;
    };

    if (prefixReg && !isPrefixedOp(op)) {
      // Prefix doesn't apply to this instruction. Treat the prefix byte(s) as db, and reset pointer to decode op in next iteration
      for (let pIdx = startIdx; pIdx < i; pIdx++) {
        instructions.push({
          address: baseAddress + pIdx,
          bytes: data.slice(pIdx, pIdx + 1),
          mnemonic: 'db',
          opStr: `0x${data[pIdx].toString(16).padStart(2, '0')}`,
          operands: [],
          size: 1,
        });
      }
      prefixReg = null;
      startIdx = i;
    }

    let mnemonic = 'db';
    let opStr = '';
    let operands: Operand[] = [];
    let size = 1;

    const isCB = op === 0xcb;
    const isED = op === 0xed;

    if (isCB) {
      if (prefixReg) {
        // format: prefix, 0xcb, d, opcode
        if (i + 2 < data.length) {
          const d = getSigned(data[i + 1]);
          const opcode = data[i + 2];
          size = i + 3 - startIdx;
          i = i + 3; // consume all 4 bytes

          const b = (opcode >> 3) & 7;
          const memStr = `(${prefixReg}${d >= 0 ? '+' : ''}${d})`;
          const memOp: Operand = {
            type: 'mem',
            mem: { base: prefixReg, disp: d },
          };

          if ((opcode & 0xc0) === 0x40) {
            mnemonic = 'bit';
            opStr = `${b}, ${memStr}`;
            operands = [{ type: 'imm', imm: b }, memOp];
          } else if ((opcode & 0xc0) === 0x80) {
            mnemonic = 'res';
            opStr = `${b}, ${memStr}`;
            operands = [{ type: 'imm', imm: b }, memOp];
          } else if ((opcode & 0xc0) === 0xc0) {
            mnemonic = 'set';
            opStr = `${b}, ${memStr}`;
            operands = [{ type: 'imm', imm: b }, memOp];
          } else {
            const shift_op = (opcode >> 3) & 7;
            const shiftMnemonics = [
              'rlc',
              'rrc',
              'rl',
              'rr',
              'sla',
              'sra',
              'sll',
              'srl',
            ];
            mnemonic = shiftMnemonics[shift_op];
            opStr = memStr;
            operands = [memOp];
          }
        } else {
          // not enough bytes
          const remaining = data.slice(startIdx);
          instructions.push({
            address: addr,
            bytes: remaining,
            mnemonic: 'db',
            opStr: Array.from(remaining)
              .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
              .join(', '),
            operands: [],
            size: remaining.length,
          });
          break;
        }
      } else {
        // standard CB: opcode at i+1
        if (i + 1 < data.length) {
          const opcode = data[i + 1];
          size = i + 2 - startIdx;
          i = i + 2;

          const b = (opcode >> 3) & 7;
          const r = opcode & 7;
          const rName = r8[r];
          const rOp: Operand =
            r === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: rName };

          if ((opcode & 0xc0) === 0x40) {
            mnemonic = 'bit';
            opStr = `${b}, ${rName}`;
            operands = [{ type: 'imm', imm: b }, rOp];
          } else if ((opcode & 0xc0) === 0x80) {
            mnemonic = 'res';
            opStr = `${b}, ${rName}`;
            operands = [{ type: 'imm', imm: b }, rOp];
          } else if ((opcode & 0xc0) === 0xc0) {
            mnemonic = 'set';
            opStr = `${b}, ${rName}`;
            operands = [{ type: 'imm', imm: b }, rOp];
          } else {
            const shift_op = (opcode >> 3) & 7;
            const shiftMnemonics = [
              'rlc',
              'rrc',
              'rl',
              'rr',
              'sla',
              'sra',
              'sll',
              'srl',
            ];
            mnemonic = shiftMnemonics[shift_op];
            opStr = rName;
            operands = [rOp];
          }
        } else {
          const remaining = data.slice(startIdx);
          instructions.push({
            address: addr,
            bytes: remaining,
            mnemonic: 'db',
            opStr: Array.from(remaining)
              .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
              .join(', '),
            operands: [],
            size: remaining.length,
          });
          break;
        }
      }
    } else if (isED) {
      if (i + 1 < data.length) {
        const opcode = data[i + 1];
        size = 2;
        i = i + 2;

        if (opcode === 0xb0) {
          mnemonic = 'ldir';
          opStr = '';
        } else if (opcode === 0xb8) {
          mnemonic = 'lddr';
          opStr = '';
        } else if (opcode === 0xb1) {
          mnemonic = 'cpir';
          opStr = '';
        } else if (opcode === 0xb9) {
          mnemonic = 'cpdr';
          opStr = '';
        } else if (opcode === 0xb3) {
          mnemonic = 'otir';
          opStr = '';
        } else if (opcode === 0xbb) {
          mnemonic = 'otdr';
          opStr = '';
        } else if (opcode === 0x46 || opcode === 0x66) {
          mnemonic = 'im';
          opStr = '0';
          operands = [{ type: 'imm', imm: 0 }];
        } else if (opcode === 0x56 || opcode === 0x76) {
          mnemonic = 'im';
          opStr = '1';
          operands = [{ type: 'imm', imm: 1 }];
        } else if (opcode === 0x5e || opcode === 0x7e) {
          mnemonic = 'im';
          opStr = '2';
          operands = [{ type: 'imm', imm: 2 }];
        } else if (opcode === 0x57) {
          mnemonic = 'ld';
          opStr = 'a, i';
          operands = [
            { type: 'reg', reg: 'a' },
            { type: 'reg', reg: 'i' },
          ];
        } else if (opcode === 0x5f) {
          mnemonic = 'ld';
          opStr = 'a, r';
          operands = [
            { type: 'reg', reg: 'a' },
            { type: 'reg', reg: 'r' },
          ];
        } else if (opcode === 0x47) {
          mnemonic = 'ld';
          opStr = 'i, a';
          operands = [
            { type: 'reg', reg: 'i' },
            { type: 'reg', reg: 'a' },
          ];
        } else if (opcode === 0x4f) {
          mnemonic = 'ld';
          opStr = 'r, a';
          operands = [
            { type: 'reg', reg: 'r' },
            { type: 'reg', reg: 'a' },
          ];
        } else if (
          opcode === 0x4a ||
          opcode === 0x5a ||
          opcode === 0x6a ||
          opcode === 0x7a
        ) {
          const ssTable = ['bc', 'de', 'hl', 'sp'];
          const ssIdx = (opcode >> 4) & 3;
          mnemonic = 'adc';
          opStr = `hl, ${ssTable[ssIdx]}`;
          operands = [
            { type: 'reg', reg: 'hl' },
            { type: 'reg', reg: ssTable[ssIdx] },
          ];
        } else if (
          opcode === 0x42 ||
          opcode === 0x52 ||
          opcode === 0x62 ||
          opcode === 0x72
        ) {
          const ssTable = ['bc', 'de', 'hl', 'sp'];
          const ssIdx = (opcode >> 4) & 3;
          mnemonic = 'sbc';
          opStr = `hl, ${ssTable[ssIdx]}`;
          operands = [
            { type: 'reg', reg: 'hl' },
            { type: 'reg', reg: ssTable[ssIdx] },
          ];
        } else if (
          opcode === 0x4b ||
          opcode === 0x5b ||
          opcode === 0x7b
        ) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            i += 2;
            size += 2;
            const ddTable = {
              0x4b: 'bc',
              0x5b: 'de',
              0x7b: 'sp',
            } as any;
            const dd = ddTable[opcode];
            mnemonic = 'ld';
            opStr = `${dd}, (0x${nn.toString(16)})`;
            operands = [
              { type: 'reg', reg: dd },
              { type: 'mem', mem: { disp: nn } },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (
          opcode === 0x43 ||
          opcode === 0x53 ||
          opcode === 0x73
        ) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            i += 2;
            size += 2;
            const ddTable = {
              0x43: 'bc',
              0x53: 'de',
              0x73: 'sp',
            } as any;
            const dd = ddTable[opcode];
            mnemonic = 'ld';
            opStr = `(0x${nn.toString(16)}), ${dd}`;
            operands = [
              { type: 'mem', mem: { disp: nn } },
              { type: 'reg', reg: dd },
            ];
          } else {
            mnemonic = 'db';
          }
        } else {
          mnemonic = 'db';
        }
      } else {
        const remaining = data.slice(startIdx);
        instructions.push({
          address: addr,
          bytes: remaining,
          mnemonic: 'db',
          opStr: Array.from(remaining)
            .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
            .join(', '),
          operands: [],
          size: remaining.length,
        });
        break;
      }
    } else {
      if (prefixReg) {
        // Opcode affected by prefix
        // 1. ld r, (ix+d)
        if (
          (op & 0x07) === 0x06 &&
          (op & 0xc0) === 0x40 &&
          op !== 0x76
        ) {
          if (i + 1 < data.length) {
            const d = getSigned(data[i + 1]);
            size = i + 2 - startIdx;
            i = i + 2;
            const dest = (op >> 3) & 7;
            mnemonic = 'ld';
            opStr = `${r8[dest]}, (${prefixReg}${d >= 0 ? '+' : ''}${d})`;
            operands = [
              { type: 'reg', reg: r8[dest] },
              { type: 'mem', mem: { base: prefixReg, disp: d } },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // 2. ld (ix+d), r
        else if ((op & 0xf8) === 0x70 && op !== 0x76) {
          if (i + 1 < data.length) {
            const d = getSigned(data[i + 1]);
            size = i + 2 - startIdx;
            i = i + 2;
            const src = op & 7;
            mnemonic = 'ld';
            opStr = `(${prefixReg}${d >= 0 ? '+' : ''}${d}), ${r8[src]}`;
            operands = [
              { type: 'mem', mem: { base: prefixReg, disp: d } },
              { type: 'reg', reg: r8[src] },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // 3. ld (ix+d), n
        else if (op === 0x36) {
          if (i + 2 < data.length) {
            const d = getSigned(data[i + 1]);
            const n = data[i + 2];
            size = i + 3 - startIdx;
            i = i + 3;
            mnemonic = 'ld';
            opStr = `(${prefixReg}${d >= 0 ? '+' : ''}${d}), 0x${n.toString(16)}`;
            operands = [
              { type: 'mem', mem: { base: prefixReg, disp: d } },
              { type: 'imm', imm: n },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // 4. alu a, (ix+d)
        else if ((op & 0xc0) === 0x80 && (op & 0x07) === 0x06) {
          if (i + 1 < data.length) {
            const d = getSigned(data[i + 1]);
            size = i + 2 - startIdx;
            i = i + 2;
            const alu_op = (op >> 3) & 7;
            const aluMnemonics = [
              'add',
              'adc',
              'sub',
              'sbc',
              'and',
              'xor',
              'or',
              'cp',
            ];
            mnemonic = aluMnemonics[alu_op];
            if (
              mnemonic === 'add' ||
              mnemonic === 'adc' ||
              mnemonic === 'sbc'
            ) {
              opStr = `a, (${prefixReg}${d >= 0 ? '+' : ''}${d})`;
              operands = [
                { type: 'reg', reg: 'a' },
                { type: 'mem', mem: { base: prefixReg, disp: d } },
              ];
            } else {
              opStr = `(${prefixReg}${d >= 0 ? '+' : ''}${d})`;
              operands = [
                { type: 'mem', mem: { base: prefixReg, disp: d } },
              ];
            }
          } else {
            mnemonic = 'db';
          }
        }
        // 5. inc (ix+d) / dec (ix+d)
        else if (op === 0x34 || op === 0x35) {
          if (i + 1 < data.length) {
            const d = getSigned(data[i + 1]);
            size = i + 2 - startIdx;
            i = i + 2;
            mnemonic = op === 0x34 ? 'inc' : 'dec';
            opStr = `(${prefixReg}${d >= 0 ? '+' : ''}${d})`;
            operands = [
              { type: 'mem', mem: { base: prefixReg, disp: d } },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // 6. Double reg operations:
        // add ix, ss
        else if (
          op === 0x09 ||
          op === 0x19 ||
          op === 0x29 ||
          op === 0x39
        ) {
          const ssTable = ['bc', 'de', prefixReg, 'sp'];
          const ssIdx = (op >> 4) & 3;
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = 'add';
          opStr = `${prefixReg}, ${ssTable[ssIdx]}`;
          operands = [
            { type: 'reg', reg: prefixReg },
            { type: 'reg', reg: ssTable[ssIdx] },
          ];
        }
        // inc ix / dec ix
        else if (op === 0x23 || op === 0x2b) {
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = op === 0x23 ? 'inc' : 'dec';
          opStr = prefixReg;
          operands = [{ type: 'reg', reg: prefixReg }];
        }
        // ld ix, nn
        else if (op === 0x21) {
          if (i + 2 < data.length) {
            const nn = data[i + 1] | (data[i + 2] << 8);
            size = i + 3 - startIdx;
            i = i + 3;
            mnemonic = 'ld';
            opStr = `${prefixReg}, 0x${nn.toString(16)}`;
            operands = [
              { type: 'reg', reg: prefixReg },
              { type: 'imm', imm: nn },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // ld (nn), ix
        else if (op === 0x22) {
          if (i + 2 < data.length) {
            const nn = data[i + 1] | (data[i + 2] << 8);
            size = i + 3 - startIdx;
            i = i + 3;
            mnemonic = 'ld';
            opStr = `(0x${nn.toString(16)}), ${prefixReg}`;
            operands = [
              { type: 'mem', mem: { disp: nn } },
              { type: 'reg', reg: prefixReg },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // ld ix, (nn)
        else if (op === 0x2a) {
          if (i + 2 < data.length) {
            const nn = data[i + 1] | (data[i + 2] << 8);
            size = i + 3 - startIdx;
            i = i + 3;
            mnemonic = 'ld';
            opStr = `${prefixReg}, (0x${nn.toString(16)})`;
            operands = [
              { type: 'reg', reg: prefixReg },
              { type: 'mem', mem: { disp: nn } },
            ];
          } else {
            mnemonic = 'db';
          }
        }
        // ld sp, ix
        else if (op === 0xf9) {
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = 'ld';
          opStr = `sp, ${prefixReg}`;
          operands = [
            { type: 'reg', reg: 'sp' },
            { type: 'reg', reg: prefixReg },
          ];
        }
        // pop ix
        else if (op === 0xe1) {
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = 'pop';
          opStr = prefixReg;
          operands = [{ type: 'reg', reg: prefixReg }];
        }
        // push ix
        else if (op === 0xe5) {
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = 'push';
          opStr = prefixReg;
          operands = [{ type: 'reg', reg: prefixReg }];
        }
        // jp (ix)
        else if (op === 0xe9) {
          size = i + 1 - startIdx;
          i = i + 1;
          mnemonic = 'jp';
          opStr = `(${prefixReg})`;
          operands = [{ type: 'mem', mem: { base: prefixReg } }];
        }
      } else {
        // Standard non-prefixed opcodes
        size = 1;
        i = i + 1;

        if (op === 0x00) {
          mnemonic = 'nop';
        } else if (
          op === 0x01 ||
          op === 0x11 ||
          op === 0x21 ||
          op === 0x31
        ) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            const dd = ['bc', 'de', 'hl', 'sp'][(op >> 4) & 3];
            mnemonic = 'ld';
            opStr = `${dd}, 0x${nn.toString(16)}`;
            operands = [
              { type: 'reg', reg: dd },
              { type: 'imm', imm: nn },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x02) {
          mnemonic = 'ld';
          opStr = '(bc), a';
          operands = [
            { type: 'mem', mem: { base: 'bc' } },
            { type: 'reg', reg: 'a' },
          ];
        } else if (op === 0x12) {
          mnemonic = 'ld';
          opStr = '(de), a';
          operands = [
            { type: 'mem', mem: { base: 'de' } },
            { type: 'reg', reg: 'a' },
          ];
        } else if (op === 0x22) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'ld';
            opStr = `(0x${nn.toString(16)}), hl`;
            operands = [
              { type: 'mem', mem: { disp: nn } },
              { type: 'reg', reg: 'hl' },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x32) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'ld';
            opStr = `(0x${nn.toString(16)}), a`;
            operands = [
              { type: 'mem', mem: { disp: nn } },
              { type: 'reg', reg: 'a' },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x0a) {
          mnemonic = 'ld';
          opStr = 'a, (bc)';
          operands = [
            { type: 'reg', reg: 'a' },
            { type: 'mem', mem: { base: 'bc' } },
          ];
        } else if (op === 0x1a) {
          mnemonic = 'ld';
          opStr = 'a, (de)';
          operands = [
            { type: 'reg', reg: 'a' },
            { type: 'mem', mem: { base: 'de' } },
          ];
        } else if (op === 0x2a) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'ld';
            opStr = `hl, (0x${nn.toString(16)})`;
            operands = [
              { type: 'reg', reg: 'hl' },
              { type: 'mem', mem: { disp: nn } },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x3a) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'ld';
            opStr = `a, (0x${nn.toString(16)})`;
            operands = [
              { type: 'reg', reg: 'a' },
              { type: 'mem', mem: { disp: nn } },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (
          op === 0x03 ||
          op === 0x13 ||
          op === 0x23 ||
          op === 0x33
        ) {
          const ss = ['bc', 'de', 'hl', 'sp'][(op >> 4) & 3];
          mnemonic = 'inc';
          opStr = ss;
          operands = [{ type: 'reg', reg: ss }];
        } else if (
          op === 0x0b ||
          op === 0x1b ||
          op === 0x2b ||
          op === 0x3b
        ) {
          const ss = ['bc', 'de', 'hl', 'sp'][(op >> 4) & 3];
          mnemonic = 'dec';
          opStr = ss;
          operands = [{ type: 'reg', reg: ss }];
        } else if (
          op === 0x04 ||
          op === 0x0c ||
          op === 0x14 ||
          op === 0x1c ||
          op === 0x24 ||
          op === 0x2c ||
          op === 0x34 ||
          op === 0x3c
        ) {
          const r = (op >> 3) & 7;
          mnemonic = 'inc';
          opStr = r8[r];
          operands = [
            r === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: r8[r] },
          ];
        } else if (
          op === 0x05 ||
          op === 0x0d ||
          op === 0x15 ||
          op === 0x1d ||
          op === 0x25 ||
          op === 0x2d ||
          op === 0x35 ||
          op === 0x3d
        ) {
          const r = (op >> 3) & 7;
          mnemonic = 'dec';
          opStr = r8[r];
          operands = [
            r === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: r8[r] },
          ];
        } else if (
          op === 0x06 ||
          op === 0x0e ||
          op === 0x16 ||
          op === 0x1e ||
          op === 0x26 ||
          op === 0x2e ||
          op === 0x36 ||
          op === 0x3e
        ) {
          if (i < data.length) {
            const n = data[i];
            size += 1;
            i += 1;
            const r = (op >> 3) & 7;
            const rName = r8[r];
            mnemonic = 'ld';
            opStr = `${rName}, 0x${n.toString(16)}`;
            operands = [
              r === 6
                ? { type: 'mem', mem: { base: 'hl' } }
                : { type: 'reg', reg: rName },
              { type: 'imm', imm: n },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x07) {
          mnemonic = 'rlca';
        } else if (op === 0x0f) {
          mnemonic = 'rrca';
        } else if (op === 0x17) {
          mnemonic = 'rla';
        } else if (op === 0x1f) {
          mnemonic = 'rra';
        } else if (op === 0x10) {
          if (i < data.length) {
            const d = getSigned(data[i]);
            size += 1;
            i += 1;
            const target = addr + size + d;
            mnemonic = 'djnz';
            opStr = `0x${target.toString(16)}`;
            operands = [{ type: 'imm', imm: target }];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0x18) {
          if (i < data.length) {
            const d = getSigned(data[i]);
            size += 1;
            i += 1;
            const target = addr + size + d;
            mnemonic = 'jr';
            opStr = `0x${target.toString(16)}`;
            operands = [{ type: 'imm', imm: target }];
          } else {
            mnemonic = 'db';
          }
        } else if (
          op === 0x20 ||
          op === 0x28 ||
          op === 0x30 ||
          op === 0x38
        ) {
          if (i < data.length) {
            const d = getSigned(data[i]);
            size += 1;
            i += 1;
            const target = addr + size + d;
            const cc = ['nz', 'z', 'nc', 'c'][(op >> 3) & 3];
            mnemonic = 'jr';
            opStr = `${cc}, 0x${target.toString(16)}`;
            operands = [
              { type: 'reg', reg: cc },
              { type: 'imm', imm: target },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (
          op === 0x09 ||
          op === 0x19 ||
          op === 0x29 ||
          op === 0x39
        ) {
          const ss = ['bc', 'de', 'hl', 'sp'][(op >> 4) & 3];
          mnemonic = 'add';
          opStr = `hl, ${ss}`;
          operands = [
            { type: 'reg', reg: 'hl' },
            { type: 'reg', reg: ss },
          ];
        } else if (op === 0x2f) {
          mnemonic = 'cpl';
        } else if (op === 0x37) {
          mnemonic = 'scf';
        } else if (op === 0x3f) {
          mnemonic = 'ccf';
        } else if (op === 0x76) {
          mnemonic = 'halt';
        } else if (op >= 0x40 && op <= 0x7f) {
          const dest = (op >> 3) & 7;
          const src = op & 7;
          const destName = r8[dest];
          const srcName = r8[src];
          mnemonic = 'ld';
          opStr = `${destName}, ${srcName}`;
          operands = [
            dest === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: destName },
            src === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: srcName },
          ];
        } else if (op >= 0x80 && op <= 0xbf) {
          const alu_op = (op >> 3) & 7;
          const src = op & 7;
          const srcName = r8[src];
          const aluMnemonics = [
            'add',
            'adc',
            'sub',
            'sbc',
            'and',
            'xor',
            'or',
            'cp',
          ];
          mnemonic = aluMnemonics[alu_op];
          const srcOp: Operand =
            src === 6
              ? { type: 'mem', mem: { base: 'hl' } }
              : { type: 'reg', reg: srcName };
          if (
            mnemonic === 'add' ||
            mnemonic === 'adc' ||
            mnemonic === 'sbc'
          ) {
            opStr = `a, ${srcName}`;
            operands = [{ type: 'reg', reg: 'a' }, srcOp];
          } else {
            opStr = srcName;
            operands = [srcOp];
          }
        } else if (
          op === 0xc0 ||
          op === 0xc8 ||
          op === 0xd0 ||
          op === 0xd8 ||
          op === 0xe0 ||
          op === 0xe8 ||
          op === 0xf0 ||
          op === 0xf8
        ) {
          const cc = [
            'nz',
            'z',
            'nc',
            'c',
            'po',
            'pe',
            'p',
            'm',
          ][(op >> 3) & 7];
          mnemonic = 'ret';
          opStr = cc;
          operands = [{ type: 'reg', reg: cc }];
        } else if (
          op === 0xc1 ||
          op === 0xd1 ||
          op === 0xe1 ||
          op === 0xf1
        ) {
          const qq = ['bc', 'de', 'hl', 'af'][(op >> 4) & 3];
          mnemonic = 'pop';
          opStr = qq;
          operands = [{ type: 'reg', reg: qq }];
        } else if (
          op === 0xc5 ||
          op === 0xd5 ||
          op === 0xe5 ||
          op === 0xf5
        ) {
          const qq = ['bc', 'de', 'hl', 'af'][(op >> 4) & 3];
          mnemonic = 'push';
          opStr = qq;
          operands = [{ type: 'reg', reg: qq }];
        } else if (
          op === 0xc2 ||
          op === 0xca ||
          op === 0xd2 ||
          op === 0xda ||
          op === 0xe2 ||
          op === 0xea ||
          op === 0xf2 ||
          op === 0xfa
        ) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            const cc = [
              'nz',
              'z',
              'nc',
              'c',
              'po',
              'pe',
              'p',
              'm',
            ][(op >> 3) & 7];
            mnemonic = 'jp';
            opStr = `${cc}, 0x${nn.toString(16)}`;
            operands = [
              { type: 'reg', reg: cc },
              { type: 'imm', imm: nn },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0xc3) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'jp';
            opStr = `0x${nn.toString(16)}`;
            operands = [{ type: 'imm', imm: nn }];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0xe9) {
          mnemonic = 'jp';
          opStr = '(hl)';
          operands = [{ type: 'mem', mem: { base: 'hl' } }];
        } else if (
          op === 0xc4 ||
          op === 0xcc ||
          op === 0xd4 ||
          op === 0xdc ||
          op === 0xe4 ||
          op === 0xec ||
          op === 0xf4 ||
          op === 0xfc
        ) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            const cc = [
              'nz',
              'z',
              'nc',
              'c',
              'po',
              'pe',
              'p',
              'm',
            ][(op >> 3) & 7];
            mnemonic = 'call';
            opStr = `${cc}, 0x${nn.toString(16)}`;
            operands = [
              { type: 'reg', reg: cc },
              { type: 'imm', imm: nn },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0xcd) {
          if (i + 1 < data.length) {
            const nn = data[i] | (data[i + 1] << 8);
            size += 2;
            i += 2;
            mnemonic = 'call';
            opStr = `0x${nn.toString(16)}`;
            operands = [{ type: 'imm', imm: nn }];
          } else {
            mnemonic = 'db';
          }
        } else if (
          op === 0xc6 ||
          op === 0xce ||
          op === 0xd6 ||
          op === 0xde ||
          op === 0xe6 ||
          op === 0xee ||
          op === 0xf6 ||
          op === 0xfe
        ) {
          if (i < data.length) {
            const n = data[i];
            size += 1;
            i += 1;
            const alu_op = (op >> 3) & 7;
            const aluMnemonics = [
              'add',
              'adc',
              'sub',
              'sbc',
              'and',
              'xor',
              'or',
              'cp',
            ];
            mnemonic = aluMnemonics[alu_op];
            if (
              mnemonic === 'add' ||
              mnemonic === 'adc' ||
              mnemonic === 'sbc'
            ) {
              opStr = `a, 0x${n.toString(16)}`;
              operands = [
                { type: 'reg', reg: 'a' },
                { type: 'imm', imm: n },
              ];
            } else {
              opStr = `0x${n.toString(16)}`;
              operands = [{ type: 'imm', imm: n }];
            }
          } else {
            mnemonic = 'db';
          }
        } else if (
          op === 0xc7 ||
          op === 0xcf ||
          op === 0xd7 ||
          op === 0xdf ||
          op === 0xe7 ||
          op === 0xef ||
          op === 0xf7 ||
          op === 0xff
        ) {
          const p = op & 0x38;
          mnemonic = 'rst';
          opStr = `0x${p.toString(16)}`;
          operands = [{ type: 'imm', imm: p }];
        } else if (op === 0xc9) {
          mnemonic = 'ret';
        } else if (op === 0xd3) {
          if (i < data.length) {
            const n = data[i];
            size += 1;
            i += 1;
            mnemonic = 'out';
            opStr = `(0x${n.toString(16)}), a`;
            operands = [
              { type: 'mem', mem: { disp: n } },
              { type: 'reg', reg: 'a' },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0xdb) {
          if (i < data.length) {
            const n = data[i];
            size += 1;
            i += 1;
            mnemonic = 'in';
            opStr = `a, (0x${n.toString(16)})`;
            operands = [
              { type: 'reg', reg: 'a' },
              { type: 'mem', mem: { disp: n } },
            ];
          } else {
            mnemonic = 'db';
          }
        } else if (op === 0xe3) {
          mnemonic = 'ex';
          opStr = '(sp), hl';
          operands = [
            { type: 'mem', mem: { base: 'sp' } },
            { type: 'reg', reg: 'hl' },
          ];
        } else if (op === 0xeb) {
          mnemonic = 'ex';
          opStr = 'de, hl';
          operands = [
            { type: 'reg', reg: 'de' },
            { type: 'reg', reg: 'hl' },
          ];
        } else if (op === 0xf3) {
          mnemonic = 'di';
        } else if (op === 0xfb) {
          mnemonic = 'ei';
        } else if (op === 0xd9) {
          mnemonic = 'exx';
        }
      }
    }

    if (mnemonic === 'db') {
      const rawBytes = data.slice(startIdx, i);
      instructions.push({
        address: addr,
        bytes: rawBytes,
        mnemonic: 'db',
        opStr: Array.from(rawBytes)
          .map((b) => `0x${b.toString(16).padStart(2, '0')}`)
          .join(', '),
        operands: [],
        size: rawBytes.length,
      });
    } else {
      instructions.push({
        address: addr,
        bytes: data.slice(startIdx, i),
        mnemonic,
        opStr,
        operands,
        size,
      });
    }
  }

  return instructions;
}
