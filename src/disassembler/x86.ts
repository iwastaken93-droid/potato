import { Instruction, Operand } from './types.js';
import { signExtend8, readInt32LE } from './helpers.js';

/**
 * Lightweight mock x86_64 disassembler.
 * Recognizes standard instructions and provides realistic fallback decoding.
 */
export function disassembleX86(data: Uint8Array, baseAddress: number): Instruction[] {
  const instructions: Instruction[] = [];
  const regs = [
    'rax',
    'rcx',
    'rdx',
    'rbx',
    'rsp',
    'rbp',
    'rsi',
    'rdi',
    'r8',
    'r9',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
  ];

  const arithmeticOpcodes: Record<
    number,
    { mnemonic: string; isRegToRm: boolean }
  > = {
    0x00: { mnemonic: 'add', isRegToRm: true },
    0x01: { mnemonic: 'add', isRegToRm: true },
    0x02: { mnemonic: 'add', isRegToRm: false },
    0x03: { mnemonic: 'add', isRegToRm: false },
    0x08: { mnemonic: 'or', isRegToRm: true },
    0x09: { mnemonic: 'or', isRegToRm: true },
    0x0a: { mnemonic: 'or', isRegToRm: false },
    0x0b: { mnemonic: 'or', isRegToRm: false },
    0x10: { mnemonic: 'adc', isRegToRm: true },
    0x11: { mnemonic: 'adc', isRegToRm: true },
    0x12: { mnemonic: 'adc', isRegToRm: false },
    0x13: { mnemonic: 'adc', isRegToRm: false },
    0x18: { mnemonic: 'sbb', isRegToRm: true },
    0x19: { mnemonic: 'sbb', isRegToRm: true },
    0x1a: { mnemonic: 'sbb', isRegToRm: false },
    0x1b: { mnemonic: 'sbb', isRegToRm: false },
    0x20: { mnemonic: 'and', isRegToRm: true },
    0x21: { mnemonic: 'and', isRegToRm: true },
    0x22: { mnemonic: 'and', isRegToRm: false },
    0x23: { mnemonic: 'and', isRegToRm: false },
    0x28: { mnemonic: 'sub', isRegToRm: true },
    0x29: { mnemonic: 'sub', isRegToRm: true },
    0x2a: { mnemonic: 'sub', isRegToRm: false },
    0x2b: { mnemonic: 'sub', isRegToRm: false },
    0x30: { mnemonic: 'xor', isRegToRm: true },
    0x31: { mnemonic: 'xor', isRegToRm: true },
    0x32: { mnemonic: 'xor', isRegToRm: false },
    0x33: { mnemonic: 'xor', isRegToRm: false },
    0x38: { mnemonic: 'cmp', isRegToRm: true },
    0x39: { mnemonic: 'cmp', isRegToRm: true },
    0x3a: { mnemonic: 'cmp', isRegToRm: false },
    0x3b: { mnemonic: 'cmp', isRegToRm: false },
  };

  let i = 0;
  while (i < data.length) {
    const addr = baseAddress + i;
    const b = data[i];
    let mnemonic = 'db';
    let opStr = `0x${b.toString(16).padStart(2, '0')}`;
    let size = 1;
    let operands: Operand[] = [];

    let prefix = 0;
    let pos = i;
    while (pos < data.length && (data[pos] === 0x66 || data[pos] === 0xf2 || data[pos] === 0xf3)) {
      prefix = data[pos];
      pos++;
    }

    // Check for REX prefix (0x40 - 0x4f)
    const hasRex = pos < data.length && data[pos] >= 0x40 && data[pos] <= 0x4f;
    const isRexW = hasRex && (data[pos] & 0x08) !== 0;
    const rexR = hasRex ? (data[pos] & 0x04) >> 2 : 0;
    const rexX = hasRex ? (data[pos] & 0x02) >> 1 : 0;
    const rexB = hasRex ? data[pos] & 0x01 : 0;

    const opIdx = hasRex ? pos + 1 : pos;

    if (opIdx < data.length) {
      let opcode = data[opIdx];
      let opSize = opIdx - i + 1;

      // Multi-byte escape
      let isTwoByte = false;
      if (opcode === 0x0f && opIdx + 1 < data.length) {
        isTwoByte = true;
        opcode = data[opIdx + 1];
        opSize += 1;
      }

      const nextByteIdx = opIdx + (isTwoByte ? 2 : 1);

      if (!isTwoByte) {
        // NOP
        if (opcode === 0x90) {
          mnemonic = 'nop';
          opStr = '';
          size = opSize;
        }
        // RET
        else if (opcode === 0xc3) {
          mnemonic = 'ret';
          opStr = '';
          size = opSize;
        }
        // PUSH / POP register (0x50 - 0x5f)
        else if (opcode >= 0x50 && opcode <= 0x57) {
          const regId = opcode - 0x50 + (rexB << 3);
          mnemonic = 'push';
          const regName = regs[regId] || 'rax';
          opStr = regName;
          operands = [{ type: 'reg', reg: regName }];
          size = opSize;
        } else if (opcode >= 0x58 && opcode <= 0x5f) {
          const regId = opcode - 0x58 + (rexB << 3);
          mnemonic = 'pop';
          const regName = regs[regId] || 'rax';
          opStr = regName;
          operands = [{ type: 'reg', reg: regName }];
          size = opSize;
        }
        // PUSH immediate (0x68 / 0x6a)
        else if (opcode === 0x6a && nextByteIdx < data.length) {
          mnemonic = 'push';
          const imm = signExtend8(data[nextByteIdx]);
          opStr = `0x${imm.toString(16)}`;
          operands = [{ type: 'imm', imm }];
          size = opSize + 1;
        } else if (opcode === 0x68 && nextByteIdx + 3 < data.length) {
          mnemonic = 'push';
          const imm = readInt32LE(data, nextByteIdx);
          opStr = `0x${imm.toString(16)}`;
          operands = [{ type: 'imm', imm }];
          size = opSize + 4;
        }
        // JMP (0xeb for short, 0xe9 for near)
        else if (opcode === 0xeb && nextByteIdx < data.length) {
          mnemonic = 'jmp';
          const offset = signExtend8(data[nextByteIdx]);
          const dest = addr + opSize + 1 + offset;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
          size = opSize + 1;
        } else if (opcode === 0xe9 && nextByteIdx + 3 < data.length) {
          mnemonic = 'jmp';
          const offset = readInt32LE(data, nextByteIdx);
          const dest = addr + opSize + 4 + offset;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
          size = opSize + 4;
        }
        // Conditional Jumps (short 0x70 - 0x7f)
        else if (
          opcode >= 0x70 &&
          opcode <= 0x7f &&
          nextByteIdx < data.length
        ) {
          const conds = [
            'jo',
            'jno',
            'jb',
            'jae',
            'je',
            'jne',
            'jbe',
            'ja',
            'js',
            'jns',
            'jp',
            'jnp',
            'jl',
            'jge',
            'jle',
            'jg',
          ];
          mnemonic = conds[opcode - 0x70];
          const offset = signExtend8(data[nextByteIdx]);
          const dest = addr + opSize + 1 + offset;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
          size = opSize + 1;
        }
        // CALL (0xe8)
        else if (opcode === 0xe8 && nextByteIdx + 3 < data.length) {
          mnemonic = 'call';
          const offset = readInt32LE(data, nextByteIdx);
          const dest = addr + opSize + 4 + offset;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
          size = opSize + 4;
        }
        // MOV immediate to reg/mem (0xc7 or 0xb8-0xbf or 0xc6)
        else if (opcode === 0xc7 && nextByteIdx + 1 < data.length) {
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = 'mov';

          let dispSize = 0;
          if (mod === 1) dispSize = 1;
          else if (mod === 2) dispSize = 4;
          else if (mod === 0 && (rm & 7) === 5) dispSize = 4; // RIP-relative or disp32

          if (nextByteIdx + 1 + dispSize + 4 <= data.length) {
            const disp =
              dispSize === 1
                ? signExtend8(data[nextByteIdx + 1])
                : dispSize === 4
                  ? readInt32LE(data, nextByteIdx + 1)
                  : 0;
            const imm = readInt32LE(data, nextByteIdx + 1 + dispSize);
            if (mod === 3) {
              const regName = regs[rm];
              opStr = `${regName}, 0x${imm.toString(16)}`;
              operands = [
                { type: 'reg', reg: regName },
                { type: 'imm', imm },
              ];
            } else {
              const baseRegName = regs[rm];
              const memStr = disp
                ? `${baseRegName} + 0x${disp.toString(16)}`
                : baseRegName;
              opStr = `qword ptr [${memStr}], 0x${imm.toString(16)}`;
              operands = [
                { type: 'mem', mem: { base: baseRegName, disp } },
                { type: 'imm', imm },
              ];
            }
            size = opSize + 1 + dispSize + 4;
          }
        } else if (opcode >= 0xb8 && opcode <= 0xbf) {
          const regId = opcode - 0xb8 + (rexB << 3);
          const regName = regs[regId];
          mnemonic = 'mov';
          if (isRexW && nextByteIdx + 7 < data.length) {
            const low = readInt32LE(data, nextByteIdx);
            const high = readInt32LE(data, nextByteIdx + 4);
            const val = BigInt(low) | (BigInt(high) << 32n);
            opStr = `${regName}, 0x${val.toString(16)}`;
            operands = [
              { type: 'reg', reg: regName },
              { type: 'imm', imm: val },
            ];
            size = opSize + 8;
          } else if (nextByteIdx + 3 < data.length) {
            const imm = readInt32LE(data, nextByteIdx);
            opStr = `${regName}, 0x${imm.toString(16)}`;
            operands = [
              { type: 'reg', reg: regName },
              { type: 'imm', imm },
            ];
            size = opSize + 4;
          }
        }
        // MOV reg, reg or reg, mem (0x89 or 0x8b)
        else if (
          (opcode === 0x89 || opcode === 0x8b) &&
          nextByteIdx < data.length
        ) {
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = 'mov';

          let dispSize = 0;
          if (mod === 1) dispSize = 1;
          else if (mod === 2) dispSize = 4;
          else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

          if (nextByteIdx + 1 + dispSize <= data.length) {
            const disp =
              dispSize === 1
                ? signExtend8(data[nextByteIdx + 1])
                : dispSize === 4
                  ? readInt32LE(data, nextByteIdx + 1)
                  : 0;
            const dstReg = regs[reg];
            const srcRM = regs[rm];

            if (mod === 3) {
              const dst = regs[opcode === 0x89 ? rm : reg];
              const src = regs[opcode === 0x89 ? reg : rm];
              opStr = `${dst}, ${src}`;
              operands = [
                { type: 'reg', reg: dst },
                { type: 'reg', reg: src },
              ];
            } else {
              const memStr = disp
                ? `${srcRM} + 0x${disp.toString(16)}`
                : srcRM;
              const dst = opcode === 0x89 ? `qword ptr [${memStr}]` : dstReg;
              const src = opcode === 0x89 ? dstReg : `qword ptr [${memStr}]`;
              opStr = `${dst}, ${src}`;
              operands = [
                opcode === 0x89
                  ? { type: 'mem', mem: { base: srcRM, disp } }
                  : { type: 'reg', reg: dst as string },
                opcode === 0x89
                  ? { type: 'reg', reg: src as string }
                  : { type: 'mem', mem: { base: srcRM, disp } },
              ];
            }
            size = opSize + 1 + dispSize;
          }
        }
        // ADD / SUB / CMP / XOR / AND / OR immediate (0x83 / 0x81)
        else if (
          (opcode === 0x83 || opcode === 0x81) &&
          nextByteIdx < data.length
        ) {
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const opType = (modrm & 0x38) >> 3;
          const rm = (modrm & 0x07) + (rexB << 3);

          const opMap: Record<number, string> = {
            0: 'add',
            1: 'or',
            4: 'and',
            5: 'sub',
            6: 'xor',
            7: 'cmp',
          };
          mnemonic = opMap[opType] || 'db';

          if (mnemonic !== 'db') {
            const is8BitImm = opcode === 0x83;
            const immSize = is8BitImm ? 1 : 4;

            if (nextByteIdx + 1 + immSize <= data.length) {
              const imm = is8BitImm
                ? signExtend8(data[nextByteIdx + 1])
                : readInt32LE(data, nextByteIdx + 1);
              const regName = regs[rm];
              opStr = `${regName}, 0x${imm.toString(16)}`;
              operands = [
                { type: 'reg', reg: regName },
                { type: 'imm', imm },
              ];
              size = opSize + 1 + immSize;
            }
          }
        }
        // LEA (0x8d)
        else if (opcode === 0x8d && nextByteIdx < data.length) {
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = 'lea';

          let dispSize = 0;
          if (mod === 1) dispSize = 1;
          else if (mod === 2) dispSize = 4;
          else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

          if (nextByteIdx + 1 + dispSize <= data.length) {
            const disp =
              dispSize === 1
                ? signExtend8(data[nextByteIdx + 1])
                : dispSize === 4
                  ? readInt32LE(data, nextByteIdx + 1)
                  : 0;
            const dstReg = regs[reg];
            const srcRM = regs[rm];
            const memStr = disp ? `${srcRM} + 0x${disp.toString(16)}` : srcRM;
            opStr = `${dstReg}, [${memStr}]`;
            operands = [
              { type: 'reg', reg: dstReg },
              { type: 'mem', mem: { base: srcRM, disp } },
            ];
            size = opSize + 1 + dispSize;
          }
        }
        // ADD / OR / AND / SUB / XOR / CMP (reg/reg or reg/mem)
        else if (
          arithmeticOpcodes[opcode] !== undefined &&
          nextByteIdx < data.length
        ) {
          const { mnemonic: opMnemonic, isRegToRm } =
            arithmeticOpcodes[opcode];
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = opMnemonic;

          let dispSize = 0;
          if (mod === 1) dispSize = 1;
          else if (mod === 2) dispSize = 4;
          else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

          if (nextByteIdx + 1 + dispSize <= data.length) {
            const disp =
              dispSize === 1
                ? signExtend8(data[nextByteIdx + 1])
                : dispSize === 4
                  ? readInt32LE(data, nextByteIdx + 1)
                  : 0;
            const regName = regs[reg] || 'rax';
            const rmName = regs[rm] || 'rax';

            if (mod === 3) {
              const dst = regs[isRegToRm ? rm : reg] || 'rax';
              const src = regs[isRegToRm ? reg : rm] || 'rax';
              opStr = `${dst}, ${src}`;
              operands = [
                { type: 'reg', reg: dst },
                { type: 'reg', reg: src },
              ];
            } else {
              const memStr = disp
                ? `${rmName} + 0x${disp.toString(16)}`
                : rmName;
              const dst = isRegToRm ? `qword ptr [${memStr}]` : regName;
              const src = isRegToRm ? regName : `qword ptr [${memStr}]`;
              opStr = `${dst}, ${src}`;
              operands = [
                isRegToRm
                  ? { type: 'mem', mem: { base: rmName, disp } }
                  : { type: 'reg', reg: dst },
                isRegToRm
                  ? { type: 'reg', reg: src }
                  : { type: 'mem', mem: { base: rmName, disp } },
              ];
            }
            size = opSize + 1 + dispSize;
          }
        }
        // TEST reg, reg (0x85)
        else if (opcode === 0x85 && nextByteIdx < data.length) {
          const modrm = data[nextByteIdx];
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = 'test';
          const dst = regs[rm] || 'rax';
          const src = regs[reg] || 'rax';
          opStr = `${dst}, ${src}`;
          operands = [
            { type: 'reg', reg: dst },
            { type: 'reg', reg: src },
          ];
          size = opSize + 1;
        }
        // NOT / NEG / MUL / IMUL / DIV / IDIV / TEST (0xf7)
        else if (opcode === 0xf7 && nextByteIdx < data.length) {
          const modrm = data[nextByteIdx];
          const opType = (modrm & 0x38) >> 3;
          const rm = (modrm & 0x07) + (rexB << 3);
          const mod = (modrm & 0xc0) >> 6;

          const opMap: Record<number, string> = {
            0: 'test',
            2: 'not',
            3: 'neg',
            4: 'mul',
            5: 'imul',
            6: 'div',
            7: 'idiv',
          };
          mnemonic = opMap[opType] || 'db';

          if (mnemonic !== 'db') {
            let dispSize = 0;
            if (mod === 1) dispSize = 1;
            else if (mod === 2) dispSize = 4;
            else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

            const immSize = opType === 0 ? 4 : 0;
            if (nextByteIdx + 1 + dispSize + immSize <= data.length) {
              const disp =
                dispSize === 1
                  ? signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? readInt32LE(data, nextByteIdx + 1)
                    : 0;
              const rmName = regs[rm] || 'rax';

              let targetStr = '';
              if (mod === 3) {
                targetStr = rmName;
                operands = [{ type: 'reg', reg: rmName }];
              } else {
                const memStr = disp
                  ? `${rmName} + 0x${disp.toString(16)}`
                  : rmName;
                targetStr = `qword ptr [${memStr}]`;
                operands = [{ type: 'mem', mem: { base: rmName, disp } }];
              }

              if (opType === 0) {
                const imm = readInt32LE(
                  data,
                  nextByteIdx + 1 + dispSize
                );
                opStr = `${targetStr}, 0x${imm.toString(16)}`;
                operands.push({ type: 'imm', imm });
              } else {
                opStr = targetStr;
              }
              size = opSize + 1 + dispSize + immSize;
            }
          }
        }
        // Shift and Rotate instructions (0xc1 / 0xd1 / 0xd3)
        else if (
          (opcode === 0xc1 || opcode === 0xd1 || opcode === 0xd3) &&
          nextByteIdx < data.length
        ) {
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const opType = (modrm & 0x38) >> 3;
          const rm = (modrm & 0x07) + (rexB << 3);

          const shiftOps: Record<number, string> = {
            0: 'rol',
            1: 'ror',
            2: 'rcl',
            3: 'rcr',
            4: 'shl',
            5: 'shr',
            7: 'sar',
          };
          mnemonic = shiftOps[opType] || 'db';

          if (mnemonic !== 'db') {
            let dispSize = 0;
            if (mod === 1) dispSize = 1;
            else if (mod === 2) dispSize = 4;
            else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

            const immSize = opcode === 0xc1 ? 1 : 0;

            if (nextByteIdx + 1 + dispSize + immSize <= data.length) {
              const disp =
                dispSize === 1
                  ? signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? readInt32LE(data, nextByteIdx + 1)
                    : 0;
              const rmName = regs[rm] || 'rax';

              let targetStr = '';
              if (mod === 3) {
                targetStr = rmName;
                operands = [{ type: 'reg', reg: rmName }];
              } else {
                const memStr = disp
                  ? `${rmName} + 0x${disp.toString(16)}`
                  : rmName;
                targetStr = `qword ptr [${memStr}]`;
                operands = [{ type: 'mem', mem: { base: rmName, disp } }];
              }

              if (opcode === 0xc1) {
                const imm = data[nextByteIdx + 1 + dispSize];
                opStr = `${targetStr}, 0x${imm.toString(16)}`;
                operands.push({ type: 'imm', imm });
              } else if (opcode === 0xd1) {
                opStr = `${targetStr}, 1`;
                operands.push({ type: 'imm', imm: 1 });
              } else {
                opStr = `${targetStr}, cl`;
                operands.push({ type: 'reg', reg: 'cl' });
              }
              size = opSize + 1 + dispSize + immSize;
            }
          }
        }
        // Flag instructions (0xf8 - 0xfd, 0x9c - 0x9f)
        else if (
          opcode === 0xf8 ||
          opcode === 0xf9 ||
          opcode === 0xfa ||
          opcode === 0xfb ||
          opcode === 0xfc ||
          opcode === 0xfd ||
          opcode === 0x9c ||
          opcode === 0x9d ||
          opcode === 0x9e ||
          opcode === 0x9f
        ) {
          const flagMnemonics: Record<number, string> = {
            0xf8: 'clc',
            0xf9: 'stc',
            0xfa: 'cli',
            0xfb: 'sti',
            0xfc: 'cld',
            0xfd: 'std',
            0x9c: 'pushf',
            0x9d: 'popf',
            0x9e: 'sahf',
            0x9f: 'lahf',
          };
          mnemonic = flagMnemonics[opcode];
          opStr = '';
          operands = [];
          size = opSize;
        }
        // AVX VEX instructions
        else if ((opcode === 0xc5 || opcode === 0xc4) && opIdx + 2 < data.length) {
          const isC5 = opcode === 0xc5;
          let vexVal = 0;
          let vex1 = 0;
          let vex2 = 0;
          let avxOpcode = 0;
          let nextAvxByteIdx = 0;
          let L = false;
          let vreg = 0;
          let avxRexR = 0;
          let avxRexB = 0;

          if (isC5) {
            vexVal = data[opIdx + 1];
            avxOpcode = data[opIdx + 2];
            nextAvxByteIdx = opIdx + 3;
            L = (vexVal & 0x04) !== 0;
            vreg = (~vexVal >> 3) & 0x0f;
            avxRexR = (vexVal & 0x80) ? 0 : 1;
            avxRexB = 0;
          } else {
            vex1 = data[opIdx + 1];
            vex2 = data[opIdx + 2];
            avxOpcode = data[opIdx + 3];
            nextAvxByteIdx = opIdx + 4;
            L = (vex2 & 0x04) !== 0;
            vreg = (~vex2 >> 3) & 0x0f;
            avxRexR = (vex1 & 0x80) ? 0 : 1;
            avxRexB = (vex1 & 0x20) ? 0 : 1;
          }

          if (nextAvxByteIdx < data.length) {
            const modrm = data[nextAvxByteIdx];
            const mod = (modrm & 0xc0) >> 6;
            const regId = ((modrm & 0x38) >> 3) + (avxRexR << 3);
            const rmId = (modrm & 0x07) + (avxRexB << 3);

            const regPrefix = L ? 'ymm' : 'xmm';
            const dst = `${regPrefix}${regId}`;
            const src1 = `${regPrefix}${vreg}`;
            let src2 = '';

            let dispSize = 0;
            if (mod === 1) dispSize = 1;
            else if (mod === 2) dispSize = 4;
            else if (mod === 0 && (rmId & 7) === 5) dispSize = 4;

            if (mod === 3) {
              src2 = `${regPrefix}${rmId}`;
            } else if (nextAvxByteIdx + 1 + dispSize <= data.length) {
              const disp =
                dispSize === 1
                  ? signExtend8(data[nextAvxByteIdx + 1])
                  : dispSize === 4
                    ? readInt32LE(data, nextAvxByteIdx + 1)
                    : 0;
              const baseRegName = regs[rmId] || 'rax';
              const memStr = disp ? `${baseRegName} + 0x${disp.toString(16)}` : baseRegName;
              src2 = `ptr [${memStr}]`;
            }

            const avxOps: Record<number, string> = {
              0x10: 'vmovups',
              0x11: 'vmovups',
              0x28: 'vmovaps',
              0x29: 'vmovaps',
              0x58: 'vaddps',
              0x5c: 'vsubps',
              0x59: 'vmulps',
              0x5e: 'vdivps',
              0x57: 'vxorps',
              0x54: 'vandps',
              0x56: 'vorps',
              0x51: 'vsqrtps',
              0x5d: 'vminps',
              0x5f: 'vmaxps',
              0x55: 'vandnps',
            };
            const avxMnemonic = avxOps[avxOpcode];
            if (avxMnemonic) {
              mnemonic = avxMnemonic;
              if (avxOpcode === 0x11 || avxOpcode === 0x29) {
                opStr = `${src2}, ${dst}`;
                operands = [
                  mod === 3 ? { type: 'reg', reg: src2 } : { type: 'mem', mem: { base: regs[rmId] || 'rax', disp: 0 } },
                  { type: 'reg', reg: dst }
                ];
              } else if (avxOpcode === 0x10 || avxOpcode === 0x28) {
                opStr = `${dst}, ${src2}`;
                operands = [
                  { type: 'reg', reg: dst },
                  mod === 3 ? { type: 'reg', reg: src2 } : { type: 'mem', mem: { base: regs[rmId] || 'rax', disp: 0 } }
                ];
              } else {
                opStr = `${dst}, ${src1}, ${src2}`;
                operands = [
                  { type: 'reg', reg: dst },
                  { type: 'reg', reg: src1 },
                  mod === 3 ? { type: 'reg', reg: src2 } : { type: 'mem', mem: { base: regs[rmId] || 'rax', disp: 0 } }
                ];
              }
              size = nextAvxByteIdx - i + 1 + dispSize;
            }
          }
        }
      } else {
        // Two-byte opcode escape (0x0f opcode ...)
        const sseOps: Record<number, string> = {
          0x10: prefix === 0x66 ? 'movupd' : prefix === 0xf3 ? 'movss' : prefix === 0xf2 ? 'movsd' : 'movups',
          0x11: prefix === 0x66 ? 'movupd' : prefix === 0xf3 ? 'movss' : prefix === 0xf2 ? 'movsd' : 'movups',
          0x28: prefix === 0x66 ? 'movapd' : 'movaps',
          0x29: prefix === 0x66 ? 'movapd' : 'movaps',
          0x58: prefix === 0x66 ? 'addpd' : prefix === 0xf3 ? 'addss' : prefix === 0xf2 ? 'addsd' : 'addps',
          0x5c: prefix === 0x66 ? 'subpd' : prefix === 0xf3 ? 'subss' : prefix === 0xf2 ? 'subsd' : 'subps',
          0x59: prefix === 0x66 ? 'mulpd' : prefix === 0xf3 ? 'mulss' : prefix === 0xf2 ? 'mulsd' : 'mulps',
          0x5e: prefix === 0x66 ? 'divpd' : prefix === 0xf3 ? 'divss' : prefix === 0xf2 ? 'divps' : 'divps',
          0x57: prefix === 0x66 ? 'xorpd' : 'xorps',
          0x54: prefix === 0x66 ? 'andpd' : 'andps',
          0x56: prefix === 0x66 ? 'orpd' : 'orps',
          0x51: prefix === 0x66 ? 'sqrtpd' : prefix === 0xf3 ? 'sqrtss' : prefix === 0xf2 ? 'sqrtsd' : 'sqrtps',
          0x5d: prefix === 0x66 ? 'minpd' : prefix === 0xf3 ? 'minss' : prefix === 0xf2 ? 'minsd' : 'minps',
          0x5f: prefix === 0x66 ? 'maxpd' : prefix === 0xf3 ? 'maxss' : prefix === 0xf2 ? 'maxsd' : 'maxps',
          0x55: prefix === 0x66 ? 'andnpd' : 'andnps',
          0x2e: prefix === 0x66 ? 'ucomisd' : 'ucomiss',
          0x2f: prefix === 0x66 ? 'comisd' : 'comiss',
        };

        if (sseOps[opcode] !== undefined && nextByteIdx < data.length) {
          mnemonic = sseOps[opcode];
          const modrm = data[nextByteIdx];
          const mod = (modrm & 0xc0) >> 6;
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);

          const dst = `xmm${reg}`;
          let src = '';
          let dispSize = 0;
          if (mod === 1) dispSize = 1;
          else if (mod === 2) dispSize = 4;
          else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

          if (mod === 3) {
            src = `xmm${rm}`;
          } else if (nextByteIdx + 1 + dispSize <= data.length) {
            const disp =
              dispSize === 1
                ? signExtend8(data[nextByteIdx + 1])
                : dispSize === 4
                  ? readInt32LE(data, nextByteIdx + 1)
                  : 0;
            const baseRegName = regs[rm] || 'rax';
            const memStr = disp ? `${baseRegName} + 0x${disp.toString(16)}` : baseRegName;
            src = `ptr [${memStr}]`;
          }

          if (opcode === 0x11 || opcode === 0x29) {
            opStr = `${src}, ${dst}`;
            operands = [
              mod === 3 ? { type: 'reg', reg: src } : { type: 'mem', mem: { base: regs[rm] || 'rax', disp: 0 } },
              { type: 'reg', reg: dst },
            ];
          } else {
            opStr = `${dst}, ${src}`;
            operands = [
              { type: 'reg', reg: dst },
              mod === 3 ? { type: 'reg', reg: src } : { type: 'mem', mem: { base: regs[rm] || 'rax', disp: 0 } },
            ];
          }
          size = nextByteIdx - i + 1 + dispSize;
        }
        // Conditional Jumps near (0x0f 0x80 - 0x0f 0x8f)
        else if (
          opcode >= 0x80 &&
          opcode <= 0x8f &&
          nextByteIdx + 3 < data.length
        ) {
          const conds = [
            'jo',
            'jno',
            'jb',
            'jae',
            'je',
            'jne',
            'jbe',
            'ja',
            'js',
            'jns',
            'jp',
            'jnp',
            'jl',
            'jge',
            'jle',
            'jg',
          ];
          mnemonic = conds[opcode - 0x80];
          const offset = readInt32LE(data, nextByteIdx);
          const dest = addr + opSize + 4 + offset;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
          size = opSize + 4;
        }
        // IMUL (0x0f 0xaf)
        else if (opcode === 0xaf && nextByteIdx < data.length) {
          const modrm = data[nextByteIdx];
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = 'imul';
          const dst = regs[reg];
          const src = regs[rm];
          opStr = `${dst}, ${src}`;
          operands = [
            { type: 'reg', reg: dst },
            { type: 'reg', reg: src },
          ];
          size = opSize + 1;
        }
        // MOVZX / MOVSX (0x0f 0xb6 / 0x0f 0xb7 / 0x0f 0xbe / 0x0f 0xbf)
        else if (
          (opcode === 0xb6 ||
            opcode === 0xb7 ||
            opcode === 0xbe ||
            opcode === 0xbf) &&
          nextByteIdx < data.length
        ) {
          const modrm = data[nextByteIdx];
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          mnemonic = opcode === 0xb6 || opcode === 0xb7 ? 'movzx' : 'movsx';
          const dst = regs[reg];
          const src = regs[rm];
          opStr = `${dst}, ${src}`;
          operands = [
            { type: 'reg', reg: dst },
            { type: 'reg', reg: src },
          ];
          size = opSize + 1;
        }
        // CMOVcc (0x0f 0x40 - 0x0f 0x4f)
        else if (
          opcode >= 0x40 &&
          opcode <= 0x4f &&
          nextByteIdx < data.length
        ) {
          const conds = [
            'cmovo',
            'cmovno',
            'cmovb',
            'cmovae',
            'cmove',
            'cmovne',
            'cmovbe',
            'cmova',
            'cmovs',
            'cmovns',
            'cmovp',
            'cmovnp',
            'cmovl',
            'cmovge',
            'cmovle',
            'cmovg',
          ];
          mnemonic = conds[opcode - 0x40];
          const modrm = data[nextByteIdx];
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          const dst = regs[reg];
          const src = regs[rm];
          opStr = `${dst}, ${src}`;
          operands = [
            { type: 'reg', reg: dst },
            { type: 'reg', reg: src },
          ];
          size = opSize + 1;
        }
        // BSF / BSR (0x0f 0xbc / 0x0f 0xbd)
        else if (
          (opcode === 0xbc || opcode === 0xbd) &&
          nextByteIdx < data.length
        ) {
          mnemonic = opcode === 0xbc ? 'bsf' : 'bsr';
          const modrm = data[nextByteIdx];
          const reg = ((modrm & 0x38) >> 3) + (rexR << 3);
          const rm = (modrm & 0x07) + (rexB << 3);
          const dst = regs[reg];
          const src = regs[rm];
          opStr = `${dst}, ${src}`;
          operands = [
            { type: 'reg', reg: dst },
            { type: 'reg', reg: src },
          ];
          size = opSize + 1;
        }
        // UD2 (0x0f 0x0b)
        else if (opcode === 0x0b) {
          mnemonic = 'ud2';
          opStr = '';
          operands = [];
          size = opSize;
        }
      }
    }

    // If instruction couldn't be decoded, format as raw DB
    if (mnemonic === 'db') {
      size = 1;
      opStr = `0x${b.toString(16).padStart(2, '0')}`;
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

  return instructions;
}
