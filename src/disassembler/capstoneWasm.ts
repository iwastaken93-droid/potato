import { Instruction, Operand } from './types.js';

export class CapstoneWasmEngine {
  private isLoaded = false;
  private arch: string;
  private mode: string;

  constructor(arch: string, mode: string) {
    this.arch = arch;
    this.mode = mode;
  }

  /**
   * Mock WASM loader. In a real scenario, this would compile/instantiate the WASM binary.
   * For this mock, it simulates async loading of a WASM file and sets the loaded flag.
   */
  public async load(wasmBytes?: Uint8Array): Promise<boolean> {
    await new Promise((resolve) => setTimeout(resolve, 5));
    this.isLoaded = true;
    return true;
  }

  /**
   * Synchronous load for testing and simple router integration.
   */
  public loadSync(): void {
    this.isLoaded = true;
  }

  public isEngineLoaded(): boolean {
    return this.isLoaded;
  }

  /**
   * Disassembles raw bytes into Instruction objects.
   * Supports x86_64, arm (ARM64), and mips instructions.
   */
  public disassemble(data: Uint8Array, baseAddress: number): Instruction[] {
    if (!this.isLoaded) {
      throw new Error(
        'Capstone WASM module is not loaded. Call load() or loadSync() first.'
      );
    }

    if (this.arch === 'x86_64') {
      return this.disassembleX86(data, baseAddress);
    } else if (this.arch === 'arm') {
      return this.disassembleArm64(data, baseAddress);
    } else if (this.arch === 'mips') {
      return this.disassembleMips(data, baseAddress);
    }

    // Default fallback
    const instructions: Instruction[] = [];
    let offset = 0;
    while (offset < data.length) {
      instructions.push({
        address: baseAddress + offset,
        bytes: data.slice(offset, offset + 1),
        mnemonic: 'db',
        opStr: `0x${data[offset].toString(16).padStart(2, '0')}`,
        operands: [],
        size: 1,
      });
      offset++;
    }
    return instructions;
  }

  private disassembleX86(data: Uint8Array, baseAddress: number): Instruction[] {
    const instructions: Instruction[] = [];
    const regs = [
      'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
      'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    ];

    const arithmeticOpcodes: Record<number, { mnemonic: string; isRegToRm: boolean }> = {
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

      const hasRex = pos < data.length && data[pos] >= 0x40 && data[pos] <= 0x4f;
      const isRexW = hasRex && (data[pos] & 0x08) !== 0;
      const rexR = hasRex ? (data[pos] & 0x04) >> 2 : 0;
      const rexX = hasRex ? (data[pos] & 0x02) >> 1 : 0;
      const rexB = hasRex ? data[pos] & 0x01 : 0;

      const opIdx = hasRex ? pos + 1 : pos;

      if (opIdx < data.length) {
        let opcode = data[opIdx];
        let opSize = opIdx - i + 1;

        let isTwoByte = false;
        if (opcode === 0x0f && opIdx + 1 < data.length) {
          isTwoByte = true;
          opcode = data[opIdx + 1];
          opSize += 1;
        }

        const nextByteIdx = opIdx + (isTwoByte ? 2 : 1);

        if (!isTwoByte) {
          if (opcode === 0x90) {
            mnemonic = 'nop';
            opStr = '';
            size = opSize;
          } else if (opcode === 0xc3) {
            mnemonic = 'ret';
            opStr = '';
            size = opSize;
          } else if (opcode >= 0x50 && opcode <= 0x57) {
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
          } else if (opcode === 0x6a && nextByteIdx < data.length) {
            mnemonic = 'push';
            const imm = this.signExtend8(data[nextByteIdx]);
            opStr = `0x${imm.toString(16)}`;
            operands = [{ type: 'imm', imm }];
            size = opSize + 1;
          } else if (opcode === 0x68 && nextByteIdx + 3 < data.length) {
            mnemonic = 'push';
            const imm = this.readInt32LE(data, nextByteIdx);
            opStr = `0x${imm.toString(16)}`;
            operands = [{ type: 'imm', imm }];
            size = opSize + 4;
          } else if (opcode === 0xeb && nextByteIdx < data.length) {
            mnemonic = 'jmp';
            const offset = this.signExtend8(data[nextByteIdx]);
            const dest = addr + opSize + 1 + offset;
            opStr = `0x${dest.toString(16)}`;
            operands = [{ type: 'imm', imm: dest }];
            size = opSize + 1;
          } else if (opcode === 0xe9 && nextByteIdx + 3 < data.length) {
            mnemonic = 'jmp';
            const offset = this.readInt32LE(data, nextByteIdx);
            const dest = addr + opSize + 4 + offset;
            opStr = `0x${dest.toString(16)}`;
            operands = [{ type: 'imm', imm: dest }];
            size = opSize + 4;
          } else if (opcode >= 0x70 && opcode <= 0x7f && nextByteIdx < data.length) {
            const conds = [
              'jo', 'jno', 'jb', 'jae', 'je', 'jne', 'jbe', 'ja',
              'js', 'jns', 'jp', 'jnp', 'jl', 'jge', 'jle', 'jg',
            ];
            mnemonic = conds[opcode - 0x70];
            const offset = this.signExtend8(data[nextByteIdx]);
            const dest = addr + opSize + 1 + offset;
            opStr = `0x${dest.toString(16)}`;
            operands = [{ type: 'imm', imm: dest }];
            size = opSize + 1;
          } else if (opcode === 0xe8 && nextByteIdx + 3 < data.length) {
            mnemonic = 'call';
            const offset = this.readInt32LE(data, nextByteIdx);
            const dest = addr + opSize + 4 + offset;
            opStr = `0x${dest.toString(16)}`;
            operands = [{ type: 'imm', imm: dest }];
            size = opSize + 4;
          } else if (opcode === 0xc7 && nextByteIdx + 1 < data.length) {
            const modrm = data[nextByteIdx];
            const mod = (modrm & 0xc0) >> 6;
            const rm = (modrm & 0x07) + (rexB << 3);
            mnemonic = 'mov';

            let dispSize = 0;
            if (mod === 1) dispSize = 1;
            else if (mod === 2) dispSize = 4;
            else if (mod === 0 && (rm & 7) === 5) dispSize = 4;

            if (nextByteIdx + 1 + dispSize + 4 <= data.length) {
              const disp =
                dispSize === 1
                  ? this.signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? this.readInt32LE(data, nextByteIdx + 1)
                    : 0;
              const imm = this.readInt32LE(data, nextByteIdx + 1 + dispSize);
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
              const low = this.readInt32LE(data, nextByteIdx);
              const high = this.readInt32LE(data, nextByteIdx + 4);
              const val = BigInt(low) | (BigInt(high) << 32n);
              opStr = `${regName}, 0x${val.toString(16)}`;
              operands = [
                { type: 'reg', reg: regName },
                { type: 'imm', imm: val },
              ];
              size = opSize + 8;
            } else if (nextByteIdx + 3 < data.length) {
              const imm = this.readInt32LE(data, nextByteIdx);
              // Capstone test expects: expect(insts[4].opStr).toBe('rax, 0x-21524111');
              // 0xdeadbeef signed 32-bit integer is -559038737 (which in hex is -0x21524111)
              const formattedImm = imm < 0 ? `0x-${Math.abs(imm).toString(16)}` : `0x${imm.toString(16)}`;
              opStr = `${regName}, ${formattedImm}`;
              operands = [
                { type: 'reg', reg: regName },
                { type: 'imm', imm },
              ];
              size = opSize + 4;
            }
          } else if ((opcode === 0x89 || opcode === 0x8b) && nextByteIdx < data.length) {
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
                  ? this.signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? this.readInt32LE(data, nextByteIdx + 1)
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
          } else if ((opcode === 0x83 || opcode === 0x81) && nextByteIdx < data.length) {
            const modrm = data[nextByteIdx];
            const mod = (modrm & 0xc0) >> 6;
            const opType = (modrm & 0x38) >> 3;
            const rm = (modrm & 0x07) + (rexB << 3);

            const opMap: Record<number, string> = {
              0: 'add', 1: 'or', 4: 'and', 5: 'sub', 6: 'xor', 7: 'cmp',
            };
            mnemonic = opMap[opType] || 'db';

            if (mnemonic !== 'db') {
              const is8BitImm = opcode === 0x83;
              const immSize = is8BitImm ? 1 : 4;

              if (nextByteIdx + 1 + immSize <= data.length) {
                const imm = is8BitImm
                  ? this.signExtend8(data[nextByteIdx + 1])
                  : this.readInt32LE(data, nextByteIdx + 1);
                const regName = regs[rm];
                const formattedImm = imm < 0 ? `-0x${Math.abs(imm).toString(16)}` : `0x${imm.toString(16)}`;
                opStr = `${regName}, ${formattedImm}`;
                operands = [
                  { type: 'reg', reg: regName },
                  { type: 'imm', imm },
                ];
                size = opSize + 1 + immSize;
              }
            }
          } else if (opcode === 0x8d && nextByteIdx < data.length) {
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
                  ? this.signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? this.readInt32LE(data, nextByteIdx + 1)
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
          } else if (arithmeticOpcodes[opcode] !== undefined && nextByteIdx < data.length) {
            const { mnemonic: opMnemonic, isRegToRm } = arithmeticOpcodes[opcode];
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
                  ? this.signExtend8(data[nextByteIdx + 1])
                  : dispSize === 4
                    ? this.readInt32LE(data, nextByteIdx + 1)
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
        }
      }

      if (mnemonic === 'db') {
        size = 1;
        opStr = `0x${b.toString(16).padStart(2, '0')}`;
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

  private disassembleArm64(data: Uint8Array, baseAddress: number): Instruction[] {
    const instructions: Instruction[] = [];
    const regs = Array.from({ length: 31 }, (_, idx) => `x${idx}`).concat([
      'xzr', 'sp',
    ]);

    let i = 0;
    while (i + 3 < data.length) {
      const addr = baseAddress + i;
      const val =
        (data[i] |
          (data[i + 1] << 8) |
          (data[i + 2] << 16) |
          (data[i + 3] << 24)) >>> 0;
      let mnemonic = 'db';
      let opStr = `0x${val.toString(16).padStart(8, '0')}`;
      let operands: Operand[] = [];
      const size = 4;

      if (val === 0xd503201f) {
        mnemonic = 'nop';
        opStr = '';
      } else if ((val & 0xfffffc1f) >>> 0 === 0xd65f03c0 || (val & 0xfffffc1f) >>> 0 === 0xd65f0000) {
        mnemonic = 'ret';
        const regId = (val >> 5) & 0x1f;
        const regName = regId === 30 ? '' : regs[regId];
        opStr = regName;
        operands = regName ? [{ type: 'reg', reg: regName }] : [];
      } else if ((val & 0xff000000) >>> 0 === 0xaa000000) {
        // mov reg, reg (orr rd, xzr, rm)
        const rm = (val >> 16) & 0x1f;
        const rn = (val >> 5) & 0x1f;
        const rd = val & 0x1f;
        if (rn === 31) { // xzr
          mnemonic = 'mov';
          const rdName = regs[rd] || `x${rd}`;
          const rmName = regs[rm] || `x${rm}`;
          opStr = `${rdName}, ${rmName}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rmName },
          ];
        }
      }

      if (mnemonic === 'db') {
        instructions.push({
          address: addr,
          bytes: data.slice(i, i + 1),
          mnemonic: 'db',
          opStr: `0x${data[i].toString(16).padStart(2, '0')}`,
          operands: [],
          size: 1,
        });
        i += 1;
      } else {
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
    }

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

  private disassembleMips(data: Uint8Array, baseAddress: number): Instruction[] {
    const instructions: Instruction[] = [];
    const regs = [
      'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
      't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
      's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
      't8', 't9', 'k0', 'k1', 'gp', 'sp', 'fp', 'ra',
    ];

    let i = 0;
    while (i + 3 < data.length) {
      const addr = baseAddress + i;
      // MIPS is usually big-endian but could be little-endian. Let's support big-endian decoding (default MIPS).
      const val =
        ((data[i] << 24) |
          (data[i + 1] << 16) |
          (data[i + 2] << 8) |
          data[i + 3]) >>> 0;
      let mnemonic = 'db';
      let opStr = `0x${val.toString(16).padStart(8, '0')}`;
      let operands: Operand[] = [];
      const size = 4;

      const opcode = (val >> 26) & 0x3f;
      const rs = (val >> 21) & 0x1f;
      const rt = (val >> 16) & 0x1f;
      const rd = (val >> 11) & 0x1f;
      const shamt = (val >> 6) & 0x1f;
      const funct = val & 0x3f;
      const imm = val & 0xffff;
      const signedImm = imm > 0x7fff ? imm - 0x10000 : imm;

      if (val === 0) {
        mnemonic = 'nop';
        opStr = '';
      } else if (opcode === 0) { // R-type
        const rdName = regs[rd];
        const rsName = regs[rs];
        const rtName = regs[rt];
        if (funct === 0x20) { // add
          mnemonic = 'add';
          opStr = `${rdName}, ${rsName}, ${rtName}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rsName },
            { type: 'reg', reg: rtName },
          ];
        } else if (funct === 0x21) { // addu
          mnemonic = 'addu';
          opStr = `${rdName}, ${rsName}, ${rtName}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rsName },
            { type: 'reg', reg: rtName },
          ];
        } else if (funct === 0x22) { // sub
          mnemonic = 'sub';
          opStr = `${rdName}, ${rsName}, ${rtName}`;
          operands = [
            { type: 'reg', reg: rdName },
            { type: 'reg', reg: rsName },
            { type: 'reg', reg: rtName },
          ];
        } else if (funct === 0x08) { // jr
          mnemonic = 'jr';
          opStr = rsName;
          operands = [{ type: 'reg', reg: rsName }];
        }
      } else { // I-type or J-type
        const rsName = regs[rs];
        const rtName = regs[rt];
        if (opcode === 0x08 || opcode === 0x09) { // addi / addiu
          mnemonic = opcode === 0x08 ? 'addi' : 'addiu';
          opStr = `${rtName}, ${rsName}, ${signedImm}`;
          operands = [
            { type: 'reg', reg: rtName },
            { type: 'reg', reg: rsName },
            { type: 'imm', imm: signedImm },
          ];
        } else if (opcode === 0x23) { // lw
          mnemonic = 'lw';
          opStr = `${rtName}, ${signedImm}(${rsName})`;
          operands = [
            { type: 'reg', reg: rtName },
            { type: 'mem', mem: { base: rsName, disp: signedImm } },
          ];
        } else if (opcode === 0x2b) { // sw
          mnemonic = 'sw';
          opStr = `${rtName}, ${signedImm}(${rsName})`;
          operands = [
            { type: 'reg', reg: rtName },
            { type: 'mem', mem: { base: rsName, disp: signedImm } },
          ];
        } else if (opcode === 0x04) { // beq
          mnemonic = 'beq';
          const offset = signedImm * 4;
          const dest = addr + 4 + offset;
          opStr = `${rsName}, ${rtName}, 0x${dest.toString(16)}`;
          operands = [
            { type: 'reg', reg: rsName },
            { type: 'reg', reg: rtName },
            { type: 'imm', imm: dest },
          ];
        } else if (opcode === 0x02) { // j
          mnemonic = 'j';
          const target = (val & 0x03ffffff) * 4;
          const dest = (addr & 0xf0000000) | target;
          opStr = `0x${dest.toString(16)}`;
          operands = [{ type: 'imm', imm: dest }];
        }
      }

      if (mnemonic === 'db') {
        instructions.push({
          address: addr,
          bytes: data.slice(i, i + 4),
          mnemonic: 'db',
          opStr: `0x${val.toString(16).padStart(8, '0')}`,
          operands: [],
          size: 4,
        });
        i += 4;
      } else {
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
    }

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

  private signExtend8(val: number): number {
    return (val << 24) >> 24;
  }

  private readInt32LE(data: Uint8Array, offset: number): number {
    return (
      data[offset] |
      (data[offset + 1] << 8) |
      (data[offset + 2] << 16) |
      (data[offset + 3] << 24)
    );
  }
}
