import { Instruction, Operand } from './types.js';

interface OpcodeInfo {
  mnemonic: string;
  mode:
    | 'impl'
    | 'acc'
    | 'imm'
    | 'zp'
    | 'zpx'
    | 'zpy'
    | 'abs'
    | 'absx'
    | 'absy'
    | 'ind'
    | 'indx'
    | 'indy'
    | 'rel';
}

const opcodes6502: Record<number, OpcodeInfo> = {
  0x00: { mnemonic: 'brk', mode: 'impl' },
  0x01: { mnemonic: 'ora', mode: 'indx' },
  0x05: { mnemonic: 'ora', mode: 'zp' },
  0x09: { mnemonic: 'ora', mode: 'imm' },
  0x0d: { mnemonic: 'ora', mode: 'abs' },
  0x11: { mnemonic: 'ora', mode: 'indy' },
  0x15: { mnemonic: 'ora', mode: 'zpx' },
  0x19: { mnemonic: 'ora', mode: 'absy' },
  0x1d: { mnemonic: 'ora', mode: 'absx' },

  0x06: { mnemonic: 'asl', mode: 'zp' },
  0x0a: { mnemonic: 'asl', mode: 'acc' },
  0x0e: { mnemonic: 'asl', mode: 'abs' },
  0x16: { mnemonic: 'asl', mode: 'zpx' },
  0x1e: { mnemonic: 'asl', mode: 'absx' },

  0x08: { mnemonic: 'php', mode: 'impl' },
  0x10: { mnemonic: 'bpl', mode: 'rel' },
  0x18: { mnemonic: 'clc', mode: 'impl' },
  0x20: { mnemonic: 'jsr', mode: 'abs' },

  0x21: { mnemonic: 'and', mode: 'indx' },
  0x25: { mnemonic: 'and', mode: 'zp' },
  0x29: { mnemonic: 'and', mode: 'imm' },
  0x2d: { mnemonic: 'and', mode: 'abs' },
  0x31: { mnemonic: 'and', mode: 'indy' },
  0x35: { mnemonic: 'and', mode: 'zpx' },
  0x39: { mnemonic: 'and', mode: 'absy' },
  0x3d: { mnemonic: 'and', mode: 'absx' },

  0x24: { mnemonic: 'bit', mode: 'zp' },
  0x2c: { mnemonic: 'bit', mode: 'abs' },

  0x26: { mnemonic: 'rol', mode: 'zp' },
  0x2a: { mnemonic: 'rol', mode: 'acc' },
  0x2e: { mnemonic: 'rol', mode: 'abs' },
  0x36: { mnemonic: 'rol', mode: 'zpx' },
  0x3e: { mnemonic: 'rol', mode: 'absx' },

  0x28: { mnemonic: 'plp', mode: 'impl' },
  0x30: { mnemonic: 'bmi', mode: 'rel' },
  0x38: { mnemonic: 'sec', mode: 'impl' },
  0x40: { mnemonic: 'rti', mode: 'impl' },

  0x41: { mnemonic: 'eor', mode: 'indx' },
  0x45: { mnemonic: 'eor', mode: 'zp' },
  0x49: { mnemonic: 'eor', mode: 'imm' },
  0x4d: { mnemonic: 'eor', mode: 'abs' },
  0x51: { mnemonic: 'eor', mode: 'indy' },
  0x55: { mnemonic: 'eor', mode: 'zpx' },
  0x59: { mnemonic: 'eor', mode: 'absy' },
  0x5d: { mnemonic: 'eor', mode: 'absx' },

  0x46: { mnemonic: 'lsr', mode: 'zp' },
  0x4a: { mnemonic: 'lsr', mode: 'acc' },
  0x4e: { mnemonic: 'lsr', mode: 'abs' },
  0x56: { mnemonic: 'lsr', mode: 'zpx' },
  0x5e: { mnemonic: 'lsr', mode: 'absx' },

  0x48: { mnemonic: 'pha', mode: 'impl' },
  0x4c: { mnemonic: 'jmp', mode: 'abs' },
  0x6c: { mnemonic: 'jmp', mode: 'ind' },
  0x50: { mnemonic: 'bvc', mode: 'rel' },
  0x58: { mnemonic: 'cli', mode: 'impl' },
  0x60: { mnemonic: 'rts', mode: 'impl' },

  0x61: { mnemonic: 'adc', mode: 'indx' },
  0x65: { mnemonic: 'adc', mode: 'zp' },
  0x69: { mnemonic: 'adc', mode: 'imm' },
  0x6d: { mnemonic: 'adc', mode: 'abs' },
  0x71: { mnemonic: 'adc', mode: 'indy' },
  0x75: { mnemonic: 'adc', mode: 'zpx' },
  0x79: { mnemonic: 'adc', mode: 'absy' },
  0x7d: { mnemonic: 'adc', mode: 'absx' },

  0x66: { mnemonic: 'ror', mode: 'zp' },
  0x6a: { mnemonic: 'ror', mode: 'acc' },
  0x6e: { mnemonic: 'ror', mode: 'abs' },
  0x76: { mnemonic: 'ror', mode: 'zpx' },
  0x7e: { mnemonic: 'ror', mode: 'absx' },

  0x68: { mnemonic: 'pla', mode: 'impl' },
  0x70: { mnemonic: 'bvs', mode: 'rel' },
  0x78: { mnemonic: 'sei', mode: 'impl' },

  0x81: { mnemonic: 'sta', mode: 'indx' },
  0x85: { mnemonic: 'sta', mode: 'zp' },
  0x8d: { mnemonic: 'sta', mode: 'abs' },
  0x91: { mnemonic: 'sta', mode: 'indy' },
  0x95: { mnemonic: 'sta', mode: 'zpx' },
  0x99: { mnemonic: 'sta', mode: 'absy' },
  0x9d: { mnemonic: 'sta', mode: 'absx' },

  0x86: { mnemonic: 'stx', mode: 'zp' },
  0x8e: { mnemonic: 'stx', mode: 'abs' },
  0x96: { mnemonic: 'stx', mode: 'zpy' },

  0x84: { mnemonic: 'sty', mode: 'zp' },
  0x8c: { mnemonic: 'sty', mode: 'abs' },
  0x94: { mnemonic: 'sty', mode: 'zpx' },

  0x88: { mnemonic: 'dey', mode: 'impl' },
  0x8a: { mnemonic: 'txa', mode: 'impl' },
  0xa8: { mnemonic: 'tay', mode: 'impl' },
  0xaa: { mnemonic: 'tax', mode: 'impl' },
  0x90: { mnemonic: 'bcc', mode: 'rel' },
  0x98: { mnemonic: 'tya', mode: 'impl' },
  0x9a: { mnemonic: 'txs', mode: 'impl' },

  0xa0: { mnemonic: 'ldy', mode: 'imm' },
  0xa4: { mnemonic: 'ldy', mode: 'zp' },
  0xac: { mnemonic: 'ldy', mode: 'abs' },
  0xb4: { mnemonic: 'ldy', mode: 'zpx' },
  0xbc: { mnemonic: 'ldy', mode: 'absx' },

  0xa1: { mnemonic: 'lda', mode: 'indx' },
  0xa5: { mnemonic: 'lda', mode: 'zp' },
  0xa9: { mnemonic: 'lda', mode: 'imm' },
  0xad: { mnemonic: 'lda', mode: 'abs' },
  0xb1: { mnemonic: 'lda', mode: 'indy' },
  0xb5: { mnemonic: 'lda', mode: 'zpx' },
  0xb9: { mnemonic: 'lda', mode: 'absy' },
  0xbd: { mnemonic: 'lda', mode: 'absx' },

  0xa2: { mnemonic: 'ldx', mode: 'imm' },
  0xa6: { mnemonic: 'ldx', mode: 'zp' },
  0xae: { mnemonic: 'ldx', mode: 'abs' },
  0xb6: { mnemonic: 'ldx', mode: 'zpy' },
  0xbe: { mnemonic: 'ldx', mode: 'absy' },

  0xb0: { mnemonic: 'bcs', mode: 'rel' },
  0xb8: { mnemonic: 'clv', mode: 'impl' },
  0xba: { mnemonic: 'tsx', mode: 'impl' },

  0xc0: { mnemonic: 'cpy', mode: 'imm' },
  0xc4: { mnemonic: 'cpy', mode: 'zp' },
  0xcc: { mnemonic: 'cpy', mode: 'abs' },

  0xc1: { mnemonic: 'cmp', mode: 'indx' },
  0xc5: { mnemonic: 'cmp', mode: 'zp' },
  0xc9: { mnemonic: 'cmp', mode: 'imm' },
  0xcd: { mnemonic: 'cmp', mode: 'abs' },
  0xd1: { mnemonic: 'cmp', mode: 'indy' },
  0xd5: { mnemonic: 'cmp', mode: 'zpx' },
  0xd9: { mnemonic: 'cmp', mode: 'absy' },
  0xdd: { mnemonic: 'cmp', mode: 'absx' },

  0xc6: { mnemonic: 'dec', mode: 'zp' },
  0xce: { mnemonic: 'dec', mode: 'abs' },
  0xd6: { mnemonic: 'dec', mode: 'zpx' },
  0xde: { mnemonic: 'dec', mode: 'absx' },

  0xc8: { mnemonic: 'iny', mode: 'impl' },
  0xca: { mnemonic: 'dex', mode: 'impl' },
  0xd0: { mnemonic: 'bne', mode: 'rel' },
  0xd8: { mnemonic: 'cld', mode: 'impl' },

  0xe0: { mnemonic: 'cpx', mode: 'imm' },
  0xe4: { mnemonic: 'cpx', mode: 'zp' },
  0xec: { mnemonic: 'cpx', mode: 'abs' },

  0xe6: { mnemonic: 'inc', mode: 'zp' },
  0xee: { mnemonic: 'inc', mode: 'abs' },
  0xf6: { mnemonic: 'inc', mode: 'zpx' },
  0xfe: { mnemonic: 'inc', mode: 'absx' },

  0xe1: { mnemonic: 'sbc', mode: 'indx' },
  0xe5: { mnemonic: 'sbc', mode: 'zp' },
  0xe9: { mnemonic: 'sbc', mode: 'imm' },
  0xed: { mnemonic: 'sbc', mode: 'abs' },
  0xf1: { mnemonic: 'sbc', mode: 'indy' },
  0xf5: { mnemonic: 'sbc', mode: 'zpx' },
  0xf9: { mnemonic: 'sbc', mode: 'absy' },
  0xfd: { mnemonic: 'sbc', mode: 'absx' },

  0xe8: { mnemonic: 'inx', mode: 'impl' },
  0xea: { mnemonic: 'nop', mode: 'impl' },
  0xf0: { mnemonic: 'beq', mode: 'rel' },
  0xf8: { mnemonic: 'sed', mode: 'impl' },
};

/**
 * Lightweight 6502 disassembler.
 */
export function disassemble6502(
  data: Uint8Array,
  baseAddress: number
): Instruction[] {
  const instructions: Instruction[] = [];
  let i = 0;

  while (i < data.length) {
    const addr = baseAddress + i;
    const op = data[i];
    const info = opcodes6502[op];

    if (!info) {
      // Treat unknown opcode as 1-byte raw data
      instructions.push({
        address: addr,
        bytes: data.slice(i, i + 1),
        mnemonic: 'db',
        opStr: `0x${op.toString(16).padStart(2, '0')}`,
        operands: [],
        size: 1,
      });
      i += 1;
      continue;
    }

    let size = 1;
    switch (info.mode) {
      case 'impl':
      case 'acc':
        size = 1;
        break;
      case 'imm':
      case 'zp':
      case 'zpx':
      case 'zpy':
      case 'indx':
      case 'indy':
      case 'rel':
        size = 2;
        break;
      case 'abs':
      case 'absx':
      case 'absy':
      case 'ind':
        size = 3;
        break;
    }

    if (i + size > data.length) {
      // Not enough bytes remaining, emit as db sequence
      const remaining = data.slice(i);
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

    let opStr = '';
    let operands: Operand[] = [];

    switch (info.mode) {
      case 'impl':
        opStr = '';
        operands = [];
        break;
      case 'acc':
        opStr = 'a';
        operands = [{ type: 'reg', reg: 'a' }];
        break;
      case 'imm': {
        const val = data[i + 1];
        opStr = `#0x${val.toString(16).padStart(2, '0')}`;
        operands = [{ type: 'imm', imm: val }];
        break;
      }
      case 'zp': {
        const val = data[i + 1];
        opStr = `0x${val.toString(16).padStart(2, '0')}`;
        operands = [{ type: 'mem', mem: { disp: val } }];
        break;
      }
      case 'zpx': {
        const val = data[i + 1];
        opStr = `0x${val.toString(16).padStart(2, '0')}, x`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'x' } }];
        break;
      }
      case 'zpy': {
        const val = data[i + 1];
        opStr = `0x${val.toString(16).padStart(2, '0')}, y`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'y' } }];
        break;
      }
      case 'abs': {
        const val = data[i + 1] | (data[i + 2] << 8);
        opStr = `0x${val.toString(16).padStart(4, '0')}`;
        operands = [{ type: 'mem', mem: { disp: val } }];
        break;
      }
      case 'absx': {
        const val = data[i + 1] | (data[i + 2] << 8);
        opStr = `0x${val.toString(16).padStart(4, '0')}, x`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'x' } }];
        break;
      }
      case 'absy': {
        const val = data[i + 1] | (data[i + 2] << 8);
        opStr = `0x${val.toString(16).padStart(4, '0')}, y`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'y' } }];
        break;
      }
      case 'ind': {
        const val = data[i + 1] | (data[i + 2] << 8);
        opStr = `(0x${val.toString(16).padStart(4, '0')})`;
        operands = [{ type: 'mem', mem: { disp: val } }];
        break;
      }
      case 'indx': {
        const val = data[i + 1];
        opStr = `(0x${val.toString(16).padStart(2, '0')}, x)`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'x' } }];
        break;
      }
      case 'indy': {
        const val = data[i + 1];
        opStr = `(0x${val.toString(16).padStart(2, '0')}), y`;
        operands = [{ type: 'mem', mem: { disp: val, index: 'y' } }];
        break;
      }
      case 'rel': {
        const disp = data[i + 1];
        const dispSign = disp >= 128 ? disp - 256 : disp;
        const target = addr + 2 + dispSign;
        opStr = `0x${target.toString(16)}`;
        operands = [{ type: 'imm', imm: target }];
        break;
      }
    }

    instructions.push({
      address: addr,
      bytes: data.slice(i, i + size),
      mnemonic: info.mnemonic,
      opStr,
      operands,
      size,
    });

    i += size;
  }

  return instructions;
}
