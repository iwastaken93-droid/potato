/**
 * CPU state management for x86_64 emulation.
 * Part of the Universal Reverse Engineering Tool.
 */

export const GPR_LIST = [
  'rax',
  'rbx',
  'rcx',
  'rdx',
  'rsi',
  'rdi',
  'rbp',
  'rsp',
  'r8',
  'r9',
  'r10',
  'r11',
  'r12',
  'r13',
  'r14',
  'r15',
  'rip',
  'rflags',
] as const;

export type GPR = (typeof GPR_LIST)[number];

// RFLAGS bits
export enum RFlag {
  CF = 1 << 0, // Carry Flag
  PF = 1 << 2, // Parity Flag
  AF = 1 << 4, // Auxiliary Carry Flag
  ZF = 1 << 6, // Zero Flag
  SF = 1 << 7, // Sign Flag
  TF = 1 << 8, // Trap Flag
  IF = 1 << 9, // Interrupt Enable Flag
  DF = 1 << 10, // Direction Flag
  OF = 1 << 11, // Overflow Flag
}

interface RegisterInfo {
  gpr: GPR;
  size: 8 | 16 | 32 | 64;
  shift: number;
  mask: bigint;
  zeroExtend: boolean;
}

// Map sub-register names to their GPR representation, size, shift, and behavior.
const SUB_REG_MAP: Record<string, RegisterInfo> = {};

function registerSubReg(
  name: string,
  gpr: GPR,
  size: 8 | 16 | 32 | 64,
  shift: number,
  zeroExtend = false
) {
  let mask = 0xffffffffffffffffn;
  if (size === 8) mask = 0xffn;
  else if (size === 16) mask = 0xffffn;
  else if (size === 32) mask = 0xffffffffn;

  SUB_REG_MAP[name.toLowerCase()] = {
    gpr,
    size,
    shift,
    mask,
    zeroExtend,
  };
}

// Initialize GPR mappings
for (const gpr of GPR_LIST) {
  registerSubReg(gpr, gpr, 64, 0, false);
}

// 32-bit sub-registers
registerSubReg('eax', 'rax', 32, 0, true);
registerSubReg('ebx', 'rbx', 32, 0, true);
registerSubReg('ecx', 'rcx', 32, 0, true);
registerSubReg('edx', 'rdx', 32, 0, true);
registerSubReg('esi', 'rsi', 32, 0, true);
registerSubReg('edi', 'rdi', 32, 0, true);
registerSubReg('ebp', 'rbp', 32, 0, true);
registerSubReg('esp', 'rsp', 32, 0, true);
registerSubReg('eip', 'rip', 32, 0, true);

// 16-bit sub-registers
registerSubReg('ax', 'rax', 16, 0, false);
registerSubReg('bx', 'rbx', 16, 0, false);
registerSubReg('cx', 'rcx', 16, 0, false);
registerSubReg('dx', 'rdx', 16, 0, false);
registerSubReg('si', 'rsi', 16, 0, false);
registerSubReg('di', 'rdi', 16, 0, false);
registerSubReg('bp', 'rbp', 16, 0, false);
registerSubReg('sp', 'rsp', 16, 0, false);
registerSubReg('ip', 'rip', 16, 0, false);

// 8-bit low sub-registers
registerSubReg('al', 'rax', 8, 0, false);
registerSubReg('bl', 'rbx', 8, 0, false);
registerSubReg('cl', 'rcx', 8, 0, false);
registerSubReg('dl', 'rdx', 8, 0, false);
registerSubReg('sil', 'rsi', 8, 0, false);
registerSubReg('dil', 'rdi', 8, 0, false);
registerSubReg('bpl', 'rbp', 8, 0, false);
registerSubReg('spl', 'rsp', 8, 0, false);

// 8-bit high sub-registers
registerSubReg('ah', 'rax', 8, 8, false);
registerSubReg('bh', 'rbx', 8, 8, false);
registerSubReg('ch', 'rcx', 8, 8, false);
registerSubReg('dh', 'rdx', 8, 8, false);

// R8-R15 sub-registers
for (let i = 8; i <= 15; i++) {
  const gpr = `r${i}` as GPR;
  registerSubReg(`${gpr}d`, gpr, 32, 0, true); // r8d
  registerSubReg(`${gpr}w`, gpr, 16, 0, false); // r8w
  registerSubReg(`${gpr}b`, gpr, 8, 0, false); // r8b
}

export class CPU {
  private registers: Record<GPR, bigint>;

  constructor() {
    this.registers = {
      rax: 0n,
      rbx: 0n,
      rcx: 0n,
      rdx: 0n,
      rsi: 0n,
      rdi: 0n,
      rbp: 0n,
      rsp: 0n,
      r8: 0n,
      r9: 0n,
      r10: 0n,
      r11: 0n,
      r12: 0n,
      r13: 0n,
      r14: 0n,
      r15: 0n,
      rip: 0n,
      rflags: 0n,
    };
  }

  /**
   * Reset all registers to 0.
   */
  reset(): void {
    for (const key of GPR_LIST) {
      this.registers[key] = 0n;
    }
  }

  /**
   * Check if a register name is valid.
   */
  isValidRegister(name: string): boolean {
    return name.toLowerCase() in SUB_REG_MAP;
  }

  /**
   * Read from a register by name (supports GPRs and sub-registers).
   */
  read(name: string): bigint {
    const key = name.toLowerCase();
    const info = SUB_REG_MAP[key];
    if (!info) {
      throw new Error(`Unknown register: ${name}`);
    }

    const val = this.registers[info.gpr];
    return (val >> BigInt(info.shift)) & info.mask;
  }

  /**
   * Write to a register by name (supports GPRs and sub-registers).
   * Handles zero-extension for 32-bit sub-registers.
   */
  write(name: string, value: bigint): void {
    const key = name.toLowerCase();
    const info = SUB_REG_MAP[key];
    if (!info) {
      throw new Error(`Unknown register: ${name}`);
    }

    const cleanVal = value & info.mask;

    if (info.size === 64) {
      this.registers[info.gpr] = cleanVal;
    } else if (info.zeroExtend && info.size === 32) {
      // 32-bit write on x86_64 zero-extends to 64-bit
      this.registers[info.gpr] = cleanVal;
    } else {
      // 16-bit or 8-bit write preserves other bits of the 64-bit register
      const current = this.registers[info.gpr];
      const shift = BigInt(info.shift);
      const preserveMask = ~(info.mask << shift) & 0xffffffffffffffffn;
      this.registers[info.gpr] = (current & preserveMask) | (cleanVal << shift);
    }
  }

  /**
   * Read the whole 64-bit value of a main GPR directly.
   */
  readGPR(gpr: GPR): bigint {
    return this.registers[gpr];
  }

  /**
   * Write a whole 64-bit value to a main GPR directly.
   */
  writeGPR(gpr: GPR, value: bigint): void {
    this.registers[gpr] = value & 0xffffffffffffffffn;
  }

  /**
   * Get the state of a specific flag in RFLAGS.
   */
  getFlag(flag: RFlag): boolean {
    const rflags = Number(this.registers.rflags);
    return (rflags & flag) !== 0;
  }

  /**
   * Set or clear a specific flag in RFLAGS.
   */
  setFlag(flag: RFlag, value: boolean): void {
    let rflags = Number(this.registers.rflags);
    if (value) {
      rflags |= flag;
    } else {
      rflags &= ~flag;
    }
    this.registers.rflags = BigInt(rflags) & 0xffffffffffffffffn;
  }

  /**
   * Get copies of all registers (useful for UI/debugging).
   */
  getState(): Record<GPR, bigint> {
    return { ...this.registers };
  }
}
