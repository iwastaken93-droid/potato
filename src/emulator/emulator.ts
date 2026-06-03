/**
 * Emulator class for x86_64 emulation.
 * Part of the Universal Reverse Engineering Tool.
 */

import { CPU, RFlag, SUB_REG_MAP } from './cpu.js';
import { Memory } from './memory.js';
import { Instruction, Operand, MemoryOperand } from '../disassembler/types.js';
import { SyscallHandler } from './syscall.js';
import { SymbolicExecutor, SymbolicState, SymbolicExpr } from '../analyzer/symbolic.js';
import { IRTranslator, IROperand } from '../disassembler/ir.js';
import { DisassemblerRouter } from '../disassembler/router.js';

export interface ExecutionResult {
  success: boolean;
  error?: string;
  halted: boolean;
  hitBreakpoint: boolean;
}

export class Emulator {
  public cpu: CPU;
  public memory: Memory;
  public instructions: Map<number, Instruction> = new Map();
  public breakpoints: Set<number> = new Set();
  public isRunning: boolean = false;
  public syscallHandler?: SyscallHandler;
  public symbolicState: SymbolicState = new SymbolicState();
  public trace: {
    stepIndex: number;
    rip: bigint;
    instruction: {
      address: number;
      mnemonic: string;
      opStr: string;
      bytes?: Uint8Array;
    };
    registers: Record<string, bigint>;
  }[] = [];
  private maxInstructions: number = 100000;
  private pcWritten: boolean = false;

  constructor() {
    this.cpu = new CPU();
    this.memory = new Memory();
  }

  /**
   * Load instructions into the emulator instruction memory map.
   */
  public loadInstructions(insts: Instruction[]): void {
    this.instructions.clear();
    for (const inst of insts) {
      this.instructions.set(inst.address, inst);
      if (inst.bytes && inst.bytes.length > 0) {
        this.memory.map(BigInt(inst.address), inst.bytes.length);
        this.memory.writeBuffer(BigInt(inst.address), inst.bytes, true);
      }
    }
  }

  /**
   * Breakpoint management.
   */
  public addBreakpoint(addr: number): void {
    this.breakpoints.add(addr);
  }

  public removeBreakpoint(addr: number): void {
    this.breakpoints.delete(addr);
  }

  public clearBreakpoints(): void {
    this.breakpoints.clear();
  }

  public isBreakpoint(addr: number): boolean {
    return this.breakpoints.has(addr);
  }

  /**
   * Reset CPU state and clear memory.
   */
  public reset(entryPoint: number = 0): void {
    this.cpu.reset();
    this.memory.clear();
    this.trace = [];
    this.cpu.write('rip', BigInt(entryPoint));
    this.symbolicState = new SymbolicState();

    // Setup a default stack segment (e.g. 1MB size at 0x70000000)
    const stackStart = 0x70000000n;
    const stackSize = 0x100000;
    this.memory.map(stackStart, stackSize);
    this.cpu.write('rsp', stackStart + BigInt(stackSize) - 16n);

    // Re-initialize instruction memory if we have instructions loaded
    for (const [addr, inst] of this.instructions.entries()) {
      if (inst.bytes && inst.bytes.length > 0) {
        this.memory.map(BigInt(addr), inst.bytes.length);
        this.memory.writeBuffer(BigInt(addr), inst.bytes);
      }
    }

    this.isRunning = false;
  }

  /**
   * Execute a single instruction at the current RIP.
   */
  public step(): ExecutionResult {
    const ripVal = Number(this.cpu.read('rip'));
    if (this.syscallHandler && this.syscallHandler.hasHook(ripVal)) {
      try {
        this.syscallHandler.executeHook(ripVal, this);
        return {
          success: true,
          halted: this.syscallHandler.context.exitCode !== null,
          hitBreakpoint: false,
        };
      } catch (err: any) {
        return {
          success: false,
          error: err.message || String(err),
          halted: true,
          hitBreakpoint: false,
        };
      }
    }

    let inst = this.instructions.get(ripVal);
    if (!inst) {
      try {
        const router = new DisassemblerRouter();
        const bytes = new Uint8Array(15);
        let readLen = 0;
        for (let i = 0; i < 15; i++) {
          try {
            bytes[i] = this.memory.read8(BigInt(ripVal + i));
            readLen = i + 1;
          } catch {
            break;
          }
        }
        if (readLen > 0) {
          const insts = router.disassemble(bytes.subarray(0, readLen), {
            arch: 'x86_64',
            baseAddress: ripVal
          });
          if (insts && insts.length > 0) {
            const firstInst = insts[0];
            const mnemonic = firstInst.mnemonic;
            const operands = (firstInst.operands || []).map((arg: any) => {
              if (typeof arg === 'object') {
                if (arg.type === 'imm' && typeof arg.imm !== 'bigint') {
                  return { type: 'imm', imm: BigInt(arg.imm) };
                }
                return arg;
              }
              const trimmed = String(arg).trim();
              if (trimmed.startsWith('0x') || /^\d+$/.test(trimmed)) {
                return { type: 'imm', imm: BigInt(trimmed) };
              }
              return { type: 'reg', reg: trimmed };
            });
            inst = {
              address: firstInst.address,
              bytes: firstInst.bytes || new Uint8Array(0),
              mnemonic,
              opStr: firstInst.opStr || '',
              operands,
              size: firstInst.size || 4
            };
            this.instructions.set(ripVal, inst);
          }
        }
      } catch (_) {
        // Ignore parsing errors and proceed with fallback check
      }
    }

    if (!inst) {
      return {
        success: false,
        error: `No instruction found at address 0x${ripVal.toString(16)}`,
        halted: true,
        hitBreakpoint: false,
      };
    }

    this.trace.push({
      stepIndex: this.trace.length,
      rip: BigInt(ripVal),
      instruction: {
        address: ripVal,
        mnemonic: inst.mnemonic,
        opStr: inst.opStr,
        bytes: inst.bytes
      },
      registers: this.cpu.getState()
    });

    try {
      const savedRip = this.cpu.read('rip');
      this.pcWritten = false;
      this.executeInstruction(inst);

      // If instruction execution didn't change RIP, advance sequentially
      if (!this.pcWritten) {
        this.cpu.write('rip', savedRip + BigInt(inst.size || 1));
      }

      this.stepSymbolic(inst);

      const halted = this.syscallHandler
        ? this.syscallHandler.context.exitCode !== null
        : false;
      return { success: true, halted, hitBreakpoint: false };
    } catch (err: any) {
      return {
        success: false,
        error: err.message || String(err),
        halted: true,
        hitBreakpoint: false,
      };
    }
  }

  /**
   * Execute instructions in a loop until paused, hit breakpoint, or halted.
   */
  public run(): ExecutionResult {
    this.isRunning = true;
    let stepCount = 0;

    while (this.isRunning) {
      const ripVal = Number(this.cpu.read('rip'));
      if (this.breakpoints.has(ripVal) && stepCount > 0) {
        this.isRunning = false;
        return { success: true, halted: false, hitBreakpoint: true };
      }

      const res = this.step();
      if (!res.success || res.halted) {
        this.isRunning = false;
        return res;
      }

      stepCount++;
      if (stepCount >= this.maxInstructions) {
        this.isRunning = false;
        return {
          success: false,
          error: 'Maximum instruction execution limit reached',
          halted: true,
          hitBreakpoint: false,
        };
      }
    }

    return { success: true, halted: false, hitBreakpoint: false };
  }

  /**
   * Pause execution.
   */
  public pause(): void {
    this.isRunning = false;
  }

  /**
   * Core execution of parsed/disassembled Instruction structure.
   */
  private executeInstruction(inst: Instruction): boolean {
    const mnemonic = inst.mnemonic.toLowerCase();
    const ops =
      inst.operands && inst.operands.length > 0
        ? inst.operands
        : this.parseOpStr(inst.opStr);

    let opSize = 64;
    if (ops.length > 0) {
      if (ops[0].type === 'reg') {
        opSize = this.getRegisterSize(String(ops[0].reg));
      } else if (ops.length > 1 && ops[1].type === 'reg') {
        opSize = this.getRegisterSize(String(ops[1].reg));
      }
    }

    switch (mnemonic) {
      case 'syscall': {
        if (this.syscallHandler) {
          this.syscallHandler.handleSyscall(this);
        } else {
          throw new Error('Syscall handler not registered');
        }
        break;
      }

      case 'mov': {
        const val = this.readOperand(ops[1], opSize);
        this.writeOperand(ops[0], val, opSize);
        break;
      }

      case 'lea': {
        if (ops[1].type !== 'mem') {
          throw new Error('LEA source operand must be a memory reference');
        }
        const addr = this.resolveAddress(ops[1].mem);
        this.writeOperand(ops[0], addr, opSize);
        break;
      }

      case 'add':
      case 'sub':
      case 'cmp': {
        const destVal = this.readOperand(ops[0], opSize);
        const srcVal = this.readOperand(ops[1], opSize);
        let result = 0n;

        const mask =
          opSize === 8
            ? 0xffn
            : opSize === 16
              ? 0xffffn
              : opSize === 32
                ? 0xffffffffn
                : 0xffffffffffffffffn;

        if (mnemonic === 'add') {
          result = (destVal + srcVal) & mask;
          this.cpu.setFlag(RFlag.ZF, result === 0n);

          const msb = 1n << BigInt(opSize - 1);
          this.cpu.setFlag(RFlag.SF, (result & msb) !== 0n);
          this.cpu.setFlag(RFlag.CF, destVal + srcVal > mask);

          const signDest = (destVal & msb) !== 0n;
          const signSrc = (srcVal & msb) !== 0n;
          const signRes = (result & msb) !== 0n;
          this.cpu.setFlag(
            RFlag.OF,
            signDest === signSrc && signRes !== signDest
          );

          this.writeOperand(ops[0], result, opSize);
        } else {
          // sub or cmp
          result = (destVal - srcVal) & mask;
          this.cpu.setFlag(RFlag.ZF, result === 0n);

          const msb = 1n << BigInt(opSize - 1);
          this.cpu.setFlag(RFlag.SF, (result & msb) !== 0n);
          this.cpu.setFlag(RFlag.CF, destVal < srcVal);

          const signDest = (destVal & msb) !== 0n;
          const signSrc = (srcVal & msb) !== 0n;
          const signRes = (result & msb) !== 0n;
          this.cpu.setFlag(
            RFlag.OF,
            signDest !== signSrc && signRes !== signDest
          );

          if (mnemonic !== 'cmp') {
            this.writeOperand(ops[0], result, opSize);
          }
        }
        break;
      }

      case 'xor': {
        const destVal = this.readOperand(ops[0], opSize);
        const srcVal = this.readOperand(ops[1], opSize);
        const result = destVal ^ srcVal;

        this.writeOperand(ops[0], result, opSize);

        this.cpu.setFlag(RFlag.ZF, result === 0n);
        const msb = 1n << BigInt(opSize - 1);
        this.cpu.setFlag(RFlag.SF, (result & msb) !== 0n);
        this.cpu.setFlag(RFlag.CF, false);
        this.cpu.setFlag(RFlag.OF, false);
        break;
      }

      case 'push': {
        const val = this.readOperand(ops[0], 64);
        let rsp = this.cpu.read('rsp');
        rsp -= 8n;
        this.cpu.write('rsp', rsp);
        this.memory.write64(rsp, val);
        break;
      }

      case 'pop': {
        let rsp = this.cpu.read('rsp');
        const val = this.memory.read64(rsp);
        this.writeOperand(ops[0], val, 64);
        rsp += 8n;
        this.cpu.write('rsp', rsp);
        break;
      }

      case 'jmp': {
        const target = this.readOperand(ops[0], 64);
        this.cpu.write('rip', target);
        this.pcWritten = true;
        break;
      }

      case 'call': {
        const target = this.readOperand(ops[0], 64);
        const nextRip = this.cpu.read('rip') + BigInt(inst.size || 1);
        let rsp = this.cpu.read('rsp');
        rsp -= 8n;
        this.cpu.write('rsp', rsp);
        this.memory.write64(rsp, nextRip);
        this.cpu.write('rip', target);
        this.pcWritten = true;
        break;
      }

      case 'ret': {
        let rsp = this.cpu.read('rsp');
        const returnAddr = this.memory.read64(rsp);
        rsp += 8n;
        this.cpu.write('rsp', rsp);
        this.cpu.write('rip', returnAddr);
        this.pcWritten = true;
        break;
      }

      case 'nop': {
        break;
      }

      default: {
        if (mnemonic.startsWith('j')) {
          let jump = false;
          const zf = this.cpu.getFlag(RFlag.ZF);
          const sf = this.cpu.getFlag(RFlag.SF);
          const cf = this.cpu.getFlag(RFlag.CF);
          const of = this.cpu.getFlag(RFlag.OF);

          switch (mnemonic) {
            case 'je':
            case 'jz':
              jump = zf;
              break;
            case 'jne':
            case 'jnz':
              jump = !zf;
              break;
            case 'js':
              jump = sf;
              break;
            case 'jns':
              jump = !sf;
              break;
            case 'jg':
            case 'jnle':
              jump = !zf && sf === of;
              break;
            case 'jge':
            case 'jnl':
              jump = sf === of;
              break;
            case 'jl':
            case 'jnge':
              jump = sf !== of;
              break;
            case 'jle':
            case 'jng':
              jump = zf || sf !== of;
              break;
            case 'ja':
            case 'jnbe':
              jump = !cf && !zf;
              break;
            case 'jae':
            case 'jnb':
              jump = !cf;
              break;
            case 'jb':
            case 'jnae':
            case 'jc':
              jump = cf;
              break;
            case 'jbe':
            case 'jna':
              jump = cf || zf;
              break;
            case 'jnc':
              jump = !cf;
              break;
            case 'jo':
              jump = of;
              break;
            case 'jno':
              jump = !of;
              break;
            default:
              throw new Error(`Unsupported jump instruction: ${inst.mnemonic}`);
          }

          if (jump) {
            const target = this.readOperand(ops[0], 64);
            this.cpu.write('rip', target);
            this.pcWritten = true;
            return true;
          }
        } else {
          throw new Error(`Unsupported emulator instruction: ${inst.mnemonic}`);
        }
      }
    }
    return false;
  }

  /**
   * Determine register size from register name.
   */
  private getRegisterSize(regName: string): number {
    const name = regName.toLowerCase();
    if (
      name.startsWith('r') &&
      (name.endsWith('d') || name.endsWith('w') || name.endsWith('b'))
    ) {
      if (name.endsWith('d')) return 32;
      if (name.endsWith('w')) return 16;
      if (name.endsWith('b')) return 8;
    }
    if (
      name.startsWith('r') &&
      name.length >= 2 &&
      !isNaN(Number(name.slice(1)))
    ) {
      return 64;
    }
    if (
      [
        'rax',
        'rbx',
        'rcx',
        'rdx',
        'rsi',
        'rdi',
        'rbp',
        'rsp',
        'rip',
        'rflags',
      ].includes(name)
    ) {
      return 64;
    }
    if (name.startsWith('e')) return 32;
    if (
      [
        'al',
        'bl',
        'cl',
        'dl',
        'sil',
        'dil',
        'bpl',
        'spl',
        'ah',
        'bh',
        'ch',
        'dh',
      ].includes(name)
    ) {
      return 8;
    }
    if (['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'ip'].includes(name)) {
      return 16;
    }
    return 64;
  }

  /**
   * Read operand value.
   */
  private readOperand(operand: Operand, operandSize: number): bigint {
    if (operand.type === 'reg') {
      return this.cpu.read(String(operand.reg));
    } else if (operand.type === 'imm') {
      return BigInt(operand.imm ?? 0);
    } else if (operand.type === 'mem') {
      const addr = this.resolveAddress(operand.mem);
      if (operandSize === 8) return BigInt(this.memory.read8(addr));
      if (operandSize === 16) return BigInt(this.memory.read16(addr));
      if (operandSize === 32) return BigInt(this.memory.read32(addr));
      return this.memory.read64(addr);
    }
    return 0n;
  }

  /**
   * Write operand value.
   */
  private writeOperand(
    operand: Operand,
    value: bigint,
    operandSize: number
  ): void {
    if (operand.type === 'reg') {
      this.cpu.write(String(operand.reg), value);
    } else if (operand.type === 'mem') {
      const addr = this.resolveAddress(operand.mem);
      if (operandSize === 8) {
        this.memory.write8(addr, Number(value & 0xffn));
      } else if (operandSize === 16) {
        this.memory.write16(addr, Number(value & 0xffffn));
      } else if (operandSize === 32) {
        this.memory.write32(addr, Number(value & 0xffffffffn));
      } else {
        this.memory.write64(addr, value);
      }
    }
  }

  /**
   * Resolve virtual address of a memory operand.
   */
  private resolveAddress(mem?: MemoryOperand): bigint {
    if (!mem) return 0n;
    let addr = 0n;
    if (mem.base !== undefined) {
      addr += this.cpu.read(String(mem.base));
    }
    if (mem.index !== undefined) {
      const scale = BigInt(mem.scale ?? 1);
      addr += this.cpu.read(String(mem.index)) * scale;
    }
    if (mem.disp !== undefined) {
      addr += BigInt(mem.disp);
    }
    return addr & 0xffffffffffffffffn;
  }

  /**
   * Parse operand string fallback helper.
   */
  private parseOpStr(opStr: string): Operand[] {
    if (!opStr || !opStr.trim()) return [];
    const ops: Operand[] = [];

    const parts: string[] = [];
    let current = '';
    let bracketCount = 0;
    for (let i = 0; i < opStr.length; i++) {
      const char = opStr[i];
      if (char === '[') bracketCount++;
      if (char === ']') bracketCount--;
      if (char === ',' && bracketCount === 0) {
        parts.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    parts.push(current.trim());

    for (const part of parts) {
      if (!part) continue;
      ops.push(this.parseSingleOperandStr(part));
    }
    return ops;
  }

  private parseSingleOperandStr(part: string): Operand {
    let clean = part.trim();

    // Check size prefixes like 'qword ptr', 'dword ptr', 'word ptr', 'byte ptr'
    clean = clean.replace(/^(qword|dword|word|byte)\s+ptr\s+/i, '');

    // Check if immediate
    if (/^-?(0x[0-9a-fA-F]+|\d+)$/.test(clean)) {
      const val = this.tryParseBigInt(clean);
      return { type: 'imm', imm: val ?? 0n };
    }

    // Check if memory operand
    if (clean.includes('[') && clean.includes(']')) {
      const openBracket = clean.indexOf('[');
      const closeBracket = clean.indexOf(']');
      const inside = clean.substring(openBracket + 1, closeBracket).trim();

      const memOp: MemoryOperand = {};
      const sanitized = inside.replace(/-/g, '+-');
      const tokens = sanitized
        .split('+')
        .map((t) => t.trim())
        .filter(Boolean);

      for (const token of tokens) {
        if (token.includes('*')) {
          const parts = token.split('*').map((p) => p.trim());
          let regPart = '';
          let scalePart = 1;
          if (isNaN(Number(parts[0]))) {
            regPart = parts[0];
            scalePart = Number(parts[1]) || 1;
          } else {
            scalePart = Number(parts[0]) || 1;
            regPart = parts[1];
          }
          memOp.index = regPart;
          memOp.scale = scalePart;
        } else {
          const num = this.tryParseBigInt(token);
          if (num !== null) {
            const currentDisp =
              memOp.disp !== undefined ? BigInt(memOp.disp) : 0n;
            memOp.disp = currentDisp + num;
          } else {
            if (!memOp.base) {
              memOp.base = token;
            } else {
              memOp.index = token;
              memOp.scale = 1;
            }
          }
        }
      }
      return { type: 'mem', mem: memOp };
    }

    return { type: 'reg', reg: clean };
  }

  private tryParseBigInt(str: string): bigint | null {
    try {
      if (str.startsWith('-0x')) {
        return -BigInt('0x' + str.substring(3));
      }
      if (str.startsWith('0x')) {
        return BigInt(str);
      }
      if (/^-?\d+$/.test(str)) {
        return BigInt(str);
      }
      return null;
    } catch {
      return null;
    }
  }

  public symbolicateRegister(reg: string, varName?: string): void {
    const rootReg = this.getRootRegister(reg);
    const name = varName || rootReg;
    this.symbolicState.registers.set(rootReg, { type: 'variable', name });
  }

  public symbolicateMemory(address: bigint, varName: string): void {
    this.symbolicState.memory.set(address.toString(), { type: 'variable', name: varName });
  }

  private getRootRegister(reg: string): string {
    const r = reg.toLowerCase();
    const info = SUB_REG_MAP[r];
    return info ? info.gpr : r;
  }

  private stepSymbolic(inst: Instruction): void {
    // Sync concrete register values to symbolic state (only if they aren't already symbolicated)
    const gprs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
    for (const reg of gprs) {
      if (!this.symbolicState.registers.has(reg)) {
        this.symbolicState.registers.set(reg, { type: 'constant', value: this.cpu.read(reg) });
      }
    }

    const mnemonic = inst.mnemonic.toLowerCase();

    // 1. Handle conditional branches
    if (mnemonic.startsWith('j') && mnemonic !== 'jmp') {
      const cond = this.getSymbolicBranchCond(mnemonic, this.symbolicState);
      const ops = inst.operands && inst.operands.length > 0 ? inst.operands : this.parseOpStr(inst.opStr);
      if (ops.length > 0) {
        const targetAddr = this.readOperand(ops[0], 64);
        const branchTaken = this.cpu.read('rip') === targetAddr;
        if (branchTaken) {
          this.symbolicState.constraints.push(cond);
        } else {
          this.symbolicState.constraints.push({ type: 'unary', op: 'NOT', operand: cond });
        }
      }
      return;
    }

    // 2. Normal instruction execution
    const ops = inst.operands && inst.operands.length > 0 ? inst.operands : this.parseOpStr(inst.opStr);
    const instWithOps = { ...inst, operands: ops };
    const translator = new IRTranslator();
    const irInsts = translator.translateInstructions([instWithOps]);

    const normalizeIROperand = (op: IROperand): IROperand => {
      if (op.type === 'reg' && op.name) {
        return { ...op, name: this.getRootRegister(op.name) };
      }
      if (op.type === 'mem' && op.name) {
        return { ...op, name: this.getRootRegister(op.name) };
      }
      return op;
    };

    for (const irInst of irInsts) {
      if (irInst.dest) {
        irInst.dest = normalizeIROperand(irInst.dest);
      }
      irInst.args = irInst.args.map(normalizeIROperand);
    }

    const executor = new SymbolicExecutor();
    for (const irInst of irInsts) {
      const nextStates = executor.executeInstruction(irInst, this.symbolicState);
      if (nextStates.length > 0) {
        this.symbolicState = nextStates[0];
      }
    }
  }

  private getSymbolicBranchCond(mnemonic: string, state: SymbolicState): SymbolicExpr {
    const getFlag = (f: string) => state.flags.get(f) || { type: 'variable' as const, name: f };
    const zf = getFlag('ZF');
    const sf = getFlag('SF');
    const cf = getFlag('CF');
    const of = getFlag('OF');

    const not = (expr: SymbolicExpr): SymbolicExpr => ({ type: 'unary', op: 'NOT', operand: expr });
    const and = (l: SymbolicExpr, r: SymbolicExpr): SymbolicExpr => ({ type: 'binary', op: 'AND', left: l, right: r });
    const or = (l: SymbolicExpr, r: SymbolicExpr): SymbolicExpr => ({ type: 'binary', op: 'OR', left: l, right: r });
    const eq = (l: SymbolicExpr, r: SymbolicExpr): SymbolicExpr => ({ type: 'binary', op: '==', left: l, right: r });
    const neq = (l: SymbolicExpr, r: SymbolicExpr): SymbolicExpr => not(eq(l, r));

    switch (mnemonic) {
      case 'je':
      case 'jz':
        return zf;
      case 'jne':
      case 'jnz':
        return not(zf);
      case 'js':
        return sf;
      case 'jns':
        return not(sf);
      case 'jg':
      case 'jnle':
        return and(not(zf), eq(sf, of));
      case 'jge':
      case 'jnl':
        return eq(sf, of);
      case 'jl':
      case 'jnge':
        return neq(sf, of);
      case 'jle':
      case 'jng':
        return or(zf, neq(sf, of));
      case 'ja':
      case 'jnbe':
        return and(not(cf), not(zf));
      case 'jae':
      case 'jnb':
        return not(cf);
      case 'jb':
      case 'jnae':
      case 'jc':
        return cf;
      case 'jbe':
      case 'jna':
        return or(cf, zf);
      case 'jnc':
        return not(cf);
      case 'jo':
        return of;
      case 'jno':
        return not(of);
      default:
        return { type: 'variable', name: `cond_${mnemonic}` };
    }
  }
}
