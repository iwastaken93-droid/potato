/**
 * Intermediate Representation (IR) and Static Single Assignment (SSA) Framework
 * Part of the Universal Reverse Engineering Tool (URET)
 *
 * Defines target-independent micro-operations, translation, and SSA optimizations.
 */

import { Instruction } from './types.js';
import { BasicBlock } from './cfg.js';

/**
 * Operations supported in the Intermediate Representation.
 */
export enum IROp {
  /** Addition */
  ADD = 'ADD',
  /** Subtraction */
  SUB = 'SUB',
  /** Multiplication */
  MUL = 'MUL',
  /** Division */
  DIV = 'DIV',
  /** Bitwise AND */
  AND = 'AND',
  /** Bitwise OR */
  OR = 'OR',
  /** Bitwise XOR */
  XOR = 'XOR',
  /** Shift left */
  SHL = 'SHL',
  /** Shift right */
  SHR = 'SHR',
  /** Load from memory */
  LOAD = 'LOAD',
  /** Store to memory */
  STORE = 'STORE',
  /** PHI function for SSA form */
  PHI = 'PHI',
  /** Conditional branch */
  BRANCH = 'BRANCH',
  /** Move value */
  MOV = 'MOV',
  /** Compare values */
  CMP = 'CMP',
  /** Unconditional jump */
  JMP = 'JMP',
  /** Return from function */
  RET = 'RET',
  /** Call function */
  CALL = 'CALL',
}

/**
 * Valid operand types for IR instructions.
 */
export type IROperandType = 'reg' | 'temp' | 'imm' | 'mem' | 'var';

/**
 * Represents an operand in an IR instruction.
 */
export interface IROperand {
  /** The type of the operand */
  type: IROperandType;
  /** Name of the register, temp, or variable, if applicable */
  name?: string;
  /** Immediate value or constant, if applicable */
  value?: bigint | number;
  /** SSA version number, if applicable */
  version?: number;
  /** Memory offset, if applicable */
  offset?: number;
}

/**
 * Represents a single instruction in the Intermediate Representation.
 */
export interface IRInstruction {
  /** The operation code */
  op: IROp;
  /** The destination operand, if the operation writes a result */
  dest?: IROperand;
  /** Arguments / source operands for the operation */
  args: IROperand[];
  /** Virtual address of the original machine instruction */
  address?: number;
}

/**
 * Represents a basic block containing IR instructions.
 */
export interface IRBlock {
  /** Unique identifier for the block */
  id: string;
  /** Sequence of IR instructions in the block */
  instructions: IRInstruction[];
  /** List of predecessor block IDs */
  predecessors: string[];
  /** List of successor block IDs */
  successors: string[];
  /** Start virtual address of the block, if known */
  startAddress?: number;
}

/**
 * Represents the Control Flow Graph (CFG) of IR blocks.
 */
export interface IRCFG {
  /** Map of block ID to basic block */
  blocks: Map<string, IRBlock>;
}

/**
 * Translates target-dependent machine instructions/blocks to target-independent IR.
 */
export class IRTranslator {
  /**
   * Translates a list of target-dependent machine instructions into target-independent IR instructions.
   * 
   * @param instructions Array of disassembled machine instructions.
   * @returns An array of translated IR instructions.
   */
  public translateInstructions(instructions: Instruction[]): IRInstruction[] {
    const irInsts: IRInstruction[] = [];

    for (const inst of instructions) {
      const address = inst.address;
      const mnemonic = inst.mnemonic.toLowerCase();

      switch (mnemonic) {
        case 'mov': {
          const dest = this.parseOperand(inst.operands[0]);
          const src = this.parseOperand(inst.operands[1]);
          irInsts.push({ op: IROp.MOV, dest, args: src ? [src] : [], address });
          break;
        }
        case 'add': {
          const dest = this.parseOperand(inst.operands[0]);
          const src = this.parseOperand(inst.operands[1]);
          irInsts.push({ op: IROp.ADD, dest, args: dest && src ? [dest, src] : [], address });
          break;
        }
        case 'sub': {
          const dest = this.parseOperand(inst.operands[0]);
          const src = this.parseOperand(inst.operands[1]);
          irInsts.push({ op: IROp.SUB, dest, args: dest && src ? [dest, src] : [], address });
          break;
        }
        case 'push': {
          const src = this.parseOperand(inst.operands[0]);
          // push src => rsp = rsp - 8; store [rsp], src
          const rspOperand: IROperand = { type: 'reg', name: 'rsp' };
          const eightOperand: IROperand = { type: 'imm', value: 8 };
          irInsts.push({ op: IROp.SUB, dest: rspOperand, args: [rspOperand, eightOperand], address });
          irInsts.push({
            op: IROp.STORE,
            args: [{ type: 'mem', name: 'rsp', offset: 0 }, src],
            address,
          });
          break;
        }
        case 'pop': {
          const dest = this.parseOperand(inst.operands[0]);
          // pop dest => load dest, [rsp]; rsp = rsp + 8
          const rspOperand: IROperand = { type: 'reg', name: 'rsp' };
          const eightOperand: IROperand = { type: 'imm', value: 8 };
          irInsts.push({
            op: IROp.LOAD,
            dest,
            args: [{ type: 'mem', name: 'rsp', offset: 0 }],
            address,
          });
          irInsts.push({ op: IROp.ADD, dest: rspOperand, args: [rspOperand, eightOperand], address });
          break;
        }
        case 'cmp': {
          const src1 = this.parseOperand(inst.operands[0]);
          const src2 = this.parseOperand(inst.operands[1]);
          irInsts.push({ op: IROp.CMP, args: src1 && src2 ? [src1, src2] : [], address });
          break;
        }
        case 'jmp': {
          const target = this.parseOperand(inst.operands[0]);
          irInsts.push({ op: IROp.JMP, args: target ? [target] : [], address });
          break;
        }
        case 'ret':
        case 'retn': {
          irInsts.push({ op: IROp.RET, args: [], address });
          break;
        }
        default: {
          // General fallback mapping using generic operations or MOV
          if (inst.operands.length > 0) {
            const dest = this.parseOperand(inst.operands[0]);
            const args = inst.operands.slice(1).map(op => this.parseOperand(op));
            irInsts.push({
              op: IROp.MOV,
              dest,
              args,
              address,
            });
          } else {
            irInsts.push({
              op: IROp.MOV,
              args: [],
              address,
            });
          }
          break;
        }
      }
    }

    return irInsts;
  }

  /**
   * Translates CFG basic blocks to an IR Control Flow Graph.
   * 
   * @param cfgBlocks Array of basic blocks from the disassembler's CFG.
   * @returns The generated target-independent IR Control Flow Graph.
   */
  public translateCFG(cfgBlocks: BasicBlock[]): IRCFG {
    const irBlocks = new Map<string, IRBlock>();

    for (const block of cfgBlocks) {
      const irBlock: IRBlock = {
        id: block.id,
        instructions: this.translateInstructions(block.instructions),
        predecessors: [],
        successors: [...block.successors],
        startAddress: block.startAddress,
      };
      irBlocks.set(block.id, irBlock);
    }

    // Populate predecessors
    for (const [id, block] of irBlocks.entries()) {
      for (const succId of block.successors) {
        const succ = irBlocks.get(succId);
        if (succ && !succ.predecessors.includes(id)) {
          succ.predecessors.push(id);
        }
      }
    }

    return { blocks: irBlocks };
  }

  private parseOperand(op: any): IROperand {
    if (!op) return { type: 'temp' };
    if (op.type === 'reg') {
      return { type: 'reg', name: String(op.reg) };
    } else if (op.type === 'imm') {
      return { type: 'imm', value: op.imm };
    } else if (op.type === 'mem') {
      return {
        type: 'mem',
        name: op.mem?.base ? String(op.mem.base) : undefined,
        offset: op.mem?.disp ? Number(op.mem.disp) : 0,
      };
    }
    return { type: 'temp' };
  }
}

/**
 * Builds SSA Form (Single Static Assignment) for an IR CFG.
 */
export class SSABuilder {
  private varVersions = new Map<string, number>();
  private activeDefs = new Map<string, IROperand>();

  /**
   * Converts an IR CFG into SSA form by versioning registers/variables and inserting PHI nodes.
   * 
   * @param cfg The IR Control Flow Graph to transform into SSA form.
   * @returns The modified IR Control Flow Graph in SSA form.
   */
  public buildSSA(cfg: IRCFG): IRCFG {
    this.varVersions.clear();
    this.activeDefs.clear();

    const visited = new Set<string>();

    // Step 1: Insert PHI nodes at merge points (blocks with > 1 predecessor)
    for (const block of cfg.blocks.values()) {
      if (block.predecessors.length > 1) {
        // Collect all variables written in predecessor paths
        const writtenVars = this.collectWrittenVariables(cfg, block);
        for (const varName of writtenVars) {
          const phiArgs: IROperand[] = block.predecessors.map(() => ({
            type: 'var',
            name: varName,
            version: 0,
          }));

          const phiDest: IROperand = {
            type: 'var',
            name: varName,
            version: this.nextVersion(varName),
          };

          block.instructions.unshift({
            op: IROp.PHI,
            dest: phiDest,
            args: phiArgs,
          });
        }
      }
    }

    // Step 2: Version variables sequentially in instruction order
    for (const block of cfg.blocks.values()) {
      this.versionBlock(block);
    }

    // Step 3: Populate PHI arguments from predecessors' final variable versions
    for (const block of cfg.blocks.values()) {
      if (block.predecessors.length > 1) {
        for (const inst of block.instructions) {
          if (inst.op === IROp.PHI && inst.dest && inst.dest.name) {
            const varName = inst.dest.name;
            inst.args = block.predecessors.map(predId => {
              const predBlock = cfg.blocks.get(predId);
              const lastVer = predBlock ? this.findLastWrite(predBlock, varName) : 0;
              return {
                type: 'var',
                name: varName,
                version: lastVer,
              };
            });
          }
        }
      }
    }

    return cfg;
  }

  private collectWrittenVariables(cfg: IRCFG, startBlock: IRBlock): Set<string> {
    const vars = new Set<string>();
    const visited = new Set<string>();
    const queue = [...startBlock.predecessors];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (visited.has(currentId)) continue;
      visited.add(currentId);

      const block = cfg.blocks.get(currentId);
      if (!block) continue;

      for (const inst of block.instructions) {
        if (inst.dest && (inst.dest.type === 'reg' || inst.dest.type === 'var') && inst.dest.name) {
          vars.add(inst.dest.name);
        }
      }

      queue.push(...block.predecessors);
    }

    return vars;
  }

  private versionBlock(block: IRBlock): void {
    for (const inst of block.instructions) {
      // 1. Version the input arguments first (read accesses)
      inst.args = inst.args.map(arg => {
        if ((arg.type === 'reg' || arg.type === 'var') && arg.name) {
          const currentVer = this.varVersions.get(arg.name) ?? 0;
          return {
            ...arg,
            type: 'var',
            version: currentVer,
          };
        }
        return arg;
      });

      // 2. Version the destination operand (write access)
      if (inst.dest && (inst.dest.type === 'reg' || inst.dest.type === 'var') && inst.dest.name) {
        const varName = inst.dest.name;
        inst.dest = {
          ...inst.dest,
          type: 'var',
          version: this.nextVersion(varName),
        };
      }
    }
  }

  private findLastWrite(block: IRBlock, varName: string): number {
    for (let i = block.instructions.length - 1; i >= 0; i--) {
      const inst = block.instructions[i];
      if (inst.dest && inst.dest.name === varName && inst.dest.version !== undefined) {
        return inst.dest.version;
      }
    }
    return 0;
  }

  private nextVersion(varName: string): number {
    const current = this.varVersions.get(varName) ?? -1;
    const next = current + 1;
    this.varVersions.set(varName, next);
    return next;
  }
}

/**
 * Performs target-independent optimization passes on the IR CFG.
 */
export class IROptimizer {
  /**
   * Constant folding: Simplifies arithmetic operations on constant arguments.
   * 
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public constantFolding(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.args.length === 2 && inst.args.every(arg => arg.type === 'imm')) {
          const val1 = Number(inst.args[0].value ?? 0);
          const val2 = Number(inst.args[1].value ?? 0);
          let foldedValue: number | null = null;

          switch (inst.op) {
            case IROp.ADD:
              foldedValue = val1 + val2;
              break;
            case IROp.SUB:
              foldedValue = val1 - val2;
              break;
            case IROp.MUL:
              foldedValue = val1 * val2;
              break;
            case IROp.DIV:
              if (val2 !== 0) foldedValue = Math.floor(val1 / val2);
              break;
            case IROp.AND:
              foldedValue = val1 & val2;
              break;
            case IROp.OR:
              foldedValue = val1 | val2;
              break;
            case IROp.XOR:
              foldedValue = val1 ^ val2;
              break;
          }

          if (foldedValue !== null && inst.dest) {
            inst.op = IROp.MOV;
            inst.args = [{ type: 'imm', value: foldedValue }];
          }
        }
      }
    }
    return cfg;
  }

  /**
   * Dead Code Elimination (DCE): Removes instructions whose outputs are never read.
   * 
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with dead code removed.
   */
  public deadCodeElimination(cfg: IRCFG): IRCFG {
    const readCount = new Map<string, number>();

    // Count usages of each versioned variable
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        for (const arg of inst.args) {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            const key = `${arg.name}_${arg.version}`;
            readCount.set(key, (readCount.get(key) ?? 0) + 1);
          }
        }
      }
    }

    // Remove instructions writing to variables that are never read
    for (const block of cfg.blocks.values()) {
      block.instructions = block.instructions.filter(inst => {
        // Do not eliminate memory stores, jumps, branches, rets, calls, or volatile ops
        if ([IROp.STORE, IROp.JMP, IROp.BRANCH, IROp.RET, IROp.CALL].includes(inst.op)) {
          return true;
        }

        if (inst.dest && inst.dest.type === 'var' && inst.dest.name && inst.dest.version !== undefined) {
          const key = `${inst.dest.name}_${inst.dest.version}`;
          return (readCount.get(key) ?? 0) > 0;
        }

        return true;
      });
    }

    return cfg;
  }

  /**
   * Copy propagation: Replaces uses of variables that are copies of other variables or constants.
   * 
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with copy propagation applied.
   */
  public copyPropagation(cfg: IRCFG): IRCFG {
    const copyMap = new Map<string, IROperand>();

    // Helper to compare two operands
    const operandsEqual = (a: IROperand, b: IROperand): boolean => {
      return (
        a.type === b.type &&
        a.name === b.name &&
        a.value === b.value &&
        a.version === b.version &&
        a.offset === b.offset
      );
    };

    // Helper to resolve an operand to its root source if it has been propagated
    const resolve = (op: IROperand, visited = new Set<string>()): IROperand => {
      if (op.type === 'var' && op.name && op.version !== undefined) {
        const key = `${op.name}_${op.version}`;
        if (visited.has(key)) {
          return op;
        }
        visited.add(key);
        if (copyMap.has(key)) {
          return resolve(copyMap.get(key)!, visited);
        }
      }
      return op;
    };

    let changed = true;
    while (changed) {
      changed = false;
      for (const block of cfg.blocks.values()) {
        for (const inst of block.instructions) {
          // Replace arguments
          for (let i = 0; i < inst.args.length; i++) {
            const resolved = resolve(inst.args[i]);
            // If they are not equal, we change them
            if (!operandsEqual(resolved, inst.args[i])) {
              inst.args[i] = resolved;
              changed = true;
            }
          }

          // If the instruction is a copy (MOV dest, src) and dest is a variable, register it
          if (
            inst.op === IROp.MOV &&
            inst.dest &&
            inst.dest.type === 'var' &&
            inst.dest.name &&
            inst.dest.version !== undefined &&
            inst.args.length === 1
          ) {
            const key = `${inst.dest.name}_${inst.dest.version}`;
            const src = inst.args[0];
            const resolvedSrc = resolve(src);
            
            // Check if we already have this copy mapped, or if we should map it
            const existing = copyMap.get(key);
            if (!existing || !operandsEqual(existing, resolvedSrc)) {
              // Avoid self-reference loop
              if (resolvedSrc.type !== 'var' || `${resolvedSrc.name}_${resolvedSrc.version}` !== key) {
                copyMap.set(key, resolvedSrc);
                changed = true;
              }
            }
          }
        }
      }
    }

    return cfg;
  }

  /**
   * Strength Reduction: Replaces expensive operations (like MUL/DIV by powers of two)
   * with cheaper operations (like SHL/SHR).
   * 
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with strength reductions applied.
   */
  public strengthReduction(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.op === IROp.MUL && inst.args.length === 2) {
          // Check if one operand is an immediate constant which is a power of 2
          let valOp: IROperand | null = null;
          let immVal: number | bigint | null = null;

          if (inst.args[1].type === 'imm' && inst.args[1].value !== undefined) {
            valOp = inst.args[0];
            immVal = inst.args[1].value;
          } else if (inst.args[0].type === 'imm' && inst.args[0].value !== undefined) {
            valOp = inst.args[1];
            immVal = inst.args[0].value;
          }

          if (immVal !== null && valOp !== null) {
            const numVal = Number(immVal);
            if (numVal > 0 && (numVal & (numVal - 1)) === 0) {
              const shift = Math.log2(numVal);
              inst.op = IROp.SHL;
              inst.args = [valOp, { type: 'imm', value: shift }];
            } else if (numVal === 0) {
              inst.op = IROp.MOV;
              inst.args = [{ type: 'imm', value: 0 }];
            } else if (numVal === 1) {
              inst.op = IROp.MOV;
              inst.args = [valOp];
            }
          }
        } else if (inst.op === IROp.DIV && inst.args.length === 2) {
          // Division by power of 2: DIV x, power_of_2 => SHR x, log2(power_of_2)
          const divisor = inst.args[1];
          const valOp = inst.args[0];
          if (divisor.type === 'imm' && divisor.value !== undefined) {
            const numVal = Number(divisor.value);
            if (numVal > 0 && (numVal & (numVal - 1)) === 0) {
              const shift = Math.log2(numVal);
              inst.op = IROp.SHR;
              inst.args = [valOp, { type: 'imm', value: shift }];
            } else if (numVal === 1) {
              inst.op = IROp.MOV;
              inst.args = [valOp];
            }
          }
        }
      }
    }
    return cfg;
  }
}
