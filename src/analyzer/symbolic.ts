/**
 * Symbolic Execution Engine for URET Intermediate Representation (IR)
 * Part of the Universal Reverse Engineering Tool (URET)
 */

import { IROp, IRInstruction, IRBlock, IRCFG, IROperand } from '../disassembler/ir.js';

export type SymbolicExpr =
  | { type: 'constant'; value: bigint }
  | { type: 'variable'; name: string; version?: number }
  | { type: 'binary'; op: string; left: SymbolicExpr; right: SymbolicExpr }
  | { type: 'unary'; op: string; operand: SymbolicExpr }
  | { type: 'memory'; address: SymbolicExpr }
  | { type: 'phi'; operands: SymbolicExpr[] }
  | { type: 'unknown' };

/**
 * Pretty printer for Symbolic Expressions
 */
export function stringifyExpr(expr: SymbolicExpr): string {
  switch (expr.type) {
    case 'constant':
      return expr.value.toString();
    case 'variable':
      return expr.version !== undefined ? `${expr.name}_${expr.version}` : expr.name;
    case 'binary':
      return `(${stringifyExpr(expr.left)} ${expr.op} ${stringifyExpr(expr.right)})`;
    case 'unary':
      return `(${expr.op} ${stringifyExpr(expr.operand)})`;
    case 'memory':
      return `*[${stringifyExpr(expr.address)}]`;
    case 'phi':
      return `phi(${expr.operands.map(stringifyExpr).join(', ')})`;
    case 'unknown':
      return '?';
  }
}

export function simplifyExpr(expr: SymbolicExpr): SymbolicExpr {
  if (expr.type === 'binary') {
    const left = simplifyExpr(expr.left);
    const right = simplifyExpr(expr.right);
    if (left.type === 'constant' && right.type === 'constant') {
      if (expr.op === '+') return { type: 'constant', value: left.value + right.value };
      if (expr.op === '-') return { type: 'constant', value: left.value - right.value };
      if (expr.op === '*') return { type: 'constant', value: left.value * right.value };
      if (expr.op === '/') return { type: 'constant', value: right.value !== 0n ? left.value / right.value : 0n };
      if (expr.op === 'ADD') return { type: 'constant', value: left.value + right.value };
      if (expr.op === 'SUB') return { type: 'constant', value: left.value - right.value };
      if (expr.op === 'MUL') return { type: 'constant', value: left.value * right.value };
      if (expr.op === 'DIV') return { type: 'constant', value: right.value !== 0n ? left.value / right.value : 0n };
    }
    return { ...expr, left, right };
  }
  if (expr.type === 'unary') {
    const operand = simplifyExpr(expr.operand);
    return { ...expr, operand };
  }
  return expr;
}

export class SymbolicState {
  public registers = new Map<string, SymbolicExpr>();
  public memory = new Map<string, SymbolicExpr>();
  public constraints: SymbolicExpr[] = [];
  public path: string[] = [];
  public currentBlockId = '';
  public pc = 0;
  public terminated = false;
  public flags = new Map<string, SymbolicExpr>();

  public clone(): SymbolicState {
    const s = new SymbolicState();
    s.registers = new Map(this.registers);
    s.memory = new Map(this.memory);
    s.constraints = [...this.constraints];
    s.path = [...this.path];
    s.currentBlockId = this.currentBlockId;
    s.pc = this.pc;
    s.terminated = this.terminated;
    s.flags = new Map(this.flags);
    return s;
  }
}

export interface SymbolicExecutorOptions {
  maxDepth?: number;
  maxPaths?: number;
}

export class SymbolicExecutor {
  /**
   * Evaluates an operand in the context of a symbolic state
   */
  public evaluateOperand(op: IROperand, state: SymbolicState): SymbolicExpr {
    switch (op.type) {
      case 'imm':
        return { type: 'constant', value: BigInt(op.value ?? 0) };
      case 'reg':
      case 'temp':
      case 'var': {
        const key = op.version !== undefined ? `${op.name}_${op.version}` : (op.name ?? '');
        if (state.registers.has(key)) {
          return state.registers.get(key)!;
        }
        return { type: 'variable', name: op.name ?? 'unknown', version: op.version };
      }
      case 'mem': {
        // Simple address translation
        const baseExpr: SymbolicExpr = op.name
          ? (state.registers.get(op.name) || { type: 'variable', name: op.name })
          : { type: 'constant', value: 0n };
        const offsetExpr: SymbolicExpr = { type: 'constant', value: BigInt(op.offset ?? 0) };
        const addrExpr: SymbolicExpr = simplifyExpr({
          type: 'binary',
          op: '+',
          left: baseExpr,
          right: offsetExpr,
        });
        const addrStr = stringifyExpr(addrExpr);
        if (state.memory.has(addrStr)) {
          return state.memory.get(addrStr)!;
        }
        return { type: 'memory', address: addrExpr };
      }
      default:
        return { type: 'unknown' };
    }
  }

  /**
   * Evaluates the address of an operand for memory operations
   */
  public getAddress(op: IROperand, state: SymbolicState): SymbolicExpr {
    if (op.type === 'mem') {
      const baseExpr: SymbolicExpr = op.name
        ? (state.registers.get(op.name) || { type: 'variable', name: op.name })
        : { type: 'constant', value: 0n };
      const offsetExpr: SymbolicExpr = { type: 'constant', value: BigInt(op.offset ?? 0) };
      return simplifyExpr({
        type: 'binary',
        op: '+',
        left: baseExpr,
        right: offsetExpr,
      });
    }
    return this.evaluateOperand(op, state);
  }

  /**
   * Executes a single IR instruction on a given symbolic state
   */
  public executeInstruction(inst: IRInstruction, state: SymbolicState): SymbolicState[] {
    const nextState = state.clone();
    nextState.pc++;

    switch (inst.op) {
      case IROp.MOV: {
        if (inst.dest) {
          const srcVal = inst.args[0]
            ? this.evaluateOperand(inst.args[0], state)
            : { type: 'unknown' as const };
          const destKey = inst.dest.version !== undefined ? `${inst.dest.name}_${inst.dest.version}` : (inst.dest.name ?? '');
          nextState.registers.set(destKey, srcVal);
        }
        break;
      }

      case IROp.ADD:
      case IROp.SUB:
      case IROp.MUL:
      case IROp.DIV:
      case IROp.AND:
      case IROp.OR:
      case IROp.XOR:
      case IROp.SHL:
      case IROp.SHR: {
        if (inst.dest) {
          const left = inst.args[0] ? this.evaluateOperand(inst.args[0], state) : { type: 'constant' as const, value: 0n };
          const right = inst.args[1] ? this.evaluateOperand(inst.args[1], state) : { type: 'constant' as const, value: 0n };
          const result: SymbolicExpr = {
            type: 'binary',
            op: inst.op,
            left,
            right,
          };
          const destKey = inst.dest.version !== undefined ? `${inst.dest.name}_${inst.dest.version}` : (inst.dest.name ?? '');
          nextState.registers.set(destKey, result);
        }
        break;
      }

      case IROp.CMP: {
        if (inst.args.length >= 2) {
          const left = this.evaluateOperand(inst.args[0], state);
          const right = this.evaluateOperand(inst.args[1], state);
          nextState.flags.set('ZF', { type: 'binary', op: '==', left, right });
          nextState.flags.set('SF', { type: 'binary', op: '<', left, right });
          nextState.flags.set('CMP', { type: 'binary', op: 'CMP', left, right });
        }
        break;
      }

      case IROp.LOAD: {
        if (inst.dest && inst.args[0]) {
          const addr = this.getAddress(inst.args[0], state);
          const val = state.memory.get(stringifyExpr(addr)) || { type: 'memory', address: addr };
          const destKey = inst.dest.version !== undefined ? `${inst.dest.name}_${inst.dest.version}` : (inst.dest.name ?? '');
          nextState.registers.set(destKey, val);
        }
        break;
      }

      case IROp.STORE: {
        if (inst.args[0] && inst.args[1]) {
          const addr = this.getAddress(inst.args[0], state);
          const val = this.evaluateOperand(inst.args[1], state);
          nextState.memory.set(stringifyExpr(addr), val);
        }
        break;
      }

      case IROp.PHI: {
        if (inst.dest) {
          const ops = inst.args.map(arg => this.evaluateOperand(arg, state));
          const destKey = inst.dest.version !== undefined ? `${inst.dest.name}_${inst.dest.version}` : (inst.dest.name ?? '');
          nextState.registers.set(destKey, { type: 'phi', operands: ops });
        }
        break;
      }

      case IROp.JMP: {
        if (inst.args[0]) {
          const target = this.evaluateOperand(inst.args[0], state);
          if (target.type === 'constant') {
            // Unconditional jump to constant address (or target block ID if resolved/mapped)
            // Just let the CFG traversal handle standard block JMPs
          }
        }
        break;
      }

      case IROp.BRANCH: {
        if (inst.args[0]) {
          const cond = this.evaluateOperand(inst.args[0], state);
          
          // Split state into two paths
          const trueState = nextState.clone();
          trueState.constraints.push(cond);

          const falseState = nextState.clone();
          falseState.constraints.push({ type: 'unary', op: 'NOT', operand: cond });

          return [trueState, falseState];
        }
        break;
      }

      case IROp.RET: {
        nextState.terminated = true;
        break;
      }

      default:
        // Do nothing for other/unknown operations
        break;
    }

    return [nextState];
  }

  /**
   * Executes symbolic execution over a complete CFG starting from an entry block
   */
  public executeCFG(
    cfg: IRCFG,
    entryBlockId: string,
    initialState: SymbolicState = new SymbolicState(),
    options: SymbolicExecutorOptions = {}
  ): SymbolicState[] {
    const maxDepth = options.maxDepth ?? 50;
    const maxPaths = options.maxPaths ?? 100;

    const startState = initialState.clone();
    startState.currentBlockId = entryBlockId;
    startState.path.push(entryBlockId);
    
    let queue: SymbolicState[] = [startState];
    const completed: SymbolicState[] = [];

    while (queue.length > 0 && completed.length < maxPaths) {
      const state = queue.shift()!;

      // Handle terminated states
      if (state.terminated) {
        completed.push(state);
        continue;
      }

      // Check max path length / depth
      if (state.path.length > maxDepth) {
        state.terminated = true;
        completed.push(state);
        continue;
      }

      const block = cfg.blocks.get(state.currentBlockId);
      if (!block) {
        state.terminated = true;
        completed.push(state);
        continue;
      }

      // If we still have instructions in current block to execute
      if (state.pc < block.instructions.length) {
        const inst = block.instructions[state.pc];
        const outputs = this.executeInstruction(inst, state);
        
        for (const out of outputs) {
          queue.push(out);
        }
        continue;
      }

      // End of block reached: trace successors
      const successors = block.successors;
      if (successors.length === 0) {
        state.terminated = true;
        completed.push(state);
      } else if (successors.length === 1) {
        const nextState = state.clone();
        nextState.currentBlockId = successors[0];
        nextState.pc = 0;
        nextState.path.push(successors[0]);
        queue.push(nextState);
      } else {
        // Multi-successor block (branching)
        // Check if last instruction was a BRANCH
        const lastInst = block.instructions[block.instructions.length - 1];
        if (lastInst && lastInst.op === IROp.BRANCH && lastInst.args[0]) {
          const cond = this.evaluateOperand(lastInst.args[0], state);
          
          // True successor (usually first successor)
          const trueState = state.clone();
          trueState.constraints.push(cond);
          trueState.currentBlockId = successors[0];
          trueState.pc = 0;
          trueState.path.push(successors[0]);

          // False successor (usually second successor)
          const falseState = state.clone();
          falseState.constraints.push({ type: 'unary', op: 'NOT', operand: cond });
          falseState.currentBlockId = successors[1] ?? successors[0];
          falseState.pc = 0;
          falseState.path.push(successors[1] ?? successors[0]);

          queue.push(trueState, falseState);
        } else {
          // Fallback flag-based branching or generic branch if no explicit condition is known
          const cond = state.flags.get('ZF') || { type: 'variable', name: `branch_cond_${state.currentBlockId}` };
          
          const trueState = state.clone();
          trueState.constraints.push(cond);
          trueState.currentBlockId = successors[0];
          trueState.pc = 0;
          trueState.path.push(successors[0]);

          const falseState = state.clone();
          falseState.constraints.push({ type: 'unary', op: 'NOT', operand: cond });
          falseState.currentBlockId = successors[1] ?? successors[0];
          falseState.pc = 0;
          falseState.path.push(successors[1] ?? successors[0]);

          queue.push(trueState, falseState);
        }
      }
    }

    return completed;
  }
}
