import { describe, it, expect } from 'vitest';
import { IROp, IRBlock, IRCFG, IRInstruction } from '../src/disassembler/ir.js';
import {
  SymbolicExecutor,
  SymbolicState,
  stringifyExpr,
} from '../src/analyzer/symbolic.js';

describe('Symbolic Execution Engine Tests', () => {
  it('should evaluate constants and registers correctly', () => {
    const executor = new SymbolicExecutor();
    const state = new SymbolicState();
    state.registers.set('rax', { type: 'constant', value: 42n });

    const opImm = executor.evaluateOperand({ type: 'imm', value: 100 }, state);
    expect(opImm).toEqual({ type: 'constant', value: 100n });

    const opReg = executor.evaluateOperand({ type: 'reg', name: 'rax' }, state);
    expect(opReg).toEqual({ type: 'constant', value: 42n });

    const opUnboundReg = executor.evaluateOperand({ type: 'reg', name: 'rbx' }, state);
    expect(opUnboundReg).toEqual({ type: 'variable', name: 'rbx', version: undefined });
  });

  it('should execute MOV and binary arithmetic instructions', () => {
    const executor = new SymbolicExecutor();
    const state = new SymbolicState();

    // mov rax, 5
    const instMov: IRInstruction = {
      op: IROp.MOV,
      dest: { type: 'reg', name: 'rax' },
      args: [{ type: 'imm', value: 5 }],
    };

    const [state2] = executor.executeInstruction(instMov, state);
    expect(state2.registers.get('rax')).toEqual({ type: 'constant', value: 5n });

    // add rax, rbx
    const instAdd: IRInstruction = {
      op: IROp.ADD,
      dest: { type: 'reg', name: 'rax' },
      args: [{ type: 'reg', name: 'rax' }, { type: 'reg', name: 'rbx' }],
    };

    const [state3] = executor.executeInstruction(instAdd, state2);
    expect(state3.registers.get('rax')).toEqual({
      type: 'binary',
      op: 'ADD',
      left: { type: 'constant', value: 5n },
      right: { type: 'variable', name: 'rbx', version: undefined },
    });

    expect(stringifyExpr(state3.registers.get('rax')!)).toBe('(5 ADD rbx)');
  });

  it('should handle memory LOAD and STORE operations', () => {
    const executor = new SymbolicExecutor();
    const state = new SymbolicState();

    // store [rsp + 8], 999
    const instStore: IRInstruction = {
      op: IROp.STORE,
      args: [
        { type: 'mem', name: 'rsp', offset: 8 },
        { type: 'imm', value: 999 },
      ],
    };

    const [state2] = executor.executeInstruction(instStore, state);
    expect(state2.memory.get('(rsp + 8)')).toEqual({ type: 'constant', value: 999n });

    // load rax, [rsp + 8]
    const instLoad: IRInstruction = {
      op: IROp.LOAD,
      dest: { type: 'reg', name: 'rax' },
      args: [{ type: 'mem', name: 'rsp', offset: 8 }],
    };

    const [state3] = executor.executeInstruction(instLoad, state2);
    expect(state3.registers.get('rax')).toEqual({ type: 'constant', value: 999n });
  });

  it('should track paths and path constraints in basic branching CFG', () => {
    const executor = new SymbolicExecutor();

    // We build a CFG representing:
    // block_1:
    //   mov rax, rbx
    //   cmp rax, 10
    //   (branch to block_2 if rax == 10, else block_3)
    // block_2:
    //   ret
    // block_3:
    //   ret

    const block1: IRBlock = {
      id: 'block_1',
      instructions: [
        {
          op: IROp.MOV,
          dest: { type: 'reg', name: 'rax' },
          args: [{ type: 'reg', name: 'rbx' }],
        },
        {
          op: IROp.CMP,
          args: [{ type: 'reg', name: 'rax' }, { type: 'imm', value: 10 }],
        },
      ],
      predecessors: [],
      successors: ['block_2', 'block_3'],
    };

    const block2: IRBlock = {
      id: 'block_2',
      instructions: [{ op: IROp.RET, args: [] }],
      predecessors: ['block_1'],
      successors: [],
    };

    const block3: IRBlock = {
      id: 'block_3',
      instructions: [{ op: IROp.RET, args: [] }],
      predecessors: ['block_1'],
      successors: [],
    };

    const blocks = new Map<string, IRBlock>([
      ['block_1', block1],
      ['block_2', block2],
      ['block_3', block3],
    ]);

    const cfg: IRCFG = { blocks };

    const results = executor.executeCFG(cfg, 'block_1');

    // Should have 2 paths
    expect(results.length).toBe(2);

    // Path 1 (True branch)
    const pathTrue = results.find((r) => r.path.includes('block_2'))!;
    expect(pathTrue).toBeDefined();
    expect(pathTrue.path).toEqual(['block_1', 'block_2']);
    expect(pathTrue.constraints.length).toBe(1);
    expect(stringifyExpr(pathTrue.constraints[0])).toBe('(rbx == 10)');

    // Path 2 (False branch)
    const pathFalse = results.find((r) => r.path.includes('block_3'))!;
    expect(pathFalse).toBeDefined();
    expect(pathFalse.path).toEqual(['block_1', 'block_3']);
    expect(pathFalse.constraints.length).toBe(1);
    expect(stringifyExpr(pathFalse.constraints[0])).toBe('(NOT (rbx == 10))');
  });
});
