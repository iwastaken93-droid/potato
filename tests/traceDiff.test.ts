import { describe, it, expect, vi } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';
import {
  captureEmulatorTrace,
  diffTraces,
  findFirstDivergence,
  TraceStep,
} from '../src/analyzer/traceDiff.js';

describe('Trace Diffing Engine Tests', () => {
  it('should capture trace from emulator', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'mov',
        opStr: 'rax, 0x100',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 0x100n },
        ],
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'add',
        opStr: 'rax, 0x50',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'imm', imm: 0x50n },
        ],
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);

    const trace = captureEmulatorTrace(emu, 10);
    expect(trace.length).toBe(2);
    expect(trace[0].rip).toBe(0x1000n);
    expect(trace[0].instruction.mnemonic).toBe('mov');
    expect(trace[0].registers.rax).toBe(0n); // state before executing step 1

    expect(trace[1].rip).toBe(0x1004n);
    expect(trace[1].instruction.mnemonic).toBe('add');
    expect(trace[1].registers.rax).toBe(0x100n); // state after step 1 / before step 2
  });

  it('should diff identical traces and report no differences', () => {
    const traceA: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n, rbx: 10n },
      },
      {
        stepIndex: 1,
        rip: 0x1004n,
        instruction: { address: 0x1004, mnemonic: 'add', opStr: 'rax, 5' },
        registers: { rax: 15n, rbx: 10n },
      },
    ];

    const traceB: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n, rbx: 10n },
      },
      {
        stepIndex: 1,
        rip: 0x1004n,
        instruction: { address: 0x1004, mnemonic: 'add', opStr: 'rax, 5' },
        registers: { rax: 15n, rbx: 10n },
      },
    ];

    const diff = diffTraces(traceA, traceB);
    expect(diff.length).toBe(2);
    expect(diff.every((d) => d.type === 'equal')).toBe(true);
    expect(diff.every((d) => d.registerDiffs.length === 0)).toBe(true);
    expect(findFirstDivergence(diff)).toBe(-1);
  });

  it('should detect register divergence', () => {
    const traceA: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n, rbx: 10n },
      },
    ];

    const traceB: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 20n, rbx: 10n },
      },
    ];

    const diff = diffTraces(traceA, traceB);
    expect(diff.length).toBe(1);
    expect(diff[0].type).toBe('equal');
    expect(diff[0].registerDiffs.length).toBe(1);
    expect(diff[0].registerDiffs[0]).toEqual({
      register: 'rax',
      valueA: 10n,
      valueB: 20n,
    });
    expect(findFirstDivergence(diff)).toBe(0);
  });

  it('should detect instruction divergence and deletions/insertions', () => {
    const traceA: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n },
      },
      {
        stepIndex: 1,
        rip: 0x1004n,
        instruction: { address: 0x1004, mnemonic: 'jmp', opStr: '0x2000' },
        registers: { rax: 10n },
      },
    ];

    const traceB: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n },
      },
      {
        stepIndex: 1,
        rip: 0x1008n,
        instruction: { address: 0x1008, mnemonic: 'nop', opStr: '' },
        registers: { rax: 10n },
      },
    ];

    const diff = diffTraces(traceA, traceB);
    // Myers diff will replace or insert/delete
    expect(diff.length).toBe(2);
    expect(diff[0].type).toBe('equal');
    expect(diff[1].type).toBe('replace');
    expect(findFirstDivergence(diff)).toBe(1);
  });

  it('should return empty trace when emulator starts at invalid rip', () => {
    const emu = new Emulator();
    emu.reset(0x9999); // No instructions loaded
    const trace = captureEmulatorTrace(emu, 10);
    expect(trace).toEqual([]);
  });

  it('should stop capturing trace if emulator step fails or halts', () => {
    const emu = new Emulator();
    const insts = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0]),
        mnemonic: 'nop',
        opStr: '',
        size: 4,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0]),
        mnemonic: 'nop',
        opStr: '',
        size: 4,
      },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);

    // Spy on step to simulate a halting execution result
    vi.spyOn(emu, 'step').mockReturnValue({
      success: false,
      halted: true,
      hitBreakpoint: false,
    });

    const trace = captureEmulatorTrace(emu, 10);
    // Should capture the initial state at 0x1000, then halt on the step attempt
    expect(trace.length).toBe(1);
    expect(trace[0].rip).toBe(0x1000n);
  });

  it('should handle deletion and insertion trace differences correctly', () => {
    const traceA: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n },
      },
      {
        stepIndex: 1,
        rip: 0x1004n,
        instruction: { address: 0x1004, mnemonic: 'add', opStr: 'rax, 5' },
        registers: { rax: 15n },
      },
    ];

    const traceB: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n },
      },
    ];

    // Trace A -> Trace B (delete 1 step)
    const diffDel = diffTraces(traceA, traceB);
    expect(diffDel.length).toBe(2);
    expect(diffDel[0].type).toBe('equal');
    expect(diffDel[1].type).toBe('delete');
    expect(diffDel[1].stepA).toEqual(traceA[1]);
    expect(diffDel[1].stepB).toBeNull();

    // Trace B -> Trace A (insert 1 step)
    const diffIns = diffTraces(traceB, traceA);
    expect(diffIns.length).toBe(2);
    expect(diffIns[0].type).toBe('equal');
    expect(diffIns[1].type).toBe('insert');
    expect(diffIns[1].stepA).toBeNull();
    expect(diffIns[1].stepB).toEqual(traceA[1]);
  });

  it('should detect register differences when keys diverge or are missing', () => {
    const traceA: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n, rbx: 20n },
      },
    ];

    const traceB: TraceStep[] = [
      {
        stepIndex: 0,
        rip: 0x1000n,
        instruction: { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx' },
        registers: { rax: 10n }, // missing rbx
      },
    ];

    const diff = diffTraces(traceA, traceB);
    expect(diff[0].registerDiffs.length).toBe(1);
    expect(diff[0].registerDiffs[0]).toEqual({
      register: 'rbx',
      valueA: 20n,
      valueB: undefined,
    });
  });

  it('should stop capture emulator trace at maxSteps limit', () => {
    const emu = new Emulator();
    const insts = [
      { address: 0x1000, bytes: new Uint8Array([0]), mnemonic: 'nop', opStr: '', size: 4 },
      { address: 0x1004, bytes: new Uint8Array([0]), mnemonic: 'nop', opStr: '', size: 4 },
    ];
    emu.loadInstructions(insts);
    emu.reset(0x1000);

    const trace = captureEmulatorTrace(emu, 1);
    // Even though there are 2 instructions, maxSteps = 1 should limit it to 1 step
    expect(trace.length).toBe(1);
    expect(trace[0].rip).toBe(0x1000n);
  });

  it('should diff completely empty traces', () => {
    const diff = diffTraces([], []);
    expect(diff).toEqual([]);
    expect(findFirstDivergence(diff)).toBe(-1);
  });

  it('should have empty registerDiffs for delete or insert entries', () => {
    const step: TraceStep = {
      stepIndex: 0,
      rip: 0x1000n,
      instruction: { address: 0x1000, mnemonic: 'nop', opStr: '' },
      registers: { rax: 10n },
    };

    // A delete entry (stepA = step, stepB = null)
    const diffDel = diffTraces([step], []);
    expect(diffDel).toHaveLength(1);
    expect(diffDel[0].type).toBe('delete');
    expect(diffDel[0].stepA).toEqual(step);
    expect(diffDel[0].stepB).toBeNull();
    expect(diffDel[0].registerDiffs).toEqual([]);

    // An insert entry (stepA = null, stepB = step)
    const diffIns = diffTraces([], [step]);
    expect(diffIns).toHaveLength(1);
    expect(diffIns[0].type).toBe('insert');
    expect(diffIns[0].stepA).toBeNull();
    expect(diffIns[0].stepB).toEqual(step);
    expect(diffIns[0].registerDiffs).toEqual([]);
  });
});

