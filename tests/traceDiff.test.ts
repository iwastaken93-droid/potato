import { describe, it, expect } from 'vitest';
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
});
