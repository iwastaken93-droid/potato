/**
 * Trace Comparison Engine
 * Part of the Universal Reverse Engineering Tool (URET)
 *
 * Compares two execution traces side-by-side, capturing register differences
 * and highlighting code flow divergence points.
 */

import { Emulator } from '../emulator/emulator.js';
import { myersDiff } from './diff.js';

export interface TraceStep {
  stepIndex: number;
  rip: bigint;
  instruction: {
    address: number;
    mnemonic: string;
    opStr: string;
    bytes?: Uint8Array;
  };
  registers: Record<string, bigint>;
}

export interface RegisterDiff {
  register: string;
  valueA: bigint | null;
  valueB: bigint | null;
}

export interface TraceDiffEntry {
  type: 'equal' | 'delete' | 'insert' | 'replace';
  stepA: TraceStep | null;
  stepB: TraceStep | null;
  registerDiffs: RegisterDiff[];
}

/**
 * Capture execution trace of the emulator up to maxSteps.
 */
export function captureEmulatorTrace(
  emulator: Emulator,
  maxSteps: number = 1000
): TraceStep[] {
  const trace: TraceStep[] = [];
  let stepCount = 0;

  while (stepCount < maxSteps) {
    const ripVal = emulator.cpu.read('rip');
    const inst = emulator.instructions.get(Number(ripVal));
    if (!inst) {
      break;
    }

    const regState = emulator.cpu.getState();
    const registers: Record<string, bigint> = { ...regState };

    trace.push({
      stepIndex: stepCount,
      rip: ripVal,
      instruction: {
        address: Number(ripVal),
        mnemonic: inst.mnemonic,
        opStr: inst.opStr,
        bytes: inst.bytes,
      },
      registers,
    });

    const res = emulator.step();
    if (!res.success || res.halted) {
      break;
    }
    stepCount++;
  }

  return trace;
}

/**
 * Align and compare two traces side-by-side.
 */
export function diffTraces(
  traceA: TraceStep[],
  traceB: TraceStep[]
): TraceDiffEntry[] {
  const entries = myersDiff(traceA, traceB, (x, y) => {
    return (
      x.rip === y.rip &&
      x.instruction.mnemonic === y.instruction.mnemonic &&
      x.instruction.opStr === y.instruction.opStr
    );
  });

  return entries.map((e) => {
    const stepA = e.original;
    const stepB = e.revised;
    const registerDiffs: RegisterDiff[] = [];

    if (stepA && stepB) {
      for (const reg of Object.keys(stepA.registers)) {
        const valA = stepA.registers[reg];
        const valB = stepB.registers[reg];
        if (valA !== valB) {
          registerDiffs.push({
            register: reg,
            valueA: valA,
            valueB: valB,
          });
        }
      }
    }

    return {
      type: e.type as any,
      stepA,
      stepB,
      registerDiffs,
    };
  });
}

/**
 * Finds the index of the first divergence point (first instruction divergence or register mismatch).
 */
export function findFirstDivergence(
  diffEntries: TraceDiffEntry[]
): number {
  for (let i = 0; i < diffEntries.length; i++) {
    const entry = diffEntries[i];
    if (entry.type !== 'equal' || entry.registerDiffs.length > 0) {
      return i;
    }
  }
  return -1;
}
