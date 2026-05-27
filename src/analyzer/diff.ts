/**
 * Binary Diffing Engine
 * Part of the Universal Reverse Engineering Tool (URET)
 *
 * Compares two byte arrays or two disassembled instruction streams,
 * generating detailed side-by-side comparison markers.
 */

import { Instruction } from '../disassembler/types.js';

export type DiffType = 'equal' | 'delete' | 'insert' | 'replace';

export interface DiffEntry<T> {
  type: DiffType;
  originalIndex: number | null;
  revisedIndex: number | null;
  original: T | null;
  revised: T | null;
}

export interface ByteDiffResult {
  type: DiffType;
  offset1: number | null;
  offset2: number | null;
  byte1: number | null;
  byte2: number | null;
}

export interface InstructionDiffResult {
  type: DiffType;
  address1: number | null;
  address2: number | null;
  inst1: Instruction | null;
  inst2: Instruction | null;
}

/**
 * Standard Myers Diff Algorithm implementation with length limits for safety.
 */
export function myersDiff<T>(
  a: T[],
  b: T[],
  equals: (x: T, y: T) => boolean,
  maxSize: number = 2000
): DiffEntry<T>[] {
  const n = a.length;
  const m = b.length;

  // Fallback to a fast greedy matching if either array is too large
  if (n > maxSize || m > maxSize) {
    return fastGreedyDiff(a, b, equals);
  }

  // Myers diff implementation
  const max = n + m;
  const v: { [key: number]: number } = { 1: 0 };
  const trace: { [key: number]: number }[] = [];

  let x = 0;
  let y = 0;
  let found = false;

  for (let d = 0; d <= max; d++) {
    const vCopy = { ...v };
    trace.push(vCopy);

    for (let k = -d; k <= d; k += 2) {
      if (k === -d || (k !== d && (v[k - 1] ?? -1) < (v[k + 1] ?? -1))) {
        x = v[k + 1] ?? 0;
      } else {
        x = (v[k - 1] ?? 0) + 1;
      }

      y = x - k;

      while (x < n && y < m && equals(a[x], b[y])) {
        x++;
        y++;
      }

      v[k] = x;

      if (x >= n && y >= m) {
        found = true;
        break;
      }
    }
    if (found) break;
  }

  // Backtrack to find path
  const path: [number, number][] = [];
  x = n;
  y = m;

  for (let d = trace.length - 1; d >= 0; d--) {
    const v = trace[d];
    const k = x - y;

    let prevK = 0;
    if (k === -d || (k !== d && (v[k - 1] ?? -1) < (v[k + 1] ?? -1))) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }

    const prevX = v[prevK] ?? 0;
    const prevY = prevX - prevK;

    while (x > prevX && y > prevY) {
      path.push([x - 1, y - 1]);
      x--;
      y--;
    }

    if (d > 0) {
      path.push([x, y]);
    }

    x = prevX;
    y = prevY;
  }

  path.reverse();

  // Reconstruct edits from path
  const results: DiffEntry<T>[] = [];
  let currX = 0;
  let currY = 0;

  for (const [nextX, nextY] of path) {
    if (nextX === currX && nextY === currY + 1) {
      results.push({
        type: 'insert',
        originalIndex: null,
        revisedIndex: currY,
        original: null,
        revised: b[currY],
      });
      currY++;
    } else if (nextX === currX + 1 && nextY === currY) {
      results.push({
        type: 'delete',
        originalIndex: currX,
        revisedIndex: null,
        original: a[currX],
        revised: null,
      });
      currX++;
    } else {
      results.push({
        type: 'equal',
        originalIndex: currX,
        revisedIndex: currY,
        original: a[currX],
        revised: b[currY],
      });
      currX++;
      currY++;
    }
  }

  // Flush remaining
  while (currX < n) {
    results.push({
      type: 'delete',
      originalIndex: currX,
      revisedIndex: null,
      original: a[currX],
      revised: null,
    });
    currX++;
  }
  while (currY < m) {
    results.push({
      type: 'insert',
      originalIndex: null,
      revisedIndex: currY,
      original: null,
      revised: b[currY],
    });
    currY++;
  }

  return postProcessDiff(results);
}

/**
 * Fallback greedy diffing engine for larger arrays.
 */
function fastGreedyDiff<T>(
  a: T[],
  b: T[],
  equals: (x: T, y: T) => boolean
): DiffEntry<T>[] {
  const results: DiffEntry<T>[] = [];
  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    if (equals(a[i], b[j])) {
      results.push({
        type: 'equal',
        originalIndex: i,
        revisedIndex: j,
        original: a[i],
        revised: b[j],
      });
      i++;
      j++;
    } else {
      let matchIdxA = -1;
      let matchIdxB = -1;
      const lookahead = 20;

      for (let offset = 1; offset <= lookahead; offset++) {
        if (i + offset < a.length && equals(a[i + offset], b[j])) {
          matchIdxA = i + offset;
          matchIdxB = j;
          break;
        }
        if (j + offset < b.length && equals(a[i], b[j + offset])) {
          matchIdxA = i;
          matchIdxB = j + offset;
          break;
        }
      }

      if (matchIdxA !== -1) {
        while (i < matchIdxA) {
          results.push({
            type: 'delete',
            originalIndex: i,
            revisedIndex: null,
            original: a[i],
            revised: null,
          });
          i++;
        }
        while (j < matchIdxB) {
          results.push({
            type: 'insert',
            originalIndex: null,
            revisedIndex: j,
            original: null,
            revised: b[j],
          });
          j++;
        }
      } else {
        results.push({
          type: 'delete',
          originalIndex: i,
          revisedIndex: null,
          original: a[i],
          revised: null,
        });
        results.push({
          type: 'insert',
          originalIndex: null,
          revisedIndex: j,
          original: null,
          revised: b[j],
        });
        i++;
        j++;
      }
    }
  }

  while (i < a.length) {
    results.push({
      type: 'delete',
      originalIndex: i,
      revisedIndex: null,
      original: a[i],
      revised: null,
    });
    i++;
  }
  while (j < b.length) {
    results.push({
      type: 'insert',
      originalIndex: null,
      revisedIndex: j,
      original: null,
      revised: b[j],
    });
    j++;
  }

  return postProcessDiff(results);
}

/**
 * Combines consecutive delete + insert pairs into a 'replace' entry.
 */
function postProcessDiff<T>(entries: DiffEntry<T>[]): DiffEntry<T>[] {
  const processed: DiffEntry<T>[] = [];
  let i = 0;

  while (i < entries.length) {
    if (
      i < entries.length - 1 &&
      entries[i].type === 'delete' &&
      entries[i + 1].type === 'insert'
    ) {
      processed.push({
        type: 'replace',
        originalIndex: entries[i].originalIndex,
        revisedIndex: entries[i + 1].revisedIndex,
        original: entries[i].original,
        revised: entries[i + 1].revised,
      });
      i += 2;
    } else if (
      i < entries.length - 1 &&
      entries[i].type === 'insert' &&
      entries[i + 1].type === 'delete'
    ) {
      processed.push({
        type: 'replace',
        originalIndex: entries[i + 1].originalIndex,
        revisedIndex: entries[i].revisedIndex,
        original: entries[i + 1].original,
        revised: entries[i].revised,
      });
      i += 2;
    } else {
      processed.push(entries[i]);
      i++;
    }
  }

  return processed;
}

/**
 * Compare two byte arrays and return the diff result.
 */
export function diffBytes(a: Uint8Array, b: Uint8Array): ByteDiffResult[] {
  const arrA = Array.from(a);
  const arrB = Array.from(b);

  const entries = myersDiff(arrA, arrB, (x, y) => x === y);

  return entries.map(e => ({
    type: e.type,
    offset1: e.originalIndex,
    offset2: e.revisedIndex,
    byte1: e.original,
    byte2: e.revised,
  }));
}

function operandsEqual(op1?: any[], op2?: any[]): boolean {
  const ops1 = op1 || [];
  const ops2 = op2 || [];
  if (ops1.length !== ops2.length) return false;
  for (let i = 0; i < ops1.length; i++) {
    const o1 = ops1[i];
    const o2 = ops2[i];
    if (o1.type !== o2.type) return false;
    if (o1.reg !== o2.reg) return false;
    if (o1.value !== o2.value && o1.imm !== o2.imm) return false;
    if (o1.access !== o2.access) return false;
    if (!!o1.mem !== !!o2.mem) return false;
    if (o1.mem && o2.mem) {
      if (o1.mem.base !== o2.mem.base) return false;
      if (o1.mem.index !== o2.mem.index) return false;
      if (o1.mem.scale !== o2.mem.scale) return false;
      if (o1.mem.disp !== o2.mem.disp) return false;
    }
  }
  return true;
}

/**
 * Compare two instruction streams and return the diff result.
 */
export function diffInstructions(
  a: Instruction[],
  b: Instruction[]
): InstructionDiffResult[] {
  const entries = myersDiff(a, b, (x, y) => {
    if (x.mnemonic !== y.mnemonic) return false;
    if (x.opStr !== y.opStr) return false;
    if (x.size !== y.size) return false;
    
    // Compare bytes safely
    if (x.address !== undefined && y.address !== undefined) {
      if (Math.abs(x.address - y.address) > 0x2000) return false;
    }
    if (x.bytes && y.bytes) {
      if (x.bytes.length !== y.bytes.length) return false;
      for (let i = 0; i < x.bytes.length; i++) {
        if (x.bytes[i] !== y.bytes[i]) return false;
      }
    } else if (x.bytes || y.bytes) {
      return false;
    }

    // Compare operands using operandsEqual
    return operandsEqual(x.operands, y.operands);
  });

  return entries.map(e => ({
    type: e.type,
    address1: e.original ? e.original.address : null,
    address2: e.revised ? e.revised.address : null,
    inst1: e.original,
    inst2: e.revised,
  }));
}
