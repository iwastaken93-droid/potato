import { describe, it, expect } from 'vitest';
import {
  diffBytes,
  diffInstructions,
  myersDiff,
} from '../src/analyzer/diff.js';
import { Instruction } from '../src/disassembler/types.js';

describe('Binary Diffing Engine Tests', () => {
  // Test 1: Standard byte diffs
  it('should compute byte diffs correctly', () => {
    const a = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
    const b = new Uint8Array([0x10, 0x25, 0x30, 0x50, 0x60]);

    const result = diffBytes(a, b);

    expect(result.length).toBeGreaterThan(0);
    // First byte is 0x10, equal
    expect(result[0]).toEqual({
      type: 'equal',
      offset1: 0,
      offset2: 0,
      byte1: 0x10,
      byte2: 0x10,
    });
  });

  // Test 2: Standard instruction diffs
  it('should compute instruction diffs correctly', () => {
    const instA: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        size: 1,
        operands: [],
      },
      {
        address: 0x1001,
        bytes: new Uint8Array([0x50]),
        mnemonic: 'push',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const instB: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        size: 1,
        operands: [],
      },
      {
        address: 0x1001,
        bytes: new Uint8Array([0x51]),
        mnemonic: 'push',
        opStr: 'rcx',
        size: 1,
        operands: [],
      },
      {
        address: 0x1002,
        bytes: new Uint8Array([0x58]),
        mnemonic: 'pop',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];

    const result = diffInstructions(instA, instB);
    expect(result.length).toBe(3);

    expect(result[0].type).toBe('equal');
    expect(result[1].type).toBe('replace'); // push rax replaced with push rcx
    expect(result[2].type).toBe('insert'); // pop rax inserted
  });

  // Test 3: Empty inputs for byte diff
  it('should handle empty byte inputs correctly', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(0);
  });

  // Test 4: One empty input for byte diff (only deletes)
  it('should detect only deletes when revised array is empty', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(3);
    expect(result.every((r) => r.type === 'delete')).toBe(true);
  });

  // Test 5: One empty input for byte diff (only inserts)
  it('should detect only inserts when original array is empty', () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([1, 2, 3]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(3);
    expect(result.every((r) => r.type === 'insert')).toBe(true);
  });

  // Test 6: Fully identical arrays
  it('should report all equal for identical byte arrays', () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(4);
    expect(result.every((r) => r.type === 'equal')).toBe(true);
  });

  it('should report replaces or deletes/inserts for fully different arrays', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([4, 5, 6]);
    const result = diffBytes(a, b);
    expect(result.length).toBeGreaterThan(0);
    expect(
      result.some(
        (r) =>
          r.type === 'replace' || r.type === 'delete' || r.type === 'insert'
      )
    ).toBe(true);
  });

  // Test 8: Empty instruction diffs
  it('should handle empty instruction inputs correctly', () => {
    const result = diffInstructions([], []);
    expect(result.length).toBe(0);
  });

  // Test 9: Instruction stream with only replaces
  it('should handle replaced instruction sequences', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        size: 1,
        operands: [],
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0xc3]),
        mnemonic: 'ret',
        opStr: '',
        size: 1,
        operands: [],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Test 10: Myers Diff fallback to fastGreedyDiff
  it('should fallback to fastGreedyDiff for large arrays', () => {
    const a = Array.from({ length: 50 }, (_, i) => i);
    const b = Array.from({ length: 50 }, (_, i) => (i === 25 ? 999 : i));
    // Force low limit to trigger fallback
    const result = myersDiff(a, b, (x, y) => x === y, 20);
    expect(result.length).toBeGreaterThan(0);
    const replaceOrDiff = result.filter((r) => r.type !== 'equal');
    expect(replaceOrDiff.length).toBeGreaterThan(0);
  });

  // Test 11: Myers Diff when elements are objects
  it('should correctly diff custom object arrays using custom equals', () => {
    const a = [{ id: 1 }, { id: 2 }];
    const b = [{ id: 1 }, { id: 3 }];
    const result = myersDiff(a, b, (x, y) => x.id === y.id);
    expect(result.length).toBe(2);
    expect(result[0].type).toBe('equal');
    expect(result[1].type).toBe('replace');
  });

  // Test 12: Myers Diff interleaved inserts and deletes
  it('should postprocess interleaved deletes and inserts into replaces', () => {
    const a = [1, 2, 3];
    const b = [1, 4, 3];
    const result = myersDiff(a, b, (x, y) => x === y);
    expect(result.length).toBe(3);
    expect(result[0].type).toBe('equal');
    expect(result[1].type).toBe('replace');
    expect(result[2].type).toBe('equal');
  });

  // Test 13: Myers Diff consecutive deletes and inserts postprocess check
  it('should handle insert followed by delete postprocess correctly', () => {
    // Myers path can produce insert then delete depending on search. Let's test postProcessDiff's branch for insert + delete.
    const result = myersDiff([1], [2], (x, y) => x === y);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
    expect(result[0].original).toBe(1);
    expect(result[0].revised).toBe(2);
  });

  // Test 14: diffBytes offset tracking
  it('should return correct offset tracking for diffBytes', () => {
    const a = new Uint8Array([0xaa, 0xbb]);
    const b = new Uint8Array([0xaa, 0xcc, 0xdd]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(3);
    expect(result[0]).toEqual({
      type: 'equal',
      offset1: 0,
      offset2: 0,
      byte1: 0xaa,
      byte2: 0xaa,
    });
    expect(result[1]).toEqual({
      type: 'replace',
      offset1: 1,
      offset2: 1,
      byte1: 0xbb,
      byte2: 0xcc,
    });
    expect(result[2]).toEqual({
      type: 'insert',
      offset1: null,
      offset2: 2,
      byte1: null,
      byte2: 0xdd,
    });
  });

  // Test 15: diffInstructions with different opStr but same mnemonic
  it('should treat instructions with different opStr as different', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: 'rbx',
        size: 1,
        operands: [],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Test 16: diffInstructions with different bytes but same mnemonic and opStr
  it('should treat instructions with different bytes as different', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x01]),
        mnemonic: 'nop',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x02]),
        mnemonic: 'nop',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Test 17: diffInstructions with different mnemonic but same bytes and opStr
  it('should treat instructions with different mnemonics as different', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'jmp',
        opStr: 'rax',
        size: 1,
        operands: [],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Test 18: Myers Diff handling of long matches at end
  it('should correctly handle long match sequences at the end of the arrays', () => {
    const a = [1, 2, 3, 4, 5];
    const b = [1, 9, 3, 4, 5];
    const result = myersDiff(a, b, (x, y) => x === y);
    expect(result.length).toBe(5);
    expect(result[0].type).toBe('equal');
    expect(result[1].type).toBe('replace');
    expect(result[2].type).toBe('equal');
    expect(result[3].type).toBe('equal');
    expect(result[4].type).toBe('equal');
  });

  // Test 19: myersDiff with one element arrays being different
  it('should correctly identify a replace for single element arrays', () => {
    const result = myersDiff([1], [2], (x, y) => x === y);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Test 20: fastGreedyDiff lookahead logic
  it('should match using lookahead in fastGreedyDiff', () => {
    // Array sizes must be larger than maxSize to trigger fastGreedyDiff
    const a = [1, 2, 3, 4, 5];
    const b = [1, 9, 9, 2, 3, 4, 5];
    // Set maxSize limit to 2 to trigger fastGreedyDiff
    const result = myersDiff(a, b, (x, y) => x === y, 2);
    expect(result.length).toBeGreaterThan(0);
    // Should find the match at 2, 3, 4, 5
    expect(result.some((r) => r.type === 'equal' && r.original === 2)).toBe(
      true
    );
  });

  // Test 21: fastGreedyDiff matching delete lookahead
  it('should identify delete matches using lookahead in fastGreedyDiff', () => {
    const a = [1, 9, 9, 2, 3];
    const b = [1, 2, 3];
    const result = myersDiff(a, b, (x, y) => x === y, 2);
    expect(result.length).toBeGreaterThan(0);
    expect(result.some((r) => r.type === 'equal' && r.original === 2)).toBe(
      true
    );
  });

  // Test 22: Myers Diff backtracking with no matches
  it('should handle completely disjoint arrays with no matching elements', () => {
    const a = [1, 2];
    const b = [3, 4];
    const result = myersDiff(a, b, (x, y) => x === y);
    expect(result.length).toBe(3);
    expect(result[0].type).toBe('delete');
    expect(result[1].type).toBe('replace');
    expect(result[2].type).toBe('insert');
  });

  // Extra Test 23: Myers diff when max size is 0
  it('should handle max size limit 0 by using fastGreedyDiff immediately', () => {
    const a = [1, 2, 3];
    const b = [1, 4, 3];
    const result = myersDiff(a, b, (x, y) => x === y, 0);
    expect(result.length).toBeGreaterThan(0);
  });

  // Extra Test 24: diffBytes with single-byte different inputs
  it('should identify replace for single-byte different inputs in diffBytes', () => {
    const result = diffBytes(new Uint8Array([1]), new Uint8Array([2]));
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Extra Test 25: diffInstructions differing only by operands
  it('should identify replace when operands differ in diffInstructions', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'mov',
        opStr: 'rax, rbx',
        size: 3,
        operands: [{ type: 'reg', reg: 'rax' }],
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'mov',
        opStr: 'rax, rbx',
        size: 3,
        operands: [{ type: 'reg', reg: 'rcx' }],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Extra Test 26: myersDiff with custom equality function always true
  it('should treat all elements equal if equality function always returns true', () => {
    const a = [1, 2, 3];
    const b = [4, 5, 6];
    const result = myersDiff(a, b, () => true);
    expect(result.every((r) => r.type === 'equal')).toBe(true);
  });

  // Extra Test 27: myersDiff with custom equality function always false
  it('should have no equal elements if equality function always returns false', () => {
    const a = [1, 2];
    const b = [3, 4];
    const result = myersDiff(a, b, () => false);
    expect(result.some((r) => r.type === 'equal')).toBe(false);
  });

  // Extra Test 28: Myers diff trace limit exceeded parameter low
  it('should fallback when trace limit is low', () => {
    const a = [1, 2, 3, 4, 5, 6];
    const b = [1, 2, 8, 4, 5, 9];
    const result = myersDiff(a, b, (x, y) => x === y, 3);
    expect(result.length).toBeGreaterThan(0);
  });

  // Extra Test 29: fastGreedyDiff edge case near the end
  it('should handle matching near the end in fastGreedyDiff', () => {
    const a = [1, 2, 3, 4];
    const b = [1, 2, 3, 4, 5];
    const result = myersDiff(a, b, (x, y) => x === y, 2);
    expect(result.length).toBeGreaterThan(0);
    expect(result[result.length - 1].type).toBe('insert');
  });

  // Extra Test 30: postProcessDiff for consecutive inserts and deletes
  it('should merge consecutive deletes and inserts correctly', () => {
    const a = [1, 2];
    const b = [3, 4];
    const result = myersDiff(a, b, (x, y) => x === y);
    expect(result.some((r) => r.type === 'replace')).toBe(true);
  });

  // Extra Test 31: diffInstructions with empty input arrays
  it('should return empty array for empty inputs in diffInstructions', () => {
    const result = diffInstructions([], []);
    expect(result.length).toBe(0);
  });

  // Extra Test 32: diffBytes with large offset difference
  it('should track offsets correctly on insert at start', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([0, 1, 2]);
    const result = diffBytes(a, b);
    expect(result[0].type).toBe('insert');
    expect(result[0].offset2).toBe(0);
  });

  // Extra Test 33: diffBytes with single element difference
  it('should detect replace for single byte differences', () => {
    const a = new Uint8Array([0x55]);
    const b = new Uint8Array([0x90]);
    const result = diffBytes(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Extra Test 34: diffBytes with duplicate sequences
  it('should handle duplicate sequences correctly', () => {
    const a = new Uint8Array([0x90, 0x90, 0x90]);
    const b = new Uint8Array([0x90, 0x90, 0x90, 0x90]);
    const result = diffBytes(a, b);
    expect(result.filter((r) => r.type === 'insert').length).toBe(1);
  });

  // Extra Test 35: diffBytes with alternate insertions and deletions
  it('should handle alternating edits in byte diffing', () => {
    const a = new Uint8Array([1, 3, 5]);
    const b = new Uint8Array([2, 3, 6]);
    const result = diffBytes(a, b);
    expect(result.length).toBeGreaterThan(0);
  });

  // Extra Test 36: diffInstructions with differing sizes but same mnemonics
  it('should handle same mnemonic but different instruction size', () => {
    const a: Instruction[] = [
      { address: 0x1000, mnemonic: 'nop', opStr: '', size: 1 },
    ];
    const b: Instruction[] = [
      { address: 0x1000, mnemonic: 'nop', opStr: '', size: 2 },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('replace');
  });

  // Extra Test 37: diffInstructions when size is undefined
  it('should handle instruction size being undefined', () => {
    const a: Instruction[] = [{ address: 0x1000, mnemonic: 'nop', opStr: '' }];
    const b: Instruction[] = [{ address: 0x1000, mnemonic: 'nop', opStr: '' }];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('equal');
  });

  // Extra Test 38: myersDiff fallback triggered by size threshold limit
  it('should fall back to fastGreedyDiff when array exceeds maxSize', () => {
    const a = Array.from({ length: 15 }, (_, i) => i);
    const b = Array.from({ length: 15 }, (_, i) => i + 1);
    const result = myersDiff(a, b, (x, y) => x === y, 10);
    expect(result.length).toBeGreaterThan(0);
  });

  // Extra Test 39: myersDiff with maxSize explicitly set to 0
  it('should fall back immediately to fastGreedyDiff if maxSize is 0', () => {
    const a = [1, 2];
    const b = [1, 2];
    const result = myersDiff(a, b, (x, y) => x === y, 0);
    expect(result.length).toBe(2);
    expect(result.every((r) => r.type === 'equal')).toBe(true);
  });

  // Extra Test 40: diffInstructions with completely disjoint addresses
  it('should handle completely disjoint instruction addresses', () => {
    const a: Instruction[] = [{ address: 0x1000, mnemonic: 'nop', opStr: '' }];
    const b: Instruction[] = [{ address: 0x2000, mnemonic: 'nop', opStr: '' }];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('equal');
  });

  // Extra Test 41: diffInstructions where inst1 has null operands
  it('should handle null operands array in diffInstructions comparison', () => {
    const a: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'mov',
        opStr: 'rax, rbx',
        size: 3,
        operands: undefined,
      },
    ];
    const b: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'mov',
        opStr: 'rax, rbx',
        size: 3,
        operands: [],
      },
    ];
    const result = diffInstructions(a, b);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('equal');
  });

  // Extra Test 42: myersDiff where one list has length 1 and another has length 0
  it('should handle diff when one list is empty and the other has one item', () => {
    const a = [42];
    const b: number[] = [];
    const result = myersDiff(a, b, (x, y) => x === y);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe('delete');
  });
});
