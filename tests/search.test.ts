import { describe, it, expect } from 'vitest';
import {
  searchText,
  searchHex,
  searchInstructions,
  searchInstructionSequence,
  parseHexPattern,
} from '../src/analyzer/search.js';
import { Instruction } from '../src/disassembler/types.js';

describe('Binary Search and Pattern Matching Engine', () => {
  describe('Text Search', () => {
    const textBuffer = new TextEncoder().encode('Hello, world! This is a Test buffer with some patterns.');

    it('should find exact text string matches (UTF-8/ASCII)', () => {
      const results = searchText(textBuffer, 'world');
      expect(results).toHaveLength(1);
      expect(results[0].offset).toBe(7);
      expect(results[0].match).toBe('world');
    });

    it('should find multiple matches', () => {
      const buf = new TextEncoder().encode('aba aba abba');
      const results = searchText(buf, 'aba');
      expect(results).toHaveLength(2);
      expect(results[0].offset).toBe(0);
      expect(results[1].offset).toBe(4);
    });

    it('should handle case insensitivity correctly', () => {
      const results = searchText(textBuffer, 'test', { caseInsensitive: true });
      expect(results).toHaveLength(1);
      expect(results[0].offset).toBe(24);
      expect(results[0].match.toLowerCase()).toBe('test');

      const caseSensitive = searchText(textBuffer, 'test', { caseInsensitive: false });
      expect(caseSensitive).toHaveLength(0);
    });

    it('should support UTF-16LE encoding', () => {
      // Encode "WideString" in UTF-16LE
      const original = 'WideString';
      const wideBytes = new Uint8Array(original.length * 2);
      for (let i = 0; i < original.length; i++) {
        const code = original.charCodeAt(i);
        wideBytes[i * 2] = code & 0xff;
        wideBytes[i * 2 + 1] = (code >> 8) & 0xff;
      }

      // Prepend and append some dummy bytes
      const fullBuffer = new Uint8Array([0xaa, 0xbb, ...wideBytes, 0xcc]);
      const results = searchText(fullBuffer, 'WideString', { encoding: 'utf16le' });
      expect(results).toHaveLength(1);
      expect(results[0].offset).toBe(2);
      expect(results[0].match).toBe('WideString');
    });

    it('should return empty array for empty query', () => {
      expect(searchText(textBuffer, '')).toEqual([]);
    });
  });

  describe('Hex Pattern Search with Wildcards', () => {
    it('should parse hex pattern with wildcards correctly', () => {
      expect(parseHexPattern('48 8d ?? 55')).toEqual([0x48, 0x8d, null, 0x55]);
      expect(parseHexPattern('488d?55')).toEqual([0x48, 0x8d, null, 0x55]);
      expect(parseHexPattern('  FF   00  ??  aa ')).toEqual([0xff, 0x00, null, 0xaa]);
    });

    it('should throw error on invalid hex characters', () => {
      expect(() => parseHexPattern('48 8d gg 55')).toThrow();
    });

    it('should find exact hex pattern match', () => {
      const buffer = new Uint8Array([0x48, 0x8d, 0x05, 0x55, 0x66, 0x48, 0x8d, 0x0a, 0x55]);
      const results = searchHex(buffer, '48 8d 05 55');
      expect(results).toHaveLength(1);
      expect(results[0].offset).toBe(0);
      expect(results[0].bytes).toEqual(new Uint8Array([0x48, 0x8d, 0x05, 0x55]));
    });

    it('should find hex pattern matches with wildcards', () => {
      const buffer = new Uint8Array([0x48, 0x8d, 0x05, 0x55, 0x66, 0x48, 0x8d, 0x99, 0x55]);
      const results = searchHex(buffer, '48 8d ?? 55');
      expect(results).toHaveLength(2);
      expect(results[0].offset).toBe(0);
      expect(results[0].bytes).toEqual(new Uint8Array([0x48, 0x8d, 0x05, 0x55]));
      expect(results[1].offset).toBe(5);
      expect(results[1].bytes).toEqual(new Uint8Array([0x48, 0x8d, 0x99, 0x55]));
    });
  });

  describe('Instruction Search', () => {
    const dummyBytes = new Uint8Array(0);
    const instructions: Instruction[] = [
      { address: 0x1000, bytes: dummyBytes, mnemonic: 'push', opStr: 'rbp', operands: [], size: 1 },
      { address: 0x1001, bytes: dummyBytes, mnemonic: 'mov', opStr: 'rbp, rsp', operands: [], size: 3 },
      { address: 0x1004, bytes: dummyBytes, mnemonic: 'sub', opStr: 'rsp, 0x20', operands: [], size: 4 },
      { address: 0x1008, bytes: dummyBytes, mnemonic: 'mov', opStr: 'rax, [rbp - 0x8]', operands: [], size: 4 },
      { address: 0x100c, bytes: dummyBytes, mnemonic: 'add', opStr: 'rax, 1', operands: [], size: 3 },
      { address: 0x100f, bytes: dummyBytes, mnemonic: 'pop', opStr: 'rbp', operands: [], size: 1 },
      { address: 0x1010, bytes: dummyBytes, mnemonic: 'ret', opStr: '', operands: [], size: 1 },
    ];

    it('should find instruction by exact mnemonic', () => {
      const results = searchInstructions(instructions, { mnemonic: 'mov' });
      expect(results).toHaveLength(2);
      expect(results[0].index).toBe(1);
      expect(results[0].instruction.address).toBe(0x1001);
      expect(results[1].index).toBe(3);
      expect(results[1].instruction.address).toBe(0x1008);
    });

    it('should find instruction by regex mnemonic', () => {
      const results = searchInstructions(instructions, { mnemonic: /^p/ });
      expect(results).toHaveLength(2); // push, pop
      expect(results[0].instruction.mnemonic).toBe('push');
      expect(results[1].instruction.mnemonic).toBe('pop');
    });

    it('should find instruction by operand string', () => {
      const results = searchInstructions(instructions, { opStr: 'rsp' });
      expect(results).toHaveLength(2); // mov rbp, rsp and sub rsp, 0x20
      expect(results[0].instruction.mnemonic).toBe('mov');
      expect(results[1].instruction.mnemonic).toBe('sub');
    });

    it('should filter by address range', () => {
      const results = searchInstructions(instructions, {
        mnemonic: 'mov',
        addressRange: { min: 0x1002 },
      });
      expect(results).toHaveLength(1);
      expect(results[0].instruction.address).toBe(0x1008);
    });

    it('should use custom filter functions', () => {
      const results = searchInstructions(instructions, {
        filter: inst => inst.size === 1,
      });
      expect(results).toHaveLength(3); // push, pop, ret
      expect(results.map(r => r.instruction.mnemonic)).toEqual(['push', 'pop', 'ret']);
    });
  });

  describe('Instruction Sequence Search', () => {
    const dummyBytes = new Uint8Array(0);
    const instructions: Instruction[] = [
      { address: 0x1000, bytes: dummyBytes, mnemonic: 'push', opStr: 'rbp', operands: [], size: 1 },
      { address: 0x1001, bytes: dummyBytes, mnemonic: 'mov', opStr: 'rbp, rsp', operands: [], size: 3 },
      { address: 0x1004, bytes: dummyBytes, mnemonic: 'sub', opStr: 'rsp, 0x20', operands: [], size: 4 },
      { address: 0x1008, bytes: dummyBytes, mnemonic: 'mov', opStr: 'rax, [rbp - 0x8]', operands: [], size: 4 },
      { address: 0x100c, bytes: dummyBytes, mnemonic: 'push', opStr: 'rbp', operands: [], size: 1 },
      { address: 0x100d, bytes: dummyBytes, mnemonic: 'mov', opStr: 'rbp, rsp', operands: [], size: 3 },
      { address: 0x1010, bytes: dummyBytes, mnemonic: 'ret', opStr: '', operands: [], size: 1 },
    ];

    it('should find sequences of consecutive instructions', () => {
      // Look for function prologue: push followed by mov rbp, rsp
      const sequence = [
        { mnemonic: 'push' },
        { mnemonic: 'mov', opStr: 'rbp, rsp' },
      ];

      const results = searchInstructionSequence(instructions, sequence);
      expect(results).toHaveLength(2);
      expect(results[0].startIndex).toBe(0);
      expect(results[0].instructions[0].address).toBe(0x1000);
      expect(results[1].startIndex).toBe(4);
      expect(results[1].instructions[0].address).toBe(0x100c);
    });
  });
});
