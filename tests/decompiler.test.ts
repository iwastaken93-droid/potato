import { describe, it, expect } from 'vitest';
import { Decompiler, BasicBlock, Instruction } from '../src/disassembler/decompiler.js';

describe('Decompiler Core Analysis', () => {
  // Helper to construct basic blocks easily
  function createBlock(id: string, successors: string[], instructions: Instruction[] = []): BasicBlock {
    return {
      id,
      instructions,
      successors,
    };
  }

  it('should compute dominator tree correctly on a simple DAG with branches and merges', () => {
    // A simple CFG:
    //      A
    //     / \
    //    B   C
    //     \ /
    //      D
    //      |
    //      E
    const blocks = [
      createBlock('A', ['B', 'C']),
      createBlock('B', ['D']),
      createBlock('C', ['D']),
      createBlock('D', ['E']),
      createBlock('E', []),
    ];

    const blockMap = new Map<string, BasicBlock>();
    for (const b of blocks) {
      blockMap.set(b.id, b);
    }

    const decompiler = new Decompiler();
    // Accessing private method computeDominators
    const dominators: Map<string, Set<string>> = (
      decompiler as any
    ).computeDominators(blockMap, 'A');

    expect(dominators).toBeDefined();

    // Check dominator set sizes and contents
    expect(dominators.get('A')).toEqual(new Set(['A']));
    expect(dominators.get('B')).toEqual(new Set(['A', 'B']));
    expect(dominators.get('C')).toEqual(new Set(['A', 'C']));
    expect(dominators.get('D')).toEqual(new Set(['A', 'D']));
    expect(dominators.get('E')).toEqual(new Set(['A', 'D', 'E']));
  });

  it('should identify natural loops and loop bodies correctly', () => {
    // A CFG with a loop:
    //      Entry
    //        |
    //      Header <--- Latch
    //       /  \        |
    //    Body  Exit     |
    //      \____________|
    const blocks = [
      createBlock('Entry', ['Header']),
      createBlock('Header', ['Body', 'Exit']),
      createBlock('Body', ['Latch']),
      createBlock('Latch', ['Header']),
      createBlock('Exit', []),
    ];

    const blockMap = new Map<string, BasicBlock>();
    for (const b of blocks) {
      blockMap.set(b.id, b);
    }

    const decompiler = new Decompiler();
    const dominators: Map<string, Set<string>> = (
      decompiler as any
    ).computeDominators(blockMap, 'Entry');
    const loops = (decompiler as any).identifyLoops(
      blockMap,
      'Entry',
      dominators
    );

    expect(loops).toBeDefined();
    expect(loops.has('Header')).toBe(true);

    const loopInfo = loops.get('Header');
    expect(loopInfo).toBeDefined();
    expect(loopInfo.header).toBe('Header');
    expect(loopInfo.latch).toBe('Latch');
    expect(loopInfo.body).toEqual(new Set(['Header', 'Body', 'Latch']));
    expect(loopInfo.body.has('Entry')).toBe(false);
    expect(loopInfo.body.has('Exit')).toBe(false);
  });

  it('should reconstruct a struct correctly from field accesses', () => {
    // Struct pointer is in ESI. Field 0, 4, 8 are accessed.
    const blocks = [
      createBlock('Entry', [], [
        { address: 0x1000, op: 'MOV', args: ['eax', '[esi + 0]'] },
        { address: 0x1004, op: 'MOV', args: ['[esi + 4]', 'ebx'] },
        { address: 0x1008, op: 'MOV', args: ['[esi + 8]', '100'] },
        { address: 0x100c, op: 'RET', args: [] },
      ]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile('test_func', ['esi', 'ebx'], blocks, 'Entry');

    expect(decompiled.structs).toBeDefined();
    expect(decompiled.structs!.length).toBe(1);
    expect(decompiled.structs![0]).toContain('struct struct_1');
    expect(decompiled.structs![0]).toContain('int field_0');
    expect(decompiled.structs![0]).toContain('int field_4');
    expect(decompiled.structs![0]).toContain('int field_8');

    expect(decompiled.pseudocode).toContain('eax = esi->field_0');
    expect(decompiled.pseudocode).toContain('esi->field_4 = ebx');
    expect(decompiled.pseudocode).toContain('esi->field_8 = 100');
  });

  it('should reconstruct an array access pattern correctly', () => {
    // Array access using index register
    const blocks = [
      createBlock('Entry', [], [
        { address: 0x1000, op: 'MOV', args: ['eax', '[esi + edi * 4]'] },
        { address: 0x1004, op: 'MOV', args: ['[esi + ecx * 4]', 'ebx'] },
        { address: 0x1008, op: 'RET', args: [] },
      ]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile('array_test', ['esi', 'edi', 'ecx', 'ebx'], blocks, 'Entry');

    expect(decompiled.pseudocode).toContain('eax = esi[edi]');
    expect(decompiled.pseudocode).toContain('esi[ecx] = ebx');
  });

  it('should compute post-dominators and structure if-else control flow correctly', () => {
    // Structure nested control flow:
    //      Entry
    //     /     \
    //  Then     Else
    //    \       /
    //      Merge
    const blocks = [
      createBlock('Entry', ['Then', 'Else'], [
        { address: 0x1000, op: 'CMP', args: ['eax', '10'] },
        { address: 0x1004, op: 'JE', args: ['Then'] },
      ]),
      createBlock('Then', ['Merge'], [
        { address: 0x1008, op: 'MOV', args: ['ebx', '1'] },
      ]),
      createBlock('Else', ['Merge'], [
        { address: 0x100c, op: 'MOV', args: ['ebx', '2'] },
      ]),
      createBlock('Merge', [], [
        { address: 0x1010, op: 'RET', args: ['ebx'] },
      ]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile('branch_test', ['eax'], blocks, 'Entry');

    expect(decompiled.pseudocode).toContain('if (je(eax, 10))');
    expect(decompiled.pseudocode).toContain('ebx = 1');
    expect(decompiled.pseudocode).toContain('else');
    expect(decompiled.pseudocode).toContain('ebx = 2');
    expect(decompiled.pseudocode).toContain('return ebx');
  });

  it('should propagate variable types correctly', () => {
    // Trace type from constant to local stack variables, then through registers
    const blocks = [
      createBlock('Entry', [], [
        { address: 0x1000, op: 'MOV', args: ['[ebp - 4]', '42'] }, // local_4 = int
        { address: 0x1004, op: 'MOV', args: ['eax', '[ebp - 4]'] }, // eax = int
        { address: 0x1008, op: 'RET', args: [] },
      ]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile('type_prop_test', [], blocks, 'Entry');

    // Type of local_4 and eax should be int
    expect(decompiled.pseudocode).toContain('int local_4');
    expect(decompiled.pseudocode).toContain('int eax');
  });
});
