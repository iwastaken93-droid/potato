import { describe, it, expect } from 'vitest';
import {
  Decompiler,
  BasicBlock,
  Instruction,
} from '../src/disassembler/decompiler.js';
import { ASTPrinter } from '../src/disassembler/astPrinter.js';

describe('Decompiler Core Analysis', () => {
  // Helper to construct basic blocks easily
  function createBlock(
    id: string,
    successors: string[],
    instructions: Instruction[] = []
  ): BasicBlock {
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
      createBlock(
        'Entry',
        [],
        [
          { address: 0x1000, op: 'MOV', args: ['eax', '[esi + 0]'] },
          { address: 0x1004, op: 'MOV', args: ['[esi + 4]', 'ebx'] },
          { address: 0x1008, op: 'MOV', args: ['[esi + 8]', '100'] },
          { address: 0x100c, op: 'RET', args: [] },
        ]
      ),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'test_func',
      ['esi', 'ebx'],
      blocks,
      'Entry'
    );

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
      createBlock(
        'Entry',
        [],
        [
          { address: 0x1000, op: 'MOV', args: ['eax', '[esi + edi * 4]'] },
          { address: 0x1004, op: 'MOV', args: ['[esi + ecx * 4]', 'ebx'] },
          { address: 0x1008, op: 'RET', args: [] },
        ]
      ),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'array_test',
      ['esi', 'edi', 'ecx', 'ebx'],
      blocks,
      'Entry'
    );

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
      createBlock(
        'Entry',
        ['Then', 'Else'],
        [
          { address: 0x1000, op: 'CMP', args: ['eax', '10'] },
          { address: 0x1004, op: 'JE', args: ['Then'] },
        ]
      ),
      createBlock(
        'Then',
        ['Merge'],
        [{ address: 0x1008, op: 'MOV', args: ['ebx', '1'] }]
      ),
      createBlock(
        'Else',
        ['Merge'],
        [{ address: 0x100c, op: 'MOV', args: ['ebx', '2'] }]
      ),
      createBlock('Merge', [], [{ address: 0x1010, op: 'RET', args: ['ebx'] }]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'branch_test',
      ['eax'],
      blocks,
      'Entry'
    );

    expect(decompiled.pseudocode).toContain('if (je(eax, 10))');
    expect(decompiled.pseudocode).toContain('ebx = 1');
    expect(decompiled.pseudocode).toContain('else');
    expect(decompiled.pseudocode).toContain('ebx = 2');
    expect(decompiled.pseudocode).toContain('return ebx');
  });

  it('should propagate variable types correctly', () => {
    // Trace type from constant to local stack variables, then through registers
    const blocks = [
      createBlock(
        'Entry',
        [],
        [
          { address: 0x1000, op: 'MOV', args: ['[ebp - 4]', '42'] }, // local_4 = int
          { address: 0x1004, op: 'MOV', args: ['eax', '[ebp - 4]'] }, // eax = int
          { address: 0x1008, op: 'RET', args: [] },
        ]
      ),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'type_prop_test',
      [],
      blocks,
      'Entry'
    );

    // Type of local_4 and eax should be int
    expect(decompiled.pseudocode).toContain('int local_4');
    expect(decompiled.pseudocode).toContain('int eax');
  });

  it('should decompile a while loop and a do-while loop correctly', () => {
    // While loop CFG:
    // Entry -> Header
    // Header -> Body (if condition true) or Exit (if condition false)
    // Body -> Latch
    // Latch -> Header
    // Exit -> End
    const blocks = [
      createBlock(
        'Entry',
        ['Header'],
        [{ address: 0x1000, op: 'MOV', args: ['eax', '10'] }]
      ),
      createBlock(
        'Header',
        ['Body', 'Exit'],
        [
          { address: 0x1004, op: 'CMP', args: ['eax', '0'] },
          { address: 0x1008, op: 'JLE', args: ['Exit'] },
        ]
      ),
      createBlock(
        'Body',
        ['Latch'],
        [{ address: 0x100c, op: 'SUB', args: ['eax', '1'] }]
      ),
      createBlock(
        'Latch',
        ['Header'],
        [{ address: 0x1010, op: 'JMP', args: ['Header'] }]
      ),
      createBlock('Exit', [], [{ address: 0x1014, op: 'RET', args: ['eax'] }]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile('while_test', [], blocks, 'Entry');

    expect(decompiled.pseudocode).toContain('while (jle(eax, 0))');
    expect(decompiled.pseudocode).toContain('sub(eax, 1)');
  });

  it('should structure nested branches and complex paths in structureBranch', () => {
    // Nested branch CFG:
    // Entry -> Then / Else
    // Then -> ThenLeft / ThenRight
    // ThenLeft -> Merge
    // ThenRight -> Merge
    // Else -> Merge
    // Merge -> Exit
    const blocks = [
      createBlock(
        'Entry',
        ['Then', 'Else'],
        [
          { address: 0x2000, op: 'CMP', args: ['eax', '5'] },
          { address: 0x2004, op: 'JG', args: ['Then'] },
        ]
      ),
      createBlock(
        'Then',
        ['ThenLeft', 'ThenRight'],
        [
          { address: 0x2008, op: 'CMP', args: ['ebx', '10'] },
          { address: 0x200c, op: 'JE', args: ['ThenLeft'] },
        ]
      ),
      createBlock(
        'ThenLeft',
        ['Merge'],
        [{ address: 0x2010, op: 'MOV', args: ['ecx', '1'] }]
      ),
      createBlock(
        'ThenRight',
        ['Merge'],
        [{ address: 0x2014, op: 'MOV', args: ['ecx', '2'] }]
      ),
      createBlock(
        'Else',
        ['Merge'],
        [{ address: 0x2018, op: 'MOV', args: ['ecx', '3'] }]
      ),
      createBlock('Merge', [], [{ address: 0x201c, op: 'RET', args: ['ecx'] }]),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'nested_branch_test',
      ['eax', 'ebx'],
      blocks,
      'Entry'
    );
    expect(decompiled.pseudocode).toContain('if (jg(eax, 5))');
    expect(decompiled.pseudocode).toContain('if (je(ebx, 10))');
  });

  it('should handle complex memory operands, constants, and default pointer formatting', () => {
    // Test complex addressing, default pointer fallback, empty operands, and type changes
    const blocks = [
      createBlock(
        'Entry',
        [],
        [
          // Base + Index * Scale + Offset
          { address: 0x3000, op: 'MOV', args: ['eax', '[esi + edi * 4 + 16]'] },
          // Fallback memory syntax: *( base + offset ) - using ADD so it doesn't propagate struct type
          { address: 0x3004, op: 'ADD', args: ['[edx + 8]', 'ebx'] },
          // Empty instruction args handling or unknown op
          { address: 0x3008, op: 'UNKNOWN_OP', args: [] },
          { address: 0x300c, op: 'RET', args: [] },
        ]
      ),
    ];

    const decompiler = new Decompiler();
    const decompiled = decompiler.decompile(
      'mem_test',
      ['esi', 'edi', 'edx', 'ebx'],
      blocks,
      'Entry'
    );

    // Check fallback syntax
    expect(decompiled.pseudocode).toContain('add(*( edx + 8 ), ebx)');
    expect(decompiled.pseudocode).toContain('unknown_op()');
  });

  it('should structure DoWhile loops, nested branches with sequential steps, nested merges, and branches with no successors', () => {
    // 1. Do-While Loop
    // Entry -> Header
    // Header -> Body
    // Body -> Latch
    // Latch -> Header (if JNE condition) or Exit
    const blocks1 = [
      createBlock('Entry', ['Header']),
      createBlock('Header', ['Body']),
      createBlock(
        'Body',
        ['Latch'],
        [{ address: 0x4000, op: 'MOV', args: ['eax', '1'] }]
      ),
      createBlock(
        'Latch',
        ['Header', 'Exit'],
        [
          { address: 0x4004, op: 'CMP', args: ['eax', '10'] },
          { address: 0x4008, op: 'JNE', args: ['Header'] },
        ]
      ),
      createBlock('Exit', [], [{ address: 0x400c, op: 'RET', args: [] }]),
    ];

    const decompiler = new Decompiler();
    const decompiled1 = decompiler.decompile(
      'dowhile_test',
      [],
      blocks1,
      'Entry'
    );
    expect(decompiled1.pseudocode).toContain('do {');
    expect(decompiled1.pseudocode).toContain('while (true);');

    // 2. Nested branches inside a branch that merges before the outer merge point,
    // sequential steps inside branches, and branches with no successors (RET)
    const blocks2 = [
      createBlock(
        'Entry',
        ['Then', 'Else'],
        [
          { address: 0x5000, op: 'CMP', args: ['eax', '1'] },
          { address: 0x5004, op: 'JE', args: ['Then'] },
        ]
      ),
      createBlock('Then', ['ThenSeq']),
      createBlock(
        'ThenSeq',
        ['ThenLeft', 'ThenRight'],
        [
          { address: 0x5008, op: 'CMP', args: ['ebx', '2'] },
          { address: 0x500c, op: 'JE', args: ['ThenLeft'] },
        ]
      ),
      createBlock(
        'ThenLeft',
        [],
        [
          { address: 0x5010, op: 'RET', args: ['1'] }, // 0 successors
        ]
      ),
      createBlock(
        'ThenRight',
        ['ThenMerge'],
        [{ address: 0x5014, op: 'MOV', args: ['ecx', '2'] }]
      ),
      createBlock('ThenMerge', ['ThenFinal']),
      createBlock(
        'ThenFinal',
        [],
        [
          { address: 0x5018, op: 'RET', args: ['ecx'] }, // 0 successors, making it end of branch
        ]
      ),
      createBlock(
        'Else',
        [],
        [
          { address: 0x501c, op: 'RET', args: ['0'] }, // 0 successors
        ]
      ),
    ];

    const decompiled2 = decompiler.decompile(
      'complex_branch_test',
      ['eax', 'ebx'],
      blocks2,
      'Entry'
    );
    expect(decompiled2.pseudocode).toContain('if (je(eax, 1))');
    expect(decompiled2.pseudocode).toContain('if (je(ebx, 2))');
  });

  it('should compute dominators and post-dominators correctly with unreachable nodes and complex CFG using CHK', () => {
    // Construct a complex CFG with loops, branches, merge nodes, and unreachable nodes:
    // Entry -> A -> B -> C -> D
    // A -> C
    // B -> B (self-loop)
    // Unreachable block: U1 -> U2
    const blocks = [
      createBlock('Entry', ['A']),
      createBlock('A', ['B', 'C']),
      createBlock('B', ['B', 'C']),
      createBlock('C', ['D']),
      createBlock('D', []),
      createBlock('U1', ['U2']),
      createBlock('U2', []),
    ];

    const blockMap = new Map<string, BasicBlock>();
    for (const b of blocks) {
      blockMap.set(b.id, b);
    }

    const decompiler = new Decompiler();
    const dominators: Map<string, Set<string>> = (
      decompiler as any
    ).computeDominators(blockMap, 'Entry');
    const postDominators: Map<string, Set<string>> = (
      decompiler as any
    ).computePostDominators(blockMap);

    expect(dominators).toBeDefined();
    expect(postDominators).toBeDefined();

    // Dominators assertions
    expect(dominators.get('Entry')).toEqual(new Set(['Entry']));
    expect(dominators.get('A')).toEqual(new Set(['Entry', 'A']));
    expect(dominators.get('B')).toEqual(new Set(['Entry', 'A', 'B']));
    expect(dominators.get('C')).toEqual(new Set(['Entry', 'A', 'C']));
    expect(dominators.get('D')).toEqual(new Set(['Entry', 'A', 'C', 'D']));

    // Post-dominators assertions
    expect(postDominators.get('Entry')?.has('A')).toBe(true);
    expect(postDominators.get('Entry')?.has('C')).toBe(true);
    expect(postDominators.get('Entry')?.has('D')).toBe(true);
    expect(postDominators.get('Entry')?.has('B')).toBe(false);

    expect(postDominators.get('A')?.has('C')).toBe(true);
    expect(postDominators.get('A')?.has('D')).toBe(true);
    expect(postDominators.get('A')?.has('B')).toBe(false);

    expect(postDominators.get('B')?.has('C')).toBe(true);
    expect(postDominators.get('B')?.has('D')).toBe(true);

    expect(postDominators.get('C')?.has('D')).toBe(true);
    expect(postDominators.get('D')).toEqual(new Set(['D']));
  });

  it('should format BinaryExpr and AssignExpr correctly using ASTPrinter visitor', () => {
    const printer = new ASTPrinter();

    // 1. BinaryExpr
    const binaryExpr = {
      type: 'Binary' as const,
      operator: '+',
      left: { type: 'Identifier' as const, name: 'eax' },
      right: { type: 'Constant' as const, value: '4' },
    };
    expect(printer.renderExpr(binaryExpr)).toBe('eax + 4');

    // 2. AssignExpr
    const assignExpr = {
      type: 'Assign' as const,
      left: { type: 'Identifier' as const, name: 'ebx' },
      right: binaryExpr,
    };
    expect(printer.renderExpr(assignExpr)).toBe('ebx = eax + 4');

    // 3. StatementNode
    const statementNode = {
      type: 'Statement' as const,
      expr: assignExpr,
    };
    expect(printer.render(statementNode)).toBe('ebx = eax + 4;');
  });

  describe('C++ Symbol Demangling Support in Decompiler', () => {
    it('should identify and demangle mangled call targets and annotate imports', () => {
      const blocks = [
        createBlock(
          'Entry',
          [],
          [
            { address: 0x1000, op: 'CALL', args: ['_Z3foov'] },
            { address: 0x1004, op: 'CALL', args: ['?add@Math@@YAHHH@Z'] },
            { address: 0x1008, op: 'CALL', args: ['__imp__ZN3foo3bar3bazEib'] },
            { address: 0x100c, op: 'RET', args: [] },
          ]
        ),
      ];

      const decompiler = new Decompiler();
      const decompiled = decompiler.decompile(
        '_ZN3foo6helperEPiRKc',
        [],
        blocks,
        'Entry'
      );

      // Verify the decompiled function name itself is demangled
      expect(decompiled.pseudocode).toContain('function foo::helper(');

      // Verify the annotations inside pseudocode
      expect(decompiled.pseudocode).toContain('// Decompiled Imports:');
      expect(decompiled.pseudocode).toContain('// - foo() (mangled: _Z3foov)');
      expect(decompiled.pseudocode).toContain('// - int Math::add(int, int) (mangled: ?add@Math@@YAHHH@Z)');
      expect(decompiled.pseudocode).toContain('// - foo::bar::baz(int, bool) (mangled: __imp__ZN3foo3bar3bazEib)');

      // Verify the call arguments in instructions are demangled in-place
      expect(decompiled.pseudocode).toContain('call(foo);');
      expect(decompiled.pseudocode).toContain('call(Math::add);');
      expect(decompiled.pseudocode).toContain('call(foo::bar::baz);');

      // Verify returned imports array
      expect(decompiled.imports).toBeDefined();
      expect(decompiled.imports).toContain('foo() (mangled: _Z3foov)');
      expect(decompiled.imports).toContain('int Math::add(int, int) (mangled: ?add@Math@@YAHHH@Z)');
      expect(decompiled.imports).toContain('foo::bar::baz(int, bool) (mangled: __imp__ZN3foo3bar3bazEib)');
    });
  });
});
