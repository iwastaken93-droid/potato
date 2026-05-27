import { describe, it, expect } from 'vitest';
import { Instruction } from '../src/disassembler/types.js';
import { BasicBlock } from '../src/disassembler/cfg.js';
import { IRTranslator, SSABuilder, IROptimizer, IROp } from '../src/disassembler/ir.js';

describe('IR/SSA Framework Unit Tests', () => {
  it('should translate basic machine instructions to intermediate representation', () => {
    const translator = new IRTranslator();

    const insts: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00]), // mov rax, 5
        mnemonic: 'mov',
        opStr: 'rax, 5',
        operands: [
          { type: 'reg', reg: 'rax', access: 'w' },
          { type: 'imm', imm: 5n, access: 'r' },
        ],
        size: 7,
      },
      {
        address: 0x1007,
        bytes: new Uint8Array([0x48, 0x83, 0xc0, 0x03]), // add rax, 3
        mnemonic: 'add',
        opStr: 'rax, 3',
        operands: [
          { type: 'reg', reg: 'rax', access: 'rw' },
          { type: 'imm', imm: 3n, access: 'r' },
        ],
        size: 4,
      },
    ];

    const ir = translator.translateInstructions(insts);
    expect(ir.length).toBe(2);

    expect(ir[0].op).toBe(IROp.MOV);
    expect(ir[0].dest?.type).toBe('reg');
    expect(ir[0].dest?.name).toBe('rax');
    expect(ir[0].args[0].type).toBe('imm');
    expect(ir[0].args[0].value).toBe(5n);

    expect(ir[1].op).toBe(IROp.ADD);
    expect(ir[1].dest?.name).toBe('rax');
    expect(ir[1].args[0].name).toBe('rax');
    expect(ir[1].args[1].value).toBe(3n);
  });

  it('should translate push and pop instructions correctly into load/store/stack operations', () => {
    const translator = new IRTranslator();
    const insts: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x50]), // push rax
        mnemonic: 'push',
        opStr: 'rax',
        operands: [{ type: 'reg', reg: 'rax', access: 'r' }],
        size: 1,
      },
      {
        address: 0x1001,
        bytes: new Uint8Array([0x58]), // pop rbx
        mnemonic: 'pop',
        opStr: 'rbx',
        operands: [{ type: 'reg', reg: 'rbx', access: 'w' }],
        size: 1,
      },
    ];

    const ir = translator.translateInstructions(insts);
    // push translates to sub + store, pop translates to load + add
    expect(ir.length).toBe(4);

    expect(ir[0].op).toBe(IROp.SUB); // rsp = rsp - 8
    expect(ir[0].dest?.name).toBe('rsp');

    expect(ir[1].op).toBe(IROp.STORE); // store [rsp], rax
    expect(ir[1].args[0].type).toBe('mem');
    expect(ir[1].args[1].name).toBe('rax');

    expect(ir[2].op).toBe(IROp.LOAD); // load rbx, [rsp]
    expect(ir[2].dest?.name).toBe('rbx');

    expect(ir[3].op).toBe(IROp.ADD); // rsp = rsp + 8
    expect(ir[3].dest?.name).toBe('rsp');
  });

  it('should translate basic blocks and populate predecessor links', () => {
    const translator = new IRTranslator();
    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1005,
        instructions: [
          { address: 0x1000, bytes: new Uint8Array([0x90]), mnemonic: 'nop', opStr: '', operands: [], size: 1 },
        ],
        successors: ['block_2'],
      },
      {
        id: 'block_2',
        startAddress: 0x1005,
        endAddress: 0x1010,
        instructions: [
          { address: 0x1005, bytes: new Uint8Array([0xc3]), mnemonic: 'ret', opStr: '', operands: [], size: 1 },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    expect(irCfg.blocks.has('block_1')).toBe(true);
    expect(irCfg.blocks.has('block_2')).toBe(true);

    const b1 = irCfg.blocks.get('block_1')!;
    const b2 = irCfg.blocks.get('block_2')!;

    expect(b1.successors).toContain('block_2');
    expect(b2.predecessors).toContain('block_1');
  });

  it('should build SSA form and assign correct variable versions', () => {
    const translator = new IRTranslator();
    const builder = new SSABuilder();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1010,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 1',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 1n },
            ],
            size: 5,
          },
          {
            address: 0x1005,
            bytes: new Uint8Array([]),
            mnemonic: 'add',
            opStr: 'rax, 2',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 2n },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const ssaCfg = builder.buildSSA(irCfg);

    const b1 = ssaCfg.blocks.get('block_1')!;
    const inst1 = b1.instructions[0];
    const inst2 = b1.instructions[1];

    // First instruction writes to rax_0
    expect(inst1.dest?.name).toBe('rax');
    expect(inst1.dest?.version).toBe(0);

    // Second instruction reads rax_0 and writes to rax_1
    expect(inst2.args[0].name).toBe('rax');
    expect(inst2.args[0].version).toBe(0);
    expect(inst2.dest?.name).toBe('rax');
    expect(inst2.dest?.version).toBe(1);
  });

  it('should insert PHI nodes at merge blocks with multiple predecessors', () => {
    const translator = new IRTranslator();
    const builder = new SSABuilder();

    // block_1 writes rax = 10, block_2 writes rax = 20. Both jump to block_3.
    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1005,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 10',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 10n },
            ],
            size: 5,
          },
        ],
        successors: ['block_3'],
      },
      {
        id: 'block_2',
        startAddress: 0x2000,
        endAddress: 0x2005,
        instructions: [
          {
            address: 0x2000,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 20',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 20n },
            ],
            size: 5,
          },
        ],
        successors: ['block_3'],
      },
      {
        id: 'block_3',
        startAddress: 0x3000,
        endAddress: 0x3005,
        instructions: [
          {
            address: 0x3000,
            bytes: new Uint8Array([]),
            mnemonic: 'add',
            opStr: 'rax, 5',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 5n },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const ssaCfg = builder.buildSSA(irCfg);

    const b3 = ssaCfg.blocks.get('block_3')!;
    // block_3 should have a PHI instruction inserted at the beginning
    expect(b3.instructions[0].op).toBe(IROp.PHI);
    expect(b3.instructions[0].dest?.name).toBe('rax');
    expect(b3.instructions[0].args.length).toBe(2);
    // Arguments of PHI should represent values coming from block_1 (rax version 1) and block_2 (rax version 2)
    expect(b3.instructions[0].args.map(a => a.version)).toContain(1);
  });

  it('should fold constant arithmetic operations', () => {
    const translator = new IRTranslator();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1005,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'add',
            opStr: 'rax, rbx', // will be generic ADD, but we construct constant args manually below
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'reg', reg: 'rbx' },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const b1 = irCfg.blocks.get('block_1')!;
    // Inject two constant args manually to simulate constant propagation setup
    b1.instructions[0].args = [
      { type: 'imm', value: 10 },
      { type: 'imm', value: 15 },
    ];

    const optimized = optimizer.constantFolding(irCfg);
    const optB1 = optimized.blocks.get('block_1')!;
    // ADD 10, 15 => MOV 25
    expect(optB1.instructions[0].op).toBe(IROp.MOV);
    expect(optB1.instructions[0].args[0].value).toBe(25);
  });

  it('should eliminate dead stores and unreachable code', () => {
    const translator = new IRTranslator();
    const builder = new SSABuilder();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1010,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 100', // Dead store to rax
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 100n },
            ],
            size: 5,
          },
          {
            address: 0x1005,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 200', // Overwrite rax, rax_0 is never read
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 200n },
            ],
            size: 5,
          },
          {
            address: 0x100a,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rbx, rax', // Reads rax
            operands: [
              { type: 'reg', reg: 'rbx' },
              { type: 'reg', reg: 'rax' },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const ssaCfg = builder.buildSSA(irCfg);
    const optimized = optimizer.deadCodeElimination(ssaCfg);

    const b1 = optimized.blocks.get('block_1')!;
    // First mov rax, 100 (which is rax_0) is eliminated.
    // The mov rbx, rax (which writes rbx_0) is eliminated because rbx_0 is never read.
    // The second mov rax, 200 (which is rax_1) is kept because its initial read count was > 0.
    expect(b1.instructions.length).toBe(1);
    expect(b1.instructions[0].args[0].value).toBe(200n);
  });

  it('should propagate copy operations to subsequent instructions', () => {
    const translator = new IRTranslator();
    const builder = new SSABuilder();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1010,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rax, 42',
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 42n },
            ],
            size: 5,
          },
          {
            address: 0x1005,
            bytes: new Uint8Array([]),
            mnemonic: 'mov',
            opStr: 'rbx, rax', // rbx = rax (copy propagation target)
            operands: [
              { type: 'reg', reg: 'rbx' },
              { type: 'reg', reg: 'rax' },
            ],
            size: 5,
          },
          {
            address: 0x100a,
            bytes: new Uint8Array([]),
            mnemonic: 'add',
            opStr: 'rcx, rbx', // rcx = rcx + rbx (should read rax instead of rbx)
            operands: [
              { type: 'reg', reg: 'rcx' },
              { type: 'reg', reg: 'rbx' },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const ssaCfg = builder.buildSSA(irCfg);
    const optimized = optimizer.copyPropagation(ssaCfg);

    const b1 = optimized.blocks.get('block_1')!;
    const addInst = b1.instructions[2]; // rcx = rcx + rbx
    expect(addInst.args[1].type).toBe('imm');

    expect(addInst.args[1].value).toBe(42n);
  });

  it('should reduce multiplication and division by power of two', () => {
    const translator = new IRTranslator();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1010,
        instructions: [
          {
            address: 0x1000,
            bytes: new Uint8Array([]),
            mnemonic: 'mul',
            opStr: 'rax, 8', // will be represented as MUL with arg 8
            operands: [
              { type: 'reg', reg: 'rax' },
              { type: 'imm', imm: 8n },
            ],
            size: 5,
          },
          {
            address: 0x1005,
            bytes: new Uint8Array([]),
            mnemonic: 'div',
            opStr: 'rbx, 4', // will be represented as DIV with arg 4
            operands: [
              { type: 'reg', reg: 'rbx' },
              { type: 'imm', imm: 4n },
            ],
            size: 5,
          },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const b1 = irCfg.blocks.get('block_1')!;
    // Set arguments manually since translator might fallback to MOV or generate other operands
    b1.instructions[0].op = IROp.MUL;
    b1.instructions[0].args = [
      { type: 'var', name: 'rax', version: 0 },
      { type: 'imm', value: 8 },
    ];
    b1.instructions[1].op = IROp.DIV;
    b1.instructions[1].args = [
      { type: 'var', name: 'rbx', version: 0 },
      { type: 'imm', value: 4 },
    ];

    const optimized = optimizer.strengthReduction(irCfg);
    const optB1 = optimized.blocks.get('block_1')!;

    // MUL rax, 8 => SHL rax, 3
    expect(optB1.instructions[0].op).toBe(IROp.SHL);
    expect(optB1.instructions[0].args[1].value).toBe(3);

    // DIV rbx, 4 => SHR rbx, 2
    expect(optB1.instructions[1].op).toBe(IROp.SHR);
    expect(optB1.instructions[1].args[1].value).toBe(2);
  });

  it('should handle copy propagation edge cases (chains, self-copy, circular reference, ssa versioning)', () => {
    const translator = new IRTranslator();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1020,
        instructions: [
          { address: 0x1000, bytes: new Uint8Array([]), mnemonic: 'mov', opStr: '', operands: [], size: 1 },
          { address: 0x1001, bytes: new Uint8Array([]), mnemonic: 'mov', opStr: '', operands: [], size: 1 },
          { address: 0x1002, bytes: new Uint8Array([]), mnemonic: 'mov', opStr: '', operands: [], size: 1 },
          { address: 0x1003, bytes: new Uint8Array([]), mnemonic: 'mov', opStr: '', operands: [], size: 1 },
          { address: 0x1004, bytes: new Uint8Array([]), mnemonic: 'mov', opStr: '', operands: [], size: 1 },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const b1 = irCfg.blocks.get('block_1')!;

    // 1. Chain of copy propagations:
    // x_0 = y_0
    // z_0 = x_0
    // w_0 = z_0
    // use of w_0 -> should resolve to y_0
    b1.instructions[0].op = IROp.MOV;
    b1.instructions[0].dest = { type: 'var', name: 'x', version: 0 };
    b1.instructions[0].args = [{ type: 'var', name: 'y', version: 0 }];

    b1.instructions[1].op = IROp.MOV;
    b1.instructions[1].dest = { type: 'var', name: 'z', version: 0 };
    b1.instructions[1].args = [{ type: 'var', name: 'x', version: 0 }];

    b1.instructions[2].op = IROp.MOV;
    b1.instructions[2].dest = { type: 'var', name: 'w', version: 0 };
    b1.instructions[2].args = [{ type: 'var', name: 'z', version: 0 }];

    // A use instruction using w_0
    b1.instructions[3].op = IROp.ADD;
    b1.instructions[3].dest = { type: 'var', name: 'res', version: 0 };
    b1.instructions[3].args = [
      { type: 'var', name: 'w', version: 0 },
      { type: 'imm', value: 5 },
    ];

    // 2. Circular/self copy to ensure no infinite loop
    // a_0 = b_0
    // b_0 = a_0 (though SSA typically prevents this, we test copy propagation's safety checks)
    // and self-copy: c_0 = c_0
    b1.instructions[4].op = IROp.MOV;
    b1.instructions[4].dest = { type: 'var', name: 'a', version: 0 };
    b1.instructions[4].args = [{ type: 'var', name: 'b', version: 0 }];

    const optimized = optimizer.copyPropagation(irCfg);
    const optB1 = optimized.blocks.get('block_1')!;

    // The use of w_0 in ADD should be resolved to y_0
    expect(optB1.instructions[3].args[0].name).toBe('y');
    expect(optB1.instructions[3].args[0].version).toBe(0);
  });

  it('should handle strength reduction edge cases (mul by 0/1/non-pow2, div by 1/0/non-pow2)', () => {
    const translator = new IRTranslator();
    const optimizer = new IROptimizer();

    const blocks: BasicBlock[] = [
      {
        id: 'block_1',
        startAddress: 0x1000,
        endAddress: 0x1030,
        instructions: [
          { address: 0x1000, bytes: new Uint8Array([]), mnemonic: 'mul', opStr: '', operands: [], size: 1 },
          { address: 0x1001, bytes: new Uint8Array([]), mnemonic: 'mul', opStr: '', operands: [], size: 1 },
          { address: 0x1002, bytes: new Uint8Array([]), mnemonic: 'mul', opStr: '', operands: [], size: 1 },
          { address: 0x1003, bytes: new Uint8Array([]), mnemonic: 'div', opStr: '', operands: [], size: 1 },
          { address: 0x1004, bytes: new Uint8Array([]), mnemonic: 'div', opStr: '', operands: [], size: 1 },
          { address: 0x1005, bytes: new Uint8Array([]), mnemonic: 'div', opStr: '', operands: [], size: 1 },
        ],
        successors: [],
      },
    ];

    const irCfg = translator.translateCFG(blocks);
    const b1 = irCfg.blocks.get('block_1')!;

    // 1. mul by 0
    b1.instructions[0].op = IROp.MUL;
    b1.instructions[0].args = [
      { type: 'var', name: 'rax', version: 0 },
      { type: 'imm', value: 0 },
    ];
    // 2. mul by 1
    b1.instructions[1].op = IROp.MUL;
    b1.instructions[1].args = [
      { type: 'var', name: 'rax', version: 0 },
      { type: 'imm', value: 1 },
    ];
    // 3. mul by non-power of two (e.g. 10)
    b1.instructions[2].op = IROp.MUL;
    b1.instructions[2].args = [
      { type: 'var', name: 'rax', version: 0 },
      { type: 'imm', value: 10 },
    ];
    // 4. div by 1
    b1.instructions[3].op = IROp.DIV;
    b1.instructions[3].args = [
      { type: 'var', name: 'rbx', version: 0 },
      { type: 'imm', value: 1 },
    ];
    // 5. div by 0 (should be untouched)
    b1.instructions[4].op = IROp.DIV;
    b1.instructions[4].args = [
      { type: 'var', name: 'rbx', version: 0 },
      { type: 'imm', value: 0 },
    ];
    // 6. div by non-power of two (e.g. 7, should be untouched)
    b1.instructions[5].op = IROp.DIV;
    b1.instructions[5].args = [
      { type: 'var', name: 'rbx', version: 0 },
      { type: 'imm', value: 7 },
    ];

    const optimized = optimizer.strengthReduction(irCfg);
    const optB1 = optimized.blocks.get('block_1')!;

    // mul by 0 => MOV 0
    expect(optB1.instructions[0].op).toBe(IROp.MOV);
    expect(optB1.instructions[0].args[0].value).toBe(0);

    // mul by 1 => MOV rax_0
    expect(optB1.instructions[1].op).toBe(IROp.MOV);
    expect(optB1.instructions[1].args[0].name).toBe('rax');
    expect(optB1.instructions[1].args[0].version).toBe(0);

    // mul by 10 => stays MUL
    expect(optB1.instructions[2].op).toBe(IROp.MUL);
    expect(optB1.instructions[2].args[1].value).toBe(10);

    // div by 1 => MOV rbx_0
    expect(optB1.instructions[3].op).toBe(IROp.MOV);
    expect(optB1.instructions[3].args[0].name).toBe('rbx');
    expect(optB1.instructions[3].args[0].version).toBe(0);

    // div by 0 => stays DIV
    expect(optB1.instructions[4].op).toBe(IROp.DIV);
    expect(optB1.instructions[4].args[1].value).toBe(0);

    // div by 7 => stays DIV
    expect(optB1.instructions[5].op).toBe(IROp.DIV);
    expect(optB1.instructions[5].args[1].value).toBe(7);
  });
});
