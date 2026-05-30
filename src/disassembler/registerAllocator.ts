import { IROp, IROperand, IRInstruction, IRBlock, IRCFG } from './ir.js';

/**
 * Register Allocator using liveness-based graph coloring.
 * Maps SSA versioned variables to physical registers.
 */
export class RegisterAllocator {
  /**
   * Allocates registers for a given IR CFG.
   *
   * @param cfg The IR Control Flow Graph in SSA form.
   * @param availableRegs List of available physical registers.
   * @returns A map from SSA variable identifier (e.g., "rax_0") to physical register name or stack slot.
   */
  public allocate(cfg: IRCFG, availableRegs: string[]): Map<string, string> {
    const vars = new Set<string>();

    // Step 1: Collect all SSA variables
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (
          inst.dest &&
          inst.dest.type === 'var' &&
          inst.dest.name &&
          inst.dest.version !== undefined
        ) {
          vars.add(`${inst.dest.name}_${inst.dest.version}`);
        }
        for (const arg of inst.args) {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            vars.add(`${arg.name}_${arg.version}`);
          }
        }
      }
    }

    // Step 2: Compute def and use sets for each basic block
    const defs = new Map<string, Set<string>>();
    const uses = new Map<string, Set<string>>();

    for (const block of cfg.blocks.values()) {
      const blockDefs = new Set<string>();
      const blockUses = new Set<string>();

      for (const inst of block.instructions) {
        if (inst.op !== IROp.PHI) {
          // Read arguments (uses) before definition in the same instruction
          for (const arg of inst.args) {
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              const varId = `${arg.name}_${arg.version}`;
              if (!blockDefs.has(varId)) {
                blockUses.add(varId);
              }
            }
          }
        }

        if (
          inst.dest &&
          inst.dest.type === 'var' &&
          inst.dest.name &&
          inst.dest.version !== undefined
        ) {
          const varId = `${inst.dest.name}_${inst.dest.version}`;
          blockDefs.add(varId);
        }
      }

      defs.set(block.id, blockDefs);
      uses.set(block.id, blockUses);
    }

    // Step 3: Iterative liveness analysis
    const liveIn = new Map<string, Set<string>>();
    const liveOut = new Map<string, Set<string>>();

    for (const id of cfg.blocks.keys()) {
      liveIn.set(id, new Set<string>());
      liveOut.set(id, new Set<string>());
    }

    let changed = true;
    while (changed) {
      changed = false;
      for (const block of cfg.blocks.values()) {
        const currentLiveOut = liveOut.get(block.id)!;
        const newLiveOut = new Set<string>();

        // liveOut = union of liveIn of successors
        for (const succId of block.successors) {
          const succIn = liveIn.get(succId);
          if (succIn) {
            for (const v of succIn) {
              newLiveOut.add(v);
            }
          }

          // Handle PHI uses from successors
          const succBlock = cfg.blocks.get(succId);
          if (succBlock) {
            const predIndex = succBlock.predecessors.indexOf(block.id);
            if (predIndex !== -1) {
              for (const inst of succBlock.instructions) {
                if (inst.op === IROp.PHI && inst.args[predIndex]) {
                  const arg = inst.args[predIndex];
                  if (
                    arg.type === 'var' &&
                    arg.name &&
                    arg.version !== undefined
                  ) {
                    newLiveOut.add(`${arg.name}_${arg.version}`);
                  }
                }
              }
            }
          }
        }

        if (
          newLiveOut.size !== currentLiveOut.size ||
          Array.from(newLiveOut).some((v) => !currentLiveOut.has(v))
        ) {
          liveOut.set(block.id, newLiveOut);
          changed = true;
        }

        // liveIn = use union (liveOut - def)
        const blockUses = uses.get(block.id) || new Set();
        const blockDefs = defs.get(block.id) || new Set();
        const newLiveIn = new Set<string>(blockUses);
        for (const v of newLiveOut) {
          if (!blockDefs.has(v)) {
            newLiveIn.add(v);
          }
        }

        const currentLiveIn = liveIn.get(block.id)!;
        if (
          newLiveIn.size !== currentLiveIn.size ||
          Array.from(newLiveIn).some((v) => !currentLiveIn.has(v))
        ) {
          liveIn.set(block.id, newLiveIn);
          changed = true;
        }
      }
    }

    // Step 4: Build Interference Graph
    const interference = new Map<string, Set<string>>();
    for (const v of vars) {
      interference.set(v, new Set<string>());
    }

    const addInterference = (v1: string, v2: string) => {
      if (v1 === v2) return;
      interference.get(v1)?.add(v2);
      interference.get(v2)?.add(v1);
    };

    for (const block of cfg.blocks.values()) {
      const currentLive = new Set<string>(liveOut.get(block.id) || []);

      for (let i = block.instructions.length - 1; i >= 0; i--) {
        const inst = block.instructions[i];

        if (
          inst.dest &&
          inst.dest.type === 'var' &&
          inst.dest.name &&
          inst.dest.version !== undefined
        ) {
          const destVar = `${inst.dest.name}_${inst.dest.version}`;

          for (const v of currentLive) {
            addInterference(destVar, v);
          }

          currentLive.delete(destVar);
        }

        if (inst.op !== IROp.PHI) {
          for (const arg of inst.args) {
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              currentLive.add(`${arg.name}_${arg.version}`);
            }
          }
        }
      }
    }

    // Step 5: Color Graph (greedy allocation with spill stack slotting)
    const allocation = new Map<string, string>();
    const sortedVars = Array.from(vars).sort((a, b) => {
      const degA = interference.get(a)?.size ?? 0;
      const degB = interference.get(b)?.size ?? 0;
      return degB - degA;
    });

    for (const v of sortedVars) {
      const neighbors = interference.get(v) || new Set();
      const usedRegs = new Set<string>();
      for (const n of neighbors) {
        const reg = allocation.get(n);
        if (reg) {
          usedRegs.add(reg);
        }
      }

      let allocated = false;
      for (const reg of availableRegs) {
        if (!usedRegs.has(reg)) {
          allocation.set(v, reg);
          allocated = true;
          break;
        }
      }

      if (!allocated) {
        let slotIdx = 0;
        while (true) {
          const slot = `[rsp+${slotIdx * 8}]`;
          if (!usedRegs.has(slot)) {
            allocation.set(v, slot);
            break;
          }
          slotIdx++;
        }
      }
    }

    return allocation;
  }

  /**
   * Rewrites variables in the CFG to use allocated registers or stack slots, inserting spill loads/stores to satisfy x86 constraints.
   *
   * @param cfg The IR Control Flow Graph.
   * @param allocation Map from variable identifier to physical register/spill slot.
   * @returns The rewritten IR Control Flow Graph.
   */
  public rewrite(cfg: IRCFG, allocation: Map<string, string>): IRCFG {
    for (const block of cfg.blocks.values()) {
      const newInstructions: IRInstruction[] = [];

      for (const inst of block.instructions) {
        const preInsts: IRInstruction[] = [];
        const postInsts: IRInstruction[] = [];
        const scratchRegs = ['r10', 'r11'];
        let scratchIdx = 0;

        // Rewrite arguments
        const newArgs = inst.args.map((arg) => {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            const key = `${arg.name}_${arg.version}`;
            const reg = allocation.get(key);
            if (reg) {
              if (reg.startsWith('[rsp+')) {
                const offset = parseInt(reg.match(/\d+/)![0]);
                const memOp: IROperand = { type: 'mem', name: 'rsp', offset };
                const scratchName = scratchRegs[scratchIdx++];
                const scratchReg: IROperand = { type: 'reg', name: scratchName };
                
                preInsts.push({
                  op: IROp.LOAD,
                  dest: scratchReg,
                  args: [memOp],
                  address: inst.address,
                });
                return scratchReg;
              } else {
                return { type: 'reg' as const, name: reg } as IROperand;
              }
            }
          }
          return arg;
        });

        // Rewrite destination
        let newDest = inst.dest;
        if (
          inst.dest &&
          inst.dest.type === 'var' &&
          inst.dest.name &&
          inst.dest.version !== undefined
        ) {
          const key = `${inst.dest.name}_${inst.dest.version}`;
          const reg = allocation.get(key);
          if (reg) {
            if (reg.startsWith('[rsp+')) {
              const offset = parseInt(reg.match(/\d+/)![0]);
              const memOp: IROperand = { type: 'mem', name: 'rsp', offset };
              const scratchReg: IROperand = { type: 'reg', name: 'r10' };
              newDest = scratchReg;

              postInsts.push({
                op: IROp.STORE,
                args: [memOp, scratchReg],
                address: inst.address,
              });
            } else {
              newDest = { type: 'reg' as const, name: reg } as IROperand;
            }
          }
        }

        newInstructions.push(...preInsts);
        newInstructions.push({
          ...inst,
          dest: newDest,
          args: newArgs,
        });
        newInstructions.push(...postInsts);
      }

      block.instructions = newInstructions;
    }
    return cfg;
  }
}
