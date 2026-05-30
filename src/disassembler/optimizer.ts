import { IROp, IROperand, IRInstruction, IRBlock, IRCFG } from './ir.js';

/**
 * Performs target-independent optimization passes on the IR CFG.
 */
export class IROptimizer {
  /**
   * Constant folding: Simplifies arithmetic operations on constant arguments.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public constantFolding(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (
          inst.args.length === 2 &&
          inst.args.every((arg) => arg.type === 'imm')
        ) {
          const val1 = inst.args[0].value ?? (typeof inst.args[1].value === 'bigint' ? 0n : 0);
          const val2 = inst.args[1].value ?? (typeof inst.args[0].value === 'bigint' ? 0n : 0);
          const isBig = typeof val1 === 'bigint' || typeof val2 === 'bigint';
          const b1 = BigInt(val1);
          const b2 = BigInt(val2);
          let foldedValue: bigint | number | null = null;

          switch (inst.op) {
            case IROp.ADD:
              foldedValue = isBig ? b1 + b2 : Number(val1) + Number(val2);
              break;
            case IROp.SUB:
              foldedValue = isBig ? b1 - b2 : Number(val1) - Number(val2);
              break;
            case IROp.MUL:
              foldedValue = isBig ? b1 * b2 : Number(val1) * Number(val2);
              break;
            case IROp.DIV:
              if (b2 !== 0n) {
                foldedValue = isBig ? b1 / b2 : Math.trunc(Number(val1) / Number(val2));
              }
              break;
            case IROp.AND:
              foldedValue = isBig ? b1 & b2 : Number(val1) & Number(val2);
              break;
            case IROp.OR:
              foldedValue = isBig ? b1 | b2 : Number(val1) | Number(val2);
              break;
            case IROp.XOR:
              foldedValue = isBig ? b1 ^ b2 : Number(val1) ^ Number(val2);
              break;
          }

          if (foldedValue !== null && inst.dest) {
            inst.op = IROp.MOV;
            inst.args = [{ type: 'imm', value: foldedValue }];
          }
        }
      }
    }
    return cfg;
  }

  /**
   * Dead Code Elimination (DCE): Removes instructions whose outputs are never read.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with dead code removed.
   */
  public deadCodeElimination(cfg: IRCFG): IRCFG {
    const readCount = new Map<string, number>();

    // Count usages of each versioned variable
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        for (const arg of inst.args) {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            const key = `${arg.name}_${arg.version}`;
            readCount.set(key, (readCount.get(key) ?? 0) + 1);
          }
        }
      }
    }

    // Remove instructions writing to variables that are never read
    for (const block of cfg.blocks.values()) {
      block.instructions = block.instructions.filter((inst) => {
        // Do not eliminate memory stores, jumps, branches, rets, calls, or volatile ops
        if (
          [IROp.STORE, IROp.JMP, IROp.BRANCH, IROp.RET, IROp.CALL].includes(
            inst.op
          )
        ) {
          return true;
        }

        if (
          inst.dest &&
          inst.dest.type === 'var' &&
          inst.dest.name &&
          inst.dest.version !== undefined
        ) {
          const key = `${inst.dest.name}_${inst.dest.version}`;
          return (readCount.get(key) ?? 0) > 0;
        }

        return true;
      });
    }

    return cfg;
  }

  /**
   * Copy propagation: Replaces uses of variables that are copies of other variables or constants.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with copy propagation applied.
   */
  public copyPropagation(cfg: IRCFG): IRCFG {
    const copyMap = new Map<string, IROperand>();

    // Helper to compare two operands
    const operandsEqual = (a: IROperand, b: IROperand): boolean => {
      return (
        a.type === b.type &&
        a.name === b.name &&
        a.value === b.value &&
        a.version === b.version &&
        a.offset === b.offset
      );
    };

    // Helper to resolve an operand to its root source if it has been propagated
    const resolve = (op: IROperand, visited = new Set<string>()): IROperand => {
      if (op.type === 'var' && op.name && op.version !== undefined) {
        const key = `${op.name}_${op.version}`;
        if (visited.has(key)) {
          return op;
        }
        visited.add(key);
        if (copyMap.has(key)) {
          return resolve(copyMap.get(key)!, visited);
        }
      }
      return op;
    };

    let changed = true;
    while (changed) {
      changed = false;
      for (const block of cfg.blocks.values()) {
        for (const inst of block.instructions) {
          // Replace arguments
          for (let i = 0; i < inst.args.length; i++) {
            const resolved = resolve(inst.args[i]);
            // If they are not equal, we change them
            if (!operandsEqual(resolved, inst.args[i])) {
              inst.args[i] = resolved;
              changed = true;
            }
          }

          // If the instruction is a copy (MOV dest, src) and dest is a variable, register it
          if (
            inst.op === IROp.MOV &&
            inst.dest &&
            inst.dest.type === 'var' &&
            inst.dest.name &&
            inst.dest.version !== undefined &&
            inst.args.length === 1
          ) {
            const key = `${inst.dest.name}_${inst.dest.version}`;
            const src = inst.args[0];
            const resolvedSrc = resolve(src);

            // Check if we already have this copy mapped, or if we should map it
            const existing = copyMap.get(key);
            if (!existing || !operandsEqual(existing, resolvedSrc)) {
              // Avoid self-reference loop
              if (
                resolvedSrc.type !== 'var' ||
                `${resolvedSrc.name}_${resolvedSrc.version}` !== key
              ) {
                copyMap.set(key, resolvedSrc);
                changed = true;
              }
            }
          }
        }
      }
    }

    return cfg;
  }

  /**
   * Strength Reduction: Replaces expensive operations (like MUL/DIV by powers of two)
   * with cheaper operations (like SHL/SHR).
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with strength reductions applied.
   */
  public strengthReduction(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.op === IROp.MUL && inst.args.length === 2) {
          // Check if one operand is an immediate constant which is a power of 2
          let valOp: IROperand | null = null;
          let immVal: number | bigint | null = null;

          if (inst.args[1].type === 'imm' && inst.args[1].value !== undefined) {
            valOp = inst.args[0];
            immVal = inst.args[1].value;
          } else if (
            inst.args[0].type === 'imm' &&
            inst.args[0].value !== undefined
          ) {
            valOp = inst.args[1];
            immVal = inst.args[0].value;
          }

          if (immVal !== null && valOp !== null) {
            const numVal = Number(immVal);
            if (numVal === 0) {
              inst.op = IROp.MOV;
              inst.args = [{ type: 'imm', value: 0 }];
            } else if (numVal === 1) {
              inst.op = IROp.MOV;
              inst.args = [valOp];
            } else if (numVal > 0 && (numVal & (numVal - 1)) === 0) {
              const shift = Math.log2(numVal);
              inst.op = IROp.SHL;
              inst.args = [valOp, { type: 'imm', value: shift }];
            }
          }
        } else if (inst.op === IROp.DIV && inst.args.length === 2) {
          // Division by power of 2: DIV x, power_of_2 => SHR x, log2(power_of_2)
          const divisor = inst.args[1];
          const valOp = inst.args[0];
          if (divisor.type === 'imm' && divisor.value !== undefined) {
            const numVal = Number(divisor.value);
            if (numVal === 1) {
              inst.op = IROp.MOV;
              inst.args = [valOp];
            } else if (numVal > 0 && (numVal & (numVal - 1)) === 0) {
              const shift = Math.log2(numVal);
              inst.op = IROp.SHR;
              inst.args = [valOp, { type: 'imm', value: shift }];
            }
          }
        }
      }
    }
    return cfg;
  }

  /**
   * Algebraic Simplification: Simplifies identity operations like ADD x, 0 or SUB x, x.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public algebraicSimplification(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.op === IROp.ADD && inst.args.length === 2) {
          // x + 0 => x, 0 + x => x
          if (inst.args[1].type === 'imm' && Number(inst.args[1].value) === 0) {
            inst.op = IROp.MOV;
            inst.args = [inst.args[0]];
          } else if (
            inst.args[0].type === 'imm' &&
            Number(inst.args[0].value) === 0
          ) {
            inst.op = IROp.MOV;
            inst.args = [inst.args[1]];
          }
        } else if (inst.op === IROp.SUB && inst.args.length === 2) {
          // x - 0 => x
          if (inst.args[1].type === 'imm' && Number(inst.args[1].value) === 0) {
            inst.op = IROp.MOV;
            inst.args = [inst.args[0]];
          }
          // x - x => 0
          else if (
            inst.args[0].type === 'var' &&
            inst.args[1].type === 'var' &&
            inst.args[0].name === inst.args[1].name &&
            inst.args[0].version === inst.args[1].version
          ) {
            inst.op = IROp.MOV;
            inst.args = [{ type: 'imm', value: 0 }];
          }
        } else if (inst.op === IROp.XOR && inst.args.length === 2) {
          // x ^ x => 0
          if (
            inst.args[0].type === 'var' &&
            inst.args[1].type === 'var' &&
            inst.args[0].name === inst.args[1].name &&
            inst.args[0].version === inst.args[1].version
          ) {
            inst.op = IROp.MOV;
            inst.args = [{ type: 'imm', value: 0 }];
          }
        }
      }
    }
    return cfg;
  }

  /**
   * Phi Node Simplification: Simplifies PHI nodes where all inputs are identical.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public phiSimplification(cfg: IRCFG): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.op === IROp.PHI && inst.args.length > 0) {
          const first = inst.args[0];
          const allIdentical = inst.args.every(
            (arg) =>
              arg.type === first.type &&
              arg.name === first.name &&
              arg.value === first.value &&
              arg.version === first.version
          );
          if (allIdentical) {
            inst.op = IROp.MOV;
            inst.args = [first];
          }
        }
      }
    }
    return cfg;
  }

  /**
   * Loop Invariant Code Motion (LICM): Hoists instructions whose inputs do not change
   * within a loop to a pre-header block before the loop.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph with loop invariant code hoisted.
   */
  public loopInvariantCodeMotion(cfg: IRCFG): IRCFG {
    if (cfg.blocks.size === 0) return cfg;

    // Find the entry block (the one with no predecessors, or the first block)
    let entryBlockId = Array.from(cfg.blocks.keys())[0];
    for (const [id, block] of cfg.blocks.entries()) {
      if (block.predecessors.length === 0) {
        entryBlockId = id;
        break;
      }
    }

    // 1. Compute dominators
    const dominators = new Map<string, Set<string>>();
    const allIds = Array.from(cfg.blocks.keys());

    for (const id of allIds) {
      if (id === entryBlockId) {
        dominators.set(id, new Set([entryBlockId]));
      } else {
        dominators.set(id, new Set(allIds));
      }
    }

    let changed = true;
    while (changed) {
      changed = false;
      for (const id of allIds) {
        if (id === entryBlockId) continue;

        const block = cfg.blocks.get(id)!;
        if (block.predecessors.length === 0) continue;

        let newDoms: Set<string> | null = null;
        for (const predId of block.predecessors) {
          const predDoms = dominators.get(predId);
          if (!predDoms) continue;
          if (newDoms === null) {
            newDoms = new Set(predDoms);
          } else {
            for (const dom of newDoms) {
              if (!predDoms.has(dom)) {
                newDoms.delete(dom);
              }
            }
          }
        }

        newDoms = newDoms ?? new Set<string>();
        newDoms.add(id);

        const currentDoms = dominators.get(id)!;
        if (
          newDoms.size !== currentDoms.size ||
          Array.from(newDoms).some((d) => !currentDoms.has(d))
        ) {
          dominators.set(id, newDoms);
          changed = true;
        }
      }
    }

    // 2. Find back-edges and identify natural loops
    const backEdges: { from: string; to: string }[] = [];
    for (const [id, block] of cfg.blocks.entries()) {
      for (const succId of block.successors) {
        if (dominators.get(id)?.has(succId)) {
          backEdges.push({ from: id, to: succId });
        }
      }
    }

    // Find loops
    const loops: { header: string; blocks: Set<string> }[] = [];
    for (const edge of backEdges) {
      const loopBlocks = new Set<string>([edge.to, edge.from]);
      const stack = [edge.from];
      while (stack.length > 0) {
        const curr = stack.pop()!;
        const block = cfg.blocks.get(curr);
        if (!block) continue;
        for (const predId of block.predecessors) {
          if (!loopBlocks.has(predId)) {
            loopBlocks.add(predId);
            stack.push(predId);
          }
        }
      }
      loops.push({ header: edge.to, blocks: loopBlocks });
    }

    // Build variable definition-to-block lookup mapping
    const defBlock = new Map<string, string>();
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.dest && inst.dest.name && inst.dest.version !== undefined) {
          defBlock.set(`${inst.dest.name}_${inst.dest.version}`, block.id);
        }
      }
    }

    // Process loops
    for (const loop of loops) {
      const L = loop.blocks;
      const header = loop.header;
      const headerBlock = cfg.blocks.get(header);
      if (!headerBlock) continue;

      const invariantVars = new Set<string>();
      const invariantInstructions = new Set<IRInstruction>();

      // Iteratively identify loop invariant instructions
      let passChanged = true;
      while (passChanged) {
        passChanged = false;
        for (const blockId of L) {
          const block = cfg.blocks.get(blockId)!;
          for (const inst of block.instructions) {
            if (invariantInstructions.has(inst)) continue;

            // Cannot hoist volatile instructions, phi nodes, or control flow
            if (
              [
                IROp.STORE,
                IROp.JMP,
                IROp.BRANCH,
                IROp.RET,
                IROp.CALL,
                IROp.PHI,
              ].includes(inst.op)
            ) {
              continue;
            }

            if (!inst.dest || !inst.dest.name || inst.dest.version === undefined) {
              continue;
            }

            // Check if all arguments are invariant
            let allArgsInvariant = true;
            for (const arg of inst.args) {
              if (arg.type === 'imm') {
                continue;
              }
              if (arg.type === 'var' && arg.name && arg.version !== undefined) {
                const defId = defBlock.get(`${arg.name}_${arg.version}`);
                // Invariant if defined outside loop or is already marked invariant
                if (defId && L.has(defId) && !invariantVars.has(`${arg.name}_${arg.version}`)) {
                  allArgsInvariant = false;
                  break;
                }
              } else {
                allArgsInvariant = false;
                break;
              }
            }

            if (allArgsInvariant) {
              invariantInstructions.add(inst);
              invariantVars.add(`${inst.dest.name}_${inst.dest.version}`);
              passChanged = true;
            }
          }
        }
      }

      if (invariantInstructions.size === 0) continue;

      // Filter out and collect invariant instructions in original block instruction order
      const hoistedInsts: IRInstruction[] = [];
      for (const blockId of L) {
        const block = cfg.blocks.get(blockId)!;
        const remaining: IRInstruction[] = [];
        for (const inst of block.instructions) {
          if (invariantInstructions.has(inst)) {
            hoistedInsts.push(inst);
          } else {
            remaining.push(inst);
          }
        }
        block.instructions = remaining;
      }

      // Create a pre-header block to host the instructions
      const preheaderId = `${header}_preheader`;
      const outsidePreds = headerBlock.predecessors.filter((p) => !L.has(p));

      if (outsidePreds.length > 0) {
        const preheaderBlock: IRBlock = {
          id: preheaderId,
          instructions: [
            ...hoistedInsts,
            {
              op: IROp.JMP,
              args: [{ type: 'temp', name: header }],
            },
          ],
          predecessors: [...outsidePreds],
          successors: [header],
        };

        // Update outside predecessors to jump to preheader instead of header
        for (const predId of outsidePreds) {
          const predBlock = cfg.blocks.get(predId)!;
          predBlock.successors = predBlock.successors.map((s) =>
            s === header ? preheaderId : s
          );
          for (const inst of predBlock.instructions) {
            if (inst.op === IROp.JMP || inst.op === IROp.BRANCH) {
              inst.args = inst.args.map((arg) => {
                if (
                  (arg.type === 'temp' || arg.type === 'var') &&
                  arg.name === header
                ) {
                  return { ...arg, name: preheaderId };
                }
                return arg;
              });
            }
          }
        }

        // Update header predecessors to replace outsidePreds with preheaderId
        headerBlock.predecessors = headerBlock.predecessors.filter((p) =>
          L.has(p)
        );
        headerBlock.predecessors.push(preheaderId);

        cfg.blocks.set(preheaderId, preheaderBlock);

        // Update variable definition locations for subsequently processed loops
        for (const inst of hoistedInsts) {
          if (inst.dest && inst.dest.name && inst.dest.version !== undefined) {
            defBlock.set(
              `${inst.dest.name}_${inst.dest.version}`,
              preheaderId
            );
          }
        }
      }
    }

    return cfg;
  }

  /**
   * SSA-based Constant Propagation and Folding.
   * Propagates constant definitions through SSA variables and folds operations.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public ssaConstantFolding(cfg: IRCFG): IRCFG {
    const constants = new Map<string, number | bigint>();
    let changed = true;

    while (changed) {
      changed = false;

      for (const block of cfg.blocks.values()) {
        for (const inst of block.instructions) {
          if (inst.op === IROp.PHI && inst.args.length > 0) {
            const resolvedArgs = inst.args.map((arg) => {
              if (arg.type === 'var' && arg.name && arg.version !== undefined) {
                const key = `${arg.name}_${arg.version}`;
                if (constants.has(key)) {
                  return { type: 'imm', value: constants.get(key) };
                }
              }
              return arg;
            });
            if (resolvedArgs.every((arg) => arg.type === 'imm' && arg.value !== undefined)) {
              const firstVal = resolvedArgs[0].value;
              if (resolvedArgs.every((arg) => arg.value === firstVal)) {
                inst.op = IROp.MOV;
                inst.args = [{ type: 'imm', value: firstVal! }];
                if (inst.dest && inst.dest.name && inst.dest.version !== undefined) {
                  const destKey = `${inst.dest.name}_${inst.dest.version}`;
                  if (constants.get(destKey) !== firstVal) {
                    constants.set(destKey, firstVal!);
                    changed = true;
                  }
                }
              }
            }
            continue;
          }

          for (let i = 0; i < inst.args.length; i++) {
            const arg = inst.args[i];
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              const key = `${arg.name}_${arg.version}`;
              if (constants.has(key)) {
                inst.args[i] = { type: 'imm', value: constants.get(key) };
                changed = true;
              }
            }
          }

          if (
            inst.args.length === 2 &&
            inst.args.every((arg) => arg.type === 'imm')
          ) {
            const val1 = inst.args[0].value ?? (typeof inst.args[1].value === 'bigint' ? 0n : 0);
            const val2 = inst.args[1].value ?? (typeof inst.args[0].value === 'bigint' ? 0n : 0);
            const isBig = typeof val1 === 'bigint' || typeof val2 === 'bigint';
            const b1 = BigInt(val1);
            const b2 = BigInt(val2);
            let foldedValue: bigint | number | null = null;

            switch (inst.op) {
              case IROp.ADD:
                foldedValue = isBig ? b1 + b2 : Number(val1) + Number(val2);
                break;
              case IROp.SUB:
                foldedValue = isBig ? b1 - b2 : Number(val1) - Number(val2);
                break;
              case IROp.MUL:
                foldedValue = isBig ? b1 * b2 : Number(val1) * Number(val2);
                break;
              case IROp.DIV:
                if (b2 !== 0n) {
                  foldedValue = isBig ? b1 / b2 : Math.trunc(Number(val1) / Number(val2));
                }
                break;
              case IROp.AND:
                foldedValue = isBig ? b1 & b2 : Number(val1) & Number(val2);
                break;
              case IROp.OR:
                foldedValue = isBig ? b1 | b2 : Number(val1) | Number(val2);
                break;
              case IROp.XOR:
                foldedValue = isBig ? b1 ^ b2 : Number(val1) ^ Number(val2);
                break;
            }

            if (foldedValue !== null && inst.dest && inst.dest.name && inst.dest.version !== undefined) {
              inst.op = IROp.MOV;
              inst.args = [{ type: 'imm', value: foldedValue }];
              const destKey = `${inst.dest.name}_${inst.dest.version}`;
              if (constants.get(destKey) !== foldedValue) {
                constants.set(destKey, foldedValue);
                changed = true;
              }
            }
          }

          if (
            inst.op === IROp.MOV &&
            inst.dest &&
            inst.dest.name &&
            inst.dest.version !== undefined &&
            inst.args.length === 1 &&
            inst.args[0].type === 'imm' &&
            inst.args[0].value !== undefined
          ) {
            const destKey = `${inst.dest.name}_${inst.dest.version}`;
            const val = inst.args[0].value;
            if (constants.get(destKey) !== val) {
              constants.set(destKey, val);
              changed = true;
            }
          }
        }
      }
    }

    return cfg;
  }

  /**
   * SSA-based Iterative Dead Code Elimination (DCE).
   * Iteratively removes instructions whose outputs are never read.
   *
   * @param cfg The IR Control Flow Graph to optimize.
   * @returns The optimized IR Control Flow Graph.
   */
  public ssaDeadCodeElimination(cfg: IRCFG): IRCFG {
    let changed = true;
    while (changed) {
      changed = false;
      const readCount = new Map<string, number>();

      for (const block of cfg.blocks.values()) {
        for (const inst of block.instructions) {
          for (const arg of inst.args) {
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              const key = `${arg.name}_${arg.version}`;
              readCount.set(key, (readCount.get(key) ?? 0) + 1);
            }
          }
        }
      }

      for (const block of cfg.blocks.values()) {
        const initialCount = block.instructions.length;
        block.instructions = block.instructions.filter((inst) => {
          if (
            [IROp.STORE, IROp.JMP, IROp.BRANCH, IROp.RET, IROp.CALL].includes(
              inst.op
            )
          ) {
            return true;
          }

          if (
            inst.dest &&
            inst.dest.type === 'var' &&
            inst.dest.name &&
            inst.dest.version !== undefined
          ) {
            const key = `${inst.dest.name}_${inst.dest.version}`;
            const reads = readCount.get(key) ?? 0;
            return reads > 0;
          }

          return true;
        });

        if (block.instructions.length !== initialCount) {
          changed = true;
        }
      }
    }

    return cfg;
  }

  /**
   * Performs Live Variable Analysis on the SSA CFG.
   */
  public performLivenessAnalysis(cfg: IRCFG): {
    liveIn: Map<string, Set<string>>;
    liveOut: Map<string, Set<string>>;
  } {
    const liveIn = new Map<string, Set<string>>();
    const liveOut = new Map<string, Set<string>>();
    const ueVar = new Map<string, Set<string>>();
    const varKill = new Map<string, Set<string>>();

    for (const [blockId, block] of cfg.blocks.entries()) {
      liveIn.set(blockId, new Set());
      liveOut.set(blockId, new Set());
      const blockUeVar = new Set<string>();
      const blockVarKill = new Set<string>();

      for (const inst of block.instructions) {
        if (inst.op !== IROp.PHI) {
          for (const arg of inst.args) {
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              const varKey = `${arg.name}_${arg.version}`;
              if (!blockVarKill.has(varKey)) {
                blockUeVar.add(varKey);
              }
            }
          }
        }

        if (inst.dest && inst.dest.type === 'var' && inst.dest.name && inst.dest.version !== undefined) {
          const varKey = `${inst.dest.name}_${inst.dest.version}`;
          blockVarKill.add(varKey);
        }
      }

      ueVar.set(blockId, blockUeVar);
      varKill.set(blockId, blockVarKill);
    }

    let changed = true;
    while (changed) {
      changed = false;

      for (const [blockId, block] of cfg.blocks.entries()) {
        const currentLiveOut = liveOut.get(blockId) || new Set();
        const newLiveOut = new Set<string>();

        for (const succId of block.successors) {
          const succBlock = cfg.blocks.get(succId);
          if (!succBlock) continue;

          const succLiveIn = liveIn.get(succId) || new Set();
          for (const v of succLiveIn) {
            let isPhiDest = false;
            for (const inst of succBlock.instructions) {
              if (inst.op === IROp.PHI && inst.dest && inst.dest.name && inst.dest.version !== undefined) {
                if (`${inst.dest.name}_${inst.dest.version}` === v) {
                  isPhiDest = true;
                  break;
                }
              }
            }
            if (!isPhiDest) {
              newLiveOut.add(v);
            }
          }

          const predIndex = succBlock.predecessors.indexOf(blockId);
          if (predIndex !== -1) {
            for (const inst of succBlock.instructions) {
              if (inst.op === IROp.PHI && inst.args[predIndex]) {
                const arg = inst.args[predIndex];
                if (arg.type === 'var' && arg.name && arg.version !== undefined) {
                  newLiveOut.add(`${arg.name}_${arg.version}`);
                }
              }
            }
          }
        }

        if (newLiveOut.size !== currentLiveOut.size || Array.from(newLiveOut).some(v => !currentLiveOut.has(v))) {
          liveOut.set(blockId, newLiveOut);
          changed = true;
        }

        const blockUeVar = ueVar.get(blockId) || new Set();
        const blockVarKill = varKill.get(blockId) || new Set();
        const newLiveIn = new Set(blockUeVar);
        for (const v of newLiveOut) {
          if (!blockVarKill.has(v)) {
            newLiveIn.add(v);
          }
        }

        const currentLiveIn = liveIn.get(blockId) || new Set();
        if (newLiveIn.size !== currentLiveIn.size || Array.from(newLiveIn).some(v => !currentLiveIn.has(v))) {
          liveIn.set(blockId, newLiveIn);
          changed = true;
        }
      }
    }

    return { liveIn, liveOut };
  }

  /**
   * Constructs the Interference Graph of SSA variables.
   */
  public buildInterferenceGraph(
    cfg: IRCFG,
    liveOut: Map<string, Set<string>>
  ): Map<string, Set<string>> {
    const interference = new Map<string, Set<string>>();

    const addInterference = (u: string, v: string) => {
      if (u === v) return;
      if (!interference.has(u)) interference.set(u, new Set());
      if (!interference.has(v)) interference.set(v, new Set());
      interference.get(u)!.add(v);
      interference.get(v)!.add(u);
    };

    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.dest && inst.dest.type === 'var' && inst.dest.name && inst.dest.version !== undefined) {
          const key = `${inst.dest.name}_${inst.dest.version}`;
          if (!interference.has(key)) interference.set(key, new Set());
        }
        for (const arg of inst.args) {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            const key = `${arg.name}_${arg.version}`;
            if (!interference.has(key)) interference.set(key, new Set());
          }
        }
      }
    }

    for (const [blockId, block] of cfg.blocks.entries()) {
      const live = new Set<string>(liveOut.get(blockId) || []);

      for (let i = block.instructions.length - 1; i >= 0; i--) {
        const inst = block.instructions[i];

        if (inst.dest && inst.dest.type === 'var' && inst.dest.name && inst.dest.version !== undefined) {
          const destKey = `${inst.dest.name}_${inst.dest.version}`;
          for (const v of live) {
            addInterference(destKey, v);
          }
          live.delete(destKey);
        }

        if (inst.op !== IROp.PHI) {
          for (const arg of inst.args) {
            if (arg.type === 'var' && arg.name && arg.version !== undefined) {
              live.add(`${arg.name}_${arg.version}`);
            }
          }
        }
      }
    }

    return interference;
  }

  /**
   * Color the interference graph using available registers.
   */
  public allocateRegisters(
    cfg: IRCFG,
    availableRegisters: string[]
  ): { mapping: Map<string, string>; spilled: Set<string> } {
    const { liveOut } = this.performLivenessAnalysis(cfg);
    const interference = this.buildInterferenceGraph(cfg, liveOut);

    const mapping = new Map<string, string>();
    const spilled = new Set<string>();

    const vars = Array.from(interference.keys()).sort((a, b) => {
      const degA = interference.get(a)?.size ?? 0;
      const degB = interference.get(b)?.size ?? 0;
      return degB - degA;
    });

    for (const v of vars) {
      const neighbors = interference.get(v) || new Set();
      const usedRegs = new Set<string>();
      for (const n of neighbors) {
        if (mapping.has(n)) {
          usedRegs.add(mapping.get(n)!);
        }
      }

      let allocated = false;
      for (const reg of availableRegisters) {
        if (!usedRegs.has(reg)) {
          mapping.set(v, reg);
          allocated = true;
          break;
        }
      }

      if (!allocated) {
        spilled.add(v);
      }
    }

    return { mapping, spilled };
  }

  /**
   * Apply the register allocation mapping to rewrite the CFG operands.
   */
  public applyRegisterAllocation(
    cfg: IRCFG,
    mapping: Map<string, string>
  ): IRCFG {
    for (const block of cfg.blocks.values()) {
      for (const inst of block.instructions) {
        if (inst.dest && inst.dest.type === 'var' && inst.dest.name && inst.dest.version !== undefined) {
          const key = `${inst.dest.name}_${inst.dest.version}`;
          if (mapping.has(key)) {
            inst.dest = {
              type: 'reg',
              name: mapping.get(key)!,
            };
          }
        }

        inst.args = inst.args.map((arg) => {
          if (arg.type === 'var' && arg.name && arg.version !== undefined) {
            const key = `${arg.name}_${arg.version}`;
            if (mapping.has(key)) {
              return {
                type: 'reg',
                name: mapping.get(key)!,
              };
            }
          }
          return arg;
        });
      }
    }
    return cfg;
  }
}
