import { Instruction, Symbol } from '../disassembler/types.js';

export interface FCGNode {
  id: string;
  name: string;
  address: number;
  size?: number;
  callers: string[];
  callees: string[];
}

export interface FCGEdge {
  from: string;
  to: string;
  count: number;
}

export interface FunctionCallGraph {
  nodes: FCGNode[];
  edges: FCGEdge[];
}

/**
 * Builds a Function Call Graph (FCG) from symbols and instructions.
 * Matches call instructions to their target functions.
 */
export function buildFCG(
  symbols: Symbol[],
  instructions: Instruction[]
): FunctionCallGraph {
  const functions = symbols.filter((s) => s.type === 'function');
  if (functions.length === 0) {
    return { nodes: [], edges: [] };
  }

  // Sort functions by address to ensure binary search works
  const sortedFuncs = [...functions].sort((a, b) => a.address - b.address);

  // Map starting address to function node
  const addrToNodeMap = new Map<number, FCGNode>();
  const nodes: FCGNode[] = sortedFuncs.map((f) => {
    const node: FCGNode = {
      id: `func_0x${f.address.toString(16)}`,
      name: f.name,
      address: f.address,
      size: f.size,
      callers: [],
      callees: [],
    };
    addrToNodeMap.set(f.address, node);
    return node;
  });

  // Helper to find function enclosing an address
  const findFunctionByAddress = (address: number): FCGNode | null => {
    let low = 0;
    let high = sortedFuncs.length - 1;
    let candidate: FCGNode | null = null;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const func = sortedFuncs[mid];
      if (func.address <= address) {
        candidate = nodes[mid];
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    if (candidate) {
      if (candidate.size !== undefined && candidate.size > 0) {
        if (address < candidate.address + candidate.size) {
          return candidate;
        }
        return null;
      }
      const idx = nodes.indexOf(candidate);
      if (idx < nodes.length - 1) {
        const nextFunc = nodes[idx + 1];
        if (address < nextFunc.address) {
          return candidate;
        }
        return null;
      }
      return candidate;
    }
    return null;
  };

  // Group instructions by function
  const funcInstructions = new Map<string, Instruction[]>();
  for (const inst of instructions) {
    const func = findFunctionByAddress(inst.address);
    if (func) {
      if (!funcInstructions.has(func.id)) {
        funcInstructions.set(func.id, []);
      }
      funcInstructions.get(func.id)!.push(inst);
    }
  }

  const edgesMap = new Map<string, FCGEdge>();

  for (const [callerId, insts] of funcInstructions.entries()) {
    const callerNode = nodes.find((n) => n.id === callerId);
    if (!callerNode) continue;

    for (const inst of insts) {
      const mnemonic = inst.mnemonic.toLowerCase();
      const isCall =
        mnemonic === 'call' ||
        mnemonic === 'bl' ||
        mnemonic === 'blx' ||
        mnemonic === 'blr' ||
        mnemonic.startsWith('invoke-') ||
        mnemonic === 'jal' ||
        mnemonic === 'jalr';

      if (isCall) {
        let targetAddr: number | null = null;

        if (inst.operands) {
          for (const op of inst.operands) {
            if (op.type === 'imm' && op.imm !== undefined) {
              targetAddr = Number(op.imm);
              break;
            }
          }
        }

        if (targetAddr === null && inst.opStr) {
          const hexMatches = inst.opStr.match(/0x[0-9a-fA-F]+/g);
          if (hexMatches) {
            for (const hexStr of hexMatches) {
              const val = parseInt(hexStr, 16);
              if (!isNaN(val)) {
                targetAddr = val;
                break;
              }
            }
          }
        }

        if (targetAddr !== null) {
          const calleeNode =
            addrToNodeMap.get(targetAddr) || findFunctionByAddress(targetAddr);
          if (calleeNode && calleeNode.id !== callerNode.id) {
            if (!callerNode.callees.includes(calleeNode.id)) {
              callerNode.callees.push(calleeNode.id);
            }
            if (!calleeNode.callers.includes(callerNode.id)) {
              calleeNode.callers.push(callerNode.id);
            }

            const edgeKey = `${callerNode.id}->${calleeNode.id}`;
            if (!edgesMap.has(edgeKey)) {
              edgesMap.set(edgeKey, {
                from: callerNode.id,
                to: calleeNode.id,
                count: 0,
              });
            }
            edgesMap.get(edgeKey)!.count++;
          }
        }
      }
    }
  }

  return {
    nodes,
    edges: Array.from(edgesMap.values()),
  };
}
