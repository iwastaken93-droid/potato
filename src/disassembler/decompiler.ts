export interface Instruction {
  address: number;
  op: string; // e.g., 'MOV', 'ADD', 'SUB', 'CMP', 'JMP', 'JZ', 'JNZ', 'JE', 'JNE', 'RET', 'CALL', 'LEA'
  args: string[];
}

export interface BasicBlock {
  id: string; // unique identifier
  instructions: Instruction[];
  successors: string[]; // target block IDs
}

export interface DecompiledFunction {
  name: string;
  args: string[];
  pseudocode: string;
  structs?: string[]; // Reconstructed struct definitions
}

// Data Type representation
export interface DataType {
  type: 'int' | 'float' | 'ptr' | 'array' | 'struct' | 'unknown';
  target?: DataType; // For 'ptr' or 'array'
  name?: string; // For 'struct'
  fields?: { offset: number; name: string; type: DataType }[]; // For 'struct'
  length?: number; // For 'array'
}

// AST Nodes for Structured Control Flow
type ASTNode =
  | { type: 'Block'; statements: ASTNode[] }
  | { type: 'Statement'; code: string }
  | { type: 'If'; condition: string; thenBranch: ASTNode; elseBranch?: ASTNode }
  | { type: 'While'; condition: string; body: ASTNode }
  | { type: 'DoWhile'; condition: string; body: ASTNode }
  | { type: 'Return'; value?: string };

// Helper to represent parsed operands
interface ParsedOperand {
  type: 'register' | 'constant' | 'memory' | 'stack';
  raw: string;
  baseReg?: string;
  indexReg?: string;
  scale?: number;
  offset?: number;
}

export class Decompiler {
  private typeMap = new Map<string, DataType>();
  private structDefinitions = new Map<string, Map<number, DataType>>(); // structName -> fieldOffset -> fieldType
  private structNameCounter = 0;

  /**
   * Decompiles a function represented by a set of basic blocks into structured pseudocode.
   */
  public decompile(
    name: string,
    args: string[],
    blocks: BasicBlock[],
    entryBlockId: string
  ): DecompiledFunction {
    this.typeMap.clear();
    this.structDefinitions.clear();
    this.structNameCounter = 0;

    const blockMap = new Map<string, BasicBlock>();
    for (const b of blocks) {
      blockMap.set(b.id, b);
    }

    // 1. Find all actually used variables/registers
    const usedVars = new Set<string>();
    for (const b of blocks) {
      for (const inst of b.instructions) {
        for (const arg of inst.args) {
          const parsed = this.parseOperand(arg);
          if (parsed.type === 'register') {
            usedVars.add(parsed.raw.toLowerCase());
          } else if (parsed.type === 'stack') {
            usedVars.add(`local_${Math.abs(parsed.offset || 0)}`);
          } else if (parsed.type === 'memory') {
            if (parsed.baseReg) usedVars.add(parsed.baseReg.toLowerCase());
            if (parsed.indexReg) usedVars.add(parsed.indexReg.toLowerCase());
          }
        }
      }
    }

    // 2. Analyze variable types and reconstruct structures
    this.propagateTypes(blocks, args);

    // 3. Control Flow Analysis (Dominators, Post-dominators)
    const dominators = this.computeDominators(blockMap, entryBlockId);
    const postDominators = this.computePostDominators(blockMap);
    const ipdom = this.computeIPDOM(blockMap, postDominators);
    const loops = this.identifyLoops(blockMap, entryBlockId, dominators);

    // 4. Structure AST
    const ast = this.structureBlocks(
      blockMap,
      entryBlockId,
      dominators,
      ipdom,
      loops,
      new Set()
    );

    // 5. Render output
    const pseudocodeLines: string[] = [];

    // Render reconstructed structs
    const structDecls: string[] = [];
    for (const [sName, fieldsMap] of this.structDefinitions) {
      let structStr = `struct ${sName} {\n`;
      const sortedOffsets = Array.from(fieldsMap.keys()).sort((a, b) => a - b);
      for (const offset of sortedOffsets) {
        const fType = fieldsMap.get(offset)!;
        structStr += `  ${this.formatType(fType)} field_${offset};\n`;
      }
      structStr += `};`;
      structDecls.push(structStr);
    }

    // Render variables
    const localVars: string[] = [];
    for (const [varName, varType] of this.typeMap) {
      const lowerVar = varName.toLowerCase();
      // Only declare local variables/registers if they are actually used, not in args, and not stack/base pointers directly
      if (
        usedVars.has(lowerVar) &&
        !args.map(a => a.toLowerCase()).includes(lowerVar) &&
        lowerVar !== 'ebp' &&
        lowerVar !== 'esp' &&
        lowerVar !== 'rbp' &&
        lowerVar !== 'rsp' &&
        (lowerVar.startsWith('local_') || lowerVar.match(/^(r|e)?[a-d]x$|^esi$|^edi$/))
      ) {
        localVars.push(`  ${this.formatType(varType)} ${varName};`);
      }
    }
    
    const renderedBody = this.renderAST(ast, 1);
    
    // Format the function signature
    const argList = args
      .map((arg) => {
        const type = this.typeMap.get(arg) || { type: 'unknown' };
        return `${this.formatType(type)} ${arg}`;
      })
      .join(', ');

    let signature = '';
    if (structDecls.length > 0) {
      signature += structDecls.join('\n\n') + '\n\n';
    }
    signature += `function ${name}(${argList}) {\n`;
    if (localVars.length > 0) {
      signature += localVars.join('\n') + '\n\n';
    }
    signature += renderedBody;
    signature += '\n}';

    return {
      name,
      args,
      pseudocode: signature,
      structs: structDecls,
    };
  }

  /**
   * Helper to format data types into C-style declarations.
   */
  private formatType(type: DataType): string {
    switch (type.type) {
      case 'int':
        return 'int';
      case 'float':
        return 'float';
      case 'ptr':
        return `${this.formatType(type.target || { type: 'unknown' })}*`;
      case 'array':
        return `${this.formatType(type.target || { type: 'unknown' })}[]`;
      case 'struct':
        return `struct ${type.name}`;
      case 'unknown':
      default:
        return 'var';
    }
  }

  /**
   * Parses an instruction operand to recognize registers, constants, stack, or memory offsets.
   */
  private parseOperand(opStr: string): ParsedOperand {
    opStr = opStr.trim();
    if (!opStr) {
      return { type: 'constant', raw: opStr, offset: 0 };
    }

    // Memory or stack operand: [expr]
    if (opStr.startsWith('[') && opStr.endsWith(']')) {
      const expr = opStr.slice(1, -1).trim();

      // Check stack pointer bases
      if (expr.includes('ebp') || expr.includes('esp') || expr.includes('rbp') || expr.includes('rsp')) {
        const match = expr.match(/(ebp|esp|rbp|rsp)\s*([+-])\s*(\d+)/i);
        if (match) {
          const baseReg = match[1];
          const sign = match[2];
          const val = parseInt(match[3], 10);
          const offset = sign === '-' ? -val : val;
          return { type: 'stack', raw: opStr, baseReg, offset };
        }
        return { type: 'stack', raw: opStr, baseReg: expr, offset: 0 };
      }

      // Reconstruct complex addressing: [base + index * scale + offset]
      // Or simply [base + offset]
      const parts = expr.split('+').map((p) => p.trim());
      let baseReg: string | undefined;
      let indexReg: string | undefined;
      let scale: number | undefined;
      let offset = 0;

      for (const part of parts) {
        if (part.includes('*')) {
          const mulParts = part.split('*').map((p) => p.trim());
          indexReg = mulParts[0];
          scale = parseInt(mulParts[1], 10);
        } else if (part.match(/^[a-z]+$/i)) {
          if (!baseReg) {
            baseReg = part;
          } else {
            indexReg = part;
            scale = 1;
          }
        } else if (part.match(/^-?\d+$/)) {
          offset = parseInt(part, 10);
        }
      }

      return {
        type: 'memory',
        raw: opStr,
        baseReg: baseReg || 'unknown',
        indexReg,
        scale,
        offset,
      };
    }

    // Constant number
    if (opStr.match(/^-?\d+$/) || opStr.startsWith('0x')) {
      return { type: 'constant', raw: opStr, offset: parseInt(opStr, 10) };
    }

    // Register / Variable
    return { type: 'register', raw: opStr };
  }

  /**
   * Iterative data-flow analysis to propagate types across the CFG.
   */
  private propagateTypes(blocks: BasicBlock[], args: string[]) {
    // Initialize args to 'int' or generic type if not specified
    for (const arg of args) {
      this.typeMap.set(arg.toLowerCase(), { type: 'int' });
    }

    // Default register types
    const registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp'];
    for (const reg of registers) {
      if (!this.typeMap.has(reg)) {
        this.typeMap.set(reg, { type: 'unknown' });
      }
    }

    // Keep running the type propagation until fixed-point reached (limit iterations to prevent infinite loop)
    let changed = true;
    let iterations = 0;
    const maxIterations = 5;

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      for (const block of blocks) {
        for (const inst of block.instructions) {
          if (inst.op === 'MOV' || inst.op === 'LEA') {
            const dest = inst.args[0];
            const src = inst.args[1];

            if (!dest || !src) continue;

            const parsedDest = this.parseOperand(dest);
            const parsedSrc = this.parseOperand(src);

            let srcType: DataType = { type: 'unknown' };

            // Infer src type
            if (parsedSrc.type === 'constant') {
              srcType = { type: 'int' };
            } else if (parsedSrc.type === 'register') {
              srcType = this.typeMap.get(parsedSrc.raw.toLowerCase()) || { type: 'unknown' };
            } else if (parsedSrc.type === 'stack') {
              srcType = this.typeMap.get(`local_${Math.abs(parsedSrc.offset || 0)}`) || { type: 'unknown' };
            } else if (parsedSrc.type === 'memory') {
              // It is loading from memory [base + offset] or [base + index * scale]
              const baseLower = parsedSrc.baseReg?.toLowerCase() || '';
              const baseType = this.typeMap.get(baseLower) || { type: 'unknown' };
              
              if (parsedSrc.indexReg && parsedSrc.scale) {
                // E.g., [base + index * scale] => array access
                if (baseType.type !== 'array') {
                  this.typeMap.set(baseLower, {
                    type: 'array',
                    target: { type: 'int' },
                  });
                  changed = true;
                }
                srcType = { type: 'int' };
              } else {
                // E.g., [base + offset] => struct member dereference
                let structName = '';
                if (baseType.type === 'ptr' && baseType.target?.type === 'struct') {
                  structName = baseType.target.name!;
                } else {
                  // Infer a new struct type
                  this.structNameCounter++;
                  structName = `struct_${this.structNameCounter}`;
                  const structType: DataType = { type: 'struct', name: structName };
                  this.typeMap.set(baseLower, { type: 'ptr', target: structType });
                  this.structDefinitions.set(structName, new Map<number, DataType>());
                  changed = true;
                }

                // Get or register struct field
                const fieldsMap = this.structDefinitions.get(structName)!;
                const fieldOffset = parsedSrc.offset || 0;
                if (!fieldsMap.has(fieldOffset)) {
                  fieldsMap.set(fieldOffset, { type: 'int' }); // Default to int
                  changed = true;
                }
                srcType = fieldsMap.get(fieldOffset)!;
              }
            }

            // Propagate srcType to dest
            if (parsedDest.type === 'register') {
              const destLower = parsedDest.raw.toLowerCase();
              const prevType = this.typeMap.get(destLower);
              const newType: DataType = inst.op === 'LEA' ? { type: 'ptr', target: srcType } : srcType;
              if (!prevType || prevType.type !== newType.type || (prevType.target?.type !== newType.target?.type)) {
                this.typeMap.set(destLower, newType);
                changed = true;
              }
            } else if (parsedDest.type === 'stack') {
              const varName = `local_${Math.abs(parsedDest.offset || 0)}`;
              const prevType = this.typeMap.get(varName);
              if (!prevType || prevType.type !== srcType.type) {
                this.typeMap.set(varName, srcType);
                changed = true;
              }
            } else if (parsedDest.type === 'memory') {
              // Storing to memory [base + offset]
              const baseLower = parsedDest.baseReg?.toLowerCase() || '';
              const baseType = this.typeMap.get(baseLower) || { type: 'unknown' };
              if (parsedDest.indexReg && parsedDest.scale) {
                if (baseType.type !== 'array') {
                  this.typeMap.set(baseLower, {
                    type: 'array',
                    target: srcType.type !== 'unknown' ? srcType : { type: 'int' },
                  });
                  changed = true;
                }
              } else {
                let structName = '';
                if (baseType.type === 'ptr' && baseType.target?.type === 'struct') {
                  structName = baseType.target.name!;
                } else {
                  this.structNameCounter++;
                  structName = `struct_${this.structNameCounter}`;
                  const structType: DataType = { type: 'struct', name: structName };
                  this.typeMap.set(baseLower, { type: 'ptr', target: structType });
                  this.structDefinitions.set(structName, new Map<number, DataType>());
                  changed = true;
                }

                const fieldsMap = this.structDefinitions.get(structName)!;
                const fieldOffset = parsedDest.offset || 0;
                if (!fieldsMap.has(fieldOffset) || (srcType.type !== 'unknown' && fieldsMap.get(fieldOffset)!.type === 'unknown')) {
                  fieldsMap.set(fieldOffset, srcType.type !== 'unknown' ? srcType : { type: 'int' });
                  changed = true;
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * Helper to reconstruct a statement expression or C-style access notation.
   */
  private reconstructExpression(opStr: string): string {
    const parsed = this.parseOperand(opStr);
    if (parsed.type === 'constant') {
      return parsed.raw;
    }
    if (parsed.type === 'stack') {
      return `local_${Math.abs(parsed.offset || 0)}`;
    }
    if (parsed.type === 'memory') {
      const baseLower = parsed.baseReg?.toLowerCase() || '';
      const baseType = this.typeMap.get(baseLower);
      if (parsed.indexReg && parsed.scale) {
        return `${parsed.baseReg}[${parsed.indexReg}]`;
      }
      if (baseType && baseType.type === 'ptr' && baseType.target?.type === 'struct') {
        return `${parsed.baseReg}->field_${parsed.offset}`;
      }
      return `*( ${parsed.baseReg} + ${parsed.offset} )`;
    }
    return parsed.raw;
  }

  /**
   * Computes the dominator relation for each block.
   */
  private computeDominators(
    blockMap: Map<string, BasicBlock>,
    entryBlockId: string
  ): Map<string, Set<string>> {
    const visited = new Set<string>();
    const postOrder: string[] = [];

    function dfs(nodeId: string) {
      visited.add(nodeId);
      const block = blockMap.get(nodeId);
      if (block) {
        for (const succ of block.successors) {
          if (blockMap.has(succ) && !visited.has(succ)) {
            dfs(succ);
          }
        }
      }
      postOrder.push(nodeId);
    }

    dfs(entryBlockId);

    for (const id of blockMap.keys()) {
      if (!visited.has(id)) {
        dfs(id);
      }
    }

    const rpo = [...postOrder].reverse();
    const rpoRank = new Map<string, number>();
    rpo.forEach((id, index) => {
      rpoRank.set(id, index);
    });

    const predecessors = new Map<string, string[]>();
    for (const id of blockMap.keys()) {
      predecessors.set(id, []);
    }
    for (const [id, block] of blockMap) {
      for (const succ of block.successors) {
        if (predecessors.has(succ)) {
          predecessors.get(succ)!.push(id);
        }
      }
    }

    const idom = new Map<string, string>();
    idom.set(entryBlockId, entryBlockId);

    const intersect = (b1: string, b2: string): string => {
      let finger1 = b1;
      let finger2 = b2;
      while (finger1 !== finger2) {
        while (rpoRank.get(finger1)! > rpoRank.get(finger2)!) {
          finger1 = idom.get(finger1)!;
        }
        while (rpoRank.get(finger2)! > rpoRank.get(finger1)!) {
          finger2 = idom.get(finger2)!;
        }
      }
      return finger1;
    };

    let changed = true;
    while (changed) {
      changed = false;
      for (const node of rpo) {
        if (node === entryBlockId) continue;

        const preds = predecessors.get(node) || [];
        const processedPreds = preds.filter((p) => idom.has(p));

        if (processedPreds.length === 0) continue;

        let newIdom = processedPreds[0];
        for (let i = 1; i < processedPreds.length; i++) {
          newIdom = intersect(newIdom, processedPreds[i]);
        }

        if (idom.get(node) !== newIdom) {
          idom.set(node, newIdom);
          changed = true;
        }
      }
    }

    const dominators = new Map<string, Set<string>>();
    for (const id of blockMap.keys()) {
      const domSet = new Set<string>();
      if (idom.has(id)) {
        let curr = id;
        while (true) {
          domSet.add(curr);
          const next = idom.get(curr)!;
          if (next === curr) break;
          curr = next;
        }
      } else {
        domSet.add(id);
      }
      dominators.set(id, domSet);
    }

    return dominators;
  }

  /**
   * Computes post-dominator sets by reversing the CFG.
   */
  private computePostDominators(
    blockMap: Map<string, BasicBlock>
  ): Map<string, Set<string>> {
    const allBlockIds = Array.from(blockMap.keys());
    const exitBlocks = allBlockIds.filter((id) => {
      const b = blockMap.get(id)!;
      return b.successors.length === 0 || b.instructions.some((i) => i.op === 'RET');
    });

    const predecessors = new Map<string, string[]>();
    for (const id of allBlockIds) {
      predecessors.set(id, []);
    }
    for (const [id, block] of blockMap) {
      for (const succ of block.successors) {
        if (predecessors.has(succ)) {
          predecessors.get(succ)!.push(id);
        }
      }
    }

    const virtualExit = 'VIRTUAL_EXIT';

    const getReverseSuccessors = (nodeId: string): string[] => {
      if (nodeId === virtualExit) {
        return exitBlocks;
      }
      return predecessors.get(nodeId) || [];
    };

    const getReversePredecessors = (nodeId: string): string[] => {
      if (nodeId === virtualExit) {
        return [];
      }
      const preds = [...(blockMap.get(nodeId)?.successors || [])];
      if (exitBlocks.includes(nodeId)) {
        preds.push(virtualExit);
      }
      return preds;
    };

    const visited = new Set<string>();
    const postOrder: string[] = [];

    function dfsReverse(nodeId: string) {
      visited.add(nodeId);
      const succs = getReverseSuccessors(nodeId);
      for (const succ of succs) {
        if (!visited.has(succ)) {
          dfsReverse(succ);
        }
      }
      postOrder.push(nodeId);
    }

    dfsReverse(virtualExit);

    for (const id of allBlockIds) {
      if (!visited.has(id)) {
        dfsReverse(id);
      }
    }

    const rpo = [...postOrder].reverse();
    const rpoRank = new Map<string, number>();
    rpo.forEach((id, index) => {
      rpoRank.set(id, index);
    });

    const idomReverse = new Map<string, string>();
    idomReverse.set(virtualExit, virtualExit);

    const intersect = (b1: string, b2: string): string => {
      let finger1 = b1;
      let finger2 = b2;
      while (finger1 !== finger2) {
        while (rpoRank.get(finger1)! > rpoRank.get(finger2)!) {
          finger1 = idomReverse.get(finger1)!;
        }
        while (rpoRank.get(finger2)! > rpoRank.get(finger1)!) {
          finger2 = idomReverse.get(finger2)!;
        }
      }
      return finger1;
    };

    let changed = true;
    while (changed) {
      changed = false;
      for (const node of rpo) {
        if (node === virtualExit) continue;

        const preds = getReversePredecessors(node);
        const processedPreds = preds.filter((p) => idomReverse.has(p));

        if (processedPreds.length === 0) continue;

        let newIdom = processedPreds[0];
        for (let i = 1; i < processedPreds.length; i++) {
          newIdom = intersect(newIdom, processedPreds[i]);
        }

        if (idomReverse.get(node) !== newIdom) {
          idomReverse.set(node, newIdom);
          changed = true;
        }
      }
    }

    const postDominators = new Map<string, Set<string>>();
    for (const id of allBlockIds) {
      const domSet = new Set<string>();
      if (idomReverse.has(id)) {
        let curr = id;
        while (true) {
          domSet.add(curr);
          const next = idomReverse.get(curr)!;
          if (next === curr) break;
          curr = next;
        }
      } else {
        domSet.add(id);
      }
      domSet.delete(virtualExit);
      postDominators.set(id, domSet);
    }

    return postDominators;
  }

  /**
   * Computes the immediate post-dominator for each node.
   */
  private computeIPDOM(
    blockMap: Map<string, BasicBlock>,
    postDominators: Map<string, Set<string>>
  ): Map<string, string> {
    const ipdom = new Map<string, string>();

    for (const [node, doms] of postDominators) {
      // Find the unique node d in doms - {node} that is post-dominated by all other nodes in doms - {node}
      const candidates = new Set(doms);
      candidates.delete(node);

      for (const cand of candidates) {
        let isIPDOM = true;
        for (const other of candidates) {
          if (other === cand) continue;
          // If cand is not post-dominated by other, it cannot be the immediate post-dominator
          if (!postDominators.get(cand)?.has(other)) {
            isIPDOM = false;
            break;
          }
        }
        if (isIPDOM) {
          ipdom.set(node, cand);
          break;
        }
      }
    }

    return ipdom;
  }

  /**
   * Identifies loop structures (headers and back-edges).
   */
  private identifyLoops(
    blockMap: Map<string, BasicBlock>,
    entryBlockId: string,
    dominators: Map<string, Set<string>>
  ): Map<string, { header: string; latch: string; body: Set<string> }> {
    const loops = new Map<
      string,
      { header: string; latch: string; body: Set<string> }
    >();

    for (const [nodeId, block] of blockMap) {
      for (const succId of block.successors) {
        if (dominators.get(nodeId)?.has(succId)) {
          const body = this.findLoopBody(blockMap, succId, nodeId);
          loops.set(succId, { header: succId, latch: nodeId, body });
        }
      }
    }

    return loops;
  }

  private findLoopBody(
    blockMap: Map<string, BasicBlock>,
    header: string,
    latch: string
  ): Set<string> {
    const body = new Set<string>([header, latch]);
    const stack: string[] = [latch];

    while (stack.length > 0) {
      const node = stack.pop()!;
      const predecessors = Array.from(blockMap.keys()).filter((pId) =>
        blockMap.get(pId)!.successors.includes(node)
      );

      for (const pred of predecessors) {
        if (!body.has(pred)) {
          body.add(pred);
          stack.push(pred);
        }
      }
    }

    return body;
  }

  /**
   * Structure blocks recursively using post-dominators to handle nested controls accurately.
   */
  private structureBlocks(
    blockMap: Map<string, BasicBlock>,
    currentId: string,
    dominators: Map<string, Set<string>>,
    ipdom: Map<string, string>,
    loops: Map<string, { header: string; latch: string; body: Set<string> }>,
    visited: Set<string>
  ): ASTNode {
    if (visited.has(currentId)) {
      return { type: 'Block', statements: [] };
    }
    visited.add(currentId);

    const block = blockMap.get(currentId);
    if (!block) {
      return { type: 'Block', statements: [] };
    }

    const statements: ASTNode[] = [];

    // 1. Process instructions inside this basic block
    const blockStatements: ASTNode[] = [];
    let conditionCode = '';
    let lastCmp: { op1: string; op2: string } | undefined = undefined;

    for (const inst of block.instructions) {
      if (inst.op === 'CMP' || inst.op === 'TEST') {
        lastCmp = {
          op1: this.reconstructExpression(inst.args[0]),
          op2: this.reconstructExpression(inst.args[1]),
        };
        blockStatements.push({
          type: 'Statement',
          code: `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`,
        });
      } else if (['JZ', 'JNZ', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'].includes(inst.op)) {
        if (lastCmp) {
          conditionCode = `${inst.op.toLowerCase()}(${lastCmp.op1}, ${lastCmp.op2})`;
        } else {
          conditionCode = `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`;
        }
      } else if (inst.op === 'RET') {
        blockStatements.push({
          type: 'Return',
          value: inst.args.map((a) => this.reconstructExpression(a)).join(' '),
        });
      } else if (inst.op === 'MOV' || inst.op === 'LEA') {
        const destExpr = this.reconstructExpression(inst.args[0]);
        const srcExpr = this.reconstructExpression(inst.args[1]);
        blockStatements.push({
          type: 'Statement',
          code: `${destExpr} = ${srcExpr}`,
        });
      } else {
        blockStatements.push({
          type: 'Statement',
          code: `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`,
        });
      }
    }
    statements.push(...blockStatements);

    // 2. Loop Header Handling
    if (loops.has(currentId)) {
      const loop = loops.get(currentId)!;
      const loopBodyVisited = new Set(visited);

      // Identify the entry point of the loop body
      const startBodyId = block.successors.find(
        (s) => loop.body.has(s) && s !== currentId
      );

      let loopBodyAST: ASTNode = { type: 'Block', statements: [] };
      if (startBodyId) {
        loopBodyAST = this.structureBlocks(
          blockMap,
          startBodyId,
          dominators,
          ipdom,
          loops,
          loopBodyVisited
        );
      }

      // Find successor outside loop
      const outsideSuccessors = block.successors.filter(
        (s) => !loop.body.has(s)
      );
      const nextId = outsideSuccessors[0];

      // Create Loop node (could be while/do-while depending on latch)
      const isDoWhile = blockMap.get(loop.latch)?.instructions.some((i) =>
        ['JZ', 'JNZ', 'JE', 'JNE'].includes(i.op)
      );

      const loopNode: ASTNode = isDoWhile
        ? {
            type: 'DoWhile',
            condition: conditionCode || 'true',
            body: loopBodyAST,
          }
        : {
            type: 'While',
            condition: conditionCode || 'true',
            body: loopBodyAST,
          };

      statements.push(loopNode);

      if (nextId) {
        statements.push(
          this.structureBlocks(blockMap, nextId, dominators, ipdom, loops, visited)
        );
      }

      return { type: 'Block', statements };
    }

    // 3. Conditional branches (If-Else / Nested conditions)
    if (block.successors.length === 2) {
      const [thenId, elseId] = block.successors;
      const mergeId = ipdom.get(currentId);

      const thenVisited = new Set(visited);
      const elseVisited = new Set(visited);

      // Structure branches up to the merge block
      const thenBranch = this.structureBranch(
        blockMap,
        thenId,
        mergeId,
        dominators,
        ipdom,
        loops,
        thenVisited
      );
      const elseBranch = this.structureBranch(
        blockMap,
        elseId,
        mergeId,
        dominators,
        ipdom,
        loops,
        elseVisited
      );

      statements.push({
        type: 'If',
        condition: conditionCode || 'true',
        thenBranch,
        elseBranch,
      });

      // Continue structuring from merge block
      if (mergeId && blockMap.has(mergeId) && !visited.has(mergeId)) {
        statements.push(
          this.structureBlocks(blockMap, mergeId, dominators, ipdom, loops, visited)
        );
      }

      return { type: 'Block', statements };
    }

    // 4. Sequential Flow
    if (block.successors.length === 1) {
      const nextId = block.successors[0];
      statements.push(
        this.structureBlocks(blockMap, nextId, dominators, ipdom, loops, visited)
      );
    }

    return { type: 'Block', statements };
  }

  /**
   * Helper to structure a specific path of a conditional branch up to its merge node.
   */
  private structureBranch(
    blockMap: Map<string, BasicBlock>,
    startId: string,
    endId: string | undefined,
    dominators: Map<string, Set<string>>,
    ipdom: Map<string, string>,
    loops: Map<string, { header: string; latch: string; body: Set<string> }>,
    visited: Set<string>
  ): ASTNode {
    if (startId === endId || visited.has(startId)) {
      return { type: 'Block', statements: [] };
    }
    visited.add(startId);

    const block = blockMap.get(startId);
    if (!block) {
      return { type: 'Block', statements: [] };
    }

    const statements: ASTNode[] = [];

    // Parse block instructions
    const blockStatements: ASTNode[] = [];
    let conditionCode = '';
    let lastCmp: { op1: string; op2: string } | undefined = undefined;

    for (const inst of block.instructions) {
      if (inst.op === 'CMP' || inst.op === 'TEST') {
        lastCmp = {
          op1: this.reconstructExpression(inst.args[0]),
          op2: this.reconstructExpression(inst.args[1]),
        };
        blockStatements.push({
          type: 'Statement',
          code: `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`,
        });
      } else if (['JZ', 'JNZ', 'JE', 'JNE', 'JG', 'JL', 'JGE', 'JLE'].includes(inst.op)) {
        if (lastCmp) {
          conditionCode = `${inst.op.toLowerCase()}(${lastCmp.op1}, ${lastCmp.op2})`;
        } else {
          conditionCode = `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`;
        }
      } else if (inst.op === 'RET') {
        blockStatements.push({
          type: 'Return',
          value: inst.args.map((a) => this.reconstructExpression(a)).join(' '),
        });
      } else if (inst.op === 'MOV' || inst.op === 'LEA') {
        const destExpr = this.reconstructExpression(inst.args[0]);
        const srcExpr = this.reconstructExpression(inst.args[1]);
        blockStatements.push({
          type: 'Statement',
          code: `${destExpr} = ${srcExpr}`,
        });
      } else {
        blockStatements.push({
          type: 'Statement',
          code: `${inst.op.toLowerCase()}(${inst.args.map((a) => this.reconstructExpression(a)).join(', ')})`,
        });
      }
    }
    statements.push(...blockStatements);

    // Stop traversing if this block has no successors
    if (block.successors.length === 0) {
      return { type: 'Block', statements };
    }

    // Merge point check
    if (block.successors.length === 1) {
      const nextId = block.successors[0];
      if (nextId !== endId) {
        statements.push(
          this.structureBranch(blockMap, nextId, endId, dominators, ipdom, loops, visited)
        );
      }
    } else if (block.successors.length === 2) {
      const [thenId, elseId] = block.successors;
      const branchMergeId = ipdom.get(startId);

      const branchThenVisited = new Set(visited);
      const branchElseVisited = new Set(visited);

      const thenBranch = this.structureBranch(
        blockMap,
        thenId,
        branchMergeId,
        dominators,
        ipdom,
        loops,
        branchThenVisited
      );
      const elseBranch = this.structureBranch(
        blockMap,
        elseId,
        branchMergeId,
        dominators,
        ipdom,
        loops,
        branchElseVisited
      );

      statements.push({
        type: 'If',
        condition: conditionCode || 'true',
        thenBranch,
        elseBranch,
      });

      if (branchMergeId && branchMergeId !== endId) {
        statements.push(
          this.structureBranch(blockMap, branchMergeId, endId, dominators, ipdom, loops, visited)
        );
      }
    }

    return { type: 'Block', statements };
  }

  /**
   * Renders the control-flow AST into beautifully formatted pseudocode.
   */
  private renderAST(node: ASTNode, indentLevel: number): string {
    const indent = '  '.repeat(indentLevel);
    switch (node.type) {
      case 'Block':
        return node.statements
          .map((s) => this.renderAST(s, indentLevel))
          .filter((s) => s.trim().length > 0)
          .join('\n');

      case 'Statement':
        return `${indent}${node.code};`;

      case 'Return':
        return `${indent}return${node.value ? ` ${node.value}` : ''};`;

      case 'If': {
        const cond = node.condition;
        let result = `${indent}if (${cond}) {\n${this.renderAST(node.thenBranch, indentLevel + 1)}\n${indent}}`;
        if (
          node.elseBranch &&
          node.elseBranch.type === 'Block' &&
          node.elseBranch.statements.length > 0
        ) {
          result += ` else {\n${this.renderAST(node.elseBranch, indentLevel + 1)}\n${indent}}`;
        }
        return result;
      }

      case 'While': {
        return `${indent}while (${node.condition}) {\n${this.renderAST(node.body, indentLevel + 1)}\n${indent}}`;
      }

      case 'DoWhile': {
        return `${indent}do {\n${this.renderAST(node.body, indentLevel + 1)}\n${indent}} while (${node.condition});`;
      }
    }
  }
}
