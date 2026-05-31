import { DisassemblerRouter } from '../disassembler/router.js';
import { Decompiler } from '../disassembler/decompiler.js';
import { parseElf } from '../parser/elf.js';
import { PEParser } from '../parser/pe.js';
import { MachoParser } from '../parser/macho.js';
import { BinaryPatcher } from './patcher.js';
import { ScriptingEngine, ScriptingContext } from './scripting.js';
import { YaraEngine } from './yara.js';
import { VulnScanner } from './vulnScanner.js';
import { diffBytes, diffInstructions } from './diff.js';
import { AIExplanationEngine } from './ai.js';
import { Emulator } from '../emulator/emulator.js';

/**
 * Helper to convert Hex or Base64 string to Uint8Array
 */
export function toUint8Array(input: string): Uint8Array {
  const trimmed = input.trim();
  // Check if hex
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = new Uint8Array(trimmed.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  // Try Base64
  try {
    const binaryString = atob(trimmed);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (e) {
    // Treat as raw UTF-8 string bytes
    return new TextEncoder().encode(trimmed);
  }
}

/**
 * Helper to convert Uint8Array to Hex string
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Standard tool / function definitions for external LLMs
 */
export const TOOL_SCHEMAS = {
  disassemble: {
    name: 'disassemble',
    description: 'Disassemble raw binary data into structured instructions.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        arch: { type: 'string', description: 'Architecture, e.g., x86_64, arm, riscv, thumb, wasm, dex, z80, etc.' },
        baseAddress: { type: 'number', description: 'Base virtual address (default 0).' }
      },
      required: ['data']
    }
  },
  decompile: {
    name: 'decompile',
    description: 'Decompile structured instructions or raw binary into C-like pseudocode.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        entryPoint: { type: 'number', description: 'Optional entry point offset/address.' },
        instructions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number' },
              op: { type: 'string' },
              args: { type: 'array', items: { type: 'string' } }
            }
          }
        }
      }
    }
  },
  parseBinary: {
    name: 'parseBinary',
    description: 'Parse ELF, PE, or Mach-O executable binary headers, sections, symbols.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        format: { type: 'string', enum: ['elf', 'pe', 'macho', 'auto'], description: 'Binary format (default auto).' }
      },
      required: ['data']
    }
  },
  patchBinary: {
    name: 'patchBinary',
    description: 'Apply patches at specified offsets or virtual addresses to binary data.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        patches: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              offset: { type: 'number', description: 'Offset in binary to apply patch.' },
              patchedBytes: { type: 'string', description: 'Hex or Base64 encoded replacement bytes.' },
              address: { type: 'number', description: 'Virtual address associated with patch.' },
              description: { type: 'string', description: 'Purpose or summary of patch.' }
            },
            required: ['offset', 'patchedBytes', 'address']
          }
        }
      },
      required: ['data', 'patches']
    }
  },
  executeScript: {
    name: 'executeScript',
    description: 'Run JavaScript analytics scripts with helper contexts on a binary.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        script: { type: 'string', description: 'JavaScript code to execute.' }
      },
      required: ['data', 'script']
    }
  },
  yaraScan: {
    name: 'yaraScan',
    description: 'Scan binary data using YARA-like text signatures.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        rules: { type: 'string', description: 'YARA rules source string.' }
      },
      required: ['data', 'rules']
    }
  },
  vulnScan: {
    name: 'vulnScan',
    description: 'Scan function instructions, imports, strings, or decompiled code for vulnerabilities.',
    parameters: {
      type: 'object',
      properties: {
        instructions: { type: 'array', items: { type: 'object' } },
        strings: { type: 'array', items: { type: 'string' } },
        importNames: { type: 'array', items: { type: 'string' } },
        decompiledText: { type: 'string' }
      }
    }
  },
  diffBinaries: {
    name: 'diffBinaries',
    description: 'Perform diffing analysis between two binaries or instruction sets.',
    parameters: {
      type: 'object',
      properties: {
        dataA: { type: 'string', description: 'Binary A (Hex or Base64).' },
        dataB: { type: 'string', description: 'Binary B (Hex or Base64).' },
        type: { type: 'string', enum: ['bytes', 'instructions'], description: 'Diff mode (default bytes).' }
      },
      required: ['dataA', 'dataB']
    }
  },
  analyzeCodeAI: {
    name: 'analyzeCodeAI',
    description: 'Use the AI engine to analyze code patterns, suggestions, complexity, and pseudocode.',
    parameters: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Assembly or C code block to explain.' },
        functionName: { type: 'string', description: 'Name of the function context.' },
        arch: { type: 'string', description: 'Architecture context.' }
      },
      required: ['code']
    }
  },
  symbolicExecute: {
    name: 'symbolicExecute',
    description: 'Symbolically execute mock/simplified assembly instructions to find inputs hitting a target.',
    parameters: {
      type: 'object',
      properties: {
        instructions: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number' },
              op: { type: 'string' },
              args: { type: 'array', items: { type: 'string' } }
            },
            required: ['op', 'args']
          }
        },
        inputs: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Variable/Register name.' },
              min: { type: 'number' },
              max: { type: 'number' }
            },
            required: ['name']
          }
        },
        targetAddress: { type: 'number', description: 'The address we want to reach.' }
      },
      required: ['instructions', 'inputs', 'targetAddress']
    }
  },
  emulatorControl: {
    name: 'emulatorControl',
    description: 'Control x86_64 emulator instance, execute instructions, read/write memory and registers.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['run', 'step', 'reset', 'readReg', 'writeReg', 'readMem', 'writeMem'] },
        instructions: { type: 'array', items: { type: 'object' } },
        registers: { type: 'object', description: 'Register key-value pairs (as string representing BigInt or number).' },
        memory: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string' },
              value: { type: 'string', description: 'Hex string or byte representation.' }
            }
          }
        },
        steps: { type: 'number', description: 'Number of steps for step/run action.' }
      },
      required: ['action']
    }
  }
};

/**
 * Symbolic Execution Engine implementation
 */
export class SymbolicExecutor {
  public execute(
    instructions: any[],
    inputs: { name: string; min?: number; max?: number }[],
    targetAddress: number
  ): {
    success: boolean;
    pathFound: boolean;
    constraints: string[];
    solutions?: Record<string, number>;
    error?: string;
  } {
    try {
      const state: Record<string, any> = {};
      let cmpState: { left: any; right: any } | null = null;
      const constraints: string[] = [];

      // Initial symbolic variables
      for (const input of inputs) {
        state[input.name] = input.name;
      }

      let currentPc = instructions[0]?.address ?? 0;
      let stepIndex = 0;
      let pathFound = false;

      while (stepIndex < instructions.length) {
        const inst = instructions[stepIndex];
        currentPc = inst.address;

        if (currentPc === targetAddress) {
          pathFound = true;
          break;
        }

        const op = inst.op.toLowerCase();
        const arg0 = inst.args[0];
        const arg1 = inst.args[1];

        const resolve = (val: string) => {
          if (!val) return 0;
          if (val.startsWith('0x')) return parseInt(val, 16);
          if (/^\d+$/.test(val)) return parseInt(val, 10);
          if (val in state) return state[val];
          return val; // Symbolic register/variable name
        };

        if (op === 'mov') {
          state[arg0] = resolve(arg1);
        } else if (op === 'add') {
          const l = resolve(arg0);
          const r = resolve(arg1);
          state[arg0] = { op: 'add', args: [l, r] };
        } else if (op === 'sub') {
          const l = resolve(arg0);
          const r = resolve(arg1);
          state[arg0] = { op: 'sub', args: [l, r] };
        } else if (op === 'mul') {
          const l = resolve(arg0);
          const r = resolve(arg1);
          state[arg0] = { op: 'mul', args: [l, r] };
        } else if (op === 'xor') {
          const l = resolve(arg0);
          const r = resolve(arg1);
          state[arg0] = { op: 'xor', args: [l, r] };
        } else if (op === 'cmp') {
          cmpState = { left: resolve(arg0), right: resolve(arg1) };
        } else if (op === 'je' || op === 'jz') {
          if (cmpState) {
            constraints.push(`${this.stringify(cmpState.left)} === ${this.stringify(cmpState.right)}`);
          }
          // Simulating branch choice to targetAddress
          const dest = parseInt(arg0, 10) || parseInt(arg0, 16);
          if (dest === targetAddress) {
            pathFound = true;
            break;
          }
        } else if (op === 'jne' || op === 'jnz') {
          if (cmpState) {
            constraints.push(`${this.stringify(cmpState.left)} !== ${this.stringify(cmpState.right)}`);
          }
          const dest = parseInt(arg0, 10) || parseInt(arg0, 16);
          if (dest === targetAddress) {
            pathFound = true;
            break;
          }
        }

        stepIndex++;
      }

      // If we reached target, let's solve the constraints
      let solutions: Record<string, number> | undefined;
      if (pathFound && constraints.length > 0) {
        solutions = this.solveConstraints(constraints, inputs);
      }

      return {
        success: true,
        pathFound,
        constraints,
        solutions
      };
    } catch (e: any) {
      return { success: false, pathFound: false, constraints: [], error: e.message };
    }
  }

  private stringify(expr: any): string {
    if (typeof expr === 'number') return expr.toString();
    if (typeof expr === 'string') return expr;
    if (!expr || !expr.op) return '';
    const argsStr = expr.args.map((arg: any) => this.stringify(arg));
    return `(${argsStr[0]} ${expr.op === 'add' ? '+' : expr.op === 'sub' ? '-' : expr.op === 'mul' ? '*' : '^'} ${argsStr[1]})`;
  }

  private solveConstraints(constraints: string[], inputs: { name: string; min?: number; max?: number }[]): Record<string, number> | undefined {
    // Simple brute-force solver for 1-2 variables over min..max range
    if (inputs.length === 0) return {};
    const inputRanges = inputs.map(i => ({
      name: i.name,
      min: i.min ?? 0,
      max: i.max ?? 1000
    }));

    // Evaluate constraints via standard JS evaluations
    const evaluate = (expr: string, vars: Record<string, number>): boolean => {
      let replaced = expr;
      for (const [name, val] of Object.entries(vars)) {
        replaced = replaced.split(name).join(val.toString());
      }
      try {
        // Safe evaluation for simple expressions
        return new Function(`return ${replaced}`)();
      } catch {
        return false;
      }
    };

    // Assuming small dimension brute force for test/demo
    if (inputRanges.length === 1) {
      const v = inputRanges[0];
      for (let val = v.min; val <= v.max; val++) {
        const testVars = { [v.name]: val };
        if (constraints.every(c => evaluate(c, testVars))) {
          return testVars;
        }
      }
    } else if (inputRanges.length === 2) {
      const v0 = inputRanges[0];
      const v1 = inputRanges[1];
      for (let val0 = v0.min; val0 <= v0.max; val0++) {
        for (let val1 = v1.min; val1 <= v1.max; val1++) {
          const testVars = { [v0.name]: val0, [v1.name]: val1 };
          if (constraints.every(c => evaluate(c, testVars))) {
            return testVars;
          }
        }
      }
    }
    return undefined;
  }
}

/**
 * Unified AI Query Bridge for URET
 */
export class AIBridge {
  private static emulatorInstance: Emulator | null = null;

  private static getEmulator(): Emulator {
    if (!this.emulatorInstance) {
      this.emulatorInstance = new Emulator();
    }
    return this.emulatorInstance;
  }

  public static async executeQuery(query: { action: string; params: any }): Promise<any> {
    const { action, params } = query;

    switch (action) {
      case 'disassemble': {
        const bytes = toUint8Array(params.data);
        const router = new DisassemblerRouter();
        const insts = router.disassemble(bytes, {
          arch: params.arch,
          baseAddress: params.baseAddress
        });
        const mappedInsts = insts.map(inst => ({
          ...inst,
          op: inst.mnemonic,
          args: inst.opStr ? inst.opStr.split(',').map(s => s.trim()) : []
        }));
        return { success: true, instructions: mappedInsts };
      }

      case 'decompile': {
        let insts = params.instructions;
        if (!insts && params.data) {
          const bytes = toUint8Array(params.data);
          const router = new DisassemblerRouter();
          insts = router.disassemble(bytes, { entryPoint: params.entryPoint });
        }
        if (!insts || insts.length === 0) {
          throw new Error('No instructions provided for decompilation');
        }

        const decompilerInsts = insts.map((inst: any) => ({
          address: inst.address,
          op: inst.op || inst.mnemonic || '',
          args: inst.args || (inst.opStr ? inst.opStr.split(',').map((s: string) => s.trim()) : [])
        }));

        const decompiler = new Decompiler();
        const blocks = [{
          id: 'entry',
          instructions: decompilerInsts,
          successors: []
        }];
        const result = decompiler.decompile('func', [], blocks, 'entry');
        return { success: true, decompiled: result };
      }

      case 'parseBinary': {
        const bytes = toUint8Array(params.data);
        const format = params.format || 'auto';
        let detected = format;
        if (format === 'auto') {
          if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
            detected = 'elf';
          } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
            detected = 'pe';
          } else if (
            (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
            (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
          ) {
            detected = 'macho';
          } else {
            detected = 'elf'; // fallback
          }
        }

        if (detected === 'elf') {
          const parsed = parseElf(bytes.buffer as ArrayBuffer);
          return { success: true, format: 'elf', header: parsed.header, sections: parsed.sectionHeaders, symbols: parsed.symbols };
        } else if (detected === 'pe') {
          const parser = new PEParser(bytes.buffer as ArrayBuffer);
          const parsed = parser.parse();
          return { success: true, format: 'pe', header: parsed.coffHeader, sections: parsed.sections, imports: parsed.imports };
        } else if (detected === 'macho') {
          const parser = new MachoParser(bytes);
          const parsed = parser.parse();
          return { success: true, format: 'macho', header: parsed.header, sections: parsed.sections, symbols: parsed.symbols };
        }
        throw new Error(`Unsupported binary format: ${detected}`);
      }

      case 'patchBinary': {
        const bytes = toUint8Array(params.data);
        const patcher = new BinaryPatcher(bytes);
        const records = [];
        for (const p of params.patches) {
          const patBytes = toUint8Array(p.patchedBytes);
          const rec = patcher.applyPatch(p.offset, patBytes, p.address, p.description || '');
          records.push(rec);
        }
        return {
          success: true,
          patchedData: toHex(patcher.getPatchedBinary()),
          records
        };
      }

      case 'executeScript': {
        const bytes = toUint8Array(params.data);
        const context: ScriptingContext = {
          binaryData: bytes,
          entryPoint: 0,
          sections: [{ name: '.text', virtualAddress: 0, virtualSize: bytes.length, fileOffset: 0, fileSize: bytes.length, flags: { read: true, write: false, execute: true } }],
          symbols: [],
          instructions: [],
          extractedStrings: [],
        };
        const engine = new ScriptingEngine(context);
        const res = engine.execute(params.script);
        return { success: true, result: res.result, logs: res.logs };
      }

      case 'yaraScan': {
        const bytes = toUint8Array(params.data);
        const yara = new YaraEngine();
        yara.compile(params.rules);
        const matches = yara.scan(bytes);
        return { success: true, matches };
      }

      case 'vulnScan': {
        const scanner = new VulnScanner();
        const data = params.data ? toUint8Array(params.data) : new Uint8Array(0);
        const sections = params.sections || [];
        const symbols = params.symbols || (params.importNames || []).map((name: string) => ({ name, address: 0 }));
        const instructions = params.instructions || [];
        const matches = scanner.scan(
          data,
          sections,
          symbols,
          instructions,
          params.config
        );
        return { success: true, vulnerabilities: matches };
      }

      case 'diffBinaries': {
        const bytesA = toUint8Array(params.dataA);
        const bytesB = toUint8Array(params.dataB);
        const type = params.type || 'bytes';

        if (type === 'bytes') {
          const diffs = diffBytes(bytesA, bytesB);
          return { success: true, diffs };
        } else {
          const router = new DisassemblerRouter();
          const instsA = router.disassemble(bytesA);
          const instsB = router.disassemble(bytesB);
          const diffs = diffInstructions(instsA, instsB);
          return { success: true, diffs };
        }
      }

      case 'analyzeCodeAI': {
        const result = AIExplanationEngine.analyze(params.code, {
          functionName: params.functionName,
          arch: params.arch
        });
        return { success: true, analysis: result };
      }

      case 'symbolicExecute': {
        const executor = new SymbolicExecutor();
        const result = executor.execute(params.instructions, params.inputs, params.targetAddress);
        return { ...result };
      }

      case 'emulatorControl': {
        const emu = this.getEmulator();
        const action = params.action;

        if (action === 'reset') {
          if (params.instructions) {
            const mapped = params.instructions.map((inst: any) => {
              if (inst.mnemonic && inst.operands) return inst;
              const mnemonic = inst.mnemonic || inst.op;
              const operands = (inst.operands || inst.args || []).map((arg: any) => {
                if (typeof arg === 'object') {
                  if (arg.type === 'imm' && typeof arg.imm !== 'bigint') {
                    return { type: 'imm', imm: BigInt(arg.imm) };
                  }
                  return arg;
                }
                const trimmed = arg.trim();
                if (trimmed.startsWith('0x') || /^\d+$/.test(trimmed)) {
                  return { type: 'imm', imm: BigInt(trimmed) };
                }
                return { type: 'reg', reg: trimmed };
              });
              return {
                address: inst.address,
                bytes: inst.bytes || new Uint8Array(0),
                mnemonic,
                opStr: inst.opStr || (inst.args ? inst.args.join(', ') : ''),
                operands,
                size: inst.size || 4
              };
            });
            emu.loadInstructions(mapped);
          }
          emu.reset(params.entryPoint || 0);
          return { success: true, cpuState: { rip: emu.cpu.read('rip').toString(), rsp: emu.cpu.read('rsp').toString() } };
        } else if (action === 'step') {
          const steps = params.steps || 1;
          let lastRes = null;
          for (let i = 0; i < steps; i++) {
            lastRes = emu.step();
            if (!lastRes.success) break;
          }
          return {
            success: true,
            executionResult: lastRes,
            cpuState: {
              rip: emu.cpu.read('rip').toString(),
              rax: emu.cpu.read('rax').toString(),
              rsp: emu.cpu.read('rsp').toString()
            }
          };
        } else if (action === 'run') {
          emu.isRunning = true;
          // Step until halted or breakpoint
          let steps = 0;
          let res = { success: true, halted: false, hitBreakpoint: false };
          while (emu.isRunning && steps < (params.steps || 100)) {
            res = emu.step();
            steps++;
            if (!res.success || res.halted || res.hitBreakpoint) {
              break;
            }
          }
          return {
            success: true,
            executionResult: res,
            stepsRun: steps,
            cpuState: {
              rip: emu.cpu.read('rip').toString(),
              rax: emu.cpu.read('rax').toString()
            }
          };
        } else if (action === 'readReg') {
          const regs: Record<string, string> = {};
          if (params.registers) {
            for (const r of Object.keys(params.registers)) {
              regs[r] = emu.cpu.read(r).toString();
            }
          } else {
            // Read standard registers
            for (const r of ['rip', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']) {
              regs[r] = emu.cpu.read(r).toString();
            }
          }
          return { success: true, registers: regs };
        } else if (action === 'writeReg') {
          if (params.registers) {
            for (const [r, val] of Object.entries(params.registers)) {
              emu.cpu.write(r, BigInt(val as string));
            }
          }
          return { success: true };
        } else if (action === 'readMem') {
          const results = [];
          if (params.memory) {
            for (const m of params.memory) {
              const addr = BigInt(m.address);
              const size = m.size || 4;
              const buf = emu.memory.readBuffer(addr, size);
              results.push({ address: m.address, hex: toHex(buf) });
            }
          }
          return { success: true, memory: results };
        } else if (action === 'writeMem') {
          if (params.memory) {
            for (const m of params.memory) {
              const addr = BigInt(m.address);
              const val = toUint8Array(m.value);
              emu.memory.map(addr, val.length);
              emu.memory.writeBuffer(addr, val);
            }
          }
          return { success: true };
        }
        throw new Error(`Unsupported emulator action: ${action}`);
      }

      default:
        throw new Error(`Unsupported bridge action: ${action}`);
    }
  }
}
