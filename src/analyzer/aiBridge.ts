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
import { extractStrings } from './strings.js';
import { calculateEntropy, findHighEntropyBlocks, mapSectionEntropy } from './entropy.js';
import { XRefEngine } from './xrefs.js';
import { buildCFG } from '../disassembler/cfg.js';
import { Section, Symbol, Instruction } from '../disassembler/types.js';

/**
 * Helper to convert Hex or Base64 string to Uint8Array
 */
export function toUint8Array(input: any): Uint8Array {
  if (input instanceof Uint8Array) {
    if (input.byteLength > 10485760) {
      throw new Error('Input size exceeds 10MB limit');
    }
    return input;
  }
  if (typeof input !== 'string') {
    input = String(input || '');
  }
  const trimmed = input.trim();
  if (trimmed.length > 20971520) {
    throw new Error('Input size exceeds 10MB limit');
  }
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
    const estimatedLen = Math.floor((trimmed.length * 3) / 4);
    if (estimatedLen > 10485760) {
      throw new Error('Input size exceeds 10MB limit');
    }
    const binaryString = atob(trimmed);
    const len = binaryString.length;
    if (len > 10485760) {
      throw new Error('Input size exceeds 10MB limit');
    }
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch (e: any) {
    if (e?.message === 'Input size exceeds 10MB limit') {
      throw e;
    }
    // Treat as raw UTF-8 string bytes
    const bytes = new TextEncoder().encode(trimmed);
    if (bytes.length > 10485760) {
      throw new Error('Input size exceeds 10MB limit');
    }
    return bytes;
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
    description: 'Disassemble raw machine code or executable binary (supports ELF, PE, Mach-O, and raw shellcode) into structured assembly instructions. Parses target sections automatically or uses provided base virtual address. Supported architectures: x86_64, arm, riscv, thumb, wasm, dex, z80, etc. Example: disassembly of a function payload at base address 0x1000.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary/machine code to disassemble. Example: "9090" (NOPs).' },
        arch: { type: 'string', description: 'Target CPU architecture. Supported: "x86_64", "x86", "arm", "arm64", "riscv", "thumb", "wasm", "dex", "z80". Default is x86_64.' },
        baseAddress: { type: 'number', description: 'Virtual address offset at which to start disassembly. Defaults to 0 or binary section address.' }
      },
      required: ['data']
    }
  },
  decompile: {
    name: 'decompile',
    description: 'Decompile structured instructions or raw binary data (ELF, PE, Mach-O, or raw) into high-level, human-readable C-like pseudocode. Requires either instructions array or raw data with optional entry offset. Useful for reverse engineering and code flow analysis.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data to decompile.' },
        entryPoint: { type: 'number', description: 'Optional entry point virtual address/offset inside the binary to begin decompilation.' },
        instructions: {
          type: 'array',
          description: 'Optional list of pre-disassembled structured instructions to decompile.',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number', description: 'Virtual address of the instruction.' },
              op: { type: 'string', description: 'Mnemonic/opcode name (e.g., "mov", "jmp").' },
              args: { type: 'array', items: { type: 'string' }, description: 'Operands/arguments of the instruction.' }
            }
          }
        }
      }
    }
  },
  parseBinary: {
    name: 'parseBinary',
    description: 'Parse standard headers, section headers, symbol tables, and export/import directories from executable binaries. Supported formats: ELF (Linux/Android), PE (Windows), Mach-O (macOS/iOS), or "auto" to detect using magic bytes (e.g., 7F 45 4C 46 for ELF, 4D 5A for PE). Useful for parsing metadata.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary file content.' },
        format: { type: 'string', enum: ['elf', 'pe', 'macho', 'auto'], description: 'Format of binary to parse. Use "auto" to sniff magic bytes, or force "elf", "pe", or "macho".' }
      },
      required: ['data']
    }
  },
  patchBinary: {
    name: 'patchBinary',
    description: 'Apply byte-level patches to a binary at specific file offsets. Works on raw binaries, ELF, PE, and Mach-O. Patched sections are returned as a hex string.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded original binary data.' },
        offset: { type: 'number', description: 'Byte offset in the raw binary file where the patch should be applied.' },
        patchedBytes: { type: 'string', description: 'Hex or Base64 encoded replacement bytes.' },
        address: { type: 'number', description: 'Optional virtual address associated with the patch location for reference/logging.' },
        description: { type: 'string', description: 'Optional context, purpose, or summary of this specific patch.' },
        patches: {
          type: 'array',
          description: 'Alternative list of patch objects to apply sequentially.',
          items: {
            type: 'object',
            properties: {
              offset: { type: 'number', description: 'Byte offset in the raw binary file where the patch should be applied.' },
              patchedBytes: { type: 'string', description: 'Hex or Base64 encoded replacement bytes.' },
              address: { type: 'number', description: 'Virtual address associated with the patch location for reference/logging.' },
              description: { type: 'string', description: 'Optional context, purpose, or summary of this specific patch.' }
            },
            required: ['offset', 'patchedBytes', 'address']
          }
        }
      },
      required: ['data']
    }
  },
  executeScript: {
    name: 'executeScript',
    description: 'Run custom JavaScript/TypeScript analytical scripts against a binary using a sandboxed ScriptingEngine. Provides a pre-populated ScriptingContext containing binary data, entry points, sections, symbols, and instruction mappings. Useful for programmatic analysis, custom pattern search, or complex validation tasks.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data to analyse.' },
        script: { type: 'string', description: 'JavaScript code to execute. Can access variables like "context.binaryData" and return a result value.' }
      },
      required: ['data', 'script']
    }
  },
  yaraScan: {
    name: 'yaraScan',
    description: 'Scan binary files or raw byte sequences using text-based signature rules similar to YARA. Allows detecting malware, specific patterns, cryptography keys, or compiler signatures. Supports raw rules strings containing rule definitions, strings, and conditions.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data/memory dump to scan.' },
        rules: { type: 'string', description: 'YARA rule string to compile and scan against. Must define standard YARA syntax with rule name, strings, and condition.' }
      },
      required: ['data', 'rules']
    }
  },
  vulnScan: {
    name: 'vulnScan',
    description: 'Statically scan binary components (including disasm instructions, symbols/imports, raw strings, and decompiled code) against a set of rules for potential vulnerabilities (e.g. use of unsafe APIs like strcpy, buffer overflows, format string vulnerabilities). Returns list of matched vulnerabilities.',
    parameters: {
      type: 'object',
      properties: {
        instructions: { type: 'array', items: { type: 'object' }, description: 'Pre-disassembled instruction list to analyze for dangerous command sequences.' },
        strings: { type: 'array', items: { type: 'string' }, description: 'Extracted strings to check for hardcoded secrets, paths, URLs, or command strings.' },
        importNames: { type: 'array', items: { type: 'string' }, description: 'Names of imported functions (e.g., from PE import table or ELF PLT) to check for banned/unsafe APIs.' },
        decompiledText: { type: 'string', description: 'Optional C-like decompiled pseudocode to scan for structural vulnerabilities.' }
      }
    }
  },
  diffBinaries: {
    name: 'diffBinaries',
    description: 'Compare two binaries (e.g., original vs patched/modified version) or instruction sequences to find differences. Supports either byte-level diff (hex offsets and differences) or disassembled instruction-level diff to identify modifications in program flow.',
    parameters: {
      type: 'object',
      properties: {
        dataA: { type: 'string', description: 'Hex or Base64 encoded original binary A.' },
        dataB: { type: 'string', description: 'Hex or Base64 encoded modified/different binary B.' },
        type: { type: 'string', enum: ['bytes', 'instructions'], description: 'Comparison mode. "bytes" performs byte-by-byte delta, "instructions" disassembles both and compares instruction flows.' }
      },
      required: ['dataA', 'dataB']
    }
  },
  analyzeCodeAI: {
    name: 'analyzeCodeAI',
    description: 'Analyze assembly instructions or decompiled C code using the built-in AI engine. Generates descriptions of the code logic, hints on arguments and return values, complexity metrics, and suggests optimization or security improvements. Requires the source code text to analyze.',
    parameters: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Assembly instructions block or C-pseudocode to analyze.' },
        functionName: { type: 'string', description: 'Name or identifier of the function being analyzed to provide context.' },
        arch: { type: 'string', description: 'Architecture context (e.g., "x86_64", "arm") to guide the AI analyzer.' }
      },
      required: ['code']
    }
  },
  symbolicExecute: {
    name: 'symbolicExecute',
    description: 'Symbolically execute a list of structured mock assembly instructions to determine register/variable inputs that force execution to hit a target virtual address. Ideal for resolving simple branch conditions, validating key check algorithms, and generating input payloads.',
    parameters: {
      type: 'object',
      properties: {
        instructions: {
          type: 'array',
          description: 'A sequential list of instructions to execute symbolically.',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number', description: 'Instruction virtual address.' },
              op: { type: 'string', description: 'Opcode/mnemonic (e.g., "mov", "cmp", "add", "je", "jg").' },
              args: { type: 'array', items: { type: 'string' }, description: 'Operands list (registers or constants).' }
            },
            required: ['op', 'args']
          }
        },
        inputs: {
          type: 'array',
          description: 'Symbolic input variables with their bounds to constrain the search space.',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Name of the variable or register (e.g., "rax", "input_0").' },
              min: { type: 'number', description: 'Minimum allowed value for search (default 0).' },
              max: { type: 'number', description: 'Maximum allowed value for search (default 1000).' }
            },
            required: ['name']
          }
        },
        targetAddress: { type: 'number', description: 'The target virtual address/PC (Program Counter) we want execution to reach.' }
      },
      required: ['instructions', 'inputs', 'targetAddress']
    }
  },
  emulatorControl: {
    name: 'emulatorControl',
    description: 'Control a lightweight x86_64 processor emulator. Allows resetting execution state, loading a set of instructions, stepping/running, reading/writing registers, and reading/writing virtual memory. Crucial for dynamic analysis, tracking register values, and analyzing instruction side-effects.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['run', 'step', 'reset', 'readReg', 'writeReg', 'readMem', 'writeMem', 'load'], description: 'Emulator action to perform. "reset": initialize with instructions/entryPoint. "step"/"run": execute. "readReg"/"writeReg": manipulate registers. "readMem"/"writeMem": manipulate memory. "load": load PE/ELF/Mach-O/raw binary.' },
        instructions: { type: 'array', items: { type: 'object' }, description: 'Instructions to load when action is "reset".' },
        data: { type: 'string', description: 'Hex, Base64, or file path of executable binary to load (load only).' },
        entryPoint: { type: 'number', description: 'Entry point address for the binary (load/reset only).' },
        registers: { type: 'object', description: 'Register name to value mappings. Values can be numbers or strings representing BigInt.' },
        memory: {
          type: 'array',
          description: 'Memory regions to read or write.',
          items: {
            type: 'object',
            properties: {
              address: { type: 'string', description: 'Hex string or decimal virtual address representation.' },
              value: { type: 'string', description: 'Hex or Base64 encoded data to write (writeMem only).' },
              size: { type: 'number', description: 'Number of bytes to read (readMem only).' }
            }
          }
        },
        steps: { type: 'number', description: 'Number of instruction steps to execute for "step" or "run" (default 1 or 100).' }
      },
      required: ['action']
    }
  },
  extractStrings: {
    name: 'extractStrings',
    description: 'Scan binary data (ELF, PE, Mach-O, or raw) and extract printable strings. Supports custom minimum length, base address mapping, and selective scanning for ASCII/UTF-8, UTF-16 Little Endian (LE), or UTF-16 Big Endian (BE). Used for locating flag strings, URLs, paths, and metadata.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        minLength: { type: 'number', description: 'Minimum number of consecutive printable characters to constitute a string (default 4).' },
        baseAddress: { type: 'number', description: 'Base virtual address used to calculate absolute string offsets in memory.' },
        ascii: { type: 'boolean', description: 'Scan for standard ASCII and UTF-8 printable strings.' },
        utf16le: { type: 'boolean', description: 'Scan for UTF-16 Little Endian strings.' },
        utf16be: { type: 'boolean', description: 'Scan for UTF-16 Big Endian strings.' }
      },
      required: ['data']
    }
  },
  getSections: {
    name: 'getSections',
    description: 'Retrieve details (names, virtual addresses, virtual sizes, permissions, entropy) of sections present in an executable binary. Supports ELF, PE, and Mach-O formats. Format can be specified or auto-detected.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded executable binary.' },
        format: { type: 'string', enum: ['elf', 'pe', 'macho', 'auto'], description: 'Format of the binary (defaults to "auto").' }
      },
      required: ['data']
    }
  },
  entropyAnalysis: {
    name: 'entropyAnalysis',
    description: 'Calculate Shannon entropy across binary data or its sections to detect compression, encryption, or packed code. Scans using block size and stride to find high-entropy segments (e.g. above 7.0 entropy). Works on any raw or structured binary (ELF, PE, Mach-O).',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        blockSize: { type: 'number', description: 'Size of the scanning window in bytes (default 256).' },
        stride: { type: 'number', description: 'Step size/increment of window movement (default 64).' },
        threshold: { type: 'number', description: 'Minimum entropy value (0.0 to 8.0) to qualify block as high-entropy (default 7.0).' }
      },
      required: ['data']
    }
  },
  hexDump: {
    name: 'hexDump',
    description: 'Generate a classic formatted hex dump of the binary data, similar to hexdump or xxd. Shows offset address, hex representation of bytes, and ASCII representation. Useful for human verification of binary payloads.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        offset: { type: 'number', description: 'Start byte offset within binary data (default 0).' },
        limit: { type: 'number', description: 'Number of bytes to dump (alias for length).' },
        length: { type: 'number', description: 'Total number of bytes to dump (defaults to remaining bytes).' },
        bytesPerLine: { type: 'number', description: 'Number of bytes to display per line (default 16).' }
      },
      required: ['data']
    }
  },
  findXRefs: {
    name: 'findXRefs',
    description: 'Find incoming and outgoing cross-references (XRefs) for a specific target address in a binary file.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary content to analyze.' },
        address: { type: 'number', description: 'The target address to query cross-references for.' },
        arch: { type: 'string', description: 'Target CPU architecture. Default is x86_64.' },
        baseAddress: { type: 'number', description: 'Optional virtual address base for raw disassembling.' }
      },
      required: ['data', 'address']
    }
  },
  buildCFG: {
    name: 'buildCFG',
    description: 'Build a Control Flow Graph (CFG) from a sequence of assembly instructions, identifying basic blocks and successors.',
    parameters: {
      type: 'object',
      properties: {
        instructions: {
          type: 'array',
          description: 'A sequential list of instructions to build the CFG from.',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number', description: 'Instruction virtual address.' },
              mnemonic: { type: 'string', description: 'Mnemonic/opcode name (e.g., "mov", "jmp").' },
              opStr: { type: 'string', description: 'Operands/arguments string (e.g., "rax, rbx").' },
              operands: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    type: { type: 'string' },
                    reg: { type: 'string' },
                    imm: { type: 'number' },
                    mem: { type: 'object' }
                  }
                }
              },
              size: { type: 'number', description: 'Size of the instruction in bytes.' }
            },
            required: ['address', 'mnemonic', 'size']
          }
        }
      },
      required: ['instructions']
    }
  },
  loadBinary: {
    name: 'loadBinary',
    description: 'Load an executable binary into the session cache. All subsequent tool calls will use this loaded binary by default if "data" is omitted.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        filePath: { type: 'string', description: 'Local path of binary to load (resolved by server).' }
      }
    }
  },
  diffSections: {
    name: 'diffSections',
    description: 'Compare raw bytes of specific sections between two loaded binaries to find changed offsets and values.',
    parameters: {
      type: 'object',
      properties: {
        dataA: { type: 'string', description: 'Hex or Base64 encoded binary A (optional if session binary loaded).' },
        dataB: { type: 'string', description: 'Hex or Base64 encoded binary B.' },
        sections: { type: 'array', items: { type: 'string' }, description: 'List of section names to compare. Default: [".text"].' }
      },
      required: ['dataB']
    }
  },
  exportToIda: {
    name: 'exportToIda',
    description: 'Generate an IDC script containing function renames and string comments for importing into IDA Pro/Ghidra.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data (optional if session binary loaded).' }
      }
    }
  },
  patchAndRun: {
    name: 'patchAndRun',
    description: 'Apply byte-level patches to a binary and emulate execution starting from entrypoint until hitting target address or step limit.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data (optional if session binary loaded).' },
        patches: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              offset: { type: 'number', description: 'Byte offset in raw binary file.' },
              patchedBytes: { type: 'string', description: 'Hex or Base64 replacement bytes.' }
            },
            required: ['offset', 'patchedBytes']
          }
        },
        runUntil: { type: 'number', description: 'Virtual address/PC to run emulation until (breakpoint).' },
        maxSteps: { type: 'number', description: 'Maximum step limit for emulator execution. Default 1000.' }
      },
      required: ['patches']
    }
  },
  callTree: {
    name: 'callTree',
    description: 'Compute the callers and callees call tree for a specific function name or virtual address in the binary.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data (optional if session binary loaded).' },
        target: { type: 'string', description: 'Function name or virtual address (hex or decimal) to query.' },
        arch: { type: 'string', description: 'Target CPU architecture. Default is x86_64.' }
      },
      required: ['target']
    }
  },
  typeStructRecovery: {
    name: 'typeStructRecovery',
    description: 'Scan binary function instructions to reconstruct struct field layouts based on base registers and offset loads/stores.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data (optional if session binary loaded).' },
        address: { type: 'number', description: 'Virtual address of the function to analyze.' },
        arch: { type: 'string', description: 'Target CPU architecture. Default is x86_64.' }
      },
      required: ['address']
    }
  },
  emulatorHooks: {
    name: 'emulatorHooks',
    description: 'Manage emulation breakpoints and run emulation with breakpoint hit reporting.',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['run', 'setBreakpoints', 'clearBreakpoints'], description: 'Emulation action. "run": execute until breakpoint or halt. "setBreakpoints": configure breakpoint list.' },
        breakpoints: { type: 'array', items: { type: 'number' }, description: 'List of virtual addresses to use as breakpoints.' },
        steps: { type: 'number', description: 'Maximum steps to execute in "run" (default 1000).' }
      },
      required: ['action']
    }
  },
  pipelineChainMode: {
    name: 'pipelineChainMode',
    description: 'Execute a series of URET tools in sequence, passing outputs from one tool as inputs to subsequent tools using reference placeholders.',
    parameters: {
      type: 'object',
      properties: {
        pipeline: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              tool: { type: 'string', description: 'Name of the tool to execute.' },
              params: { type: 'object', description: 'Parameters for the tool, supporting "$$prev.property$$" placeholder resolution.' }
            },
            required: ['tool', 'params']
          }
        }
      },
      required: ['pipeline']
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
      if (!instructions || instructions.length === 0) {
        return { success: true, pathFound: false, constraints: [] };
      }

      const addrToIndex = new Map<number, number>();
      for (let i = 0; i < instructions.length; i++) {
        addrToIndex.set(instructions[i].address, i);
      }

      const initialState: Record<string, any> = {};
      for (const input of inputs) {
        initialState[input.name] = input.name;
      }

      const parseAddress = (val: string): number => {
        if (!val) return -1;
        if (val.startsWith('0x')) return parseInt(val, 16);
        if (/^\d+$/.test(val)) return parseInt(val, 10);
        return -1;
      };

      const cloneState = (s: Record<string, any>) => {
        const next: Record<string, any> = {};
        for (const [k, v] of Object.entries(s)) {
          if (v && typeof v === 'object') {
            next[k] = { op: v.op, args: [...v.args] };
          } else {
            next[k] = v;
          }
        }
        return next;
      };

      const cloneCmp = (c: { left: any; right: any } | null) => {
        if (!c) return null;
        const cloneVal = (v: any) => {
          if (v && typeof v === 'object') {
            return { op: v.op, args: [...v.args] };
          }
          return v;
        };
        return { left: cloneVal(c.left), right: cloneVal(c.right) };
      };

      interface PathState {
        pc: number;
        state: Record<string, any>;
        cmpState: { left: any; right: any } | null;
        constraints: string[];
        history: Map<number, number>;
      }

      const queue: PathState[] = [{
        pc: instructions[0].address,
        state: initialState,
        cmpState: null,
        constraints: [],
        history: new Map()
      }];

      let reachedState: PathState | null = null;
      let solutions: Record<string, number> | undefined;
      const maxSteps = 1000;
      let stepsCount = 0;

      while (queue.length > 0 && stepsCount < maxSteps) {
        const curr = queue.shift()!;
        stepsCount++;

        if (curr.pc === targetAddress) {
          reachedState = curr;
          const sol = this.solveConstraints(curr.constraints, inputs);
          if (sol) {
            solutions = sol;
            break;
          }
        }

        const instIdx = addrToIndex.get(curr.pc);
        if (instIdx === undefined || instIdx >= instructions.length) {
          continue;
        }

        const visited = curr.history.get(curr.pc) || 0;
        if (visited >= 3) {
          continue; // Loop bound
        }
        const nextHistory = new Map(curr.history);
        nextHistory.set(curr.pc, visited + 1);

        const inst = instructions[instIdx];
        const op = inst.op.toLowerCase();
        const arg0 = inst.args[0];
        const arg1 = inst.args[1];

        const resolve = (val: string) => {
          if (!val) return 0;
          if (val.startsWith('0x')) return parseInt(val, 16);
          if (/^\d+$/.test(val)) return parseInt(val, 10);
          if (val in curr.state) return curr.state[val];
          return val;
        };

        const fallthroughPc = instIdx + 1 < instructions.length ? instructions[instIdx + 1].address : -1;

        if (op === 'mov') {
          const nextState = cloneState(curr.state);
          nextState[arg0] = resolve(arg1);
          queue.push({
            pc: fallthroughPc,
            state: nextState,
            cmpState: cloneCmp(curr.cmpState),
            constraints: [...curr.constraints],
            history: nextHistory
          });
        } else if (['add', 'sub', 'mul', 'xor', 'div', 'or', 'and', 'shl', 'shr'].includes(op)) {
          const nextState = cloneState(curr.state);
          const l = resolve(arg0);
          const r = resolve(arg1);
          nextState[arg0] = { op, args: [l, r] };
          queue.push({
            pc: fallthroughPc,
            state: nextState,
            cmpState: cloneCmp(curr.cmpState),
            constraints: [...curr.constraints],
            history: nextHistory
          });
        } else if (op === 'cmp') {
          queue.push({
            pc: fallthroughPc,
            state: cloneState(curr.state),
            cmpState: { left: resolve(arg0), right: resolve(arg1) },
            constraints: [...curr.constraints],
            history: nextHistory
          });
        } else if (op === 'jmp') {
          const dest = parseAddress(arg0);
          if (dest !== -1) {
            queue.push({
              pc: dest,
              state: cloneState(curr.state),
              cmpState: cloneCmp(curr.cmpState),
              constraints: [...curr.constraints],
              history: nextHistory
            });
          }
        } else if (['je', 'jz', 'jne', 'jnz', 'jl', 'jnge', 'jle', 'jng', 'jg', 'jnle', 'jge', 'jnl'].includes(op)) {
          const dest = parseAddress(arg0);
          if (dest !== -1 && curr.cmpState) {
            const leftStr = this.stringify(curr.cmpState.left);
            const rightStr = this.stringify(curr.cmpState.right);

            let condTrue = '';
            let condFalse = '';
            if (op === 'je' || op === 'jz') {
              condTrue = `${leftStr} === ${rightStr}`;
              condFalse = `${leftStr} !== ${rightStr}`;
            } else if (op === 'jne' || op === 'jnz') {
              condTrue = `${leftStr} !== ${rightStr}`;
              condFalse = `${leftStr} === ${rightStr}`;
            } else if (op === 'jl' || op === 'jnge') {
              condTrue = `${leftStr} < ${rightStr}`;
              condFalse = `${leftStr} >= ${rightStr}`;
            } else if (op === 'jle' || op === 'jng') {
              condTrue = `${leftStr} <= ${rightStr}`;
              condFalse = `${leftStr} > ${rightStr}`;
            } else if (op === 'jg' || op === 'jnle') {
              condTrue = `${leftStr} > ${rightStr}`;
              condFalse = `${leftStr} <= ${rightStr}`;
            } else if (op === 'jge' || op === 'jnl') {
              condTrue = `${leftStr} >= ${rightStr}`;
              condFalse = `${leftStr} < ${rightStr}`;
            }

            // Taken branch path
            queue.push({
              pc: dest,
              state: cloneState(curr.state),
              cmpState: cloneCmp(curr.cmpState),
              constraints: [...curr.constraints, condTrue],
              history: nextHistory
            });

            // Not taken branch path
            if (fallthroughPc !== -1) {
              queue.push({
                pc: fallthroughPc,
                state: cloneState(curr.state),
                cmpState: cloneCmp(curr.cmpState),
                constraints: [...curr.constraints, condFalse],
                history: nextHistory
              });
            }
          } else {
            // Fallback: just follow fallthrough if cmpState missing or invalid dest
            if (fallthroughPc !== -1) {
              queue.push({
                pc: fallthroughPc,
                state: cloneState(curr.state),
                cmpState: cloneCmp(curr.cmpState),
                constraints: [...curr.constraints],
                history: nextHistory
              });
            }
          }
        } else {
          // Unsupported ops: just step through
          if (fallthroughPc !== -1) {
            queue.push({
              pc: fallthroughPc,
              state: cloneState(curr.state),
              cmpState: cloneCmp(curr.cmpState),
              constraints: [...curr.constraints],
              history: nextHistory
            });
          }
        }
      }

      return {
        success: true,
        pathFound: reachedState !== null,
        constraints: reachedState ? reachedState.constraints : [],
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
    const opMap: Record<string, string> = {
      'add': '+',
      'sub': '-',
      'mul': '*',
      'xor': '^',
      'div': '/',
      'or': '|',
      'and': '&',
      'shl': '<<',
      'shr': '>>'
    };
    const opStr = opMap[expr.op.toLowerCase()] || expr.op;
    return `(${argsStr[0]} ${opStr} ${argsStr[1]})`;
  }

  private solveConstraints(constraints: string[], inputs: { name: string; min?: number; max?: number }[]): Record<string, number> | undefined {
    if (inputs.length === 0) return {};
    const inputRanges = inputs.map(i => ({
      name: i.name,
      min: i.min ?? 0,
      max: i.max ?? 1000
    }));

    const evaluate = (expr: string, vars: Record<string, number>): boolean => {
      let replaced = expr;
      for (const [name, val] of Object.entries(vars)) {
        replaced = replaced.split(name).join(val.toString());
      }
      try {
        return new Function(`return ${replaced}`)();
      } catch {
        return false;
      }
    };

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
 * Helper to resolve ELF/PE base address, entrypoint, and slice data section
 */
interface ResolvedBinaryInfo {
  data: Uint8Array;
  baseAddress: number;
}

function resolveElfOrPe(
  bytes: Uint8Array,
  providedBaseAddress?: number,
  providedEntryPoint?: number
): ResolvedBinaryInfo {
  const baseAddr = providedBaseAddress !== undefined ? providedBaseAddress : providedEntryPoint;
  
  // Check if ELF
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
    try {
      const elf = parseElf(bytes.buffer as ArrayBuffer);
      let sliceBytes = bytes;
      let resolvedBase = baseAddr;

      if (resolvedBase === undefined || resolvedBase === null) {
        // Try .text section first
        const textSec = elf.sectionHeaders.find(s => s.name === '.text');
        if (textSec) {
          sliceBytes = bytes.subarray(Number(textSec.offset), Number(textSec.offset) + Number(textSec.size));
          resolvedBase = Number(textSec.addr);
        } else if (elf.header.entryPoint) {
          resolvedBase = Number(elf.header.entryPoint);
          const entryVaddr = BigInt(elf.header.entryPoint);
          const sec = elf.sectionHeaders.find(s => {
            const sAddr = BigInt(s.addr);
            const sSize = BigInt(s.size);
            return entryVaddr >= sAddr && entryVaddr < sAddr + sSize;
          });
          if (sec) {
            const offset = Number(sec.offset) + Number(entryVaddr - BigInt(sec.addr));
            sliceBytes = bytes.subarray(offset, Number(sec.offset) + Number(sec.size));
          }
        }
      } else {
        // Base address or entrypoint provided
        const vaddr = BigInt(resolvedBase);
        const sec = elf.sectionHeaders.find(s => {
          const sAddr = BigInt(s.addr);
          const sSize = BigInt(s.size);
          return vaddr >= sAddr && vaddr < sAddr + sSize;
        });
        if (sec) {
          const offset = Number(sec.offset) + Number(vaddr - BigInt(sec.addr));
          sliceBytes = bytes.subarray(offset, Number(sec.offset) + Number(sec.size));
        }
      }

      return { data: sliceBytes, baseAddress: resolvedBase ?? 0 };
    } catch (e) {
      // ignore
    }
  }

  // Check if PE
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    try {
      const pe = new PEParser(bytes.buffer as ArrayBuffer).parse();
      let sliceBytes = bytes;
      let resolvedBase = baseAddr;

      const rvaToOffset = (rva: number): number => {
        for (const section of pe.sections) {
          const va = section.virtualAddress;
          const vs = section.virtualSize;
          const sd = section.sizeOfRawData;
          const limit = va + (vs > sd ? vs : sd);
          if (rva >= va && rva < limit) {
            return rva - va + section.pointerToRawData;
          }
        }
        return 0;
      };

      if (resolvedBase === undefined || resolvedBase === null) {
        // Try .text section first
        const textSec = pe.sections.find(s => s.name === '.text');
        if (textSec) {
          sliceBytes = bytes.subarray(textSec.pointerToRawData, textSec.pointerToRawData + textSec.sizeOfRawData);
          resolvedBase = Number(pe.optionalHeader.imageBase) + textSec.virtualAddress;
        } else if (pe.optionalHeader.addressOfEntryPoint) {
          resolvedBase = Number(pe.optionalHeader.imageBase) + pe.optionalHeader.addressOfEntryPoint;
          const entryOffset = rvaToOffset(pe.optionalHeader.addressOfEntryPoint);
          if (entryOffset > 0) {
            const sec = pe.sections.find(s => {
              const va = s.virtualAddress;
              const vs = s.virtualSize;
              const sd = s.sizeOfRawData;
              const limit = va + (vs > sd ? vs : sd);
              return pe.optionalHeader.addressOfEntryPoint >= va && pe.optionalHeader.addressOfEntryPoint < limit;
            });
            if (sec) {
              sliceBytes = bytes.subarray(entryOffset, sec.pointerToRawData + sec.sizeOfRawData);
            } else {
              sliceBytes = bytes.subarray(entryOffset);
            }
          }
        }
      } else {
        // Base address or entrypoint provided
        let rva = resolvedBase;
        const imgBase = Number(pe.optionalHeader.imageBase);
        if (rva >= imgBase) {
          rva -= imgBase;
        }
        const offset = rvaToOffset(rva);
        if (offset > 0) {
          const sec = pe.sections.find(s => {
            const va = s.virtualAddress;
            const vs = s.virtualSize;
            const sd = s.sizeOfRawData;
            const limit = va + (vs > sd ? vs : sd);
            return rva >= va && rva < limit;
          });
          if (sec) {
            sliceBytes = bytes.subarray(offset, sec.pointerToRawData + sec.sizeOfRawData);
          } else {
            sliceBytes = bytes.subarray(offset);
          }
        }
      }

      return { data: sliceBytes, baseAddress: resolvedBase ?? 0 };
    } catch (e) {
      // ignore
    }
  }

  return {
    data: bytes,
    baseAddress: baseAddr ?? 0
  };
}

/**
 * Unified AI Query Bridge for URET
 */
export class AIBridge {
  private static emulatorInstance: Emulator | null = null;
  private static loadedBinaryBytes: Uint8Array | null = null;

  private static getEmulator(): Emulator {
    if (!this.emulatorInstance) {
      this.emulatorInstance = new Emulator();
    }
    return this.emulatorInstance;
  }

  public static async executeQuery(query: { action: string; params: any }): Promise<any> {
    const { action, params } = query;

    if (params) {
      if (!params.data && !params.dataA && !params.instructions && AIBridge.loadedBinaryBytes) {
        params.data = toHex(AIBridge.loadedBinaryBytes);
      }
      if (!params.dataA && AIBridge.loadedBinaryBytes) {
        params.dataA = toHex(AIBridge.loadedBinaryBytes);
      }
    }

    switch (action) {
      case 'disassemble': {
        const bytes = toUint8Array(params.data);
        const resolved = resolveElfOrPe(bytes, params.baseAddress ?? params.address, undefined);
        const router = new DisassemblerRouter();
        const insts = router.disassemble(resolved.data, {
          arch: params.arch,
          baseAddress: resolved.baseAddress
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
          const resolved = resolveElfOrPe(bytes, undefined, params.entryPoint ?? params.address ?? params.baseAddress);
          const router = new DisassemblerRouter();
          insts = router.disassemble(resolved.data, {
            baseAddress: resolved.baseAddress
          });
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
          const entryPoint = Number(parsed.header.entryPoint);
          return {
            success: true,
            format: 'elf',
            header: parsed.header,
            sections: parsed.sectionHeaders,
            symbols: parsed.symbols,
            entryPoint,
            entryPointAddress: entryPoint
          };
        } else if (detected === 'pe') {
          const parser = new PEParser(bytes.buffer as ArrayBuffer);
          const parsed = parser.parse();
          const entryPoint = parsed.optionalHeader?.addressOfEntryPoint || 0;
          const imageBase = parsed.optionalHeader?.imageBase || 0;
          const entryPointAddress = Number(imageBase) + entryPoint;
          return {
            success: true,
            format: 'pe',
            header: parsed.coffHeader,
            sections: parsed.sections,
            imports: parsed.imports,
            entryPoint,
            entryPointAddress,
            entryPointRVA: entryPoint,
            imageBase: typeof imageBase === 'bigint' ? imageBase.toString() : imageBase
          };
        } else if (detected === 'macho') {
          const parser = new MachoParser(bytes);
          const parsed = parser.parse();
          let entryPoint = 0;
          const lcMain = parsed.loadCommands.find(lc => lc.cmd === 0x80000028);
          if (lcMain && lcMain.payload && typeof (lcMain.payload as any).entryoff === 'number') {
            entryPoint = (lcMain.payload as any).entryoff;
          }
          const textSegment = parsed.segments.find(seg => seg.segname === '__TEXT');
          const imageBase = textSegment ? Number(textSegment.vmaddr) : 0;
          const entryPointAddress = imageBase + entryPoint;
          return {
            success: true,
            format: 'macho',
            header: parsed.header,
            sections: parsed.sections,
            symbols: parsed.symbols,
            entryPoint,
            entryPointAddress,
            imageBase
          };
        }
        throw new Error(`Unsupported binary format: ${detected}`);
      }

      case 'patchBinary': {
        const bytes = toUint8Array(params.data);
        const patcher = new BinaryPatcher(bytes);
        const records = [];
        if (params.offset !== undefined && params.patchedBytes !== undefined) {
          const patBytes = toUint8Array(params.patchedBytes);
          const rec = patcher.applyPatch(params.offset, patBytes, params.address || params.offset, params.description || '');
          records.push(rec);
        } else if (params.patches && Array.isArray(params.patches)) {
          for (const p of params.patches) {
            const patBytes = toUint8Array(p.patchedBytes);
            const rec = patcher.applyPatch(p.offset, patBytes, p.address || p.offset, p.description || '');
            records.push(rec);
          }
        } else {
          throw new Error('Missing patch parameters: either specify top-level "offset" and "patchedBytes", or a "patches" array.');
        }
        return {
          success: true,
          patchedData: toHex(patcher.getPatchedBinary()),
          records
        };
      }

      case 'executeScript': {
        const bytes = toUint8Array(params.data);
        let detected = 'auto';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
          detected = 'elf';
        } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
          detected = 'pe';
        } else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) {
          detected = 'macho';
        }

        let entryPoint = 0;
        let sections: any[] = [];
        let symbols: any[] = [];
        let imports: any[] = [];
        let exports: any[] = [];

        if (detected === 'elf') {
          try {
            const parsed = parseElf(bytes.buffer as ArrayBuffer);
            entryPoint = Number(parsed.header.entryPoint);
            sections = parsed.sectionHeaders.map(s => ({
              name: s.name,
              virtualAddress: Number(s.addr),
              virtualSize: Number(s.size),
              fileOffset: Number(s.offset),
              fileSize: Number(s.size),
              flags: {
                read: (Number(s.flags) & 4) !== 0 || true,
                write: (Number(s.flags) & 1) !== 0,
                execute: (Number(s.flags) & 2) !== 0
              }
            }));
            symbols = parsed.symbols.map(sym => ({
              name: sym.name,
              address: Number(sym.value),
              size: Number(sym.size),
              type: sym.type === 'FUNC' ? 'function' : 'object',
              binding: sym.bind === 'GLOBAL' ? 'global' : 'local'
            }));
          } catch (_) {
            // Ignore parsing errors and fallback
          }
        } else if (detected === 'pe') {
          try {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const parsed = parser.parse();
            entryPoint = Number(parsed.optionalHeader.imageBase) + parsed.optionalHeader.addressOfEntryPoint;
            sections = parsed.sections.map(s => ({
              name: s.name,
              virtualAddress: Number(parsed.optionalHeader.imageBase) + s.virtualAddress,
              virtualSize: s.virtualSize,
              fileOffset: s.pointerToRawData,
              fileSize: s.sizeOfRawData,
              flags: {
                read: (s.characteristics & 0x40000000) !== 0,
                write: (s.characteristics & 0x80000000) !== 0,
                execute: (s.characteristics & 0x20000000) !== 0
              }
            }));
            imports = parsed.imports.flatMap(imp => imp.imports.map(i => ({ library: imp.dllName, name: i.name || '', address: i.iatRva ? Number(parsed.optionalHeader.imageBase) + i.iatRva : undefined })));
            if (parsed.exports) {
              exports = parsed.exports.exports.map(e => ({ name: e.name || '', address: e.address }));
            }
          } catch (_) {
            // Ignore parsing errors and fallback
          }
        } else if (detected === 'macho') {
          try {
            const parser = new MachoParser(bytes);
            const parsed = parser.parse();
            entryPoint = 0;
            sections = parsed.sections.map((s: any) => ({
              name: s.sectname,
              virtualAddress: Number(s.addr),
              virtualSize: Number(s.size),
              fileOffset: s.offset,
              fileSize: Number(s.size),
              flags: { read: true, write: true, execute: true }
            }));
            symbols = parsed.symbols.map((sym: any) => ({
              name: sym.name,
              address: Number(sym.value),
              size: 0,
              type: sym.symbolType,
              binding: sym.binding
            }));
          } catch (_) {
            // Ignore parsing errors and fallback
          }
        }

        if (sections.length === 0) {
          sections = [{ name: '.text', virtualAddress: 0, virtualSize: bytes.length, fileOffset: 0, fileSize: bytes.length, flags: { read: true, write: false, execute: true } }];
        }

        let instructions: any[] = [];
        try {
          const resolved = resolveElfOrPe(bytes, undefined, entryPoint);
          const router = new DisassemblerRouter();
          const insts = router.disassemble(resolved.data, {
            baseAddress: resolved.baseAddress
          });
          instructions = insts.map(inst => ({
            ...inst,
            op: inst.mnemonic,
            args: inst.opStr ? inst.opStr.split(',').map(s => s.trim()) : []
          }));
        } catch (_) {
          // Ignore disasm errors and proceed
        }

        let extractedStrings: any[] = [];
        try {
          extractedStrings = extractStrings(bytes, { minLength: 4, ascii: true, utf16le: true });
        } catch (_) {
          // Ignore string extraction errors
        }

        const context: ScriptingContext = {
          binaryData: bytes,
          entryPoint,
          sections,
          symbols,
          instructions,
          extractedStrings,
          dependencies: {
            binaryName: params.dataName || 'binary',
            imports,
            exports,
            locals: []
          }
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
              const data = toUint8Array(m.value);
              try {
                emu.memory.writeBuffer(addr, data);
              } catch (e) {
                emu.memory.map(addr, data.length);
                emu.memory.writeBuffer(addr, data);
              }
            }
          }
          return { success: true };
        } else if (action === 'load') {
          if (!params.data) {
            throw new Error('Missing "data" parameter for load action');
          }
          const bytes = toUint8Array(params.data);
          let detected = 'auto';
          if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
            detected = 'elf';
          } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
            detected = 'pe';
          } else if (
            (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
            (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
          ) {
            detected = 'macho';
          }

          let entryPoint = 0;

          if (detected === 'elf') {
            const parsed = parseElf(bytes.buffer as ArrayBuffer);
            entryPoint = Number(parsed.header.entryPoint);
            emu.reset(entryPoint);

            if (parsed.programHeaders && parsed.programHeaders.length > 0) {
              for (const ph of parsed.programHeaders) {
                if (ph.type === 1) { // PT_LOAD
                  const vaddr = BigInt(ph.vaddr);
                  const memsz = Number(ph.memsz);
                  const filesz = Number(ph.filesz);
                  const offset = Number(ph.offset);
                  if (memsz > 0) {
                    emu.memory.map(vaddr, memsz);
                    if (filesz > 0) {
                      const segmentData = bytes.subarray(offset, offset + filesz);
                      emu.memory.writeBuffer(vaddr, segmentData);
                    }
                  }
                }
              }
            } else {
              for (const sec of parsed.sectionHeaders) {
                const size = Number(sec.size);
                const addr = BigInt(sec.addr);
                const offset = Number(sec.offset);
                if (size > 0 && addr > 0n) {
                  emu.memory.map(addr, size);
                  const secData = bytes.subarray(offset, offset + size);
                  emu.memory.writeBuffer(addr, secData);
                }
              }
            }
          } else if (detected === 'pe') {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const parsed = parser.parse();
            const imageBase = Number(parsed.optionalHeader.imageBase);
            entryPoint = imageBase + parsed.optionalHeader.addressOfEntryPoint;
            emu.reset(entryPoint);

            for (const sec of parsed.sections) {
              const size = sec.virtualSize || sec.sizeOfRawData;
              const addr = BigInt(imageBase + sec.virtualAddress);
              if (size > 0) {
                emu.memory.map(addr, size);
                if (sec.sizeOfRawData > 0) {
                  const secData = bytes.subarray(sec.pointerToRawData, sec.pointerToRawData + sec.sizeOfRawData);
                  emu.memory.writeBuffer(addr, secData);
                }
              }
            }
          } else if (detected === 'macho') {
            const parser = new MachoParser(bytes);
            const parsed = parser.parse();
            entryPoint = 0;
            emu.reset(entryPoint);
            for (const s of parsed.sections) {
              const size = Number(s.size);
              const addr = BigInt(s.addr);
              if (size > 0) {
                emu.memory.map(addr, size);
                const secData = bytes.subarray(s.offset, s.offset + size);
                emu.memory.writeBuffer(addr, secData);
              }
            }
          } else {
            entryPoint = params.entryPoint || 0;
            emu.reset(entryPoint);
            emu.memory.map(BigInt(entryPoint), bytes.length);
            emu.memory.writeBuffer(BigInt(entryPoint), bytes);
          }

          emu.cpu.write('rip', BigInt(entryPoint));

          return {
            success: true,
            entryPoint,
            cpuState: {
              rip: emu.cpu.read('rip').toString(),
              rsp: emu.cpu.read('rsp').toString()
            }
          };
        }
        throw new Error(`Unsupported emulator action: ${action}`);
      }

      case 'extractStrings': {
        const bytes = toUint8Array(params.data);
        const options = {
          minLength: params.minLength,
          baseAddress: params.baseAddress,
          ascii: params.ascii,
          utf16le: params.utf16le,
          utf16be: params.utf16be
        };
        const strings = extractStrings(bytes, options);
        return { success: true, strings };
      }

      case 'getSections': {
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

        let sections: any[] = [];
        if (detected === 'elf') {
          const parsed = parseElf(bytes.buffer as ArrayBuffer);
          sections = parsed.sectionHeaders;
        } else if (detected === 'pe') {
          const parser = new PEParser(bytes.buffer as ArrayBuffer);
          const parsed = parser.parse();
          sections = parsed.sections;
        } else if (detected === 'macho') {
          const parser = new MachoParser(bytes);
          const parsed = parser.parse();
          sections = parsed.sections;
        }
        return { success: true, format: detected, sections };
      }

      case 'entropyAnalysis': {
        const bytes = toUint8Array(params.data);
        const overall = calculateEntropy(bytes);
        const blocks = findHighEntropyBlocks(bytes, {
          blockSize: params.blockSize,
          stride: params.stride,
          threshold: params.threshold
        });

        let format = 'unknown';
        const sectionBreakdown: { name: string; offset: number; size: number; entropy: number }[] = [];

        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
          format = 'elf';
        } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
          format = 'pe';
        } else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) {
          format = 'macho';
        }

        try {
          if (format === 'elf') {
            const parsed = parseElf(bytes.buffer as ArrayBuffer);
            for (const section of parsed.sectionHeaders) {
              const secOffset = Number(section.offset);
              const secSize = Number(section.size);
              if (secOffset > 0 && secSize > 0 && secOffset + secSize <= bytes.length) {
                const secBytes = bytes.subarray(secOffset, secOffset + secSize);
                const entropy = calculateEntropy(secBytes);
                sectionBreakdown.push({ name: section.name, offset: secOffset, size: secSize, entropy });
              }
            }
          } else if (format === 'pe') {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const parsed = parser.parse();
            for (const section of parsed.sections) {
              const secOffset = section.pointerToRawData;
              const secSize = section.sizeOfRawData;
              if (secOffset > 0 && secSize > 0 && secOffset + secSize <= bytes.length) {
                const secBytes = bytes.subarray(secOffset, secOffset + secSize);
                const entropy = calculateEntropy(secBytes);
                sectionBreakdown.push({ name: section.name, offset: secOffset, size: secSize, entropy });
              }
            }
          } else if (format === 'macho') {
            const parser = new MachoParser(bytes);
            const parsed = parser.parse();
            for (const section of parsed.sections) {
              const secOffset = section.offset;
              const secSize = Number(section.size);
              if (secOffset > 0 && secSize > 0 && secOffset + secSize <= bytes.length) {
                const secBytes = bytes.subarray(secOffset, secOffset + secSize);
                const entropy = calculateEntropy(secBytes);
                sectionBreakdown.push({ name: section.sectname, offset: secOffset, size: secSize, entropy });
              }
            }
          }
        } catch (_) {
          // ignore parsing error for sections, fallback to empty array
        }

        return {
          success: true,
          overall,
          highEntropyBlocks: blocks.filter(b => b.isHighEntropy),
          sectionBreakdown
        };
      }

      case 'hexDump': {
        const bytes = toUint8Array(params.data);
        const offset = params.offset || 0;
        const limit = params.limit !== undefined ? params.limit : params.length;
        const length = limit !== undefined ? limit : bytes.length - offset;
        const bytesPerLine = params.bytesPerLine || 16;

        const startOffset = Math.max(0, Math.min(offset, bytes.length));
        const endOffset = Math.max(startOffset, Math.min(startOffset + length, bytes.length));
        const sub = bytes.subarray(startOffset, endOffset);
        const lines: string[] = [];

        for (let i = 0; i < sub.length; i += bytesPerLine) {
          const lineAddr = offset + i;
          const chunk = sub.subarray(i, i + bytesPerLine);
          
          const hexParts: string[] = [];
          for (let j = 0; j < bytesPerLine; j++) {
            if (j < chunk.length) {
              hexParts.push(chunk[j].toString(16).padStart(2, '0'));
            } else {
              hexParts.push('  ');
            }
          }

          const asciiParts: string[] = [];
          for (let j = 0; j < chunk.length; j++) {
            const b = chunk[j];
            if (b >= 0x20 && b <= 0x7e) {
              asciiParts.push(String.fromCharCode(b));
            } else {
              asciiParts.push('.');
            }
          }

          const addrHex = lineAddr.toString(16).padStart(8, '0');
          const hexStr = hexParts.join(' ');
          const asciiStr = asciiParts.join('');
          lines.push(`${addrHex}  ${hexStr}  |${asciiStr}|`);
        }

        return {
          success: true,
          formatted: lines.join('\n'),
          lines
        };
      }

      case 'findXRefs': {
        const bytes = toUint8Array(params.data);
        let sections: Section[] = [];
        let symbols: Symbol[] = [];
        let baseAddress = params.baseAddress ?? params.address ?? 0;

        let detected = 'auto';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
          detected = 'elf';
        } else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
          detected = 'pe';
        } else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) {
          detected = 'macho';
        }

        if (detected === 'elf') {
          try {
            const elf = parseElf(bytes.buffer as ArrayBuffer);
            sections = elf.sectionHeaders.map(s => {
              const flagsNum = Number(s.flags);
              const isWritable = (flagsNum & 1) !== 0;
              const isAlloc = (flagsNum & 2) !== 0;
              const isExecutable = (flagsNum & 4) !== 0;
              return {
                name: s.name,
                virtualAddress: Number(s.addr),
                virtualSize: Number(s.size),
                fileOffset: Number(s.offset),
                fileSize: Number(s.size),
                flags: { read: isAlloc, write: isWritable, execute: isExecutable }
              };
            });
            symbols = elf.symbols.map(sym => ({
              name: sym.name,
              address: Number(sym.value),
              size: Number(sym.size),
              type: sym.type === 'FUNC' ? 'function' : sym.type === 'OBJECT' ? 'object' : 'none',
              binding: sym.bind === 'GLOBAL' ? 'global' : sym.bind === 'WEAK' ? 'weak' : 'local'
            }));
            baseAddress = Number(elf.header.entryPoint);
          } catch (_) {
            // fallback
          }
        } else if (detected === 'pe') {
          try {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const pe = parser.parse();
            const imgBase = Number(pe.optionalHeader.imageBase);
            sections = pe.sections.map(s => {
              const isExecutable = (s.characteristics & 0x20000000) !== 0;
              const isReadable = (s.characteristics & 0x40000000) !== 0;
              const isWritable = (s.characteristics & 0x80000000) !== 0;
              return {
                name: s.name,
                virtualAddress: imgBase + s.virtualAddress,
                virtualSize: s.virtualSize,
                fileOffset: s.pointerToRawData,
                fileSize: s.sizeOfRawData,
                flags: { read: isReadable, write: isWritable, execute: isExecutable }
              };
            });
            baseAddress = imgBase + pe.optionalHeader.addressOfEntryPoint;
          } catch (_) {
            // fallback
          }
        } else if (detected === 'macho') {
          try {
            const parser = new MachoParser(bytes);
            const macho = parser.parse();
            sections = macho.sections.map(s => {
              const isText = s.sectname === '__text' || s.segname === '__TEXT';
              return {
                name: s.sectname,
                virtualAddress: Number(s.addr),
                virtualSize: Number(s.size),
                fileOffset: s.offset,
                fileSize: Number(s.size),
                flags: { read: true, write: s.segname === '__DATA', execute: isText }
              };
            });
            symbols = macho.symbols.map(sym => ({
              name: sym.name,
              address: Number(sym.value),
              binding: 'global',
              type: 'none'
            }));
          } catch (_) {
            // fallback
          }
        }

        if (sections.length === 0) {
          sections = [{
            name: '.text',
            virtualAddress: baseAddress,
            virtualSize: bytes.length,
            fileOffset: 0,
            fileSize: bytes.length,
            flags: { read: true, write: false, execute: true }
          }];
        }

        const router = new DisassemblerRouter();
        const allInstructions: Instruction[] = [];
        for (const sec of sections) {
          if (sec.flags.execute && sec.fileSize > 0) {
            try {
              const secBytes = bytes.subarray(sec.fileOffset, sec.fileOffset + sec.fileSize);
              const insts = router.disassemble(secBytes, {
                arch: params.arch || 'x86_64',
                baseAddress: sec.virtualAddress
              });
              const mappedInsts = insts.map(inst => ({
                ...inst,
                op: inst.mnemonic,
                args: inst.opStr ? inst.opStr.split(',').map(s => s.trim()) : []
              }));
              allInstructions.push(...mappedInsts);
            } catch (_) {
              // ignore
            }
          }
        }

        if (allInstructions.length === 0) {
          try {
            const insts = router.disassemble(bytes, {
              arch: params.arch || 'x86_64',
              baseAddress: baseAddress
            });
            const mappedInsts = insts.map(inst => ({
              ...inst,
              op: inst.mnemonic,
              args: inst.opStr ? inst.opStr.split(',').map(s => s.trim()) : []
            }));
            allInstructions.push(...mappedInsts);
          } catch (_) {
            // ignore
          }
        }

        const engine = new XRefEngine();
        engine.analyze(allInstructions, sections, symbols, bytes, baseAddress);

        const targetAddr = Number(params.address);
        const incoming = engine.getXRefsTo(targetAddr);
        const outgoing = engine.getXRefsFrom(targetAddr);

        return { success: true, incoming, outgoing };
      }

      case 'buildCFG': {
        const insts: any[] = params.instructions;
        if (!insts || !Array.isArray(insts)) {
          throw new Error('Instructions array is required');
        }
        const mappedInsts = insts.map((inst: any) => ({
          address: Number(inst.address),
          bytes: inst.bytes instanceof Uint8Array ? inst.bytes : new Uint8Array(),
          mnemonic: inst.mnemonic || inst.op || '',
          opStr: inst.opStr || (inst.args ? inst.args.join(', ') : ''),
          operands: inst.operands || [],
          size: Number(inst.size || 1)
        }));
        const blocks = buildCFG(mappedInsts);
        return { success: true, blocks };
      }

      case 'loadBinary': {
        if (!params.data && !params.filePath) {
          throw new Error('Either "data" or "filePath" must be provided');
        }
        let bytes: Uint8Array;
        if (params.filePath) {
          try {
            const fs = await import('fs');
            if (fs.existsSync(params.filePath)) {
              bytes = new Uint8Array(fs.readFileSync(params.filePath));
            } else {
              bytes = toUint8Array(params.filePath);
            }
          } catch (e) {
            bytes = toUint8Array(params.filePath);
          }
        } else {
          bytes = toUint8Array(params.data);
        }
        AIBridge.loadedBinaryBytes = bytes;
        
        let detected = 'unknown';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) detected = 'elf';
        else if (bytes[0] === 0x4d && bytes[1] === 0x5a) detected = 'pe';
        else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) detected = 'macho';

        return { success: true, message: 'Binary loaded successfully into session context', size: bytes.length, format: detected };
      }

      case 'diffSections': {
        const bytesA = toUint8Array(params.dataA);
        const bytesB = toUint8Array(params.dataB);
        const sectionsList = params.sections || ['.text'];

        const getSectionsData = (bytes: Uint8Array): Record<string, Uint8Array> => {
          const res: Record<string, Uint8Array> = {};
          let detected = 'auto';
          if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) detected = 'elf';
          else if (bytes[0] === 0x4d && bytes[1] === 0x5a) detected = 'pe';
          else if (
            (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
            (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
          ) detected = 'macho';

          try {
            if (detected === 'elf') {
              const parsed = parseElf(bytes.buffer as ArrayBuffer);
              for (const s of parsed.sectionHeaders) {
                const off = Number(s.offset);
                const sz = Number(s.size);
                if (off > 0 && sz > 0 && off + sz <= bytes.length) {
                  res[s.name] = bytes.subarray(off, off + sz);
                }
              }
            } else if (detected === 'pe') {
              const parser = new PEParser(bytes.buffer as ArrayBuffer);
              const parsed = parser.parse();
              for (const s of parsed.sections) {
                const off = s.pointerToRawData;
                const sz = s.sizeOfRawData;
                if (off > 0 && sz > 0 && off + sz <= bytes.length) {
                  res[s.name] = bytes.subarray(off, off + sz);
                }
              }
            } else if (detected === 'macho') {
              const parser = new MachoParser(bytes);
              const parsed = parser.parse();
              for (const s of parsed.sections) {
                const off = s.offset;
                const sz = Number(s.size);
                if (off > 0 && sz > 0 && off + sz <= bytes.length) {
                  res[s.sectname] = bytes.subarray(off, off + sz);
                }
              }
            }
          } catch (_) {}
          return res;
        };

        const secA = getSectionsData(bytesA);
        const secB = getSectionsData(bytesB);
        const diffs: Record<string, { sizeA: number; sizeB: number; differences: { offset: number; valA: number; valB: number }[] }> = {};

        for (const name of sectionsList) {
          const bufA = secA[name] || new Uint8Array(0);
          const bufB = secB[name] || new Uint8Array(0);
          const differences: { offset: number; valA: number; valB: number }[] = [];
          const maxLen = Math.max(bufA.length, bufB.length);
          
          for (let i = 0; i < maxLen; i++) {
            const vA = i < bufA.length ? bufA[i] : -1;
            const vB = i < bufB.length ? bufB[i] : -1;
            if (vA !== vB) {
              differences.push({ offset: i, valA: vA, valB: vB });
            }
            if (differences.length >= 100) break;
          }
          diffs[name] = { sizeA: bufA.length, sizeB: bufB.length, differences };
        }

        return { success: true, diffs };
      }

      case 'exportToIda': {
        const bytes = toUint8Array(params.data);
        let detected = 'auto';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) detected = 'elf';
        else if (bytes[0] === 0x4d && bytes[1] === 0x5a) detected = 'pe';
        else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) detected = 'macho';

        let symbols: any[] = [];
        let imgBase = 0;
        try {
          if (detected === 'elf') {
            const parsed = parseElf(bytes.buffer as ArrayBuffer);
            symbols = parsed.symbols.map(s => ({ name: s.name, address: Number(s.value) }));
            imgBase = Number(parsed.header.entryPoint);
          } else if (detected === 'pe') {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const parsed = parser.parse();
            imgBase = Number(parsed.optionalHeader.imageBase);
            symbols = (parsed.imports || []).flatMap(imp => imp.imports.map(i => ({ name: i.name, address: imgBase + (i.iatRva || 0) })));
          } else if (detected === 'macho') {
            const parser = new MachoParser(bytes);
            const parsed = parser.parse();
            symbols = parsed.symbols.map(s => ({ name: s.name, address: Number(s.value) }));
          }
        } catch (_) {}

        let idc = '#include <idc.idc>\n\nstatic main() {\n';
        for (const sym of symbols) {
          if (sym.name && sym.address > 0) {
            idc += `  MakeName(0x${sym.address.toString(16)}, "${sym.name.replace(/[^a-zA-Z0-9_]/g, '_')}");\n`;
          }
        }
        idc += '  Message("URET Symbols imported!\\n");\n}\n';
        return { success: true, format: 'idc', script: idc };
      }

      case 'patchAndRun': {
        const bytes = toUint8Array(params.data);
        const patcher = new BinaryPatcher(bytes);
        if (params.patches && Array.isArray(params.patches)) {
          for (const p of params.patches) {
            const patBytes = toUint8Array(p.patchedBytes);
            patcher.applyPatch(p.offset, patBytes, p.address || p.offset, p.description || '');
          }
        }
        const patched = patcher.getPatchedBinary();
        
        const emu = this.getEmulator();
        await this.executeQuery({ action: 'emulatorControl', params: { action: 'load', data: toHex(patched) } });
        
        const runUntil = params.runUntil;
        const maxSteps = params.maxSteps || 1000;
        let steps = 0;
        let res = { success: true, halted: false, hitBreakpoint: false };
        emu.isRunning = true;
        
        while (emu.isRunning && steps < maxSteps) {
          const currentRip = Number(emu.cpu.read('rip'));
          if (runUntil !== undefined && currentRip === runUntil) {
            res.hitBreakpoint = true;
            break;
          }
          res = emu.step();
          steps++;
          if (!res.success || res.halted || res.hitBreakpoint) {
            break;
          }
        }

        return {
          success: true,
          stepsRun: steps,
          halted: res.halted,
          hitBreakpoint: res.hitBreakpoint,
          cpuState: {
            rip: emu.cpu.read('rip').toString(),
            rax: emu.cpu.read('rax').toString(),
            rsp: emu.cpu.read('rsp').toString()
          }
        };
      }

      case 'callTree': {
        const bytes = toUint8Array(params.data);
        const target = params.target.toLowerCase();
        
        let entryPoint = 0;
        let sections: Section[] = [];
        let symbols: Symbol[] = [];
        let baseAddress = params.baseAddress ?? params.address ?? 0;

        let detected = 'auto';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) detected = 'elf';
        else if (bytes[0] === 0x4d && bytes[1] === 0x5a) detected = 'pe';
        else if (
          (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && bytes[3] === 0xcf) ||
          (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe)
        ) detected = 'macho';

        try {
          if (detected === 'elf') {
            const elf = parseElf(bytes.buffer as ArrayBuffer);
            sections = elf.sectionHeaders.map(s => ({
              name: s.name,
              virtualAddress: Number(s.addr),
              virtualSize: Number(s.size),
              fileOffset: Number(s.offset),
              fileSize: Number(s.size),
              flags: { read: true, write: false, execute: (Number(s.flags) & 4) !== 0 }
            }));
            symbols = elf.symbols.map(sym => ({ name: sym.name, address: Number(sym.value), binding: 'global', type: sym.type === 'FUNC' ? 'function' : 'none' }));
            baseAddress = Number(elf.header.entryPoint);
          } else if (detected === 'pe') {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const pe = parser.parse();
            const imgBase = Number(pe.optionalHeader.imageBase);
            sections = pe.sections.map(s => ({
              name: s.name,
              virtualAddress: imgBase + s.virtualAddress,
              virtualSize: s.virtualSize,
              fileOffset: s.pointerToRawData,
              fileSize: s.sizeOfRawData,
              flags: { read: true, write: false, execute: (s.characteristics & 0x20000000) !== 0 }
            }));
            baseAddress = imgBase + pe.optionalHeader.addressOfEntryPoint;
          }
        } catch (_) {}

        if (sections.length === 0) {
          sections = [{ name: '.text', virtualAddress: baseAddress, virtualSize: bytes.length, fileOffset: 0, fileSize: bytes.length, flags: { read: true, write: false, execute: true } }];
        }

        const router = new DisassemblerRouter();
        const allInstructions: Instruction[] = [];
        for (const sec of sections) {
          if (sec.flags.execute && sec.fileSize > 0) {
            try {
              const secBytes = bytes.subarray(sec.fileOffset, sec.fileOffset + sec.fileSize);
              const insts = router.disassemble(secBytes, { arch: params.arch || 'x86_64', baseAddress: sec.virtualAddress });
              allInstructions.push(...insts.map(inst => ({
                ...inst,
                op: inst.mnemonic,
                args: inst.opStr ? inst.opStr.split(',').map(s => s.trim()) : []
              })));
            } catch (_) {}
          }
        }

        const xrefEngine = new XRefEngine();
        xrefEngine.analyze(allInstructions, sections, symbols, bytes, baseAddress);

        let targetAddr = 0;
        if (target.startsWith('0x')) {
          targetAddr = parseInt(target, 16);
        } else if (/^\d+$/.test(target)) {
          targetAddr = parseInt(target, 10);
        } else {
          const sym = symbols.find(s => s.name.toLowerCase().includes(target));
          if (sym) targetAddr = sym.address;
        }

        if (targetAddr === 0) {
          throw new Error(`Could not resolve target symbol or address: ${params.target}`);
        }

        const callers = xrefEngine.getXRefsTo(targetAddr).map(x => ({ callerAddress: x.from, instruction: x.context }));
        const callees: { calleeAddress: number; instruction: string }[] = [];
        
        const funcInsts = allInstructions.filter(i => i.address >= targetAddr && i.address < targetAddr + 512);
        for (const inst of funcInsts) {
          if (inst.mnemonic.toLowerCase() === 'call' || inst.mnemonic.toLowerCase().startsWith('jmp')) {
            const dest = inst.opStr.trim();
            let destAddr = 0;
            if (dest.startsWith('0x')) destAddr = parseInt(dest, 16);
            else if (/^\d+$/.test(dest)) destAddr = parseInt(dest, 10);
            else {
              const sym = symbols.find(s => s.name.toLowerCase().includes(dest.toLowerCase()));
              if (sym) destAddr = sym.address;
            }
            if (destAddr > 0) {
              callees.push({ calleeAddress: destAddr, instruction: `${inst.mnemonic} ${inst.opStr}` });
            }
          }
        }

        return { success: true, targetAddress: targetAddr, callers, callees };
      }

      case 'typeStructRecovery': {
        const bytes = toUint8Array(params.data);
        const address = params.address;
        
        let sections: Section[] = [];
        let baseAddress = params.baseAddress ?? params.address ?? 0;
        let detected = 'auto';
        if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) detected = 'elf';
        else if (bytes[0] === 0x4d && bytes[1] === 0x5a) detected = 'pe';

        try {
          if (detected === 'pe') {
            const pe = new PEParser(bytes.buffer as ArrayBuffer).parse();
            const imgBase = Number(pe.optionalHeader.imageBase);
            sections = pe.sections.map(s => ({
              name: s.name,
              virtualAddress: imgBase + s.virtualAddress,
              virtualSize: s.virtualSize,
              fileOffset: s.pointerToRawData,
              fileSize: s.sizeOfRawData,
              flags: { read: true, write: false, execute: (s.characteristics & 0x20000000) !== 0 }
            }));
          }
        } catch (_) {}

        if (sections.length === 0) {
          sections = [{ name: '.text', virtualAddress: baseAddress, virtualSize: bytes.length, fileOffset: 0, fileSize: bytes.length, flags: { read: true, write: false, execute: true } }];
        }

        let offset = address;
        const sec = sections.find(s => address >= s.virtualAddress && address < s.virtualAddress + s.virtualSize);
        if (sec) {
          offset = address - sec.virtualAddress + sec.fileOffset;
        }

        if (offset < 0 || offset >= bytes.length) {
          throw new Error('Function address is out of binary bounds');
        }

        const router = new DisassemblerRouter();
        const sliceBytes = bytes.subarray(offset, Math.min(offset + 512, bytes.length));
        const insts = router.disassemble(sliceBytes, { arch: params.arch || 'x86_64', baseAddress: address });

        const regs: Record<string, Record<number, { size: number; isWrite: boolean }>> = {};
        for (const inst of insts) {
          const isRet = inst.mnemonic.toLowerCase() === 'ret';
          if (isRet) break;

          if (inst.operands) {
            for (let i = 0; i < inst.operands.length; i++) {
              const op = inst.operands[i];
              if (op.type === 'mem' && op.mem) {
                const baseReg = op.mem.base;
                const disp = op.mem.disp || 0;
                if (baseReg && disp > 0) {
                  if (!regs[baseReg]) regs[baseReg] = {};
                  const size = inst.size || 4;
                  const isWrite = i === 0 && (inst.mnemonic.toLowerCase().startsWith('mov') || inst.mnemonic.toLowerCase().startsWith('str'));
                  const dispKey = disp.toString();
                  (regs[baseReg] as any)[dispKey] = { size, isWrite };
                }
              }
            }
          }
        }

        const recovered: Record<string, string> = {};
        for (const [baseReg, fields] of Object.entries(regs)) {
          let cDecl = `struct struct_${baseReg} {\n`;
          const sortedOffsets = Object.keys(fields).map(Number).sort((a, b) => a - b);
          for (const off of sortedOffsets) {
            const info = fields[off];
            let type = 'void*';
            if (info.size === 1) type = 'char';
            else if (info.size === 2) type = 'short';
            else if (info.size === 4) type = 'int';
            else if (info.size === 8) type = 'long long';
            cDecl += `  ${type} field_${off.toString(16)}; // offset 0x${off.toString(16)}\n`;
          }
          cDecl += '};';
          recovered[baseReg] = cDecl;
        }

        return { success: true, recoveredStructs: recovered };
      }

      case 'emulatorHooks': {
        const emu = this.getEmulator();
        const action = params.action;
        
        if (action === 'setBreakpoints') {
          if (params.breakpoints && Array.isArray(params.breakpoints)) {
            emu.breakpoints.clear();
            for (const bp of params.breakpoints) {
              emu.breakpoints.add(Number(bp));
            }
          }
          return { success: true, breakpointCount: emu.breakpoints.size };
        } else if (action === 'clearBreakpoints') {
          emu.breakpoints.clear();
          return { success: true };
        } else if (action === 'run') {
          emu.isRunning = true;
          let steps = 0;
          let res = { success: true, halted: false, hitBreakpoint: false };
          const limit = params.steps || 1000;
          
          while (emu.isRunning && steps < limit) {
            const currentRip = Number(emu.cpu.read('rip'));
            if (emu.breakpoints.has(currentRip)) {
              res.hitBreakpoint = true;
              break;
            }
            res = emu.step();
            steps++;
            if (!res.success || res.halted || res.hitBreakpoint) {
              break;
            }
          }
          return {
            success: true,
            stepsRun: steps,
            halted: res.halted,
            hitBreakpoint: res.hitBreakpoint || emu.breakpoints.has(Number(emu.cpu.read('rip'))),
            cpuState: {
              rip: emu.cpu.read('rip').toString(),
              rax: emu.cpu.read('rax').toString()
            }
          };
        }
        throw new Error(`Unsupported emulatorHooks action: ${action}`);
      }

      case 'pipelineChainMode': {
        const pipeline = params.pipeline;
        if (!pipeline || !Array.isArray(pipeline)) {
          throw new Error('Pipeline array is required');
        }

        const results: any[] = [];
        
        const resolvePlaceholders = (val: any, stepIdx: number): any => {
          if (typeof val === 'string') {
            if (val.startsWith('$$') && val.endsWith('$$')) {
              const expr = val.substring(2, val.length - 2).trim();
              if (expr === 'prev' || expr === 'prev.result') {
                return results.length > 0 ? results[results.length - 1] : undefined;
              }
              try {
                const context = {
                  prev: results.length > 0 ? results[results.length - 1] : undefined,
                  results: results
                };
                const fn = new Function('context', `return context.${expr}`);
                return fn(context);
              } catch (_) {
                return undefined;
              }
            }
          } else if (val && typeof val === 'object') {
            if (Array.isArray(val)) {
              return val.map(item => resolvePlaceholders(item, stepIdx));
            } else {
              const res: any = {};
              for (const [k, v] of Object.entries(val)) {
                res[k] = resolvePlaceholders(v, stepIdx);
              }
              return res;
            }
          }
          return val;
        };

        for (let i = 0; i < pipeline.length; i++) {
          const step = pipeline[i];
          const resolvedParams = resolvePlaceholders(step.params, i);
          const res = await this.executeQuery({ action: step.tool, params: resolvedParams });
          results.push(res);
        }

        return { success: true, pipelineResults: results };
      }

      default:
        throw new Error(`Unsupported bridge action: ${action}`);
    }
  }
}
