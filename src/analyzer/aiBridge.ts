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
import { extractStrings, isUrl, isFilePath, isRegistryKey, isFormatString, isBase64OrHighEntropy } from './strings.js';
import { calculateEntropy, findHighEntropyBlocks, mapSectionEntropy } from './entropy.js';
import { XRefEngine } from './xrefs.js';
import { buildCFG, BasicBlock, InstructionClassifier, getBranchTarget } from '../disassembler/cfg.js';
import { Section, Symbol, Instruction } from '../disassembler/types.js';
import { ReportGenerator } from './reportGenerator.js';

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

export function parseAddress(
  value: any,
  symbols?: Symbol[],
  peImports?: any[],
  imageBase: number = 0
): number {
  if (value === undefined || value === null) return 0;
  if (typeof value === 'number') return value;
  const str = String(value).trim();
  if (str.startsWith('0x') || str.startsWith('0X')) {
    return parseInt(str, 16);
  }
  if (/^-?\d+$/.test(str)) {
    return parseInt(str, 10);
  }
  const lowerStr = str.toLowerCase();
  
  const activeSymbols = symbols || (typeof AIBridge !== 'undefined' ? (AIBridge as any).getSymbols() : undefined);
  if (activeSymbols) {
    const sym = activeSymbols.find((s: Symbol) => s.name.toLowerCase() === lowerStr || s.name.toLowerCase().includes(lowerStr));
    if (sym) {
      return sym.address;
    }
  }

  const activePeImports = peImports || (typeof AIBridge !== 'undefined' ? (AIBridge as any).cachedPeImports : undefined);
  const activeImageBase = imageBase || (typeof AIBridge !== 'undefined' ? (AIBridge as any).cachedImageBase : 0);
  if (activePeImports) {
    for (const impTable of activePeImports) {
      for (const entry of impTable.imports) {
        if (entry.name && entry.name.toLowerCase() === lowerStr) {
          if (entry.iatRva !== undefined) {
            return activeImageBase + entry.iatRva;
          }
        }
      }
    }
  }
  const parsed = parseInt(str, 10);
  return isNaN(parsed) ? 0 : parsed;
}

export function parseAddressOptional(value: any): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'number') return value;
  const str = String(value).trim();
  if (str.startsWith('0x') || str.startsWith('0X')) {
    return parseInt(str, 16);
  }
  if (/^-?\d+$/.test(str)) {
    return parseInt(str, 10);
  }
  const parsed = parseInt(str, 10);
  return isNaN(parsed) ? undefined : parsed;
}

export function parseBigInt(value: any): bigint {
  if (value === undefined || value === null) return 0n;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  const str = String(value).trim();
  if (str.startsWith('0x') || str.startsWith('0X')) {
    try {
      return BigInt(str);
    } catch (_) {
      return 0n;
    }
  }
  if (/^-?\d+$/.test(str)) {
    try {
      return BigInt(str);
    } catch (_) {
      return 0n;
    }
  }
  try {
    return BigInt(str);
  } catch (_) {
    return 0n;
  }
}


/**
 * Standard tool / function definitions for external LLMs
 */
export const TOOL_SCHEMAS = {
  disassemble: {
    name: 'disassemble',
    description: 'Disassemble raw machine code or executable binary (supports ELF, PE, Mach-O, and raw shellcode) into structured assembly instructions. Parses target sections automatically or uses provided base virtual address. If data is omitted, automatically falls back to the session-loaded binary and starts disassembly at the `.text` entry point by default. Supported architectures: x86_64, arm, riscv, thumb, wasm, dex, z80, etc.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary/machine code to disassemble. Example: "9090" (NOPs). Optional if a binary is loaded in the session.' },
        arch: { type: 'string', description: 'Target CPU architecture. Supported: "x86_64", "x86", "arm", "arm64", "riscv", "thumb", "wasm", "dex", "z80". Default is x86_64.' },
        baseAddress: { type: 'number', description: 'Virtual address offset at which to start disassembly. Defaults to 0 or binary section address.' }
      }
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
        data: { type: 'string', description: 'Hex or Base64 encoded original binary data. Optional if action is undo or redo.' },
        action: { type: 'string', enum: ['patch', 'undo', 'redo'], description: 'Patch action to perform: "patch" to apply a new patch, "undo" to revert the last applied patch, or "redo" to re-apply the last undone patch. Default is "patch".' },
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
      }
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
  analyzeStrings: {
    name: 'analyzeStrings',
    description: 'Scan binary data and extract printable strings, categorizing them into URLs, Windows/Linux file paths, registry keys (HKEY_...), base64/high-entropy strings, and format strings (%s, %d). Returns lists of categorized strings with their offsets and virtual addresses.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data.' },
        minLength: { type: 'number', description: 'Minimum number of characters to constitute a string (default 4).' },
        baseAddress: { type: 'number', description: 'Base virtual address used to calculate absolute string offsets in memory.' }
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
    description: 'Generate a classic formatted hex dump of the binary data, similar to hexdump or xxd. Shows offset address, hex representation of bytes, and ASCII representation. Useful for human verification of binary payloads. Falls back to session-loaded binary when data is omitted, and supports section-name queries.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data. Optional if a binary is loaded in the session.' },
        offset: { type: 'number', description: 'Start byte offset within binary data (default 0).' },
        limit: { type: 'number', description: 'Number of bytes to dump (alias for length).' },
        length: { type: 'number', description: 'Total number of bytes to dump (defaults to remaining bytes).' },
        bytesPerLine: { type: 'number', description: 'Number of bytes to display per line (default 16).' },
        section: { type: 'string', description: 'Optional section name (e.g., ".text") to automatically load offset and size of that section from the session binary.' }
      }
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
        },
        startVA: { type: 'number', description: 'Optional virtual address/offset inside the loaded binary to begin disassembling if instructions are not provided.' },
        format: { type: 'string', enum: ['json', 'dot', 'ascii'], description: 'Optional visualization format output.' },
        arch: { type: 'string', description: 'Optional target CPU architecture (e.g. x86_64, arm). Default is x86_64.' }
      }
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
        runUntil: {
          anyOf: [
            { type: 'number' },
            { type: 'string' }
          ],
          description: 'Virtual address/PC to run emulation until (breakpoint).'
        },
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
        breakpoints: {
          type: 'array',
          items: {
            anyOf: [
              { type: 'number' },
              { type: 'string' }
            ]
          },
          description: 'List of virtual addresses to use as breakpoints.'
        },
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
  },
  findFunctions: {
    name: 'findFunctions',
    description: 'Scan binary data (ELF, PE, Mach-O, or raw) to detect function entry points using prologue signature scanning and return function boundary details.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data to scan.' },
        section: { type: 'string', description: 'Optional name of specific section to scan (e.g., ".text").' },
        arch: { type: 'string', description: 'Optional target CPU architecture context.' }
      }
    }
  },
  sessionSave: {
    name: 'sessionSave',
    description: 'Save the current URET analysis/emulator session state (loaded binary bytes, register values, virtual memory mappings, execution trace logs, and breakpoint list) to a JSON file on disk.',
    parameters: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Absolute or relative local file path where the session JSON should be saved.' }
      },
      required: ['filePath']
    }
  },
  sessionLoad: {
    name: 'sessionLoad',
    description: 'Restore a saved URET session from a JSON file on disk, reloading the binary bytes, emulator registers, virtual memory pages, traces, and breakpoints.',
    parameters: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Absolute or relative local file path from where the session JSON should be loaded.' }
      },
      required: ['filePath']
    }
  },
  generateReport: {
    name: 'generateReport',
    description: 'Execute a sequence of analysis tools (loadBinary, parseBinary, extractStrings, entropyAnalysis, yaraScan, vulnScan, exportToIda) to generate a comprehensive JSON and Markdown report of the binary.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data (optional if binary is already loaded).' },
        filePath: { type: 'string', description: 'Local path of binary to load (optional).' },
        rules: { type: 'string', description: 'Optional YARA rule string to compile and scan against. If not provided, a default rule searching for suspicious strings is used.' },
        fileName: { type: 'string', description: 'Optional file name to use in the report metadata.' }
      }
    }
  },
  deobfuscate: {
    name: 'deobfuscate',
    description: 'Scan binary function instructions for common obfuscation patterns: XOR key-decryption loops, stack-string construction (successive moves of character constants into stack offsets), and Control Flow Flattening (switch-state loops). Returns detected patterns and suggestions on how to deobfuscate them.',
    parameters: {
      type: 'object',
      properties: {
        data: { type: 'string', description: 'Hex or Base64 encoded binary data containing the function instructions.' },
        instructions: {
          type: 'array',
          description: 'Optional list of pre-disassembled structured instructions to analyze.',
          items: {
            type: 'object',
            properties: {
              address: { type: 'number', description: 'Virtual address of the instruction.' },
              op: { type: 'string', description: 'Mnemonic/opcode name (e.g., "mov", "jmp").' },
              args: { type: 'array', items: { type: 'string' }, description: 'Operands/arguments of the instruction.' }
            }
          }
        },
        arch: { type: 'string', description: 'Target CPU architecture (e.g. "x86_64", "arm").' },
        baseAddress: { type: 'number', description: 'Virtual address offset at which to start disassembly.' }
      }
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
  providedBaseAddress?: number | string,
  providedEntryPoint?: number | string
): ResolvedBinaryInfo {
  const parsedBase = parseAddressOptional(providedBaseAddress);
  const parsedEntry = parseAddressOptional(providedEntryPoint);
  const baseAddr = parsedBase !== undefined ? parsedBase : parsedEntry;
  
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

  // Check if Mach-O
  const isMacho =
    (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && (bytes[3] === 0xce || bytes[3] === 0xcf)) ||
    ((bytes[0] === 0xce || bytes[0] === 0xcf) && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
    (bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe);
  if (isMacho) {
    try {
      const macho = new MachoParser(bytes).parse();
      let sliceBytes = bytes;
      let resolvedBase = baseAddr;

      if (resolvedBase === undefined || resolvedBase === null) {
        // Try __text section first
        const textSec = macho.sections.find(s => s.sectname === '__text' || s.sectname === '.text');
        if (textSec) {
          sliceBytes = bytes.subarray(textSec.offset, textSec.offset + Number(textSec.size));
          resolvedBase = Number(textSec.addr);
        } else {
          // Fallback to entry point
          let entryPoint = 0;
          const lcMain = macho.loadCommands.find(lc => lc.cmd === 0x80000028);
          if (lcMain && lcMain.payload && typeof (lcMain.payload as any).entryoff === 'number') {
            entryPoint = (lcMain.payload as any).entryoff;
          }
          const textSegment = macho.segments.find(seg => seg.segname === '__TEXT');
          const imageBase = textSegment ? Number(textSegment.vmaddr) : 0;
          resolvedBase = imageBase + entryPoint;

          // Find section containing the entry point address
          const rBase = resolvedBase;
          const sec = macho.sections.find(s => {
            const sAddr = Number(s.addr);
            const sSize = Number(s.size);
            return rBase !== undefined && rBase >= sAddr && rBase < sAddr + sSize;
          });
          if (sec && rBase !== undefined) {
            const offset = sec.offset + (rBase - Number(sec.addr));
            sliceBytes = bytes.subarray(offset, sec.offset + Number(sec.size));
          }
        }
      } else {
        // Base address or entrypoint provided
        const vaddr = resolvedBase;
        const sec = macho.sections.find(s => {
          const sAddr = Number(s.addr);
          const sSize = Number(s.size);
          return vaddr >= sAddr && vaddr < sAddr + sSize;
        });
        if (sec) {
          const offset = sec.offset + (vaddr - Number(sec.addr));
          sliceBytes = bytes.subarray(offset, sec.offset + Number(sec.size));
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

function toDOT(blocks: BasicBlock[]): string {
  let dot = 'digraph CFG {\n';
  dot += '  node [shape=box, fontname="Courier", fontsize=10];\n';
  for (const block of blocks) {
    const instLines = block.instructions.map(inst => {
      const addrHex = '0x' + inst.address.toString(16);
      const opStr = inst.opStr ? ' ' + inst.opStr : '';
      return `${addrHex}: ${inst.mnemonic}${opStr}`;
    });
    const label = `${block.id}\\n` + instLines.join('\\n');
    dot += `  ${block.id} [label="${label}"];\n`;
  }
  for (const block of blocks) {
    for (const succ of block.successors) {
      dot += `  ${block.id} -> ${succ};\n`;
    }
  }
  dot += '}';
  return dot;
}

function toASCII(blocks: BasicBlock[]): string {
  if (blocks.length === 0) return '';
  
  const blockMap = new Map<string, BasicBlock>();
  const inDegree = new Map<string, number>();
  
  for (const block of blocks) {
    blockMap.set(block.id, block);
    inDegree.set(block.id, 0);
  }
  
  for (const block of blocks) {
    for (const succ of block.successors) {
      inDegree.set(succ, (inDegree.get(succ) || 0) + 1);
    }
  }
  
  let roots = blocks.filter(b => (inDegree.get(b.id) || 0) === 0);
  if (roots.length === 0) {
    const minBlock = blocks.reduce((min, b) => b.startAddress < min.startAddress ? b : min, blocks[0]);
    roots = [minBlock];
  }
  
  const visited = new Set<string>();
  const lines: string[] = [];
  
  function formatBlockInstructions(block: BasicBlock, indent: string): string[] {
    return block.instructions.map(inst => {
      const addrHex = '0x' + inst.address.toString(16);
      const opStr = inst.opStr ? ' ' + inst.opStr : '';
      return `${indent}${addrHex}: ${inst.mnemonic}${opStr}`;
    });
  }
  
  function printTree(blockId: string, prefix: string, isLast: boolean) {
    const block = blockMap.get(blockId);
    if (!block) return;
    
    const connector = isLast ? '└── ' : '├── ';
    lines.push(`${prefix}${connector}${block.id} (0x${block.startAddress.toString(16)} - 0x${block.endAddress.toString(16)})`);
    
    const nextPrefix = prefix + (isLast ? '    ' : '│   ');
    
    const instLines = formatBlockInstructions(block, nextPrefix + '  ');
    lines.push(...instLines);
    
    if (visited.has(blockId)) {
      lines.push(`${nextPrefix}  [already visited / loop back]`);
      return;
    }
    visited.add(blockId);
    
    const successors = block.successors.filter(s => blockMap.has(s));
    for (let i = 0; i < successors.length; i++) {
      const succId = successors[i];
      const isLastSucc = i === successors.length - 1;
      printTree(succId, nextPrefix, isLastSucc);
    }
  }
  
  for (let i = 0; i < roots.length; i++) {
    const root = roots[i];
    printTree(root.id, '', i === roots.length - 1);
  }
  
  const unvisited = blocks.filter(b => !visited.has(b.id));
  if (unvisited.length > 0) {
    lines.push('');
    lines.push('Disconnected / Unreachable Blocks:');
    for (let i = 0; i < unvisited.length; i++) {
      const block = unvisited[i];
      printTree(block.id, '', i === unvisited.length - 1);
    }
  }
  
  return lines.join('\n');
}

/**
 * Unified AI Query Bridge for URET
 */
export class AIBridge {
  private static emulatorInstance: Emulator | null = null;
  private static loadedBinaryBytes: Uint8Array | null = null;
  private static cachedSymbols: Symbol[] | null = null;
  private static cachedPeImports: any[] | null = null;
  private static cachedImageBase: number = 0;
  private static patcherInstance: BinaryPatcher | null = null;

  private static getSymbols(): Symbol[] {
    if (this.cachedSymbols) return this.cachedSymbols;
    if (!this.loadedBinaryBytes) return [];
    const b = this.loadedBinaryBytes;
    const symbols: Symbol[] = [];
    if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
      try {
        const parsed = parseElf(b.buffer as ArrayBuffer);
        if (parsed.symbols) {
          for (const sym of parsed.symbols) {
            symbols.push({
              name: sym.name,
              address: Number(sym.value),
              binding: sym.bind?.toLowerCase() === 'local' ? 'local' : (sym.bind?.toLowerCase() === 'weak' ? 'weak' : 'global'),
              type: sym.type === 'FUNC' ? 'function' : (sym.type === 'OBJECT' ? 'object' : 'none')
            });
          }
        }
      } catch (_) {}
    } else if (b[0] === 0x4d && b[1] === 0x5a) {
      try {
        const parser = new PEParser(b.buffer as ArrayBuffer);
        const parsed = parser.parse();
        const imgBase = Number(parsed.optionalHeader.imageBase || 0);
        this.cachedImageBase = imgBase;
        if (parsed.imports) {
          const peImports: any[] = [];
          for (const impTable of parsed.imports) {
            for (const entry of impTable.imports) {
              if (entry.name && entry.iatRva !== undefined) {
                symbols.push({
                  name: entry.name,
                  address: imgBase + entry.iatRva,
                  binding: 'global',
                  type: 'none'
                });
              }
            }
            peImports.push(impTable);
          }
          this.cachedPeImports = peImports;
        }
      } catch (_) {}
    }
    this.cachedSymbols = symbols;
    return symbols;
  }

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
        if (action !== 'disassemble' && action !== 'hexDump') {
          params.data = toHex(AIBridge.loadedBinaryBytes);
        }
      }
      if (!params.dataA && AIBridge.loadedBinaryBytes) {
        params.dataA = toHex(AIBridge.loadedBinaryBytes);
      }
    }

    switch (action) {
      case 'disassemble': {
        let bytes: Uint8Array;
        if (params && params.data) {
          bytes = toUint8Array(params.data);
        } else if (AIBridge.loadedBinaryBytes) {
          bytes = AIBridge.loadedBinaryBytes;
        } else {
          throw new Error('No data provided and no binary loaded in session');
        }
        const resolved = resolveElfOrPe(bytes, params ? (params.baseAddress ?? params.address) : undefined, undefined);
        const router = new DisassemblerRouter();
        const insts = router.disassemble(resolved.data, {
          arch: params ? params.arch : undefined,
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

        const mappedInsts = insts.map((inst: any) => ({
          address: Number(inst.address),
          bytes: inst.bytes instanceof Uint8Array ? inst.bytes : new Uint8Array(),
          mnemonic: inst.mnemonic || inst.op || '',
          opStr: inst.opStr || (inst.args ? inst.args.join(', ') : ''),
          operands: inst.operands || [],
          size: Number(inst.size || 1),
          args: inst.args,
          op: inst.op
        }));

        const cfgBlocks = buildCFG(mappedInsts);
        const decompilerBlocks = cfgBlocks.map(block => ({
          id: block.id,
          instructions: block.instructions.map((inst: any) => ({
            address: Number(inst.address),
            op: inst.mnemonic || inst.op || '',
            args: inst.args || (inst.opStr ? inst.opStr.split(',').map((s: string) => s.trim()) : [])
          })),
          successors: block.successors
        }));

        const entryAddrVal = (params.entryPoint !== undefined || params.address !== undefined || params.baseAddress !== undefined)
          ? parseAddress(params.entryPoint ?? params.address ?? params.baseAddress)
          : undefined;

        let entryBlockId = cfgBlocks[0]?.id || 'entry';
        if (entryAddrVal !== undefined) {
          const found = cfgBlocks.find(b => b.startAddress <= entryAddrVal && entryAddrVal < b.endAddress);
          if (found) {
            entryBlockId = found.id;
          }
        }

        const decompiler = new Decompiler();
        const result = decompiler.decompile('func', [], decompilerBlocks, entryBlockId);
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
        const action = params.action || 'patch';
        if (action === 'undo') {
          AIBridge.patcherInstance?.undo();
        } else if (action === 'redo') {
          AIBridge.patcherInstance?.redo();
        } else if (action === 'patch') {
          if (!params.data) {
            throw new Error('Missing "data" parameter for patch action.');
          }
          const bytes = toUint8Array(params.data);
          const areBytesEqual = (a: Uint8Array, b: Uint8Array) => {
            if (a.length !== b.length) return false;
            for (let i = 0; i < a.length; i++) {
              if (a[i] !== b[i]) return false;
            }
            return true;
          };
          const hasInstance = !!AIBridge.patcherInstance;
          const bytesChanged = hasInstance && !areBytesEqual(bytes, AIBridge.patcherInstance!.getOriginalBinary());
          if (!hasInstance || bytesChanged) {
            AIBridge.patcherInstance = new BinaryPatcher(bytes);
          }

          if (params.offset !== undefined && params.patchedBytes !== undefined) {
            const patBytes = toUint8Array(params.patchedBytes);
            const offset = parseAddress(params.offset);
            const addr = params.address !== undefined ? parseAddress(params.address) : offset;
            AIBridge.patcherInstance!.applyPatch(offset, patBytes, addr, params.description || '');
          } else if (params.patches && Array.isArray(params.patches)) {
            for (const p of params.patches) {
              const patBytes = toUint8Array(p.patchedBytes);
              const offset = parseAddress(p.offset);
              const addr = p.address !== undefined ? parseAddress(p.address) : offset;
              AIBridge.patcherInstance!.applyPatch(offset, patBytes, addr, p.description || '');
            }
          } else {
            throw new Error('Missing patch parameters: either specify top-level "offset" and "patchedBytes", or a "patches" array.');
          }
        } else {
          throw new Error(`Unsupported action: ${action}`);
        }

        return {
          success: true,
          patchedData: AIBridge.patcherInstance ? toHex(AIBridge.patcherInstance.getPatchedBinary()) : '',
          records: AIBridge.patcherInstance ? AIBridge.patcherInstance.getHistory() : []
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
        const targetAddress = parseAddress(params.targetAddress);
        const result = executor.execute(params.instructions, params.inputs, targetAddress);
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
          emu.reset(params.entryPoint !== undefined ? parseAddress(params.entryPoint) : 0);
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
              emu.cpu.write(r, parseBigInt(val));
            }
          }
          return { success: true };
        } else if (action === 'readMem') {
          const results = [];
          if (params.memory) {
            for (const m of params.memory) {
              const addr = parseBigInt(m.address);
              const size = m.size || 4;
              const buf = emu.memory.readBuffer(addr, size);
              results.push({ address: m.address, hex: toHex(buf) });
            }
          }
          return { success: true, memory: results };
        } else if (action === 'writeMem') {
          if (params.memory) {
            for (const m of params.memory) {
              const addr = parseBigInt(m.address);
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
            entryPoint = params.entryPoint !== undefined ? parseAddress(params.entryPoint) : 0;
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
          baseAddress: params.baseAddress !== undefined ? parseAddress(params.baseAddress) : undefined,
          ascii: params.ascii,
          utf16le: params.utf16le,
          utf16be: params.utf16be
        };
        const strings = extractStrings(bytes, options);
        return { success: true, strings };
      }

      case 'analyzeStrings': {
        const bytes = toUint8Array(params.data);
        const options = {
          minLength: params.minLength,
          baseAddress: params.baseAddress !== undefined ? parseAddress(params.baseAddress) : undefined,
          ascii: true,
          utf16le: true,
          utf16be: true
        };
        const strings = extractStrings(bytes, options);

        const urls: any[] = [];
        const paths: any[] = [];
        const registryKeys: any[] = [];
        const highEntropy: any[] = [];
        const formatStrings: any[] = [];

        for (const s of strings) {
          const val = s.value;
          if (isUrl(val)) {
            urls.push(s);
          } else if (isFilePath(val)) {
            paths.push(s);
          } else if (isRegistryKey(val)) {
            registryKeys.push(s);
          } else if (isFormatString(val)) {
            formatStrings.push(s);
          } else if (isBase64OrHighEntropy(val)) {
            highEntropy.push(s);
          }
        }

        return {
          success: true,
          urls,
          paths,
          registryKeys,
          highEntropy,
          formatStrings
        };
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
        let bytes: Uint8Array;
        if (params && params.data) {
          bytes = toUint8Array(params.data);
        } else if (AIBridge.loadedBinaryBytes) {
          bytes = AIBridge.loadedBinaryBytes;
        } else {
          throw new Error('No data provided and no binary loaded in session');
        }

        let offset = params ? parseAddress(params.offset) : 0;
        let limit = params ? (params.limit !== undefined ? params.limit : params.length) : undefined;
        let length = limit !== undefined ? limit : undefined;

        if (params && params.section && AIBridge.loadedBinaryBytes) {
          const sectionName = params.section;
          const sessionBytes = AIBridge.loadedBinaryBytes;
          let detected = 'unknown';
          if (sessionBytes[0] === 0x7f && sessionBytes[1] === 0x45 && sessionBytes[2] === 0x4c && sessionBytes[3] === 0x46) {
            detected = 'elf';
          } else if (sessionBytes[0] === 0x4d && sessionBytes[1] === 0x5a) {
            detected = 'pe';
          } else if (
            (sessionBytes[0] === 0xfe && sessionBytes[1] === 0xed && sessionBytes[2] === 0xfa && (sessionBytes[3] === 0xce || sessionBytes[3] === 0xcf)) ||
            ((sessionBytes[0] === 0xce || sessionBytes[0] === 0xcf) && sessionBytes[1] === 0xfa && sessionBytes[2] === 0xed && sessionBytes[3] === 0xfe) ||
            (sessionBytes[0] === 0xca && sessionBytes[1] === 0xfe && sessionBytes[2] === 0xba && sessionBytes[3] === 0xbe)
          ) {
            detected = 'macho';
          }

          let found = false;
          if (detected === 'elf') {
            try {
              const parsed = parseElf(sessionBytes.buffer as ArrayBuffer);
              const sec = parsed.sectionHeaders.find(s => s.name === sectionName);
              if (sec) {
                offset = Number(sec.offset);
                length = Number(sec.size);
                found = true;
              }
            } catch (_) {}
          } else if (detected === 'pe') {
            try {
              const parser = new PEParser(sessionBytes.buffer as ArrayBuffer);
              const parsed = parser.parse();
              const sec = parsed.sections.find(s => s.name === sectionName);
              if (sec) {
                offset = sec.pointerToRawData;
                length = sec.sizeOfRawData;
                found = true;
              }
            } catch (_) {}
          } else if (detected === 'macho') {
            try {
              const parser = new MachoParser(sessionBytes);
              const parsed = parser.parse();
              const normalizedSectionName = sectionName.startsWith('.') ? sectionName : `.${sectionName}`;
              const sec = parsed.sections.find(s => 
                s.sectname === sectionName || 
                s.sectname === `__${sectionName.replace(/^\./, '')}` ||
                s.sectname === normalizedSectionName
              );
              if (sec) {
                offset = sec.offset;
                length = Number(sec.size);
                found = true;
              }
            } catch (_) {}
          }

          if (!found) {
            throw new Error(`Section "${sectionName}" not found in session binary`);
          }
        }

        const finalLength = length !== undefined ? length : (bytes.length - offset);
        const bytesPerLine = (params && params.bytesPerLine) || 16;

        const startOffset = Math.max(0, Math.min(offset, bytes.length));
        const endOffset = Math.max(startOffset, Math.min(startOffset + finalLength, bytes.length));
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
        let baseAddress = 0;
        if (params.baseAddress !== undefined) {
          baseAddress = parseAddress(params.baseAddress, []);
        } else if (params.address !== undefined) {
          const addrStr = String(params.address).trim();
          if (addrStr.startsWith('0x') || /^\d+$/.test(addrStr)) {
            baseAddress = parseAddress(params.address, []);
          }
        }

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
            if (baseAddress === 0) {
              baseAddress = Number(elf.header.entryPoint);
            }
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
            const peSymbols: Symbol[] = [];
            if (pe.imports) {
              for (const impTable of pe.imports) {
                for (const imp of impTable.imports) {
                  if (imp.name && imp.iatRva !== undefined) {
                    peSymbols.push({
                      name: imp.name,
                      address: imgBase + imp.iatRva,
                      binding: 'global',
                      type: 'none'
                    });
                  }
                }
              }
            }
            if (pe.exports && pe.exports.exports) {
              for (const exp of pe.exports.exports) {
                if (exp.name) {
                  peSymbols.push({
                    name: exp.name,
                    address: imgBase + exp.address,
                    binding: 'global',
                    type: 'none'
                  });
                }
              }
            }
            symbols = peSymbols;
            if (baseAddress === 0) {
              baseAddress = imgBase + pe.optionalHeader.addressOfEntryPoint;
            }
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

        const targetAddr = parseAddress(params.address, symbols);
        const incoming = engine.getXRefsTo(targetAddr);
        const outgoing = engine.getXRefsFrom(targetAddr);

        return { success: true, incoming, outgoing };
      }
      case 'buildCFG': {
        let mappedInsts: any[] = [];
        if (!params.instructions || !Array.isArray(params.instructions)) {
          if (!AIBridge.loadedBinaryBytes) {
            throw new Error('Instructions array is required when no binary is loaded in session cache');
          }
          const bytes = AIBridge.loadedBinaryBytes;
          
          const getEntryPoint = (b: Uint8Array): number => {
            if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
              try {
                const parsed = parseElf(b.buffer as ArrayBuffer);
                return Number(parsed.header.entryPoint || 0);
              } catch (_) {}
            }
            if (b[0] === 0x4d && b[1] === 0x5a) {
              try {
                const parser = new PEParser(b.buffer as ArrayBuffer);
                const parsed = parser.parse();
                return Number(parsed.optionalHeader.imageBase || 0) + (parsed.optionalHeader.addressOfEntryPoint || 0);
              } catch (_) {}
            }
            if (
              (b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa && b[3] === 0xcf) ||
              (b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe)
            ) {
              try {
                const parser = new MachoParser(b);
                const parsed = parser.parse();
                let entryPoint = 0;
                const lcMain = parsed.loadCommands.find(lc => lc.cmd === 0x80000028);
                if (lcMain && lcMain.payload && typeof (lcMain.payload as any).entryoff === 'number') {
                  entryPoint = (lcMain.payload as any).entryoff;
                }
                const textSegment = parsed.segments.find(seg => seg.segname === '__TEXT');
                const imageBase = textSegment ? Number(textSegment.vmaddr) : 0;
                return imageBase + entryPoint;
              } catch (_) {}
            }
            return 0;
          };

          const startVA = params.startVA !== undefined ? parseAddress(params.startVA) : getEntryPoint(bytes);
          const resolved = resolveElfOrPe(bytes, startVA, undefined);
          const router = new DisassemblerRouter();
          const insts = router.disassemble(resolved.data, {
            arch: params.arch || 'x86_64',
            baseAddress: resolved.baseAddress
          });
          mappedInsts = insts.map(inst => ({
            address: Number(inst.address),
            bytes: inst.bytes instanceof Uint8Array ? inst.bytes : new Uint8Array(),
            mnemonic: inst.mnemonic || '',
            opStr: inst.opStr || '',
            operands: inst.operands || [],
            size: Number(inst.size || 1)
          }));
        } else {
          const insts: any[] = params.instructions;
          mappedInsts = insts.map((inst: any) => ({
            address: Number(inst.address),
            bytes: inst.bytes instanceof Uint8Array ? inst.bytes : new Uint8Array(),
            mnemonic: inst.mnemonic || inst.op || '',
            opStr: inst.opStr || (inst.args ? inst.args.join(', ') : ''),
            operands: inst.operands || [],
            size: Number(inst.size || 1)
          }));
        }

        const blocks = buildCFG(mappedInsts);
        
        const format = params.format || 'json';
        let formatted: string | undefined = undefined;
        if (format === 'dot') {
          formatted = toDOT(blocks);
        } else if (format === 'ascii') {
          formatted = toASCII(blocks);
        } else if (format === 'json') {
          formatted = JSON.stringify(blocks, null, 2);
        }

        return {
          success: true,
          blocks,
          format,
          formatted
        };
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
        AIBridge.cachedSymbols = null;
        AIBridge.cachedPeImports = null;
        AIBridge.cachedImageBase = 0;
        AIBridge.patcherInstance = null;
        
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
            const offset = parseAddress(p.offset);
            const patBytes = toUint8Array(p.patchedBytes);
            const addr = p.address !== undefined ? parseAddress(p.address) : offset;
            patcher.applyPatch(offset, patBytes, addr, p.description || '');
          }
        }
        const patched = patcher.getPatchedBinary();
        
        const emu = this.getEmulator();
        await this.executeQuery({ action: 'emulatorControl', params: { action: 'load', data: toHex(patched) } });
        
        const runUntil = params.runUntil !== undefined ? parseAddress(params.runUntil) : undefined;
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
        
        let baseAddress = 0;
        let sections: Section[] = [];
        let symbols: Symbol[] = [];
        if (params.baseAddress !== undefined) {
          baseAddress = parseAddress(params.baseAddress, []);
        } else if (params.address !== undefined) {
          const addrStr = String(params.address).trim();
          if (addrStr.startsWith('0x') || /^\d+$/.test(addrStr)) {
            baseAddress = parseAddress(params.address, []);
          }
        }

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
            if (baseAddress === 0) {
              baseAddress = Number(elf.header.entryPoint);
            }
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
            const peSymbols: Symbol[] = [];
            if (pe.imports) {
              for (const impTable of pe.imports) {
                for (const imp of impTable.imports) {
                  if (imp.name && imp.iatRva !== undefined) {
                    peSymbols.push({
                      name: imp.name,
                      address: imgBase + imp.iatRva,
                      binding: 'global',
                      type: 'none'
                    });
                  }
                }
              }
            }
            if (pe.exports && pe.exports.exports) {
              for (const exp of pe.exports.exports) {
                if (exp.name) {
                  peSymbols.push({
                    name: exp.name,
                    address: imgBase + exp.address,
                    binding: 'global',
                    type: 'none'
                  });
                }
              }
            }
            symbols = peSymbols;
            if (baseAddress === 0) {
              baseAddress = imgBase + pe.optionalHeader.addressOfEntryPoint;
            }
          } else if (detected === 'macho') {
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

        const targetAddr = parseAddress(params.target, symbols);

        if (targetAddr === 0 && params.target !== 0 && params.target !== '0' && params.target !== '0x0') {
          throw new Error(`Could not resolve target symbol or address: ${params.target}`);
        }

        const callers = xrefEngine.getXRefsTo(targetAddr).map(x => ({ callerAddress: x.from, instruction: x.context }));
        const callees: { calleeAddress: number; instruction: string }[] = [];
        
        const funcInsts = allInstructions.filter(i => i.address >= targetAddr && i.address < targetAddr + 512);
        for (const inst of funcInsts) {
          if (inst.mnemonic.toLowerCase() === 'call' || inst.mnemonic.toLowerCase().startsWith('jmp')) {
            const dest = inst.opStr.trim();
            const destAddr = parseAddress(dest, symbols);
            if (destAddr > 0) {
              callees.push({ calleeAddress: destAddr, instruction: `${inst.mnemonic} ${inst.opStr}` });
            }
          }
        }

        return { success: true, targetAddress: targetAddr, callers, callees };
      }

      case 'typeStructRecovery': {
        const bytes = toUint8Array(params.data);
        const address = parseAddress(params.address);
        
        let sections: Section[] = [];
        let baseAddress = params.baseAddress !== undefined ? parseAddress(params.baseAddress) : address;
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
              emu.breakpoints.add(parseAddress(bp));
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
            const exactMatch = /^\$\$(.+?)\$\$$/.exec(val);
            if (exactMatch) {
              const expr = exactMatch[1].trim();
              if (expr === 'prev' || expr === 'prev.result') {
                return results.length > 0 ? results[results.length - 1] : undefined;
              }
              try {
                const context = {
                  prev: results.length > 0 ? results[results.length - 1] : undefined,
                  results: results
                };
                const fn = new Function('context', `const { prev, results } = context; return ${expr};`);
                return fn(context);
              } catch (_) {
                return undefined;
              }
            }

            if (val.includes('$$')) {
              let replaced = val;
              const regex = /\$\$(.+?)\$\$/g;
              let match;
              while ((match = regex.exec(val)) !== null) {
                const placeholder = match[0];
                const expr = match[1].trim();
                let resolvedVal: any;
                if (expr === 'prev' || expr === 'prev.result') {
                  resolvedVal = results.length > 0 ? results[results.length - 1] : undefined;
                } else {
                  try {
                    const context = {
                      prev: results.length > 0 ? results[results.length - 1] : undefined,
                      results: results
                    };
                    const fn = new Function('context', `const { prev, results } = context; return ${expr};`);
                    resolvedVal = fn(context);
                  } catch (_) {
                    resolvedVal = undefined;
                  }
                }

                let stringVal = '';
                if (resolvedVal === undefined || resolvedVal === null) {
                  stringVal = '';
                } else if (typeof resolvedVal === 'object') {
                  if (resolvedVal instanceof Uint8Array) {
                    stringVal = toHex(resolvedVal);
                  } else {
                    stringVal = JSON.stringify(resolvedVal);
                  }
                } else {
                  stringVal = String(resolvedVal);
                }

                replaced = replaced.split(placeholder).join(stringVal);
              }
              return replaced;
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

      case 'findFunctions': {
        const bytes = toUint8Array(params.data);
        const format = params.format || 'auto';
        const targetSectionName = params.section;
        const arch = params.arch;

        // Detect format
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
            detected = 'raw';
          }
        }

        let entryPoint = 0;
        let sections: any[] = [];
        let symbols: any[] = [];

        if (detected === 'elf') {
          try {
            const parsed = parseElf(bytes.buffer as ArrayBuffer);
            entryPoint = Number(parsed.header.entryPoint);
            sections = parsed.sectionHeaders.map(s => {
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
            symbols = parsed.symbols.map(sym => ({
              name: sym.name,
              address: Number(sym.value),
              size: Number(sym.size),
              type: sym.type === 'FUNC' ? 'function' : sym.type === 'OBJECT' ? 'object' : 'none',
              binding: sym.bind === 'GLOBAL' ? 'global' : sym.bind === 'WEAK' ? 'weak' : 'local'
            }));
          } catch (_) {}
        } else if (detected === 'pe') {
          try {
            const parser = new PEParser(bytes.buffer as ArrayBuffer);
            const parsed = parser.parse();
            const imgBase = Number(parsed.optionalHeader.imageBase);
            entryPoint = imgBase + parsed.optionalHeader.addressOfEntryPoint;
            sections = parsed.sections.map(s => {
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
            if (parsed.exports && parsed.exports.exports) {
              symbols = parsed.exports.exports.map(e => ({
                name: e.name || '',
                address: imgBase + e.address,
                binding: 'global',
                type: 'function'
              }));
            }
          } catch (_) {}
        } else if (detected === 'macho') {
          try {
            const parser = new MachoParser(bytes);
            const parsed = parser.parse();
            const textSegment = parsed.segments.find(seg => seg.segname === '__TEXT');
            const imgBase = textSegment ? Number(textSegment.vmaddr) : 0;
            const lcMain = parsed.loadCommands.find(lc => lc.cmd === 0x80000028);
            if (lcMain && lcMain.payload && typeof (lcMain.payload as any).entryoff === 'number') {
              entryPoint = imgBase + (lcMain.payload as any).entryoff;
            }
            sections = parsed.sections.map((s: any) => {
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
            symbols = parsed.symbols.map((sym: any) => ({
              name: sym.name,
              address: Number(sym.value),
              binding: 'global',
              type: 'none'
            }));
          } catch (_) {}
        }

        if (sections.length === 0) {
          sections = [{
            name: '.text',
            virtualAddress: 0,
            virtualSize: bytes.length,
            fileOffset: 0,
            fileSize: bytes.length,
            flags: { read: true, write: false, execute: true }
          }];
        }

        let sectionsToScan = sections;
        if (targetSectionName) {
          sectionsToScan = sections.filter(s => s.name === targetSectionName);
        } else {
          sectionsToScan = sections.filter(s => s.flags.execute && s.fileSize > 0);
        }

        if (sectionsToScan.length === 0 && targetSectionName) {
          return { success: true, boundaries: [] };
        }

        const router = new DisassemblerRouter();
        const detectedArch = arch || DisassemblerRouter.detectArchitecture(bytes);
        const allBoundaries: { startVA: number; endVA: number; estimatedName: string }[] = [];

        for (const sec of sectionsToScan) {
          if (sec.fileSize === 0) continue;
          const secBytes = bytes.subarray(sec.fileOffset, sec.fileOffset + sec.fileSize);
          let insts: Instruction[] = [];
          try {
            insts = router.disassemble(secBytes, {
              arch: detectedArch as any,
              baseAddress: sec.virtualAddress
            });
          } catch (_) {
            continue;
          }

          if (insts.length === 0) continue;

          const entryPoints = new Set<number>();

          if (entryPoint >= sec.virtualAddress && entryPoint < sec.virtualAddress + sec.virtualSize) {
            entryPoints.add(entryPoint);
          }

          for (const sym of symbols) {
            if (sym.address >= sec.virtualAddress && sym.address < sec.virtualAddress + sec.virtualSize) {
              entryPoints.add(sym.address);
            }
          }

          for (let i = 0; i < insts.length; i++) {
            const inst = insts[i];
            const mnemonic = inst.mnemonic ? inst.mnemonic.toLowerCase() : '';
            const opStr = inst.opStr ? inst.opStr.toLowerCase() : '';

            // Pattern A: push rbp; mov rbp, rsp
            if (mnemonic === 'push' && (opStr === 'rbp' || opStr === 'ebp')) {
              if (i + 1 < insts.length) {
                const nextInst = insts[i + 1];
                const nextMnemonic = nextInst.mnemonic ? nextInst.mnemonic.toLowerCase() : '';
                const nextOpStr = nextInst.opStr ? nextInst.opStr.toLowerCase() : '';
                if (nextMnemonic === 'mov') {
                  const cleaned = nextOpStr.replace(/\s+/g, '');
                  if (cleaned === 'rbp,rsp' || cleaned === 'ebp,esp') {
                    entryPoints.add(inst.address);
                  }
                }
              }
            }

            // Pattern B: push rdi; push rsi
            if (mnemonic === 'push' && (opStr === 'rdi' || opStr === 'rsi' || opStr === 'rbx' || opStr === 'r12' || opStr === 'r13' || opStr === 'r14' || opStr === 'r15')) {
              if (i + 1 < insts.length) {
                const nextInst = insts[i + 1];
                const nextMnemonic = nextInst.mnemonic ? nextInst.mnemonic.toLowerCase() : '';
                const nextOpStr = nextInst.opStr ? nextInst.opStr.toLowerCase() : '';
                if (nextMnemonic === 'push' && (nextOpStr === 'rsi' || nextOpStr === 'rdi' || nextOpStr === 'rbx' || nextOpStr === 'r12' || nextOpStr === 'r13' || nextOpStr === 'r14' || nextOpStr === 'r15')) {
                  entryPoints.add(inst.address);
                }
              }
            }

            // Pattern C: sub rsp, imm
            if (mnemonic === 'sub' && (opStr.startsWith('rsp') || opStr.startsWith('esp') || opStr.startsWith('sp'))) {
              let isLikelyStart = false;
              if (i === 0) {
                isLikelyStart = true;
              } else {
                const prevInst = insts[i - 1];
                const prevMnemonic = prevInst.mnemonic ? prevInst.mnemonic.toLowerCase() : '';
                if (prevMnemonic === 'ret' || prevMnemonic === 'jmp' || prevMnemonic === 'hlt') {
                  isLikelyStart = true;
                }
              }
              if (isLikelyStart) {
                entryPoints.add(inst.address);
              }
            }

            // ARM patterns
            if (detectedArch === 'arm' || detectedArch === 'arm64') {
              if (mnemonic === 'push' && opStr.includes('lr')) {
                entryPoints.add(inst.address);
              }
              if (mnemonic === 'stp' && opStr.startsWith('x29, x30')) {
                entryPoints.add(inst.address);
              }
            }
          }

          // Heuristic 4: Call targets within this section
          for (const inst of insts) {
            const mnemonic = inst.mnemonic ? inst.mnemonic.toLowerCase() : '';
            if (mnemonic === 'call' || mnemonic === 'bl') {
              const opStr = inst.opStr ? inst.opStr.trim() : '';
              let destAddr = 0;
              if (opStr.startsWith('0x')) {
                destAddr = parseInt(opStr, 16);
              } else if (/^\d+$/.test(opStr)) {
                destAddr = parseInt(opStr, 10);
              }
              if (destAddr >= sec.virtualAddress && destAddr < sec.virtualAddress + sec.virtualSize) {
                entryPoints.add(destAddr);
              }
            }
          }

          const sortedEPs = Array.from(entryPoints).sort((a, b) => a - b);
          if (sortedEPs.length === 0) {
            sortedEPs.push(sec.virtualAddress);
          }

          const addrToIdx = new Map<number, number>();
          for (let idx = 0; idx < insts.length; idx++) {
            addrToIdx.set(insts[idx].address, idx);
          }

          for (let idx = 0; idx < sortedEPs.length; idx++) {
            const startVA = sortedEPs[idx];
            const nextStartVA = idx + 1 < sortedEPs.length ? sortedEPs[idx + 1] : sec.virtualAddress + sec.virtualSize;

            const instIdx = addrToIdx.get(startVA);
            let endVA = nextStartVA;

            if (instIdx !== undefined) {
              let lastTerminalAddr = -1;
              let lastTerminalSize = 0;

              for (let k = instIdx; k < insts.length; k++) {
                const checkInst = insts[k];
                if (checkInst.address >= nextStartVA) break;

                const checkMnemonic = checkInst.mnemonic ? checkInst.mnemonic.toLowerCase() : '';
                if (checkMnemonic === 'ret' || checkMnemonic === 'hlt') {
                  lastTerminalAddr = checkInst.address;
                  lastTerminalSize = checkInst.size;
                } else if (checkMnemonic === 'jmp') {
                  const checkOpStr = checkInst.opStr ? checkInst.opStr.trim() : '';
                  let destAddr = 0;
                  if (checkOpStr.startsWith('0x')) {
                    destAddr = parseInt(checkOpStr, 16);
                  } else if (/^\d+$/.test(checkOpStr)) {
                    destAddr = parseInt(checkOpStr, 10);
                  }
                  if (destAddr > 0 && (destAddr < startVA || destAddr >= nextStartVA)) {
                    lastTerminalAddr = checkInst.address;
                    lastTerminalSize = checkInst.size;
                  }
                }
              }

              if (lastTerminalAddr !== -1) {
                endVA = lastTerminalAddr + lastTerminalSize;
              }
            }

            const matchingSym = symbols.find(s => s.address === startVA);
            const estimatedName = matchingSym ? matchingSym.name : `func_0x${startVA.toString(16)}`;

            allBoundaries.push({
              startVA,
              endVA,
              estimatedName
            });
          }
        }

        return { success: true, boundaries: allBoundaries };
      }

      case 'sessionSave': {
        const filePath = params.filePath;
        if (!filePath) {
          throw new Error('Missing "filePath" parameter');
        }

        const emu = this.getEmulator();
        
        // Serialize CPU state
        const cpuState: Record<string, string> = {};
        for (const [reg, val] of Object.entries(emu.cpu.getState())) {
          cpuState[reg] = val.toString();
        }

        // Serialize Memory
        const memoryRegions = emu.memory.getMemoryMap().map(region => ({
          address: region.address.toString(),
          size: region.size,
          name: region.name,
          permissions: { ...region.permissions }
        }));

        const memoryPages: Record<string, string> = {};
        for (const [pageKey, pageData] of emu.memory.getPages().entries()) {
          let isAllZero = true;
          for (let i = 0; i < pageData.length; i++) {
            if (pageData[i] !== 0) {
              isAllZero = false;
              break;
            }
          }
          if (!isAllZero) {
            memoryPages[pageKey.toString()] = toHex(pageData);
          }
        }

        // Serialize Breakpoints
        const breakpoints = Array.from(emu.breakpoints);

        // Serialize Execution Traces
        const trace = emu.trace.map(step => ({
          stepIndex: step.stepIndex,
          rip: step.rip.toString(),
          instruction: {
            address: step.instruction.address,
            mnemonic: step.instruction.mnemonic,
            opStr: step.instruction.opStr,
            bytes: step.instruction.bytes ? toHex(step.instruction.bytes) : undefined
          },
          registers: Object.fromEntries(
            Object.entries(step.registers).map(([reg, val]) => [reg, val.toString()])
          )
        }));

        // Serialize instructions cache
        const instructions = Array.from(emu.instructions.entries()).map(([addr, inst]) => ({
          address: addr,
          bytes: inst.bytes ? toHex(inst.bytes) : undefined,
          mnemonic: inst.mnemonic,
          opStr: inst.opStr,
          operands: inst.operands ? inst.operands.map(op => {
            if (op.type === 'imm' && typeof op.imm === 'bigint') {
              return { ...op, imm: op.imm.toString() };
            }
            return op;
          }) : undefined,
          size: inst.size
        }));

        // Serialize loaded binary bytes
        const loadedBinaryHex = AIBridge.loadedBinaryBytes ? toHex(AIBridge.loadedBinaryBytes) : null;

        const sessionData = {
          loadedBinaryHex,
          cpuState,
          memory: {
            regions: memoryRegions,
            pages: memoryPages
          },
          breakpoints,
          trace,
          instructions
        };

        const fs = await import('fs');
        const path = await import('path');
        const absolutePath = path.resolve(filePath);
        const dir = path.dirname(absolutePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(absolutePath, JSON.stringify(sessionData, null, 2), 'utf-8');

        return {
          success: true,
          message: `Session saved successfully to ${filePath}`
        };
      }

      case 'sessionLoad': {
        const filePath = params.filePath;
        if (!filePath) {
          throw new Error('Missing "filePath" parameter');
        }

        const fs = await import('fs');
        const path = await import('path');
        const absolutePath = path.resolve(filePath);
        
        if (!fs.existsSync(absolutePath)) {
          throw new Error(`Session file not found: ${filePath}`);
        }

        const content = fs.readFileSync(absolutePath, 'utf-8');
        const sessionData = JSON.parse(content);

        // Restore loaded binary bytes
        if (sessionData.loadedBinaryHex) {
          AIBridge.loadedBinaryBytes = toUint8Array(sessionData.loadedBinaryHex);
        } else {
          AIBridge.loadedBinaryBytes = null;
        }

        const emu = this.getEmulator();

        // Restore CPU State
        if (sessionData.cpuState) {
          emu.cpu.reset();
          for (const [reg, val] of Object.entries(sessionData.cpuState)) {
            emu.cpu.writeGPR(reg as any, BigInt(val as string));
          }
        }

        // Restore Breakpoints
        emu.breakpoints.clear();
        if (sessionData.breakpoints && Array.isArray(sessionData.breakpoints)) {
          for (const bp of sessionData.breakpoints) {
            emu.breakpoints.add(Number(bp));
          }
        }

        // Restore Memory Regions and Pages
        if (sessionData.memory) {
          const regions = (sessionData.memory.regions || []).map((r: any) => ({
            address: BigInt(r.address),
            size: Number(r.size),
            name: String(r.name),
            permissions: {
              read: Boolean(r.permissions?.read),
              write: Boolean(r.permissions?.write),
              execute: Boolean(r.permissions?.execute)
            }
          }));

          const pagesMap = new Map<bigint, Uint8Array>();
          if (sessionData.memory.pages) {
            for (const [key, hexVal] of Object.entries(sessionData.memory.pages)) {
              pagesMap.set(BigInt(key), toUint8Array(hexVal as string));
            }
          }
          emu.memory.clearAndLoad(regions, pagesMap);
        }

        // Restore Trace
        emu.trace = [];
        if (sessionData.trace && Array.isArray(sessionData.trace)) {
          emu.trace = sessionData.trace.map((step: any) => ({
            stepIndex: Number(step.stepIndex),
            rip: BigInt(step.rip),
            instruction: {
              address: Number(step.instruction.address),
              mnemonic: String(step.instruction.mnemonic),
              opStr: String(step.instruction.opStr),
              bytes: step.instruction.bytes ? toUint8Array(step.instruction.bytes) : new Uint8Array()
            },
            registers: Object.fromEntries(
              Object.entries(step.registers || {}).map(([reg, val]) => [reg, BigInt(val as string)])
            )
          }));
        }

        // Restore instructions cache
        emu.instructions.clear();
        if (sessionData.instructions && Array.isArray(sessionData.instructions)) {
          for (const inst of sessionData.instructions) {
            emu.instructions.set(inst.address, {
              address: inst.address,
              bytes: inst.bytes ? toUint8Array(inst.bytes) : new Uint8Array(),
              mnemonic: inst.mnemonic,
              opStr: inst.opStr,
              operands: inst.operands ? inst.operands.map((op: any) => {
                if (op.type === 'imm' && op.imm !== undefined) {
                  return { ...op, imm: BigInt(op.imm) };
                }
                return op;
              }) : undefined,
              size: inst.size
            });
          }
        }

        return {
          success: true,
          message: `Session loaded successfully from ${filePath}`
        };
      }

      case 'generateReport': {
        // Step 1: loadBinary if data or filePath is provided
        if (params.data || params.filePath) {
          await AIBridge.executeQuery({
            action: 'loadBinary',
            params: { data: params.data, filePath: params.filePath }
          });
        }

        const bytes = AIBridge.loadedBinaryBytes;
        if (!bytes) {
          throw new Error('No binary loaded. Provide "data" or "filePath", or load a binary first.');
        }

        // Step 2: parseBinary
        let parsed: any;
        try {
          parsed = await AIBridge.executeQuery({
            action: 'parseBinary',
            params: { data: toHex(bytes), format: 'auto' }
          });
        } catch (e: any) {
          parsed = {
            success: false,
            format: 'unknown',
            sections: [],
            symbols: [],
            entryPoint: 0,
            entryPointAddress: 0
          };
        }

        // Step 3: extractStrings
        let strings: any[] = [];
        try {
          const stringsResult = await AIBridge.executeQuery({
            action: 'extractStrings',
            params: { data: toHex(bytes), minLength: 4, ascii: true, utf16le: true }
          });
          strings = stringsResult.strings || [];
        } catch (_) {}

        const normalizedSymbols = (parsed.symbols || []).map((sym: any) => {
          const address = sym.address !== undefined ? Number(sym.address) : (sym.value !== undefined ? Number(sym.value) : 0);
          const size = sym.size !== undefined ? Number(sym.size) : 0;
          return {
            name: sym.name || '',
            address,
            size,
            binding: sym.binding || sym.bind || 'global',
            type: sym.type || 'unknown'
          };
        });

        const unsafeApiNames = new Set([
          'strcpy', 'strcat', 'sprintf', 'gets', 'system', 'exec', 'popen'
        ]);
        for (const strObj of strings) {
          if (strObj && strObj.value && unsafeApiNames.has(strObj.value.toLowerCase().trim())) {
            const exists = normalizedSymbols.some((s: any) => s.name.toLowerCase() === strObj.value.toLowerCase().trim());
            if (!exists) {
              normalizedSymbols.push({
                name: strObj.value.trim(),
                address: strObj.address || 0,
                size: 0,
                binding: 'global',
                type: 'function'
              });
            }
          }
        }

        // Step 4: entropyAnalysis
        let entropyResult: any = { overall: 0, highEntropyBlocks: [] };
        try {
          const entRes = await AIBridge.executeQuery({
            action: 'entropyAnalysis',
            params: { data: toHex(bytes) }
          });
          if (entRes.success) {
            entropyResult = entRes;
          }
        } catch (_) {}

        // Step 5: yaraScan
        const defaultYaraRules = `
          rule SuspiciousStrings {
            meta:
              description = "Default URET rule searching for typical suspicious strings"
            strings:
              $cmd = "cmd.exe" ascii nocase
              $ps = "powershell.exe" ascii nocase
              $sh = "/bin/sh" ascii nocase
              $bash = "/bin/bash" ascii nocase
            condition:
              any of them
          }
        `;
        const rulesToUse = params.rules || defaultYaraRules;
        let yaraMatches: any[] = [];
        try {
          const yaraResult = await AIBridge.executeQuery({
            action: 'yaraScan',
            params: { data: toHex(bytes), rules: rulesToUse }
          });
          yaraMatches = yaraResult.matches || [];
        } catch (_) {}

        // Step 6: disassemble and vulnScan
        let instructions: any[] = [];
        try {
          const disasmRes = await AIBridge.executeQuery({
            action: 'disassemble',
            params: {
              data: toHex(bytes),
              baseAddress: parsed.entryPointAddress || undefined
            }
          });
          if (disasmRes.success) {
            instructions = disasmRes.instructions || [];
          }
        } catch (_) {}

        let vulnerabilities: any[] = [];
        try {
          const vulnResult = await AIBridge.executeQuery({
            action: 'vulnScan',
            params: {
              data: toHex(bytes),
              sections: parsed.sections || [],
              symbols: normalizedSymbols,
              instructions: instructions
            }
          });
          vulnerabilities = vulnResult.vulnerabilities || [];
        } catch (_) {}

        // Step 7: exportToIda
        let idaScript = '';
        try {
          const idaResult = await AIBridge.executeQuery({
            action: 'exportToIda',
            params: { data: toHex(bytes) }
          });
          idaScript = idaResult.script || '';
        } catch (_) {}

        // Normalize sections & symbols for ReportGenerator
        const normalizedSections = (parsed.sections || []).map((s: any) => {
          const virtualAddress = s.virtualAddress !== undefined ? Number(s.virtualAddress) : (s.addr !== undefined ? Number(s.addr) : 0);
          const virtualSize = s.virtualSize !== undefined ? Number(s.virtualSize) : (s.size !== undefined ? Number(s.size) : 0);
          const fileOffset = s.fileOffset !== undefined ? Number(s.fileOffset) : (s.offset !== undefined ? Number(s.offset) : 0);
          const fileSize = s.fileSize !== undefined ? Number(s.fileSize) : (s.size !== undefined ? Number(s.size) : 0);
          
          let flags = s.flags || { read: true, write: false, execute: false };
          if (typeof s.flags === 'bigint' || typeof s.flags === 'number') {
            const fNum = Number(s.flags);
            flags = {
              read: true,
              write: (fNum & 1) !== 0 || (fNum & 0x80000000) !== 0,
              execute: (fNum & 4) !== 0 || (fNum & 2) !== 0 || (fNum & 0x20000000) !== 0
            };
          }

          let entropy = s.entropy;
          if (entropy === undefined && bytes && fileOffset >= 0 && fileSize > 0 && fileOffset + fileSize <= bytes.length) {
            try {
              const secBytes = bytes.subarray(fileOffset, fileOffset + fileSize);
              entropy = calculateEntropy(secBytes);
            } catch (_) {}
          }

          return {
            name: s.name || s.sectname || '',
            virtualAddress,
            virtualSize,
            fileOffset,
            fileSize,
            entropy,
            flags
          };
        });

        // Build ReportData
        const reportFileName = params.fileName || (params.filePath ? params.filePath.split(/[\\/]/).pop() : null) || 'loaded_binary';
        const reportData: any = {
          fileName: reportFileName,
          fileSize: bytes.length,
          architecture: parsed.format === 'pe' ? 'x86_64' : (parsed.format === 'macho' ? 'x86_64' : 'x86_64'),
          entryPoint: parsed.entryPointAddress || parsed.entryPoint || 0,
          sections: normalizedSections,
          symbols: normalizedSymbols,
          signatures: [],
          entropy: {
            overall: entropyResult.overall || 0,
            highEntropyBlocks: entropyResult.highEntropyBlocks || []
          },
          strings: strings,
          binaryData: bytes
        };

        // Construct JSON report
        const jsonReportObj = JSON.parse(ReportGenerator.generateJSON(reportData));
        jsonReportObj.yaraMatches = yaraMatches;
        jsonReportObj.vulnerabilities = vulnerabilities;
        jsonReportObj.idaScript = idaScript;

        // Construct Markdown report
        let markdownReport = ReportGenerator.generateMarkdown(reportData);

        // Append YARA matches section
        markdownReport += `\n## 🛡️ YARA Scan Results\n\n`;
        if (yaraMatches && yaraMatches.length > 0) {
          markdownReport += `| Rule Name | Matched | Matches Count |\n`;
          markdownReport += `|---|---|---|\n`;
          for (const match of yaraMatches) {
            markdownReport += `| **${match.ruleName}** | \`${match.matched}\` | ${match.matches?.length || 0} |\n`;
          }
        } else {
          markdownReport += `No YARA signatures matched.\n`;
        }
        markdownReport += `\n`;

        // Append Vulnerabilities section
        markdownReport += `\n## ⚠️ Vulnerability / Unsafe API Scan Results\n\n`;
        if (vulnerabilities && vulnerabilities.length > 0) {
          markdownReport += `| Category | Severity | Description | Evidence | Address |\n`;
          markdownReport += `|---|---|---|---|---|\n`;
          for (const vuln of vulnerabilities) {
            const addrStr = vuln.address !== undefined ? `0x${vuln.address.toString(16).toUpperCase()}` : 'N/A';
            markdownReport += `| \`${vuln.category}\` | \`${vuln.severity}\` | ${vuln.description} | \`${vuln.evidence}\` | ${addrStr} |\n`;
          }
        } else {
          markdownReport += `No vulnerabilities detected.\n`;
        }
        markdownReport += `\n`;

        // Append IDA script
        markdownReport += `\n## 🔌 IDA Pro / Ghidra Export Script\n\n`;
        if (idaScript) {
          markdownReport += `\`\`\`cpp\n${idaScript}\n\`\`\`\n`;
        } else {
          markdownReport += `No IDA script generated.\n`;
        }
        markdownReport += `\n`;

        return {
          success: true,
          jsonReport: jsonReportObj,
          markdownReport: markdownReport
        };
      }

      case 'deobfuscate': {
        let insts = params.instructions;
        if (!insts && params.data) {
          const bytes = toUint8Array(params.data);
          const resolved = resolveElfOrPe(bytes, undefined, params.entryPoint ?? params.address ?? params.baseAddress);
          const router = new DisassemblerRouter();
          insts = router.disassemble(resolved.data, {
            arch: params.arch || 'x86_64',
            baseAddress: resolved.baseAddress
          });
        }
        if (!insts || insts.length === 0) {
          throw new Error('No instructions provided for analysis');
        }

        const normalizedInsts = insts.map((inst: any) => {
          const address = typeof inst.address === 'number' ? inst.address : Number(inst.address || 0);
          const mnemonic = (inst.mnemonic || inst.op || '').toLowerCase().trim();
          const opStr = inst.opStr || (inst.args ? inst.args.join(', ') : '');
          const size = typeof inst.size === 'number' ? inst.size : 4;
          
          let operands = inst.operands;
          if (!operands || operands.length === 0) {
            const args = inst.args || (opStr ? opStr.split(',').map((s: string) => s.trim()) : []);
            operands = args.map((arg: string) => {
              const clean = arg.trim();
              if (clean.startsWith('0x') || clean.startsWith('0X') || /^-?\d+$/.test(clean) || clean.startsWith('#')) {
                let numStr = clean;
                if (numStr.startsWith('#')) numStr = numStr.substring(1).trim();
                try {
                  return { type: 'imm', imm: BigInt(numStr) };
                } catch (_) {
                  return { type: 'imm', imm: 0n };
                }
              }
              if (clean.includes('[') || clean.includes(']')) {
                const match = clean.match(/([er]?sp|fp|[er]?bp|[a-z0-9]+)/i);
                return { type: 'mem', mem: { base: match ? match[1] : clean } };
              }
              return { type: 'reg', reg: clean };
            });
          }
          
          const bytes = inst.bytes || new Uint8Array();
          return {
            address,
            mnemonic,
            opStr,
            size,
            operands,
            bytes
          };
        });

        const xorLoops = detectXorLoops(normalizedInsts);
        const stackStrings = detectStackStrings(normalizedInsts);
        const flattening = detectControlFlowFlattening(normalizedInsts);

        const detectedPatterns = [...xorLoops, ...stackStrings, ...flattening];

        return {
          success: true,
          detected: detectedPatterns.length > 0,
          patterns: detectedPatterns
        };
      }

      default:
        throw new Error(`Unsupported bridge action: ${action}`);
    }
  }
}

function detectXorLoops(instructions: Instruction[]): any[] {
  const detected: any[] = [];
  const sortedInsts = [...instructions].sort((a, b) => a.address - b.address);
  const addrToInst = new Map<number, Instruction>();
  for (const inst of sortedInsts) {
    addrToInst.set(inst.address, inst);
  }
  for (const inst of sortedInsts) {
    const mnemonic = inst.mnemonic.toLowerCase();
    const isJump = InstructionClassifier.isConditionalJump(inst.mnemonic) || 
                   InstructionClassifier.isUnconditionalJump(inst.mnemonic) ||
                   mnemonic.startsWith('b') || 
                   mnemonic.startsWith('j') || 
                   mnemonic === 'loop';
    if (!isJump) continue;
    let target: number | null = null;
    if (inst.operands) {
      target = getBranchTarget(inst);
    }
    if (target === null && inst.opStr) {
      const parts = inst.opStr.split(',').map(p => p.trim());
      for (const part of parts) {
        if (part.startsWith('0x') || part.startsWith('0X')) {
          const val = parseInt(part, 16);
          if (!isNaN(val)) target = val;
        } else if (/^\d+$/.test(part)) {
          const val = parseInt(part, 10);
          if (!isNaN(val)) target = val;
        }
      }
    }
    if (target !== null && target <= inst.address) {
      if (!addrToInst.has(target)) continue;
      for (const loopInst of sortedInsts) {
        if (loopInst.address >= target && loopInst.address < inst.address) {
          const loopMnemonic = loopInst.mnemonic.toLowerCase();
          if (loopMnemonic === 'xor' || loopMnemonic === 'eor') {
            const ops = loopInst.opStr.split(',').map(s => s.trim().toLowerCase());
            const isSelfXor = ops.length >= 2 && ops[0] === ops[1];
            if (!isSelfXor) {
              let key: string | undefined = undefined;
              if (ops.length >= 2) {
                const second = ops[1];
                if (second.startsWith('0x') || second.startsWith('0X') || /^\d+$/.test(second)) {
                  key = second;
                }
              }
              detected.push({
                pattern: 'XOR key-decryption loop',
                loopStart: target,
                loopEnd: inst.address,
                xorAddress: loopInst.address,
                xorInstruction: `${loopInst.mnemonic} ${loopInst.opStr}`,
                key,
                description: `Detected a potential decryption loop starting at 0x${target.toString(16)} and ending with a backward jump at 0x${inst.address.toString(16)}. It contains a non-self XOR instruction at 0x${loopInst.address.toString(16)}: "${loopInst.mnemonic} ${loopInst.opStr}".`,
                suggestion: `Suggestions for deobfuscation:\n` +
                  `1. Statically decrypt the data by extracting the encrypted payload from the binary, applying XOR with key ${key || 'detected in loop'}, and patching it back using URET's 'patchBinary' tool.\n` +
                  `2. Dynamically execute the loop using the 'emulatorControl' or 'patchAndRun' tool to let the loop execute and decrypt the memory automatically, then dump the memory.`
              });
            }
          }
        }
      }
    }
  }
  return detected;
}

function detectStackStrings(instructions: Instruction[]): any[] {
  const detected: any[] = [];
  const sortedInsts = [...instructions].sort((a, b) => a.address - b.address);
  
  function checkIsStackWrite(inst: Instruction): boolean {
    const mnemonic = inst.mnemonic.toLowerCase();
    const isMovOrStr = mnemonic.startsWith('mov') || mnemonic.startsWith('str');
    if (!isMovOrStr) return false;
    const parts = inst.opStr.split(',').map(p => p.trim());
    if (parts.length < 2) return false;
    const dest = parts[0];
    const src = parts[1];
    const hasStackReg = /([er]?sp|fp|[er]?bp)/i.test(dest);
    if (!hasStackReg) return false;
    const isImm = src.startsWith('0x') || src.startsWith('0X') || /^-?\d+$/.test(src) || src.startsWith('#');
    return isImm;
  }
  
  function getStackWriteInfo(inst: Instruction): { offset: number; value: bigint; size: number } | null {
    const parts = inst.opStr.split(',').map(p => p.trim());
    const dest = parts[0];
    const src = parts[1];
    let offset = 0;
    const offsetMatch = dest.match(/([+-])\s*(0x[0-9a-fA-F]+|\d+)/);
    if (offsetMatch) {
      const sign = offsetMatch[1] === '-' ? -1 : 1;
      const valStr = offsetMatch[2];
      const val = valStr.startsWith('0x') || valStr.startsWith('0X') ? parseInt(valStr, 16) : parseInt(valStr, 10);
      offset = sign * val;
    }
    let cleanSrc = src;
    if (src.startsWith('#')) {
      cleanSrc = src.substring(1).trim();
    }
    let value = 0n;
    if (cleanSrc.startsWith('0x') || cleanSrc.startsWith('0X')) {
      value = BigInt(cleanSrc);
    } else if (/^-?\d+$/.test(cleanSrc)) {
      value = BigInt(cleanSrc);
    } else {
      return null;
    }
    let size = 1;
    const destLower = dest.toLowerCase();
    if (destLower.includes('byte') || inst.mnemonic.toLowerCase() === 'strb') size = 1;
    else if (destLower.includes('word') && !destLower.includes('dword') || inst.mnemonic.toLowerCase() === 'strh') size = 2;
    else if (destLower.includes('dword') || inst.mnemonic.toLowerCase() === 'str') size = 4;
    else if (destLower.includes('qword')) size = 8;
    else {
      if (value > 0xffffffffn) size = 8;
      else if (value > 0xffffn) size = 4;
      else if (value > 0xffn) size = 2;
    }
    return { offset, value, size };
  }
  
  let currentGroup: Instruction[] = [];
  let gapCount = 0;
  
  for (const inst of sortedInsts) {
    if (checkIsStackWrite(inst)) {
      currentGroup.push(inst);
      gapCount = 0;
    } else {
      if (currentGroup.length > 0) {
        gapCount++;
        if (gapCount > 2) {
          if (currentGroup.length >= 3) {
            processGroup(currentGroup);
          }
          currentGroup = [];
          gapCount = 0;
        }
      }
    }
  }
  if (currentGroup.length >= 3) {
    processGroup(currentGroup);
  }
  
  function processGroup(group: Instruction[]) {
    const stackWrites = group.filter(checkIsStackWrite);
    if (stackWrites.length < 3) return;
    const offsetToByte = new Map<number, number>();
    for (const inst of stackWrites) {
      const info = getStackWriteInfo(inst);
      if (info) {
        const { offset, value, size } = info;
        let temp = value;
        for (let i = 0; i < size; i++) {
          offsetToByte.set(offset + i, Number(temp & 0xffn));
          temp >>= 8n;
        }
      }
    }
    const sortedOffsets = Array.from(offsetToByte.keys()).sort((a, b) => a - b);
    let reconstructed = '';
    let printableCount = 0;
    for (const off of sortedOffsets) {
      const b = offsetToByte.get(off)!;
      if (b >= 32 && b <= 126) {
        reconstructed += String.fromCharCode(b);
        printableCount++;
      } else if (b === 0) {
        reconstructed += '\\0';
      } else {
        reconstructed += `\\x${b.toString(16).padStart(2, '0')}`;
      }
    }
    if (printableCount >= 3) {
      detected.push({
        pattern: 'Stack-string construction',
        startAddress: stackWrites[0].address,
        endAddress: stackWrites[stackWrites.length - 1].address + stackWrites[stackWrites.length - 1].size,
        reconstructedString: reconstructed,
        instructionsCount: stackWrites.length,
        description: `Detected successive moves of character constants into stack offsets from address 0x${stackWrites[0].address.toString(16)} to 0x${stackWrites[stackWrites.length - 1].address.toString(16)}.`,
        suggestion: `Suggestions for deobfuscation:\n` +
          `1. Reconstructed stack-string value: "${reconstructed}".\n` +
          `2. Replace the sequence of character assignments with a single string allocation or comment the reconstructed string value above the instructions.`
      });
    }
  }
  return detected;
}

function detectControlFlowFlattening(instructions: Instruction[]): any[] {
  const detected: any[] = [];
  const blocks = buildCFG(instructions);
  if (blocks.length < 3) return [];
  const inDegree = new Map<string, number>();
  for (const b of blocks) {
    inDegree.set(b.id, 0);
  }
  for (const b of blocks) {
    for (const succ of b.successors) {
      inDegree.set(succ, (inDegree.get(succ) || 0) + 1);
    }
  }
  const dispatchers = blocks.filter(b => (inDegree.get(b.id) || 0) >= 3);
  if (dispatchers.length === 0) return [];
  
  const cmpStateStats = new Map<string, Set<string>>();
  const movStateStats = new Map<string, Set<string>>();
  
  for (const inst of instructions) {
    const mnemonic = inst.mnemonic.toLowerCase();
    if (mnemonic === 'cmp') {
      const parts = inst.opStr.split(',').map(s => s.trim());
      if (parts.length === 2) {
        const op1 = parts[0];
        const op2 = parts[1];
        if (op2.startsWith('0x') || op2.startsWith('0X') || /^-?\d+$/.test(op2) || op2.startsWith('#')) {
          let cleanOp2 = op2;
          if (cleanOp2.startsWith('#')) cleanOp2 = cleanOp2.substring(1).trim();
          if (!cmpStateStats.has(op1)) {
            cmpStateStats.set(op1, new Set());
          }
          cmpStateStats.get(op1)!.add(cleanOp2);
        }
      }
    } else if (mnemonic === 'mov' || mnemonic === 'ldr' || mnemonic === 'str') {
      const parts = inst.opStr.split(',').map(s => s.trim());
      if (parts.length === 2) {
        const op1 = parts[0];
        const op2 = parts[1];
        if (op2.startsWith('0x') || op2.startsWith('0X') || /^-?\d+$/.test(op2) || op2.startsWith('#')) {
          let cleanOp2 = op2;
          if (cleanOp2.startsWith('#')) cleanOp2 = cleanOp2.substring(1).trim();
          if (!movStateStats.has(op1)) {
            movStateStats.set(op1, new Set());
          }
          movStateStats.get(op1)!.add(cleanOp2);
        }
      }
    }
  }
  for (const [stateVar, cmpVals] of cmpStateStats.entries()) {
    const movVals = movStateStats.get(stateVar) || new Set<string>();
    const allVals = new Set([...cmpVals, ...movVals]);
    if (allVals.size >= 3) {
      for (const disp of dispatchers) {
        detected.push({
          pattern: 'Control Flow Flattening',
          dispatcherAddress: disp.startAddress,
          dispatcherBlockId: disp.id,
          inDegree: inDegree.get(disp.id),
          stateVariable: stateVar,
          stateConstants: Array.from(allVals),
          description: `Detected Control Flow Flattening with dispatcher block at 0x${disp.startAddress.toString(16)} (in-degree ${inDegree.get(disp.id)}). The control flow is driven by state variable "${stateVar}" which has ${allVals.size} unique states.`,
          suggestion: `Suggestions for deobfuscation:\n` +
            `1. Trace state transitions dynamically using URET's 'emulatorControl' to execute basic blocks and record the sequence of state variables.\n` +
            `2. Use symbolic execution ('symbolicExecute') to determine which state values trigger which target blocks, bypassing the dispatcher entirely and reconstructing a clean CFG.`
        });
      }
    }
  }
  return detected;
}
