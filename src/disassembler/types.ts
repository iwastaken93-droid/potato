/**
 * Core TypeScript definitions for the Disassembler.
 * Part of the Universal Reverse Engineering Tool.
 */

/**
 * Represents a parsed machine instruction.
 */
export interface Instruction {
  /** The memory address (virtual address) of the instruction in hex string format or big-endian numeric representation */
  address: number;

  /** Raw bytes of the instruction */
  bytes: Uint8Array;

  /** Mnemonic representing the operation (e.g., 'mov', 'push', 'add', 'jmp') */
  mnemonic: string;

  /** Formatted assembly operands as a string (e.g., 'rax, [rbx + 0x10]') */
  opStr: string;

  /** List of parsed operands for deeper programmatic analysis */
  operands: Operand[];

  /** Size of the instruction in bytes */
  size: number;

  /** Optional CPU architecture group/category */
  groups?: number[];

  /** Register values read by this instruction (register IDs) */
  regsRead?: number[];

  /** Register values written by this instruction (register IDs) */
  regsWrite?: number[];

  /** Optional source code line number */
  line?: number;

  /** Optional active local variables at this instruction */
  localVariables?: { name: string; type: string; signature?: string; reg: string }[];
}

export type OperandType = 'reg' | 'imm' | 'mem' | 'invalid';

export interface Operand {
  type: OperandType;

  /** Register name or ID if type is 'reg' */
  reg?: string | number;

  /** Immediate value if type is 'imm' */
  imm?: number | bigint;

  /** Memory operand details if type is 'mem' */
  mem?: MemoryOperand;

  /** Access mode: Read, Write, or Read/Write */
  access?: 'r' | 'w' | 'rw';
}

export interface MemoryOperand {
  /** Base register (e.g., 'rax') */
  base?: string | number;

  /** Index register (e.g., 'rcx') */
  index?: string | number;

  /** Scaling factor for index register (typically 1, 2, 4, or 8) */
  scale?: number;

  /** Displacement/Offset value added to the address calculation */
  disp?: number | bigint;

  /** Segment register override if any (e.g., 'gs', 'fs') */
  segment?: string | number;
}

/**
 * Represents a logical section in a binary (e.g., .text, .data, .rodata).
 */
export interface Section {
  /** Name of the section (e.g., '.text') */
  name: string;

  /** Virtual memory address where this section starts */
  virtualAddress: number;

  /** Virtual size in memory */
  virtualSize: number;

  /** File/Raw offset where this section is located within the binary */
  fileOffset: number;

  /** Size of the section within the file */
  fileSize: number;

  /** Access permissions / flags for this section */
  flags: SectionFlags;

  /** Entropy score to identify packed or compressed regions (0.0 to 8.0) */
  entropy?: number;
}

export interface SectionFlags {
  read: boolean;
  write: boolean;
  execute: boolean;
  shared?: boolean;
}

/**
 * Represents a symbolic name mapping to a virtual memory address.
 */
export interface Symbol {
  /** Symbol name or label */
  name: string;

  /** Virtual memory address */
  address: number;

  /** Size in bytes associated with the symbol (e.g. function size) */
  size?: number;

  /** Scope of the symbol */
  binding: 'local' | 'global' | 'weak';

  /** Type of symbol (e.g., function, data variable) */
  type: 'function' | 'object' | 'section' | 'file' | 'none';
}

/**
 * Represents a relocation entry for fixing up addresses.
 */
export interface Relocation {
  /** Virtual address where the relocation fixup needs to be applied */
  address: number;

  /** The symbol referred to by this relocation, if any */
  symbolName?: string;

  /** Relocation type (architecture-dependent identifier) */
  type: string | number;

  /** Addend to be included in the relocation calculation */
  addend?: number | bigint;
}

/**
 * Represents an execution segment or program header (specifically relevant for ELF / PE loading).
 */
export interface Segment {
  /** Index or name of the segment */
  id: number | string;

  /** Segment type (e.g. LOAD, DYNAMIC, INTERP) */
  type: string;

  /** Virtual address where this segment is mapped */
  virtualAddress: number;

  /** Physical address if applicable */
  physicalAddress?: number;

  /** Size of the segment in virtual memory */
  virtualSize: number;

  /** File/Raw offset of the segment within the binary */
  fileOffset: number;

  /** Size of the segment within the file */
  fileSize: number;

  /** Memory protection flags (R, W, X) */
  flags: SegmentFlags;

  /** Segment alignment requirement */
  alignment: number;
}

export interface SegmentFlags {
  read: boolean;
  write: boolean;
  execute: boolean;
}
