import { Instruction, Section, Symbol } from '../disassembler/types.js';

/**
 * Types of cross-references (XRefs).
 */
export type XRefType =
  | 'CALL' // Subroutine/function call (e.g., x86 call, ARM bl)
  | 'JUMP' // Control flow jump/branch (e.g., jmp, jne, b)
  | 'DATA_READ' // Reading from a memory or data address
  | 'DATA_WRITE' // Writing to a memory or data address
  | 'DATA' // Generic address reference (e.g., pointer in data block)
  | 'UNKNOWN';

/**
 * Represents a single cross-reference link.
 */
export interface XRef {
  /** The address where the reference starts (source) */
  from: number;
  /** The address that is referenced (target) */
  to: number;
  /** The category of reference */
  type: XRefType;
  /** Context description (e.g., disassembled assembly line, pointer format) */
  context?: string;
}

/**
 * Cross-references (XRefs) Engine.
 * Analyzes instructions, memory segments/sections, symbols, and raw binary bytes
 * to trace, map, and query control flow and data connections.
 */
export class XRefEngine {
  private xRefsTo = new Map<number, XRef[]>();
  private xRefsFrom = new Map<number, XRef[]>();

  /**
   * Resets the entire reference maps.
   */
  public clear(): void {
    this.xRefsTo.clear();
    this.xRefsFrom.clear();
  }

  /**
   * Manually adds a cross-reference.
   */
  public addXRef(xref: XRef): void {
    // Register "to" lookup
    if (!this.xRefsTo.has(xref.to)) {
      this.xRefsTo.set(xref.to, []);
    }
    const toList = this.xRefsTo.get(xref.to)!;
    if (!toList.some((x) => x.from === xref.from && x.type === xref.type)) {
      toList.push(xref);
    }

    // Register "from" lookup
    if (!this.xRefsFrom.has(xref.from)) {
      this.xRefsFrom.set(xref.from, []);
    }
    const fromList = this.xRefsFrom.get(xref.from)!;
    if (!fromList.some((x) => x.to === xref.to && x.type === xref.type)) {
      fromList.push(xref);
    }
  }

  /**
   * Gets all references pointing TO the given address.
   */
  public getXRefsTo(address: number): XRef[] {
    return this.xRefsTo.get(address) || [];
  }

  /**
   * Gets all references originating FROM the given address.
   */
  public getXRefsFrom(address: number): XRef[] {
    return this.xRefsFrom.get(address) || [];
  }

  /**
   * Returns all extracted cross-references.
   */
  public getAllXRefs(): XRef[] {
    const all: XRef[] = [];
    const seen = new Set<string>();
    for (const refs of this.xRefsTo.values()) {
      for (const r of refs) {
        const key = `${r.from}->${r.to}:${r.type}`;
        if (!seen.has(key)) {
          seen.add(key);
          all.push(r);
        }
      }
    }
    return all;
  }

  /**
   * Traces callers (incoming call references) of a given target address.
   */
  public getCallersOf(address: number): XRef[] {
    return this.getXRefsTo(address).filter((x) => x.type === 'CALL');
  }

  /**
   * Traces callees (outgoing call references) originating from a given function/source address.
   */
  public getCalleesOf(address: number): XRef[] {
    return this.getXRefsFrom(address).filter((x) => x.type === 'CALL');
  }

  /**
   * Helper to check if a numeric address is inside any registered sections
   */
  public isValidAddress(address: number, sections: Section[]): boolean {
    if (sections.length === 0) {
      return address > 0 && address < 0xffffffffffffffff;
    }
    return sections.some(
      (sec) =>
        address >= sec.virtualAddress &&
        address < sec.virtualAddress + sec.virtualSize
    );
  }

  /**
   * Performs complete cross-reference analysis.
   */
  public analyze(
    instructions: Instruction[],
    sections: Section[] = [],
    symbols: Symbol[] = [],
    buffer?: Uint8Array,
    baseAddress = 0
  ): void {
    // 1. Analyze disassembler instructions
    for (const inst of instructions) {
      const fromAddr = inst.address;
      const mnemonic = inst.mnemonic.toLowerCase();
      const context = `${inst.mnemonic} ${inst.opStr}`.trim();

      const isCall =
        mnemonic === 'call' ||
        mnemonic === 'bl' ||
        mnemonic === 'blx' ||
        mnemonic === 'blr' ||
        mnemonic.startsWith('invoke-');

      const isJump =
        mnemonic === 'jmp' ||
        mnemonic === 'b' ||
        mnemonic === 'bx' ||
        mnemonic === 'br' ||
        mnemonic.startsWith('j') ||
        mnemonic.startsWith('b.') ||
        mnemonic === 'cbz' ||
        mnemonic === 'cbnz' ||
        mnemonic === 'tbz' ||
        mnemonic === 'tbnz' ||
        mnemonic === 'br_if' ||
        mnemonic === 'br_table' ||
        mnemonic.startsWith('goto') ||
        mnemonic.startsWith('if-');

      // Check operands
      for (const op of inst.operands) {
        if (op.type === 'imm' && op.imm !== undefined) {
          const targetAddr = Number(op.imm);
          if (isCall) {
            this.addXRef({
              from: fromAddr,
              to: targetAddr,
              type: 'CALL',
              context,
            });
          } else if (isJump) {
            this.addXRef({
              from: fromAddr,
              to: targetAddr,
              type: 'JUMP',
              context,
            });
          } else if (this.isValidAddress(targetAddr, sections)) {
            const type: XRefType =
              op.access === 'w'
                ? 'DATA_WRITE'
                : op.access === 'r'
                  ? 'DATA_READ'
                  : 'DATA';
            this.addXRef({ from: fromAddr, to: targetAddr, type, context });
          }
        } else if (op.type === 'mem' && op.mem !== undefined) {
          const { base, disp } = op.mem;
          if (
            (base === 'rip' || base === 'pc' || base === 'IP') &&
            disp !== undefined
          ) {
            const nextInstAddr = fromAddr + inst.size;
            const targetAddr = nextInstAddr + Number(disp);
            if (this.isValidAddress(targetAddr, sections)) {
              const type: XRefType =
                op.access === 'w'
                  ? 'DATA_WRITE'
                  : op.access === 'r'
                    ? 'DATA_READ'
                    : 'DATA';
              this.addXRef({ from: fromAddr, to: targetAddr, type, context });
            }
          } else if (disp !== undefined) {
            const targetAddr = Number(disp);
            if (this.isValidAddress(targetAddr, sections)) {
              const type: XRefType =
                op.access === 'w'
                  ? 'DATA_WRITE'
                  : op.access === 'r'
                    ? 'DATA_READ'
                    : 'DATA';
              this.addXRef({ from: fromAddr, to: targetAddr, type, context });
            }
          }
        }
      }

      // Fallback: Parse hexadecimal patterns in opStr if operands didn't catch them
      if (inst.operands.length === 0) {
        const hexMatches = inst.opStr.match(/0x[0-9a-fA-F]+/g);
        if (hexMatches) {
          for (const hexStr of hexMatches) {
            const targetAddr = parseInt(hexStr, 16);
            if (!isNaN(targetAddr)) {
              if (isCall) {
                this.addXRef({
                  from: fromAddr,
                  to: targetAddr,
                  type: 'CALL',
                  context,
                });
              } else if (isJump) {
                this.addXRef({
                  from: fromAddr,
                  to: targetAddr,
                  type: 'JUMP',
                  context,
                });
              } else if (this.isValidAddress(targetAddr, sections)) {
                this.addXRef({
                  from: fromAddr,
                  to: targetAddr,
                  type: 'DATA',
                  context,
                });
              }
            }
          }
        }
      }
    }

    // 2. Scan memory buffer for pointer-sized values referencing valid sections (32-bit & 64-bit)
    if (buffer && sections.length > 0) {
      this.scanBufferForPointers(buffer, sections, baseAddress);
    }
  }

  /**
   * Scanning buffer for pointers
   */
  private scanBufferForPointers(
    buffer: Uint8Array,
    sections: Section[],
    baseAddress: number
  ): void {
    const view = new DataView(
      buffer.buffer,
      buffer.byteOffset,
      buffer.byteLength
    );

    // 32-bit pointer scanning (4-byte aligned)
    if (buffer.length >= 4) {
      const limit32 = buffer.length - 4;
      for (let offset = 0; offset <= limit32; offset += 4) {
        try {
          const ptr32LE = view.getUint32(offset, true);
          const ptr32BE = view.getUint32(offset, false);

          const fromAddr = this.offsetToVirtualAddress(
            offset,
            sections,
            baseAddress
          );
          if (fromAddr !== null) {
            if (this.isValidAddress(ptr32LE, sections)) {
              this.addXRef({
                from: fromAddr,
                to: ptr32LE,
                type: 'DATA',
                context: `Ptr32 (LE) in data block`,
              });
            }
            if (this.isValidAddress(ptr32BE, sections)) {
              this.addXRef({
                from: fromAddr,
                to: ptr32BE,
                type: 'DATA',
                context: `Ptr32 (BE) in data block`,
              });
            }
          }
        } catch {
          // ignore out of bounds
        }
      }
    }

    // 64-bit pointer scanning (8-byte aligned)
    if (buffer.length >= 8) {
      const limit64 = buffer.length - 8;
      for (let offset = 0; offset <= limit64; offset += 8) {
        try {
          const ptr64LE = Number(view.getBigUint64(offset, true));
          const ptr64BE = Number(view.getBigUint64(offset, false));

          const fromAddr = this.offsetToVirtualAddress(
            offset,
            sections,
            baseAddress
          );
          if (fromAddr !== null) {
            if (this.isValidAddress(ptr64LE, sections)) {
              this.addXRef({
                from: fromAddr,
                to: ptr64LE,
                type: 'DATA',
                context: `Ptr64 (LE) in data block`,
              });
            }
            if (this.isValidAddress(ptr64BE, sections)) {
              this.addXRef({
                from: fromAddr,
                to: ptr64BE,
                type: 'DATA',
                context: `Ptr64 (BE) in data block`,
              });
            }
          }
        } catch {
          // ignore out of bounds
        }
      }
    }
  }

  private offsetToVirtualAddress(
    offset: number,
    sections: Section[],
    baseAddress: number
  ): number | null {
    for (const sec of sections) {
      if (offset >= sec.fileOffset && offset < sec.fileOffset + sec.fileSize) {
        return sec.virtualAddress + (offset - sec.fileOffset);
      }
    }
    return baseAddress + offset;
  }
}
