import { Instruction, Operand, OperandType, Section } from './types.js';
import { CapstoneWasmEngine } from './capstoneWasm.js';
import { disassembleX86 } from './x86.js';
import { disassembleArm } from './arm.js';
import { disassembleArm32, disassembleThumb } from './arm32.js';
import { disassembleWasm } from './wasm.js';
import { disassembleDalvik } from './dalvik.js';
import { disassembleRiscv } from './riscv.js';
import { disassembleMips } from './mips.js';
import { disassemblePpc } from './ppc.js';
import { disassembleSparc } from './sparc.js';
import { disassembleZ80 } from './z80.js';
import { disassemble6502 } from './m6502.js';
import { disassembleCil } from './dotnetIl.js';
import { DexDebugInfo } from '../parser/dex.js';


/**
 * Supported architectures.
 */
export type Architecture =
  | 'x86_64'
  | 'arm'
  | 'arm32'
  | 'thumb'
  | 'wasm'
  | 'dex'
  | 'riscv'
  | 'mips'
  | 'mipsel'
  | 'ppc'
  | 'sparc'
  | 'z80'
  | 'm6502'
  | 'cil'
  | 'dotnetIl';

/**
 * Metadata configuration for disassembly.
 */
export interface DisassemblyMetadata {
  arch?: Architecture;
  baseAddress?: number;
  entryPoint?: number;
  useCapstoneWasm?: boolean;
  debugInfo?: DexDebugInfo | null;
}

/**
 * Disassembler Router Engine.
 * Detects the binary architecture and disassembles code sections into structured Instruction objects.
 */
export class DisassemblerRouter {
  /**
   * Automatically detects the architecture of the given binary.
   */
  public static detectArchitecture(
    data: Uint8Array,
    metadata?: DisassemblyMetadata
  ): Architecture {
    if (metadata?.arch) {
      return metadata.arch;
    }

    // Detect DEX by magic bytes: dex\n
    if (
      data.length >= 4 &&
      data[0] === 0x64 &&
      data[1] === 0x65 &&
      data[2] === 0x78 &&
      data[3] === 0x0a
    ) {
      return 'dex';
    }

    // Detect WASM by magic bytes: \0asm
    if (
      data.length >= 4 &&
      data[0] === 0x00 &&
      data[1] === 0x61 &&
      data[2] === 0x73 &&
      data[3] === 0x6d
    ) {
      return 'wasm';
    }

    // Detect NES ROM (6502) by magic: NES\x1a
    if (
      data.length >= 4 &&
      data[0] === 0x4e &&
      data[1] === 0x45 &&
      data[2] === 0x53 &&
      data[3] === 0x1a
    ) {
      return 'm6502';
    }

    // Detect Mach-O Architecture
    if (data.length >= 4) {
      const magicLE =
        (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
      const magicBE =
        ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;

      const isFat32 = magicBE === 0xcafebabe || magicBE === 0xbebafeca;
      const isFat64 = magicBE === 0xcafebabf || magicBE === 0xbfbafeca;
      if (isFat32 || isFat64) {
        // Fat/Universal binary
        const isFatBE = magicBE === 0xcafebabe || magicBE === 0xcafebabf;
        if (data.length >= 8) {
          const nfat =
            (isFatBE
              ? (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]
              : data[4] |
                (data[5] << 8) |
                (data[6] << 16) |
                (data[7] << 24)) >>> 0;

          let offset = 8;
          const archSize = isFat64 ? 32 : 20;
          for (let i = 0; i < nfat; i++) {
            if (offset + archSize <= data.length) {
              const cputype =
                (isFatBE
                  ? (data[offset] << 24) |
                    (data[offset + 1] << 16) |
                    (data[offset + 2] << 8) |
                    data[offset + 3]
                  : data[offset] |
                    (data[offset + 1] << 8) |
                    (data[offset + 2] << 16) |
                    (data[offset + 3] << 24)) >>> 0;

              if (cputype === 0x01000007 || cputype === 7) return 'x86_64';
              if (cputype === 0x0100000c || cputype === 12) return 'arm';
              offset += archSize;
            }
          }
        }
      } else if (
        magicLE === 0xfeedfacf ||
        magicBE === 0xfeedfacf ||
        magicLE === 0xfeedface ||
        magicBE === 0xfeedface
      ) {
        const isLE = magicLE === 0xfeedface || magicLE === 0xfeedfacf;
        if (data.length >= 8) {
          const cputype =
            (isLE
              ? data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)
              : (data[4] << 24) |
                (data[5] << 16) |
                (data[6] << 8) |
                data[7]) >>> 0;

          if (cputype === 0x01000007 || cputype === 7) return 'x86_64';
          if (cputype === 0x0100000c || cputype === 12) return 'arm';
        }
      }
    }

    // Detect ELF Architecture
    if (
      data.length >= 64 &&
      data[0] === 0x7f &&
      data[1] === 0x45 &&
      data[2] === 0x4c &&
      data[3] === 0x46
    ) {
      const is64 = data[4] === 2;
      // e_machine is at offset 18 (2 bytes)
      const eMachine = data[18] | (data[19] << 8);
      if (eMachine === 62) return 'x86_64'; // EM_X86_64
      if (eMachine === 40 || eMachine === 183) return 'arm'; // EM_ARM or EM_AARCH64
      if (eMachine === 243) return 'riscv'; // EM_RISCV
      if (eMachine === 8) {
        // EM_MIPS. Offset 5 contains endianness (1 = Little Endian, 2 = Big Endian)
        return data[5] === 1 ? 'mipsel' : 'mips';
      }
      if (eMachine === 20 || eMachine === 21) return 'ppc'; // EM_PPC or EM_PPC64
      if (eMachine === 2 || eMachine === 43) return 'sparc'; // EM_SPARC or EM_SPARCV9
    }

    // Detect PE Architecture
    if (data.length >= 64 && data[0] === 0x5a && data[1] === 0x4d) {
      // MZ
      const peOffset =
        data[0x3c] |
        (data[0x3d] << 8) |
        (data[0x3e] << 16) |
        (data[0x3f] << 24);
      if (peOffset + 24 <= data.length) {
        if (data[peOffset] === 0x50 && data[peOffset + 1] === 0x45) {
          // PE\0\0
          const machine = data[peOffset + 4] | (data[peOffset + 5] << 8);
          if (machine === 0x8664) return 'x86_64'; // IMAGE_FILE_MACHINE_AMD64
          if (machine === 0xaa64 || machine === 0x01c4) return 'arm'; // IMAGE_FILE_MACHINE_ARM64 / ARMNT
        }
      }
    }

    // Detect Mach-O Architecture
    const isMacho =
      (data[0] === 0xcf &&
        data[1] === 0xfa &&
        data[2] === 0xed &&
        data[3] === 0xfe) ||
      (data[0] === 0xfe &&
        data[1] === 0xed &&
        data[2] === 0xfa &&
        data[3] === 0xcf) ||
      (data[0] === 0xce &&
        data[1] === 0xfa &&
        data[2] === 0xed &&
        data[3] === 0xfe) ||
      (data[0] === 0xfe &&
        data[1] === 0xed &&
        data[2] === 0xfa &&
        data[3] === 0xce);
    if (isMacho) {
      const isLittleEndian = data[0] === 0xcf || data[0] === 0xce;
      let cputype = 0;
      if (isLittleEndian) {
        cputype = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
      } else {
        cputype = data[7] | (data[6] << 8) | (data[5] << 16) | (data[4] << 24);
      }
      const CPU_ARCH_ABI64 = 0x01000000;
      const CPU_TYPE_ARM = 12;
      const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
      if (cputype === CPU_TYPE_ARM || cputype === CPU_TYPE_ARM64) {
        return 'arm';
      }
      return 'x86_64';
    }

    // Detect Mach-O Fat/Universal Architecture
    const isFat32 =
      (data[0] === 0xca &&
        data[1] === 0xfe &&
        data[2] === 0xba &&
        data[3] === 0xbe) ||
      (data[0] === 0xbe &&
        data[1] === 0xba &&
        data[2] === 0xfe &&
        data[3] === 0xca);
    const isFat64 =
      (data[0] === 0xca &&
        data[1] === 0xfe &&
        data[2] === 0xba &&
        data[3] === 0xbf) ||
      (data[0] === 0xbf &&
        data[1] === 0xba &&
        data[2] === 0xfe &&
        data[3] === 0xca);
    const isFat = isFat32 || isFat64;
    if (isFat) {
      const isLittleEndian = data[0] === 0xbe || data[0] === 0xbf;
      let cputype = 0;
      if (isLittleEndian) {
        cputype =
          data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
      } else {
        cputype =
          data[11] | (data[10] << 8) | (data[9] << 16) | (data[8] << 24);
      }
      const CPU_ARCH_ABI64 = 0x01000000;
      const CPU_TYPE_ARM = 12;
      const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
      if (cputype === CPU_TYPE_ARM || cputype === CPU_TYPE_ARM64) {
        return 'arm';
      }
      return 'x86_64';
    }

    // Fallback default
    return 'x86_64';
  }

  private useCapstoneWasm = false;

  constructor(options?: { useCapstoneWasm?: boolean }) {
    if (options?.useCapstoneWasm) {
      this.useCapstoneWasm = options.useCapstoneWasm;
    }
  }

  public setUseCapstoneWasm(value: boolean): void {
    this.useCapstoneWasm = value;
  }

  public isUsingCapstoneWasm(): boolean {
    return this.useCapstoneWasm;
  }

  /**
   * Disassembles a section of binary data.
   */
  public disassemble(
    data: Uint8Array,
    metadata?: DisassemblyMetadata
  ): Instruction[] {
    const arch = DisassemblerRouter.detectArchitecture(data, metadata);
    const baseAddress = metadata?.baseAddress ?? 0;

    const useCapstone = metadata?.useCapstoneWasm ?? this.useCapstoneWasm;
    if (useCapstone && (arch === 'x86_64' || arch === 'arm')) {
      const mode = arch === 'x86_64' ? '64' : 'arm';
      const engine = new CapstoneWasmEngine(arch, mode);
      engine.loadSync();
      return engine.disassemble(data, baseAddress);
    }

    switch (arch) {
      case 'wasm':
        return disassembleWasm(data);
      case 'arm32':
        return disassembleArm32(data, baseAddress);
      case 'thumb':
        return disassembleThumb(data, baseAddress);
      case 'arm': {
        const isElf32 = data.length >= 20 &&
          data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46 &&
          data[4] === 1 && (data[18] | (data[19] << 8)) === 40;
        
        let isPeThumb = false;
        if (data.length >= 64 && data[0] === 0x5a && data[1] === 0x4d) {
          const peOffset = data[0x3c] | (data[0x3d] << 8) | (data[0x3e] << 16) | (data[0x3f] << 24);
          if (peOffset + 6 <= data.length && data[peOffset] === 0x50 && data[peOffset + 1] === 0x45) {
            const machine = data[peOffset + 4] | (data[peOffset + 5] << 8);
            if (machine === 0x01c4) {
              isPeThumb = true;
            }
          }
        }
        
        let isMacho32 = false;
        if (data.length >= 8) {
          const magic = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
          const magicBE = ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0;
          if (magic === 0xfeedface || magicBE === 0xfeedface || magic === 0xcefaedfe) {
            const isLE = magic === 0xfeedface || magic === 0xcefaedfe;
            const cputype = isLE
              ? (data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24))
              : ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
            if (cputype === 12) {
              isMacho32 = true;
            }
          }
        }

        if (isPeThumb) {
          return disassembleThumb(data, baseAddress);
        }
        if (isElf32 || isMacho32) {
          return disassembleArm32(data, baseAddress);
        }
        return disassembleArm(data, baseAddress);
      }
      case 'dex':
        return disassembleDalvik(data, baseAddress, metadata?.debugInfo);
      case 'riscv':
        return disassembleRiscv(data, baseAddress);
      case 'mips':
        return disassembleMips(data, baseAddress, false);
      case 'mipsel':
        return disassembleMips(data, baseAddress, true);
      case 'ppc':
        return disassemblePpc(data, baseAddress);
      case 'sparc':
        return disassembleSparc(data, baseAddress);
      case 'z80':
        return disassembleZ80(data, baseAddress);
      case 'm6502':
        return disassemble6502(data, baseAddress);
      case 'cil':
      case 'dotnetIl':
        return disassembleCil(data, baseAddress);
      case 'x86_64':
      default:
        return disassembleX86(data, baseAddress);
    }
  }
}
