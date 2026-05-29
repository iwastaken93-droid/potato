/**
 * Mach-O Binary File Parser
 * Parses Mach-O headers, load commands, sections, symbols, and fat/universal binary wrappers.
 */

// CPU Architecture constants
const CPU_ARCH_ABI64 = 0x01000000;
const CPU_TYPE_MC680x0 = 6;
const CPU_TYPE_I386 = 7;
const CPU_TYPE_X86_64 = CPU_TYPE_I386 | CPU_ARCH_ABI64;
const CPU_TYPE_ARM = 12;
const CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
const CPU_TYPE_POWERPC = 18;
const CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

const CPU_TYPE_NAMES: Record<number, string> = {
  [CPU_TYPE_MC680x0]: 'MC680x0',
  [CPU_TYPE_I386]: 'i386',
  [CPU_TYPE_X86_64]: 'x86_64',
  [CPU_TYPE_ARM]: 'ARM',
  [CPU_TYPE_ARM64]: 'ARM64',
  [CPU_TYPE_POWERPC]: 'PowerPC',
  [CPU_TYPE_POWERPC64]: 'PowerPC64',
};

// File type constants
const FILE_TYPE_NAMES: Record<number, string> = {
  0x1: 'MH_OBJECT',
  0x2: 'MH_EXECUTE',
  0x3: 'MH_FVMLIB',
  0x4: 'MH_CORE',
  0x5: 'MH_PRELOAD',
  0x6: 'MH_DYLIB',
  0x7: 'MH_DYLINKER',
  0x8: 'MH_BUNDLE',
  0x9: 'MH_DYLIB_STUB',
  0xa: 'MH_DSYM',
  0xb: 'MH_KEXT_BUNDLE',
};

// Load command constants
const LC_NAMES: Record<number, string> = {
  0x1: 'LC_SEGMENT',
  0x2: 'LC_SYMTAB',
  0x3: 'LC_SYMSEG',
  0x4: 'LC_THREAD',
  0x5: 'LC_UNIXTHREAD',
  0x6: 'LC_LOADFVMLIB',
  0x7: 'LC_IDFVMLIB',
  0x8: 'LC_IDENT',
  0x9: 'LC_FVMFILE',
  0xa: 'LC_PREPAGE',
  0xb: 'LC_DYSYMTAB',
  0xc: 'LC_LOAD_DYLIB',
  0xd: 'LC_ID_DYLIB',
  0xe: 'LC_LOAD_DYLINKER',
  0xf: 'LC_ID_DYLINKER',
  0x10: 'LC_PREBOUND_DYLIB',
  0x11: 'LC_ROUTINES',
  0x12: 'LC_SUB_FRAMEWORK',
  0x13: 'LC_SUB_UMBRELLA',
  0x14: 'LC_SUB_CLIENT',
  0x15: 'LC_SUB_LIBRARY',
  0x16: 'LC_TWOLEVEL_HINTS',
  0x17: 'LC_PREBIND_CKSUM',
  [0x18 | 0x80000000]: 'LC_LOAD_WEAK_DYLIB',
  0x19: 'LC_SEGMENT_64',
  0x1a: 'LC_ROUTINES_64',
  0x1b: 'LC_UUID',
  [0x1c | 0x80000000]: 'LC_RPATH',
  0x1d: 'LC_CODE_SIGNATURE',
  0x1e: 'LC_SEGMENT_SPLIT_INFO',
  [0x1f | 0x80000000]: 'LC_REEXPORT_DYLIB',
  0x20: 'LC_LAZY_LOAD_DYLIB',
  0x21: 'LC_ENCRYPTION_INFO',
  0x22: 'LC_DYLD_INFO',
  [0x22 | 0x80000000]: 'LC_DYLD_INFO_ONLY',
  [0x23 | 0x80000000]: 'LC_LOAD_UPWARD_DYLIB',
  0x24: 'LC_VERSION_MIN_MACOSX',
  0x25: 'LC_VERSION_MIN_IPHONEOS',
  0x26: 'LC_FUNCTION_STARTS',
  0x27: 'LC_DYLD_ENVIRONMENT',
  [0x28 | 0x80000000]: 'LC_MAIN',
  0x29: 'LC_DATA_IN_CODE',
  0x2a: 'LC_SOURCE_VERSION',
  0x2b: 'LC_DYLIB_CODE_SIGN_DRS',
  0x2c: 'LC_ENCRYPTION_INFO_64',
  0x2d: 'LC_LINKER_OPTION',
  0x2e: 'LC_LINKER_OPTIMIZATION_HINT',
  0x2f: 'LC_VERSION_MIN_TVOS',
  0x30: 'LC_VERSION_MIN_WATCHOS',
  0x31: 'LC_NOTE',
  0x32: 'LC_BUILD_VERSION',
};

export interface MachoHeader {
  magic: number;
  cputype: number;
  cputypeName: string;
  cpusubtype: number;
  filetype: number;
  filetypeName: string;
  ncmds: number;
  sizeofcmds: number;
  flags: number;
  reserved?: number;
}

export interface MachoSection {
  sectname: string;
  segname: string;
  addr: bigint | number;
  size: bigint | number;
  offset: number;
  align: number;
  reloff: number;
  nreloc: number;
  flags: number;
  reserved1: number;
  reserved2: number;
  reserved3?: number;
}

export interface MachoSegment {
  cmd: number;
  cmdName: string;
  segname: string;
  vmaddr: bigint | number;
  vmsize: bigint | number;
  fileoff: bigint | number;
  filesz: bigint | number;
  maxprot: number;
  initprot: number;
  nsects: number;
  flags: number;
  sections: MachoSection[];
}

export interface MachoSymbol {
  name: string;
  strx: number;
  type: number;
  sect: number;
  desc: number;
  value: bigint | number;
  binding: 'local' | 'global' | 'weak';
  symbolType: 'function' | 'object' | 'section' | 'file' | 'none';
}

export interface MachoLoadCommand {
  cmd: number;
  cmdName: string;
  cmdsize: number;
  payload: any;
}

export interface FatArch {
  cputype: number;
  cputypeName: string;
  cpusubtype: number;
  offset: number;
  size: number;
  align: number;
}

export interface ParsedMacho {
  is64Bit: boolean;
  isLittleEndian: boolean;
  header: MachoHeader;
  loadCommands: MachoLoadCommand[];
  segments: MachoSegment[];
  sections: MachoSection[];
  symbols: MachoSymbol[];
  fatArches?: FatArch[];
}

export interface MachoParserOptions {
  fatIndex?: number;
}

export class MachoParser {
  private buffer: ArrayBuffer;
  private view: DataView;
  private bytes: Uint8Array;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
    this.bytes = new Uint8Array(buffer);
  }

  public parse(options: MachoParserOptions = {}): ParsedMacho {
    if (this.buffer.byteLength < 4) {
      throw new Error('File too small to be a Mach-O binary');
    }

    const magicLE = this.view.getUint32(0, true);
    const magicBE = this.view.getUint32(0, false);

    // Check for Fat/Universal binary magic
    if (magicBE === 0xcafebabe || magicBE === 0xbebafeca) {
      const isFatLittleEndian = magicBE === 0xbebafeca;
      const fatArches = this.parseFatHeader(isFatLittleEndian);

      const sliceIndex = options.fatIndex ?? 0;
      if (sliceIndex < 0 || sliceIndex >= fatArches.length) {
        throw new Error(
          `Fat architecture index ${sliceIndex} out of range (total ${fatArches.length} architectures)`
        );
      }

      const arch = fatArches[sliceIndex];
      const slicedBuffer = this.buffer.slice(
        arch.offset,
        arch.offset + arch.size
      );

      const subParser = new MachoParser(slicedBuffer);
      const parsed = subParser.parse();
      parsed.fatArches = fatArches;
      return parsed;
    }

    // Determine 64-bit and Endianness
    let is64Bit = false;
    let isLittleEndian = true;

    if (magicLE === 0xfeedface) {
      is64Bit = false;
      isLittleEndian = true;
    } else if (magicBE === 0xfeedface) {
      is64Bit = false;
      isLittleEndian = false;
    } else if (magicLE === 0xfeedfacf) {
      is64Bit = true;
      isLittleEndian = true;
    } else if (magicBE === 0xfeedfacf) {
      is64Bit = true;
      isLittleEndian = false;
    } else {
      throw new Error(`Invalid Mach-O Magic: 0x${magicBE.toString(16)}`);
    }

    const header = this.parseHeader(is64Bit, isLittleEndian);
    const loadCommands: MachoLoadCommand[] = [];
    const segments: MachoSegment[] = [];
    const sections: MachoSection[] = [];
    let symbols: MachoSymbol[] = [];

    // Parse Load Commands
    let offset = is64Bit ? 32 : 28;
    for (let i = 0; i < header.ncmds; i++) {
      if (offset + 8 > this.buffer.byteLength) {
        break;
      }

      const cmd = this.view.getUint32(offset, isLittleEndian);
      const cmdsize = this.view.getUint32(offset + 4, isLittleEndian);

      if (offset + cmdsize > this.buffer.byteLength) {
        break;
      }

      const cmdName = LC_NAMES[cmd] || `LC_UNKNOWN_0x${cmd.toString(16)}`;
      const payload: any = {};

      if (cmd === 0x1 || cmd === 0x19) {
        // LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
        const segment = this.parseSegment(
          offset,
          cmd,
          cmdsize,
          is64Bit,
          isLittleEndian
        );
        segments.push(segment);
        sections.push(...segment.sections);
      } else if (cmd === 0x2) {
        // LC_SYMTAB
        payload.symoff = this.view.getUint32(offset + 8, isLittleEndian);
        payload.nsyms = this.view.getUint32(offset + 12, isLittleEndian);
        payload.stroff = this.view.getUint32(offset + 16, isLittleEndian);
        payload.strsize = this.view.getUint32(offset + 20, isLittleEndian);

        symbols = this.parseSymbols(
          payload.symoff,
          payload.nsyms,
          payload.stroff,
          payload.strsize,
          is64Bit,
          isLittleEndian,
          sections
        );
      }

      loadCommands.push({
        cmd,
        cmdName,
        cmdsize,
        payload,
      });

      offset += cmdsize;
    }

    return {
      is64Bit,
      isLittleEndian,
      header,
      loadCommands,
      segments,
      sections,
      symbols,
    };
  }

  private parseFatHeader(isLittleEndian: boolean): FatArch[] {
    const nfat_arch = this.view.getUint32(4, isLittleEndian);
    const arches: FatArch[] = [];
    let offset = 8;

    for (let i = 0; i < nfat_arch; i++) {
      if (offset + 20 > this.buffer.byteLength) {
        break;
      }

      const cputype = this.view.getInt32(offset, isLittleEndian);
      const cpusubtype = this.view.getInt32(offset + 4, isLittleEndian);
      const archOffset = this.view.getUint32(offset + 8, isLittleEndian);
      const size = this.view.getUint32(offset + 12, isLittleEndian);
      const align = this.view.getUint32(offset + 16, isLittleEndian);

      arches.push({
        cputype,
        cputypeName: CPU_TYPE_NAMES[cputype] || `Unknown (${cputype})`,
        cpusubtype,
        offset: archOffset,
        size,
        align,
      });

      offset += 20;
    }

    return arches;
  }

  private parseHeader(is64Bit: boolean, isLittleEndian: boolean): MachoHeader {
    const magic = this.view.getUint32(0, isLittleEndian);
    const cputype = this.view.getInt32(4, isLittleEndian);
    const cpusubtype = this.view.getInt32(8, isLittleEndian);
    const filetype = this.view.getUint32(12, isLittleEndian);
    const ncmds = this.view.getUint32(16, isLittleEndian);
    const sizeofcmds = this.view.getUint32(20, isLittleEndian);
    const flags = this.view.getUint32(24, isLittleEndian);

    const cputypeName = CPU_TYPE_NAMES[cputype] || `Unknown (${cputype})`;
    const filetypeName = FILE_TYPE_NAMES[filetype] || `Unknown (${filetype})`;

    const header: MachoHeader = {
      magic,
      cputype,
      cputypeName,
      cpusubtype,
      filetype,
      filetypeName,
      ncmds,
      sizeofcmds,
      flags,
    };

    if (is64Bit) {
      header.reserved = this.view.getUint32(28, isLittleEndian);
    }

    return header;
  }

  private parseSegment(
    offset: number,
    cmd: number,
    cmdsize: number,
    is64Bit: boolean,
    isLittleEndian: boolean
  ): MachoSegment {
    const cmdName = cmd === 0x19 ? 'LC_SEGMENT_64' : 'LC_SEGMENT';
    const segname = this.readNullPaddedString(offset + 8, 16);

    let vmaddr: bigint | number;
    let vmsize: bigint | number;
    let fileoff: bigint | number;
    let filesz: bigint | number;
    let maxprot: number;
    let initprot: number;
    let nsects: number;
    let flags: number;
    let sectOffset: number;

    if (cmd === 0x19) {
      // LC_SEGMENT_64
      vmaddr = this.view.getBigUint64(offset + 24, isLittleEndian);
      vmsize = this.view.getBigUint64(offset + 32, isLittleEndian);
      fileoff = this.view.getBigUint64(offset + 40, isLittleEndian);
      filesz = this.view.getBigUint64(offset + 48, isLittleEndian);
      maxprot = this.view.getInt32(offset + 56, isLittleEndian);
      initprot = this.view.getInt32(offset + 60, isLittleEndian);
      nsects = this.view.getUint32(offset + 64, isLittleEndian);
      flags = this.view.getUint32(offset + 68, isLittleEndian);
      sectOffset = offset + 72;
    } else {
      // LC_SEGMENT
      vmaddr = this.view.getUint32(offset + 24, isLittleEndian);
      vmsize = this.view.getUint32(offset + 28, isLittleEndian);
      fileoff = this.view.getUint32(offset + 32, isLittleEndian);
      filesz = this.view.getUint32(offset + 36, isLittleEndian);
      maxprot = this.view.getInt32(offset + 40, isLittleEndian);
      initprot = this.view.getInt32(offset + 44, isLittleEndian);
      nsects = this.view.getUint32(offset + 48, isLittleEndian);
      flags = this.view.getUint32(offset + 52, isLittleEndian);
      sectOffset = offset + 56;
    }

    const sections: MachoSection[] = [];
    const sectionSize = cmd === 0x19 ? 80 : 68;

    for (let i = 0; i < nsects; i++) {
      if (sectOffset + sectionSize > offset + cmdsize) {
        break;
      }

      const sectname = this.readNullPaddedString(sectOffset, 16);
      const sSegname = this.readNullPaddedString(sectOffset + 16, 16);

      let sAddr: bigint | number;
      let sSize: bigint | number;
      let sOffset: number;
      let sAlign: number;
      let sReloff: number;
      let sNreloc: number;
      let sFlags: number;
      let sReserved1: number;
      let sReserved2: number;
      let sReserved3: number | undefined;

      if (cmd === 0x19) {
        sAddr = this.view.getBigUint64(sectOffset + 32, isLittleEndian);
        sSize = this.view.getBigUint64(sectOffset + 40, isLittleEndian);
        sOffset = this.view.getUint32(sectOffset + 48, isLittleEndian);
        sAlign = this.view.getUint32(sectOffset + 52, isLittleEndian);
        sReloff = this.view.getUint32(sectOffset + 56, isLittleEndian);
        sNreloc = this.view.getUint32(sectOffset + 60, isLittleEndian);
        sFlags = this.view.getUint32(sectOffset + 64, isLittleEndian);
        sReserved1 = this.view.getUint32(sectOffset + 68, isLittleEndian);
        sReserved2 = this.view.getUint32(sectOffset + 72, isLittleEndian);
        sReserved3 = this.view.getUint32(sectOffset + 76, isLittleEndian);
      } else {
        sAddr = this.view.getUint32(sectOffset + 32, isLittleEndian);
        sSize = this.view.getUint32(sectOffset + 36, isLittleEndian);
        sOffset = this.view.getUint32(sectOffset + 40, isLittleEndian);
        sAlign = this.view.getUint32(sectOffset + 44, isLittleEndian);
        sReloff = this.view.getUint32(sectOffset + 48, isLittleEndian);
        sNreloc = this.view.getUint32(sectOffset + 52, isLittleEndian);
        sFlags = this.view.getUint32(sectOffset + 56, isLittleEndian);
        sReserved1 = this.view.getUint32(sectOffset + 60, isLittleEndian);
        sReserved2 = this.view.getUint32(sectOffset + 64, isLittleEndian);
      }

      sections.push({
        sectname,
        segname: sSegname,
        addr: sAddr,
        size: sSize,
        offset: sOffset,
        align: sAlign,
        reloff: sReloff,
        nreloc: sNreloc,
        flags: sFlags,
        reserved1: sReserved1,
        reserved2: sReserved2,
        ...(sReserved3 !== undefined ? { reserved3: sReserved3 } : {}),
      });

      sectOffset += sectionSize;
    }

    return {
      cmd,
      cmdName,
      segname,
      vmaddr,
      vmsize,
      fileoff,
      filesz,
      maxprot,
      initprot,
      nsects,
      flags,
      sections,
    };
  }

  private parseSymbols(
    symoff: number,
    nsyms: number,
    stroff: number,
    strsize: number,
    is64Bit: boolean,
    isLittleEndian: boolean,
    sections: MachoSection[]
  ): MachoSymbol[] {
    const symbols: MachoSymbol[] = [];
    const entrySize = is64Bit ? 16 : 12;

    for (let i = 0; i < nsyms; i++) {
      const offset = symoff + i * entrySize;
      if (offset + entrySize > this.buffer.byteLength) {
        break;
      }

      const strx = this.view.getUint32(offset, isLittleEndian);
      const type = this.view.getUint8(offset + 4);
      const sect = this.view.getUint8(offset + 5);
      const desc = this.view.getUint16(offset + 6, isLittleEndian);

      let value: bigint | number;
      if (is64Bit) {
        value = this.view.getBigUint64(offset + 8, isLittleEndian);
      } else {
        value = this.view.getUint32(offset + 8, isLittleEndian);
      }

      // Resolve name from string table
      let name = '';
      if (strx > 0 && strx < strsize) {
        const nameOffset = stroff + strx;
        if (nameOffset < this.buffer.byteLength) {
          for (
            let j = nameOffset;
            j < stroff + strsize && j < this.buffer.byteLength;
            j++
          ) {
            if (this.bytes[j] === 0) {
              break;
            }
            name += String.fromCharCode(this.bytes[j]);
          }
        }
      }

      // Determine binding
      let binding: 'local' | 'global' | 'weak' = 'local';
      if ((type & 0x01) !== 0) {
        binding = 'global';
      }
      if ((desc & 0x0010) !== 0 || (desc & 0x0040) !== 0) {
        binding = 'weak';
      }

      // Determine symbolType
      let symbolType: 'function' | 'object' | 'section' | 'file' | 'none' =
        'none';
      const nType = type & 0x0e;

      if (nType === 0xe) {
        // N_SECT
        if (sect > 0 && sect <= sections.length) {
          const section = sections[sect - 1];
          if (section.sectname === '__text' || section.segname === '__TEXT') {
            symbolType = 'function';
          } else if (
            ['__data', '__bss', '__common'].includes(section.sectname) ||
            ['__DATA', '__DATA_CONST'].includes(section.segname)
          ) {
            symbolType = 'object';
          }
        }
      }

      symbols.push({
        name,
        strx,
        type,
        sect,
        desc,
        value,
        binding,
        symbolType,
      });
    }

    return symbols;
  }

  private readNullPaddedString(offset: number, maxLength: number): string {
    let result = '';
    for (let i = 0; i < maxLength; i++) {
      const charCode = this.view.getUint8(offset + i);
      if (charCode === 0) {
        break;
      }
      result += String.fromCharCode(charCode);
    }
    return result;
  }
}

export function parseMacho(
  buffer: ArrayBuffer,
  options?: MachoParserOptions
): ParsedMacho {
  const parser = new MachoParser(buffer);
  return parser.parse(options);
}
