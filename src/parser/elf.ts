export interface ElfHeader {
  class: '32-bit' | '64-bit' | 'Unknown';
  endianness: 'Little Endian' | 'Big Endian' | 'Unknown';
  osAbi: string;
  type: string;
  machine: string;
  entryPoint: bigint | number;
  phOff: bigint | number;
  shOff: bigint | number;
  flags: number;
  ehSize: number;
  phentSize: number;
  phNum: number;
  shentSize: number;
  shNum: number;
  shStrNdX: number;
}

export interface ElfSectionHeader {
  nameOffset: number;
  name: string; // resolved if shstrtab is present/parsed
  type: number;
  typeName: string;
  flags: bigint | number;
  addr: bigint | number;
  offset: bigint | number;
  size: bigint | number;
  link: number;
  info: number;
  addralign: bigint | number;
  entsize: bigint | number;
}

export interface ElfProgramHeader {
  type: number;
  typeName: string;
  flags: number;
  offset: bigint | number;
  vaddr: bigint | number;
  paddr: bigint | number;
  filesz: bigint | number;
  memsz: bigint | number;
  align: bigint | number;
}

export interface ElfSymbol {
  name: string;
  nameOffset: number;
  value: bigint | number;
  size: bigint | number;
  info: number;
  other: number;
  shndx: number;
  bind: string;
  type: string;
}

export interface ElfRelocation {
  offset: bigint | number;
  info: bigint | number;
  addend?: bigint | number;
  symbolIndex: number;
  symbolName: string;
  type: number;
  typeName: string;
}

export interface GotEntry {
  address: bigint | number;
  symbolName: string;
  relocationType: string;
  addend?: bigint | number;
}

export interface PltEntry {
  address: bigint | number;
  symbolName: string;
  gotAddress?: bigint | number;
}

export interface ParsedElf {
  header: ElfHeader;
  programHeaders: ElfProgramHeader[];
  sectionHeaders: ElfSectionHeader[];
  symbols: ElfSymbol[];
  relocations: ElfRelocation[];
  gotEntries: GotEntry[];
  pltEntries: PltEntry[];
}

// ELF Constants and Mappings
const ELF_CLASS: Record<number, '32-bit' | '64-bit' | 'Unknown'> = {
  1: '32-bit',
  2: '64-bit',
};

const ELF_DATA: Record<number, 'Little Endian' | 'Big Endian' | 'Unknown'> = {
  1: 'Little Endian',
  2: 'Big Endian',
};

const ELF_OSABI: Record<number, string> = {
  0x00: 'System V',
  0x01: 'HP-UX',
  0x02: 'NetBSD',
  0x03: 'Linux',
  0x06: 'Solaris',
  0x07: 'AIX',
  0x08: 'IRIX',
  0x09: 'FreeBSD',
  0x0c: 'OpenBSD',
  0x0d: 'OpenVMS',
  0x0e: 'NSK',
  0x0f: 'AROS',
  0x10: 'FenixOS',
  0x11: 'Nuxi CloudABI',
  0x12: 'Stratus Technologies OpenVOS',
};

const ELF_TYPE: Record<number, string> = {
  0: 'NONE (No file type)',
  1: 'REL (Relocatable file)',
  2: 'EXEC (Executable file)',
  3: 'DYN (Shared object file)',
  4: 'CORE (Core file)',
};

const ELF_MACHINE: Record<number, string> = {
  0: 'No machine',
  2: 'SPARC',
  3: 'x86',
  8: 'MIPS',
  19: 'Intel i860',
  20: 'PowerPC',
  22: 'S390',
  40: 'ARM',
  42: 'SuperH',
  50: 'IA-64',
  62: 'AMD64 (x86-64)',
  183: 'AArch64 (ARM 64-bit)',
  243: 'RISC-V',
};

const SHT_TYPE: Record<number, string> = {
  0: 'SHT_NULL',
  1: 'SHT_PROGBITS',
  2: 'SHT_SYMTAB',
  3: 'SHT_STRTAB',
  4: 'SHT_RELA',
  5: 'SHT_HASH',
  6: 'SHT_DYNAMIC',
  7: 'SHT_NOTE',
  8: 'SHT_NOBITS',
  9: 'SHT_REL',
  10: 'SHT_SHLIB',
  11: 'SHT_DYNSYM',
  14: 'SHT_INIT_ARRAY',
  15: 'SHT_FINI_ARRAY',
  16: 'SHT_PREINIT_ARRAY',
  17: 'SHT_GROUP',
  18: 'SHT_SYMTAB_SHNDX',
};

const PT_TYPE: Record<number, string> = {
  0: 'PT_NULL',
  1: 'PT_LOAD',
  2: 'PT_DYNAMIC',
  3: 'PT_INTERP',
  4: 'PT_NOTE',
  5: 'PT_SHLIB',
  6: 'PT_PHDR',
  7: 'PT_TLS',
  0x60000000: 'PT_LOOS',
  0x6fffffff: 'PT_HIOS',
  0x70000000: 'PT_LOPROC',
  0x7fffffff: 'PT_HIPROC',
  0x6474e550: 'PT_GNU_EH_FRAME',
  0x6474e551: 'PT_GNU_STACK',
  0x6474e552: 'PT_GNU_RELRO',
};

const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_RELA = 4;
const SHT_REL = 9;
const SHT_DYNSYM = 11;

const STB_NAMES: Record<number, string> = {
  0: 'LOCAL',
  1: 'GLOBAL',
  2: 'WEAK',
  10: 'LOOS',
  12: 'HIOS',
  13: 'LOPROC',
  15: 'HIPROC',
};

const STT_NAMES: Record<number, string> = {
  0: 'NOTYPE',
  1: 'OBJECT',
  2: 'FUNC',
  3: 'SECTION',
  4: 'FILE',
  5: 'COMMON',
  6: 'TLS',
  10: 'LOOS',
  12: 'HIOS',
  13: 'LOPROC',
  15: 'HIPROC',
};

const REL_TYPES_X86_64: Record<number, string> = {
  0: 'R_X86_64_NONE',
  1: 'R_X86_64_64',
  2: 'R_X86_64_PC32',
  3: 'R_X86_64_GOT32',
  4: 'R_X86_64_PLT32',
  5: 'R_X86_64_COPY',
  6: 'R_X86_64_GLOB_DAT',
  7: 'R_X86_64_JUMP_SLOT',
  8: 'R_X86_64_RELATIVE',
  9: 'R_X86_64_GOTPCREL',
  10: 'R_X86_64_32',
  11: 'R_X86_64_32S',
  12: 'R_X86_64_16',
  13: 'R_X86_64_PC16',
  14: 'R_X86_64_8',
  15: 'R_X86_64_PC8',
  16: 'R_X86_64_DTPMOD64',
  17: 'R_X86_64_DTPOFF64',
  18: 'R_X86_64_TPOFF64',
};

const REL_TYPES_I386: Record<number, string> = {
  0: 'R_386_NONE',
  1: 'R_386_32',
  2: 'R_386_PC32',
  3: 'R_386_GOT32',
  4: 'R_386_PLT32',
  5: 'R_386_COPY',
  6: 'R_386_GLOB_DAT',
  7: 'R_386_JMP_SLOT',
  8: 'R_386_RELATIVE',
  9: 'R_386_GOTOFF',
  10: 'R_386_GOTPC',
};

const REL_TYPES_AARCH64: Record<number, string> = {
  0: 'R_AARCH64_NONE',
  257: 'R_AARCH64_ABS64',
  258: 'R_AARCH64_ABS32',
  1024: 'R_AARCH64_COPY',
  1025: 'R_AARCH64_GLOB_DAT',
  1026: 'R_AARCH64_JUMP_SLOT',
  1027: 'R_AARCH64_RELATIVE',
};

const REL_TYPES_ARM: Record<number, string> = {
  0: 'R_ARM_NONE',
  2: 'R_ARM_PC24',
  17: 'R_ARM_RELATIVE',
  21: 'R_ARM_GLOB_DAT',
  22: 'R_ARM_JUMP_SLOT',
  23: 'R_ARM_RELATIVE',
};

function getRelocationTypeName(machine: string, type: number): string {
  const m = machine.toLowerCase();
  if (m.includes('amd64') || m.includes('x86-64') || m.includes('62')) {
    return REL_TYPES_X86_64[type] || `R_X86_64_UNKNOWN (${type})`;
  }
  if (m.includes('x86') || m.includes('386') || m.includes('3')) {
    return REL_TYPES_I386[type] || `R_386_UNKNOWN (${type})`;
  }
  if (m.includes('aarch64') || m.includes('arm 64') || m.includes('183')) {
    return REL_TYPES_AARCH64[type] || `R_AARCH64_UNKNOWN (${type})`;
  }
  if (m.includes('arm') || m.includes('40')) {
    return REL_TYPES_ARM[type] || `R_ARM_UNKNOWN (${type})`;
  }
  return `R_UNKNOWN (${type})`;
}

export function parseElf(arrayBuffer: ArrayBuffer): ParsedElf {
  const view = new DataView(arrayBuffer);
  const bytes = new Uint8Array(arrayBuffer);

  // Validate ELF Magic: 0x7F, 'E', 'L', 'F'
  if (
    bytes[0] !== 0x7f ||
    bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c ||
    bytes[3] !== 0x46
  ) {
    throw new Error('Invalid ELF Magic header');
  }

  const classVal = bytes[4];
  const elfClass = ELF_CLASS[classVal] || 'Unknown';
  if (elfClass === 'Unknown') {
    throw new Error(`Unsupported or unknown ELF class: ${classVal}`);
  }

  const dataVal = bytes[5];
  const endianness = ELF_DATA[dataVal] || 'Unknown';
  if (endianness === 'Unknown') {
    throw new Error(`Unsupported or unknown endianness: ${dataVal}`);
  }

  const littleEndian = endianness === 'Little Endian';
  const osAbiVal = bytes[7];
  const osAbi = ELF_OSABI[osAbiVal] || `Unknown (${osAbiVal})`;

  // Parsing Type and Machine
  const typeVal = view.getUint16(16, littleEndian);
  const type = ELF_TYPE[typeVal] || `Unknown (${typeVal})`;

  const machineVal = view.getUint16(18, littleEndian);
  const machine = ELF_MACHINE[machineVal] || `Unknown (${machineVal})`;

  let entryPoint: bigint | number;
  let phOff: bigint | number;
  let shOff: bigint | number;
  let flags: number;
  let ehSize: number;
  let phentSize: number;
  let phNum: number;
  let shentSize: number;
  let shNum: number;
  let shStrNdX: number;

  const is64 = elfClass === '64-bit';

  if (is64) {
    entryPoint = view.getBigUint64(24, littleEndian);
    phOff = view.getBigUint64(32, littleEndian);
    shOff = view.getBigUint64(40, littleEndian);
    flags = view.getUint32(48, littleEndian);
    ehSize = view.getUint16(52, littleEndian);
    phentSize = view.getUint16(54, littleEndian);
    phNum = view.getUint16(56, littleEndian);
    shentSize = view.getUint16(58, littleEndian);
    shNum = view.getUint16(60, littleEndian);
    shStrNdX = view.getUint16(62, littleEndian);
  } else {
    entryPoint = view.getUint32(24, littleEndian);
    phOff = view.getUint32(28, littleEndian);
    shOff = view.getUint32(32, littleEndian);
    flags = view.getUint32(36, littleEndian);
    ehSize = view.getUint16(40, littleEndian);
    phentSize = view.getUint16(42, littleEndian);
    phNum = view.getUint16(44, littleEndian);
    shentSize = view.getUint16(46, littleEndian);
    shNum = view.getUint16(48, littleEndian);
    shStrNdX = view.getUint16(50, littleEndian);
  }

  const header: ElfHeader = {
    class: elfClass,
    endianness,
    osAbi,
    type,
    machine,
    entryPoint,
    phOff,
    shOff,
    flags,
    ehSize,
    phentSize,
    phNum,
    shentSize,
    shNum,
    shStrNdX,
  };

  // Program Headers
  const programHeaders: ElfProgramHeader[] = [];
  const phOffsetNum = Number(phOff);
  for (let i = 0; i < phNum; i++) {
    const offset = phOffsetNum + i * phentSize;
    if (offset + phentSize > arrayBuffer.byteLength) break;

    let pType: number;
    let pFlags = 0;
    let pOffset: bigint | number;
    let pVaddr: bigint | number;
    let pPaddr: bigint | number;
    let pFilesz: bigint | number;
    let pMemsz: bigint | number;
    let pAlign: bigint | number;

    if (is64) {
      pType = view.getUint32(offset, littleEndian);
      pFlags = view.getUint32(offset + 4, littleEndian);
      pOffset = view.getBigUint64(offset + 8, littleEndian);
      pVaddr = view.getBigUint64(offset + 16, littleEndian);
      pPaddr = view.getBigUint64(offset + 24, littleEndian);
      pFilesz = view.getBigUint64(offset + 32, littleEndian);
      pMemsz = view.getBigUint64(offset + 40, littleEndian);
      pAlign = view.getBigUint64(offset + 48, littleEndian);
    } else {
      pType = view.getUint32(offset, littleEndian);
      pOffset = view.getUint32(offset + 4, littleEndian);
      pVaddr = view.getUint32(offset + 8, littleEndian);
      pPaddr = view.getUint32(offset + 12, littleEndian);
      pFilesz = view.getUint32(offset + 16, littleEndian);
      pMemsz = view.getUint32(offset + 20, littleEndian);
      pFlags = view.getUint32(offset + 24, littleEndian);
      pAlign = view.getUint32(offset + 28, littleEndian);
    }

    programHeaders.push({
      type: pType,
      typeName: PT_TYPE[pType] || `PT_UNKNOWN (${pType})`,
      flags: pFlags,
      offset: pOffset,
      vaddr: pVaddr,
      paddr: pPaddr,
      filesz: pFilesz,
      memsz: pMemsz,
      align: pAlign,
    });
  }

  // Section Headers
  const sectionHeaders: ElfSectionHeader[] = [];
  const shOffsetNum = Number(shOff);
  for (let i = 0; i < shNum; i++) {
    const offset = shOffsetNum + i * shentSize;
    if (offset + shentSize > arrayBuffer.byteLength) break;

    let shName: number;
    let shType: number;
    let shFlags: bigint | number;
    let shAddr: bigint | number;
    let shSecOffset: bigint | number;
    let shSize: bigint | number;
    let shLink: number;
    let shInfo: number;
    let shAddralign: bigint | number;
    let shEntsize: bigint | number;

    if (is64) {
      shName = view.getUint32(offset, littleEndian);
      shType = view.getUint32(offset + 4, littleEndian);
      shFlags = view.getBigUint64(offset + 8, littleEndian);
      shAddr = view.getBigUint64(offset + 16, littleEndian);
      shSecOffset = view.getBigUint64(offset + 24, littleEndian);
      shSize = view.getBigUint64(offset + 32, littleEndian);
      shLink = view.getUint32(offset + 40, littleEndian);
      shInfo = view.getUint32(offset + 44, littleEndian);
      shAddralign = view.getBigUint64(offset + 48, littleEndian);
      shEntsize = view.getBigUint64(offset + 56, littleEndian);
    } else {
      shName = view.getUint32(offset, littleEndian);
      shType = view.getUint32(offset + 4, littleEndian);
      shFlags = view.getUint32(offset + 8, littleEndian);
      shAddr = view.getUint32(offset + 12, littleEndian);
      shSecOffset = view.getUint32(offset + 16, littleEndian);
      shSize = view.getUint32(offset + 20, littleEndian);
      shLink = view.getUint32(offset + 24, littleEndian);
      shInfo = view.getUint32(offset + 28, littleEndian);
      shAddralign = view.getUint32(offset + 32, littleEndian);
      shEntsize = view.getUint32(offset + 36, littleEndian);
    }

    sectionHeaders.push({
      nameOffset: shName,
      name: '', // resolved below
      type: shType,
      typeName: SHT_TYPE[shType] || `SHT_UNKNOWN (${shType})`,
      flags: shFlags,
      addr: shAddr,
      offset: shSecOffset,
      size: shSize,
      link: shLink,
      info: shInfo,
      addralign: shAddralign,
      entsize: shEntsize,
    });
  }

  // Resolve section names using the String Table (shstrtab) if available
  if (shStrNdX > 0 && shStrNdX < sectionHeaders.length) {
    const shstrtabHeader = sectionHeaders[shStrNdX];
    const shstrtabOffset = Number(shstrtabHeader.offset);
    const shstrtabSize = Number(shstrtabHeader.size);

    if (shstrtabOffset + shstrtabSize <= arrayBuffer.byteLength) {
      for (const section of sectionHeaders) {
        const start = shstrtabOffset + section.nameOffset;
        if (start < shstrtabOffset + shstrtabSize) {
          // Extract null-terminated string
          let name = '';
          for (let j = start; j < shstrtabOffset + shstrtabSize; j++) {
            if (bytes[j] === 0) break;
            name += String.fromCharCode(bytes[j]);
          }
          section.name = name;
        }
      }
    }
  }

  const symbols: ElfSymbol[] = [];
  const symbolTables: Record<number, ElfSymbol[]> = {};

  // Parse symbols from SHT_SYMTAB and SHT_DYNSYM sections
  for (let sIdx = 0; sIdx < sectionHeaders.length; sIdx++) {
    const sec = sectionHeaders[sIdx];
    if (sec.type === SHT_SYMTAB || sec.type === SHT_DYNSYM) {
      const secOffset = Number(sec.offset);
      const secSize = Number(sec.size);
      const entSize = Number(sec.entsize) || (is64 ? 24 : 16);

      if (secOffset + secSize <= arrayBuffer.byteLength) {
        // Link points to corresponding string table section
        let strTabOffset = 0;
        let strTabSize = 0;
        if (sec.link >= 0 && sec.link < sectionHeaders.length) {
          const strSec = sectionHeaders[sec.link];
          strTabOffset = Number(strSec.offset);
          strTabSize = Number(strSec.size);
        }

        const secSymbols: ElfSymbol[] = [];
        for (let off = 0; off + entSize <= secSize; off += entSize) {
          const symAddr = secOffset + off;
          let nameOffset = 0;
          let value: bigint | number = 0;
          let size: bigint | number = 0;
          let info = 0;
          let other = 0;
          let shndx = 0;

          if (is64) {
            nameOffset = view.getUint32(symAddr, littleEndian);
            info = view.getUint8(symAddr + 4);
            other = view.getUint8(symAddr + 5);
            shndx = view.getUint16(symAddr + 6, littleEndian);
            value = view.getBigUint64(symAddr + 8, littleEndian);
            size = view.getBigUint64(symAddr + 16, littleEndian);
          } else {
            nameOffset = view.getUint32(symAddr, littleEndian);
            value = view.getUint32(symAddr + 4, littleEndian);
            size = view.getUint32(symAddr + 8, littleEndian);
            info = view.getUint8(symAddr + 12);
            other = view.getUint8(symAddr + 13);
            shndx = view.getUint16(symAddr + 14, littleEndian);
          }

          // Extract name from linked string table
          let symName = '';
          if (strTabOffset > 0 && strTabOffset + strTabSize <= arrayBuffer.byteLength) {
            const start = strTabOffset + nameOffset;
            if (start < strTabOffset + strTabSize) {
              for (let j = start; j < strTabOffset + strTabSize; j++) {
                if (bytes[j] === 0) break;
                symName += String.fromCharCode(bytes[j]);
              }
            }
          }

          const bindVal = info >> 4;
          const typeVal = info & 0xf;
          const bind = STB_NAMES[bindVal] || `UNKNOWN_BIND (${bindVal})`;
          const type = STT_NAMES[typeVal] || `UNKNOWN_TYPE (${typeVal})`;

          const parsedSym: ElfSymbol = {
            name: symName,
            nameOffset,
            value,
            size,
            info,
            other,
            shndx,
            bind,
            type,
          };
          secSymbols.push(parsedSym);
          symbols.push(parsedSym);
        }
        symbolTables[sIdx] = secSymbols;
      }
    }
  }

  const relocations: ElfRelocation[] = [];
  const gotEntries: GotEntry[] = [];
  const pltRelocs: ElfRelocation[] = [];

  // Parse relocation sections (SHT_REL and SHT_RELA)
  for (let sIdx = 0; sIdx < sectionHeaders.length; sIdx++) {
    const sec = sectionHeaders[sIdx];
    if (sec.type === SHT_REL || sec.type === SHT_RELA) {
      const secOffset = Number(sec.offset);
      const secSize = Number(sec.size);
      const isRela = sec.type === SHT_RELA;
      
      let entSize = Number(sec.entsize);
      if (!entSize) {
        if (is64) {
          entSize = isRela ? 24 : 16;
        } else {
          entSize = isRela ? 12 : 8;
        }
      }

      if (secOffset + secSize <= arrayBuffer.byteLength) {
        // Find linked symbol table
        const linkedSymTableIdx = sec.link;
        const symTable = symbolTables[linkedSymTableIdx] || [];

        for (let off = 0; off + entSize <= secSize; off += entSize) {
          const relAddr = secOffset + off;
          let offset: bigint | number = 0;
          let info: bigint | number = 0;
          let addend: bigint | number | undefined = undefined;

          if (is64) {
            offset = view.getBigUint64(relAddr, littleEndian);
            info = view.getBigUint64(relAddr + 8, littleEndian);
            if (isRela) {
              addend = view.getBigInt64(relAddr + 16, littleEndian);
            }
          } else {
            offset = view.getUint32(relAddr, littleEndian);
            info = view.getUint32(relAddr + 4, littleEndian);
            if (isRela) {
              addend = view.getInt32(relAddr + 8, littleEndian);
            }
          }

          // Unpack info
          let symbolIndex = 0;
          let relocType = 0;
          if (is64) {
            const infoBig = BigInt(info);
            symbolIndex = Number(infoBig >> 32n);
            relocType = Number(infoBig & 0xffffffffn);
          } else {
            const infoNum = Number(info);
            symbolIndex = infoNum >> 8;
            relocType = infoNum & 0xff;
          }

          const sym = symTable[symbolIndex];
          const symbolName = sym ? sym.name : '';

          const typeName = getRelocationTypeName(header.machine, relocType);

          const relocation: ElfRelocation = {
            offset,
            info,
            addend,
            symbolIndex,
            symbolName,
            type: relocType,
            typeName,
          };
          relocations.push(relocation);

          // Identify GOT Relocations
          // Usually relocations of type GLOB_DAT, JUMP_SLOT / JMP_SLOT, etc.
          // or target offset falls into a section starting with `.got`
          let isGot = false;
          if (
            typeName.includes('GLOB_DAT') ||
            typeName.includes('JUMP_SLOT') ||
            typeName.includes('JMP_SLOT') ||
            typeName.includes('RELATIVE')
          ) {
            isGot = true;
          } else {
            // Find if relocation offset falls within a .got section
            for (const s of sectionHeaders) {
              if (s.name.startsWith('.got')) {
                const sAddr = BigInt(s.addr);
                const sSize = BigInt(s.size);
                const offVal = BigInt(offset);
                if (offVal >= sAddr && offVal < sAddr + sSize) {
                  isGot = true;
                  break;
                }
              }
            }
          }

          if (isGot && symbolName) {
            gotEntries.push({
              address: offset,
              symbolName,
              relocationType: typeName,
              addend,
            });
          }

          if (typeName.includes('JUMP_SLOT') || typeName.includes('JMP_SLOT')) {
            pltRelocs.push(relocation);
          }
        }
      }
    }
  }

  const pltEntries: PltEntry[] = [];

  // PLT Resolution
  // Look for .plt or .plt.sec or .plt.got sections
  for (const pltSec of sectionHeaders) {
    if (pltSec.name === '.plt' || pltSec.name === '.plt.sec' || pltSec.name === '.plt.got') {
      const secOffset = Number(pltSec.offset);
      const secSize = Number(pltSec.size);
      const secAddr = BigInt(pltSec.addr);

      if (secOffset + secSize <= arrayBuffer.byteLength) {
        let instructionResolvedCount = 0;

        // Try x86-64 Instruction decoding: search for jmp *disp(%rip) -> ff 25 displacement_32
        const isX86_64 = header.machine.toLowerCase().includes('amd64') || header.machine.toLowerCase().includes('x86-64') || header.machine.toLowerCase().includes('62');
        if (isX86_64) {
          for (let i = 0; i <= secSize - 6; i++) {
            if (bytes[secOffset + i] === 0xff && bytes[secOffset + i + 1] === 0x25) {
              const displacement = view.getInt32(secOffset + i + 2, littleEndian);
              const pltEntryAddr = secAddr + BigInt(i);
              const gotAddr = pltEntryAddr + 6n + BigInt(displacement);

              const gotEntry = gotEntries.find(g => BigInt(g.address) === gotAddr) ||
                               relocations.find(r => BigInt(r.offset) === gotAddr);
              if (gotEntry && gotEntry.symbolName) {
                pltEntries.push({
                  address: pltEntryAddr,
                  symbolName: gotEntry.symbolName,
                  gotAddress: gotAddr,
                });
                instructionResolvedCount++;
              }
            }
          }
        }

        // Fallback: 1-to-1 sequential layout mapping
        if (instructionResolvedCount === 0 && pltRelocs.length > 0 && pltSec.name === '.plt') {
          let headerSize = 16;
          let entrySize = 16;
          const machineLower = header.machine.toLowerCase();
          if (machineLower.includes('aarch64') || machineLower.includes('183')) {
            headerSize = 32;
            entrySize = 16;
          } else if (machineLower.includes('arm') || machineLower.includes('40')) {
            headerSize = 32;
            entrySize = 16;
          }

          for (let idx = 0; idx < pltRelocs.length; idx++) {
            const rel = pltRelocs[idx];
            const pltEntryAddr = secAddr + BigInt(headerSize + idx * entrySize);
            if (headerSize + idx * entrySize + entrySize <= secSize) {
              pltEntries.push({
                address: pltEntryAddr,
                symbolName: rel.symbolName,
                gotAddress: rel.offset,
              });
            }
          }
        }
      }
    }
  }

  return {
    header,
    programHeaders,
    sectionHeaders,
    symbols,
    relocations,
    gotEntries,
    pltEntries,
  };
}
