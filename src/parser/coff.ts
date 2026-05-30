/**
 * COFF/XCOFF Binary File Parser
 * Parses file headers, section headers, symbol tables, and machine types.
 * Supports standard COFF, XCOFF32, and XCOFF64 formats.
 */

export interface CoffHeader {
  magic: number;
  machine: number;
  machineName: string;
  numberOfSections: number;
  timeDateStamp: number;
  pointerToSymbolTable: bigint | number;
  numberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
}

export interface CoffSectionHeader {
  name: string;
  physicalAddress: bigint | number;
  virtualAddress: bigint | number;
  size: bigint | number;
  pointerToRawData: bigint | number;
  pointerToRelocations: bigint | number;
  pointerToLinenumbers: bigint | number;
  numberOfRelocations: number;
  numberOfLinenumbers: number;
  characteristics: number;
}

export interface CoffSymbol {
  name: string;
  value: bigint | number;
  sectionNumber: number;
  type: number;
  storageClass: number;
  numberOfAuxSymbols: number;
}

export interface ParsedCoff {
  is64Bit: boolean;
  isBigEndian: boolean;
  header: CoffHeader;
  sections: CoffSectionHeader[];
  symbols: CoffSymbol[];
}

const COFF_MACHINE_TYPES: Record<number, string> = {
  0x14c: 'Intel 386',
  0x8664: 'AMD64 (x64)',
  0x200: 'Intel IA64',
  0x1c0: 'ARM',
  0x1c4: 'ARMNT',
  0xaa64: 'ARM64',
  0x01f0: 'PowerPC',
  0x01f1: 'PowerPCFP',
  0x01d3: 'AM33',
  0x01a2: 'SH3',
  0x01a3: 'SH3DSP',
  0x01a6: 'SH4',
  0x01a8: 'SH5',
  0x01c2: 'THUMB',
  0x0266: 'MIPS16',
  0x0366: 'MIPSFPU',
  0x0466: 'MIPSFPU16',
  0x0520: 'Infineon Tricore',
  0x0cbd: 'ARM64EC',
  0x5032: 'RISCV32',
  0x5064: 'RISCV64',
  0x5128: 'RISCV128',
  0x9041: 'M32R',
  0xc0ee: 'CEE',
  // XCOFF magic numbers
  0x01df: 'PowerPC (XCOFF32)',
  0x01f7: 'PowerPC 64-bit (XCOFF32)',
  0x01f6: 'PowerPC (XCOFF64)',
};

export class CoffParser {
  private view: DataView;
  private buffer: ArrayBuffer;
  private isBigEndian: boolean = false;
  private is64Bit: boolean = false;
  private stringTable: Uint8Array = new Uint8Array(0);

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
  }

  public parse(): ParsedCoff {
    if (this.view.byteLength < 20) {
      throw new Error('File too small to contain a COFF header');
    }

    // Detect endianness and format from the magic number
    const magicLE = this.view.getUint16(0, true);
    const magicBE = this.view.getUint16(0, false);

    // AIX XCOFF uses big endian by default
    if (magicBE === 0x01df || magicBE === 0x01f6 || magicBE === 0x01f7) {
      this.isBigEndian = true;
    } else {
      this.isBigEndian = false;
    }

    const magic = this.isBigEndian ? magicBE : magicLE;
    this.is64Bit = (magic === 0x01f6);

    const header = this.parseHeader(magic);
    this.loadStringTable(header.pointerToSymbolTable, header.numberOfSymbols);

    const sections = this.parseSections(header.numberOfSections, header.sizeOfOptionalHeader);
    const symbols = this.parseSymbols(header.pointerToSymbolTable, header.numberOfSymbols);

    return {
      is64Bit: this.is64Bit,
      isBigEndian: this.isBigEndian,
      header,
      sections,
      symbols,
    };
  }

  private parseHeader(magic: number): CoffHeader {
    const isBE = this.isBigEndian;
    
    if (this.is64Bit) {
      if (this.view.byteLength < 24) {
        throw new Error('File too small to contain an XCOFF64 header');
      }
      const machine = magic;
      const numberOfSections = this.view.getUint16(2, !isBE);
      const timeDateStamp = this.view.getUint32(4, !isBE);
      const pointerToSymbolTable = this.view.getBigUint64(8, !isBE);
      const numberOfSymbols = this.view.getUint32(16, !isBE);
      const sizeOfOptionalHeader = this.view.getUint16(20, !isBE);
      const characteristics = this.view.getUint16(22, !isBE);

      return {
        magic,
        machine,
        machineName: COFF_MACHINE_TYPES[machine] || 'Unknown',
        numberOfSections,
        timeDateStamp,
        pointerToSymbolTable,
        numberOfSymbols,
        sizeOfOptionalHeader,
        characteristics,
      };
    } else {
      const machine = magic;
      const numberOfSections = this.view.getUint16(2, !isBE);
      const timeDateStamp = this.view.getUint32(4, !isBE);
      const pointerToSymbolTable = this.view.getUint32(8, !isBE);
      const numberOfSymbols = this.view.getUint32(12, !isBE);
      const sizeOfOptionalHeader = this.view.getUint16(16, !isBE);
      const characteristics = this.view.getUint16(18, !isBE);

      return {
        magic,
        machine,
        machineName: COFF_MACHINE_TYPES[magic] || 'Unknown',
        numberOfSections,
        timeDateStamp,
        pointerToSymbolTable,
        numberOfSymbols,
        sizeOfOptionalHeader,
        characteristics,
      };
    }
  }

  private loadStringTable(pointerToSymbolTable: bigint | number, numberOfSymbols: number): void {
    const isBE = this.isBigEndian;
    const symTableOffset = Number(pointerToSymbolTable);
    if (symTableOffset === 0 || numberOfSymbols === 0) {
      return;
    }

    const stringTableOffset = symTableOffset + numberOfSymbols * 18;
    if (stringTableOffset + 4 <= this.buffer.byteLength) {
      const stringTableSize = this.view.getUint32(stringTableOffset, !isBE);
      if (stringTableSize >= 4 && stringTableOffset + stringTableSize <= this.buffer.byteLength) {
        this.stringTable = new Uint8Array(this.buffer, stringTableOffset, stringTableSize);
      }
    }
  }

  private parseSections(numberOfSections: number, sizeOfOptionalHeader: number): CoffSectionHeader[] {
    const isBE = this.isBigEndian;
    const headerSize = this.is64Bit ? 24 : 20;
    const sectionStart = headerSize + sizeOfOptionalHeader;
    const sectionEntrySize = this.is64Bit ? 72 : 40;

    const sections: CoffSectionHeader[] = [];

    for (let i = 0; i < numberOfSections; i++) {
      const offset = sectionStart + i * sectionEntrySize;
      if (offset + sectionEntrySize > this.buffer.byteLength) {
        break;
      }

      // Read name (8 bytes)
      const nameBytes = new Uint8Array(this.buffer, offset, 8);
      let name = '';
      
      // Check if it's a string table reference in standard COFF (starts with '/')
      if (nameBytes[0] === 0x2f) { // '/'
        let slashStr = '';
        for (let j = 1; j < 8 && nameBytes[j] !== 0; j++) {
          slashStr += String.fromCharCode(nameBytes[j]);
        }
        const strOffset = parseInt(slashStr, 10);
        if (!isNaN(strOffset)) {
          name = this.getString(strOffset);
        } else {
          name = slashStr;
        }
      } else {
        let len = 0;
        while (len < 8 && nameBytes[len] !== 0) {
          len++;
        }
        name = new TextDecoder().decode(nameBytes.subarray(0, len));
      }

      if (this.is64Bit) {
        const physicalAddress = this.view.getBigUint64(offset + 8, !isBE);
        const virtualAddress = this.view.getBigUint64(offset + 16, !isBE);
        const size = this.view.getBigUint64(offset + 24, !isBE);
        const pointerToRawData = this.view.getBigUint64(offset + 32, !isBE);
        const pointerToRelocations = this.view.getBigUint64(offset + 40, !isBE);
        const pointerToLinenumbers = this.view.getBigUint64(offset + 48, !isBE);
        const numberOfRelocations = this.view.getUint32(offset + 56, !isBE);
        const numberOfLinenumbers = this.view.getUint32(offset + 60, !isBE);
        const characteristics = this.view.getUint32(offset + 64, !isBE);

        sections.push({
          name,
          physicalAddress,
          virtualAddress,
          size,
          pointerToRawData,
          pointerToRelocations,
          pointerToLinenumbers,
          numberOfRelocations,
          numberOfLinenumbers,
          characteristics,
        });
      } else {
        const physicalAddress = this.view.getUint32(offset + 8, !isBE);
        const virtualAddress = this.view.getUint32(offset + 12, !isBE);
        const size = this.view.getUint32(offset + 16, !isBE);
        const pointerToRawData = this.view.getUint32(offset + 20, !isBE);
        const pointerToRelocations = this.view.getUint32(offset + 24, !isBE);
        const pointerToLinenumbers = this.view.getUint32(offset + 28, !isBE);
        const numberOfRelocations = this.view.getUint16(offset + 32, !isBE);
        const numberOfLinenumbers = this.view.getUint16(offset + 34, !isBE);
        const characteristics = this.view.getUint32(offset + 36, !isBE);

        sections.push({
          name,
          physicalAddress,
          virtualAddress,
          size,
          pointerToRawData,
          pointerToRelocations,
          pointerToLinenumbers,
          numberOfRelocations,
          numberOfLinenumbers,
          characteristics,
        });
      }
    }

    return sections;
  }

  private parseSymbols(pointerToSymbolTable: bigint | number, numberOfSymbols: number): CoffSymbol[] {
    const isBE = this.isBigEndian;
    const symTableOffset = Number(pointerToSymbolTable);
    if (symTableOffset === 0 || numberOfSymbols === 0) {
      return [];
    }

    const symbols: CoffSymbol[] = [];
    let i = 0;

    while (i < numberOfSymbols) {
      const offset = symTableOffset + i * 18;
      if (offset + 18 > this.buffer.byteLength) {
        break;
      }

      let name = '';
      let value: bigint | number = 0;
      let sectionNumber = 0;
      let type = 0;
      let storageClass = 0;
      let numberOfAuxSymbols = 0;

      if (this.is64Bit) {
        value = this.view.getBigUint64(offset, !isBE);
        const nameOffset = this.view.getUint32(offset + 8, !isBE);
        sectionNumber = this.view.getInt16(offset + 12, !isBE);
        type = this.view.getUint16(offset + 14, !isBE);
        storageClass = this.view.getUint8(offset + 16);
        numberOfAuxSymbols = this.view.getUint8(offset + 17);

        name = this.getString(nameOffset);
      } else {
        const nameZero = this.view.getUint32(offset, !isBE);
        if (nameZero === 0) {
          const nameOffset = this.view.getUint32(offset + 4, !isBE);
          name = this.getString(nameOffset);
        } else {
          const nameBytes = new Uint8Array(this.buffer, offset, 8);
          let len = 0;
          while (len < 8 && nameBytes[len] !== 0) {
            len++;
          }
          name = new TextDecoder().decode(nameBytes.subarray(0, len));
        }

        value = this.view.getUint32(offset + 8, !isBE);
        sectionNumber = this.view.getInt16(offset + 12, !isBE);
        type = this.view.getUint16(offset + 14, !isBE);
        storageClass = this.view.getUint8(offset + 16);
        numberOfAuxSymbols = this.view.getUint8(offset + 17);
      }

      symbols.push({
        name,
        value,
        sectionNumber,
        type,
        storageClass,
        numberOfAuxSymbols,
      });

      // Skip auxiliary symbol entries
      i += 1 + numberOfAuxSymbols;
    }

    return symbols;
  }

  private getString(offset: number): string {
    if (offset < 4 || offset >= this.stringTable.byteLength) {
      return '';
    }
    let end = offset;
    while (end < this.stringTable.byteLength && this.stringTable[end] !== 0) {
      end++;
    }
    return new TextDecoder().decode(this.stringTable.subarray(offset, end));
  }
}
