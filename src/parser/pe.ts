/**
 * PE/PE32+ Binary File Parser
 * Parses DOS Header, COFF File Header, Optional Header, Section Headers, and Import/Export Tables.
 */

export interface DosHeader {
  magic: string; // Should be "MZ"
  e_lfanew: number; // File offset of the PE header
}

export interface CoffHeader {
  machine: number;
  numberOfSections: number;
  timeDateStamp: number;
  pointerToSymbolTable: number;
  numberOfSymbols: number;
  sizeOfOptionalHeader: number;
  characteristics: number;
}

export interface DataDirectory {
  virtualAddress: number;
  size: number;
}

export interface OptionalHeader {
  magic: number; // 0x10b (PE32), 0x20b (PE32+)
  majorLinkerVersion: number;
  minorLinkerVersion: number;
  sizeOfCode: number;
  sizeOfInitializedData: number;
  sizeOfUninitializedData: number;
  addressOfEntryPoint: number;
  baseOfCode: number;
  baseOfData?: number; // Only in PE32

  // Windows-Specific Fields
  imageBase: bigint | number;
  sectionAlignment: number;
  fileAlignment: number;
  majorOperatingSystemVersion: number;
  minorOperatingSystemVersion: number;
  majorImageVersion: number;
  minorImageVersion: number;
  majorSubsystemVersion: number;
  minorSubsystemVersion: number;
  win32VersionValue: number;
  sizeOfImage: number;
  sizeOfHeaders: number;
  checkSum: number;
  subsystem: number;
  dllCharacteristics: number;
  sizeOfStackReserve: bigint | number;
  sizeOfStackCommit: bigint | number;
  sizeOfHeapReserve: bigint | number;
  sizeOfHeapCommit: bigint | number;
  loaderFlags: number;
  numberOfRvaAndSizes: number;

  dataDirectories: DataDirectory[];
}

export interface SectionHeader {
  name: string;
  virtualSize: number;
  virtualAddress: number;
  sizeOfRawData: number;
  pointerToRawData: number;
  pointerToRelocations: number;
  pointerToLinenumbers: number;
  numberOfRelocations: number;
  numberOfLinenumbers: number;
  characteristics: number;
}

export interface ExportEntry {
  name?: string;
  ordinal: number;
  address: number;
  forwarder?: string;
}

export interface ExportTable {
  dllName: string;
  characteristics: number;
  timeDateStamp: number;
  majorVersion: number;
  minorVersion: number;
  ordinalBase: number;
  exports: ExportEntry[];
}

export interface ImportEntry {
  name?: string;
  ordinal?: number;
  hint?: number;
}

export interface ImportTable {
  dllName: string;
  imports: ImportEntry[];
}

export interface ParsedResource {
  type: string | number;
  typeName: string;
  name: string | number;
  language: number;
  offset: number; // File offset
  size: number;
  data: Uint8Array;
}

export interface ParsedPE {
  is32Bit: boolean;
  dosHeader: DosHeader;
  coffHeader: CoffHeader;
  optionalHeader: OptionalHeader;
  sections: SectionHeader[];
  imports: ImportTable[];
  exports?: ExportTable;
  resources?: {
    manifests: string[];
    strings: Record<number, string>;
    icons: { type: number | string; size: number; offset: number }[];
    all: ParsedResource[];
  };
}

export class PEParser {
  private view: DataView;
  private buffer: ArrayBuffer;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
  }

  public parse(): ParsedPE {
    // 1. DOS Header
    if (this.view.byteLength < 64) {
      throw new Error('File too small to contain a valid DOS header');
    }

    const mzMagic = String.fromCharCode(
      this.view.getUint8(0),
      this.view.getUint8(1)
    );
    if (mzMagic !== 'MZ') {
      throw new Error('Invalid DOS MZ header signature');
    }

    const e_lfanew = this.view.getUint32(60, true);
    const dosHeader: DosHeader = { magic: mzMagic, e_lfanew };

    // 2. PE Signature
    if (e_lfanew + 4 > this.view.byteLength) {
      throw new Error('PE header offset points outside of file limits');
    }

    const peSig = this.view.getUint32(e_lfanew, true);
    if (peSig !== 0x00004550) {
      // "PE\0\0"
      throw new Error('Invalid PE signature');
    }

    // 3. COFF File Header
    const coffOffset = e_lfanew + 4;
    if (coffOffset + 20 > this.view.byteLength) {
      throw new Error('COFF file header points outside of file limits');
    }

    const coffHeader: CoffHeader = {
      machine: this.view.getUint16(coffOffset, true),
      numberOfSections: this.view.getUint16(coffOffset + 2, true),
      timeDateStamp: this.view.getUint32(coffOffset + 4, true),
      pointerToSymbolTable: this.view.getUint32(coffOffset + 8, true),
      numberOfSymbols: this.view.getUint32(coffOffset + 12, true),
      sizeOfOptionalHeader: this.view.getUint16(coffOffset + 16, true),
      characteristics: this.view.getUint16(coffOffset + 18, true),
    };

    // 4. Optional Header
    const optionalOffset = coffOffset + 20;
    if (optionalOffset + 2 > this.view.byteLength) {
      throw new Error('Optional header magic points outside of file limits');
    }

    const magic = this.view.getUint16(optionalOffset, true);
    const is32Bit = magic === 0x10b; // PE32: 0x10b, PE32+: 0x20b
    if (magic !== 0x10b && magic !== 0x20b) {
      throw new Error(
        `Unsupported PE optional header magic: 0x${magic.toString(16)}`
      );
    }

    // Parse Standard Fields
    const majorLinkerVersion = this.view.getUint8(optionalOffset + 2);
    const minorLinkerVersion = this.view.getUint8(optionalOffset + 3);
    const sizeOfCode = this.view.getUint32(optionalOffset + 4, true);
    const sizeOfInitializedData = this.view.getUint32(optionalOffset + 8, true);
    const sizeOfUninitializedData = this.view.getUint32(
      optionalOffset + 12,
      true
    );
    const addressOfEntryPoint = this.view.getUint32(optionalOffset + 16, true);
    const baseOfCode = this.view.getUint32(optionalOffset + 20, true);

    let baseOfData: number | undefined;
    let nextOffset = optionalOffset + 24;

    if (is32Bit) {
      baseOfData = this.view.getUint32(optionalOffset + 24, true);
      nextOffset = optionalOffset + 28;
    }

    // Parse Windows-Specific Fields
    let imageBase: bigint | number;
    if (is32Bit) {
      imageBase = this.view.getUint32(nextOffset, true);
      nextOffset += 4;
    } else {
      imageBase = this.view.getBigUint64(nextOffset, true);
      nextOffset += 8;
    }

    const sectionAlignment = this.view.getUint32(nextOffset, true);
    const fileAlignment = this.view.getUint32(nextOffset + 4, true);
    const majorOperatingSystemVersion = this.view.getUint16(
      nextOffset + 8,
      true
    );
    const minorOperatingSystemVersion = this.view.getUint16(
      nextOffset + 10,
      true
    );
    const majorImageVersion = this.view.getUint16(nextOffset + 12, true);
    const minorImageVersion = this.view.getUint16(nextOffset + 14, true);
    const majorSubsystemVersion = this.view.getUint16(nextOffset + 16, true);
    const minorSubsystemVersion = this.view.getUint16(nextOffset + 18, true);
    const win32VersionValue = this.view.getUint32(nextOffset + 20, true);
    const sizeOfImage = this.view.getUint32(nextOffset + 24, true);
    const sizeOfHeaders = this.view.getUint32(nextOffset + 28, true);
    const checkSum = this.view.getUint32(nextOffset + 32, true);
    const subsystem = this.view.getUint16(nextOffset + 36, true);
    const dllCharacteristics = this.view.getUint16(nextOffset + 38, true);
    nextOffset += 40;

    let sizeOfStackReserve: bigint | number;
    let sizeOfStackCommit: bigint | number;
    let sizeOfHeapReserve: bigint | number;
    let sizeOfHeapCommit: bigint | number;

    if (is32Bit) {
      sizeOfStackReserve = this.view.getUint32(nextOffset, true);
      sizeOfStackCommit = this.view.getUint32(nextOffset + 4, true);
      sizeOfHeapReserve = this.view.getUint32(nextOffset + 8, true);
      sizeOfHeapCommit = this.view.getUint32(nextOffset + 12, true);
      nextOffset += 16;
    } else {
      sizeOfStackReserve = this.view.getBigUint64(nextOffset, true);
      sizeOfStackCommit = this.view.getBigUint64(nextOffset + 8, true);
      sizeOfHeapReserve = this.view.getBigUint64(nextOffset + 16, true);
      sizeOfHeapCommit = this.view.getBigUint64(nextOffset + 24, true);
      nextOffset += 32;
    }

    const loaderFlags = this.view.getUint32(nextOffset, true);
    const numberOfRvaAndSizes = this.view.getUint32(nextOffset + 4, true);
    nextOffset += 8;

    // Parse Data Directories
    const dataDirectories: DataDirectory[] = [];
    for (let i = 0; i < numberOfRvaAndSizes; i++) {
      if (nextOffset + 8 > optionalOffset + coffHeader.sizeOfOptionalHeader) {
        break;
      }
      dataDirectories.push({
        virtualAddress: this.view.getUint32(nextOffset, true),
        size: this.view.getUint32(nextOffset + 4, true),
      });
      nextOffset += 8;
    }

    const optionalHeader: OptionalHeader = {
      magic,
      majorLinkerVersion,
      minorLinkerVersion,
      sizeOfCode,
      sizeOfInitializedData,
      sizeOfUninitializedData,
      addressOfEntryPoint,
      baseOfCode,
      baseOfData,
      imageBase,
      sectionAlignment,
      fileAlignment,
      majorOperatingSystemVersion,
      minorOperatingSystemVersion,
      majorImageVersion,
      minorImageVersion,
      majorSubsystemVersion,
      minorSubsystemVersion,
      win32VersionValue,
      sizeOfImage,
      sizeOfHeaders,
      checkSum,
      subsystem,
      dllCharacteristics,
      sizeOfStackReserve,
      sizeOfStackCommit,
      sizeOfHeapReserve,
      sizeOfHeapCommit,
      loaderFlags,
      numberOfRvaAndSizes,
      dataDirectories,
    };

    // 5. Section Headers
    // Offset of section headers starts immediately after the optional header
    const sectionHeadersOffset =
      optionalOffset + coffHeader.sizeOfOptionalHeader;
    const sections: SectionHeader[] = [];

    for (let i = 0; i < coffHeader.numberOfSections; i++) {
      const offset = sectionHeadersOffset + i * 40;
      if (offset + 40 > this.view.byteLength) {
        break;
      }

      // Parse 8-byte name
      const nameBytes: number[] = [];
      for (let j = 0; j < 8; j++) {
        const b = this.view.getUint8(offset + j);
        if (b !== 0) nameBytes.push(b);
      }
      const name = String.fromCharCode(...nameBytes);

      sections.push({
        name,
        virtualSize: this.view.getUint32(offset + 8, true),
        virtualAddress: this.view.getUint32(offset + 12, true),
        sizeOfRawData: this.view.getUint32(offset + 16, true),
        pointerToRawData: this.view.getUint32(offset + 20, true),
        pointerToRelocations: this.view.getUint32(offset + 24, true),
        pointerToLinenumbers: this.view.getUint32(offset + 28, true),
        numberOfRelocations: this.view.getUint16(offset + 32, true),
        numberOfLinenumbers: this.view.getUint16(offset + 34, true),
        characteristics: this.view.getUint32(offset + 36, true),
      });
    }

    // Helpers for RVA to Offset translation
    const rvaToOffset = (rva: number): number => {
      for (const section of sections) {
        if (
          rva >= section.virtualAddress &&
          rva <
            section.virtualAddress +
              Math.max(section.virtualSize, section.sizeOfRawData)
        ) {
          return rva - section.virtualAddress + section.pointerToRawData;
        }
      }
      return 0;
    };

    const readString = (offset: number): string => {
      const bytes: number[] = [];
      let currentOffset = offset;
      while (currentOffset < this.view.byteLength) {
        const b = this.view.getUint8(currentOffset++);
        if (b === 0) break;
        bytes.push(b);
      }
      return String.fromCharCode(...bytes);
    };

    // 6. Parse Exports (Directory 0)
    let exports: ExportTable | undefined;
    if (dataDirectories.length > 0 && dataDirectories[0].virtualAddress !== 0) {
      const exportDirRva = dataDirectories[0].virtualAddress;
      const exportDirOffset = rvaToOffset(exportDirRva);

      if (
        exportDirOffset !== 0 &&
        exportDirOffset + 40 <= this.view.byteLength
      ) {
        const characteristics = this.view.getUint32(exportDirOffset, true);
        const timeDateStamp = this.view.getUint32(exportDirOffset + 4, true);
        const majorVersion = this.view.getUint16(exportDirOffset + 8, true);
        const minorVersion = this.view.getUint16(exportDirOffset + 10, true);
        const nameRva = this.view.getUint32(exportDirOffset + 12, true);
        const ordinalBase = this.view.getUint32(exportDirOffset + 16, true);
        const numberOfFunctions = this.view.getUint32(
          exportDirOffset + 20,
          true
        );
        const numberOfNames = this.view.getUint32(exportDirOffset + 24, true);
        const addressOfFunctions = this.view.getUint32(
          exportDirOffset + 28,
          true
        );
        const addressOfNames = this.view.getUint32(exportDirOffset + 32, true);
        const addressOfNameOrdinals = this.view.getUint32(
          exportDirOffset + 36,
          true
        );

        const dllName = nameRva ? readString(rvaToOffset(nameRva)) : '';

        const funcOffset = rvaToOffset(addressOfFunctions);
        const nameTableOffset = rvaToOffset(addressOfNames);
        const ordinalTableOffset = rvaToOffset(addressOfNameOrdinals);

        const exportList: ExportEntry[] = [];

        // Parse functions first
        if (funcOffset !== 0) {
          for (let i = 0; i < numberOfFunctions; i++) {
            const funcRva = this.view.getUint32(funcOffset + i * 4, true);
            if (funcRva === 0) continue; // Unused / gap in ordinals

            const ordinal = ordinalBase + i;

            // Check if forwarded
            let forwarder: string | undefined;
            const dirSize = dataDirectories[0].size;
            if (funcRva >= exportDirRva && funcRva < exportDirRva + dirSize) {
              const forwarderOffset = rvaToOffset(funcRva);
              if (forwarderOffset !== 0) {
                forwarder = readString(forwarderOffset);
              }
            }

            exportList.push({
              ordinal,
              address: funcRva,
              forwarder,
            });
          }
        }

        // Map names to ordinals/functions
        if (nameTableOffset !== 0 && ordinalTableOffset !== 0) {
          for (let i = 0; i < numberOfNames; i++) {
            const nameStringRva = this.view.getUint32(
              nameTableOffset + i * 4,
              true
            );
            const ordinalIdx = this.view.getUint16(
              ordinalTableOffset + i * 2,
              true
            );

            const nameStr = nameStringRva
              ? readString(rvaToOffset(nameStringRva))
              : '';
            const entry = exportList.find(
              (e) => e.ordinal === ordinalBase + ordinalIdx
            );
            if (entry) {
              entry.name = nameStr;
            }
          }
        }

        exports = {
          dllName,
          characteristics,
          timeDateStamp,
          majorVersion,
          minorVersion,
          ordinalBase,
          exports: exportList,
        };
      }
    }

    // 7. Parse Imports (Directory 1)
    const imports: ImportTable[] = [];
    if (dataDirectories.length > 1 && dataDirectories[1].virtualAddress !== 0) {
      let importDirOffset = rvaToOffset(dataDirectories[1].virtualAddress);

      if (importDirOffset !== 0) {
        while (importDirOffset + 20 <= this.view.byteLength) {
          const originalFirstThunk = this.view.getUint32(importDirOffset, true);
          const timeDateStamp = this.view.getUint32(importDirOffset + 4, true);
          const forwarderChain = this.view.getUint32(importDirOffset + 8, true);
          const nameRva = this.view.getUint32(importDirOffset + 12, true);
          const firstThunk = this.view.getUint32(importDirOffset + 16, true);

          if (originalFirstThunk === 0 && firstThunk === 0 && nameRva === 0) {
            break; // Null descriptor indicates end of import table
          }

          const dllName = readString(rvaToOffset(nameRva));
          const importEntries: ImportEntry[] = [];

          // Use ILT (OriginalFirstThunk) or fallback to IAT (FirstThunk)
          const thunkRva =
            originalFirstThunk !== 0 ? originalFirstThunk : firstThunk;
          let thunkOffset = rvaToOffset(thunkRva);

          if (thunkOffset !== 0) {
            if (is32Bit) {
              while (thunkOffset + 4 <= this.view.byteLength) {
                const val = this.view.getUint32(thunkOffset, true);
                if (val === 0) break;

                const isOrdinal = (val & 0x80000000) !== 0;
                if (isOrdinal) {
                  importEntries.push({
                    ordinal: val & 0xffff,
                  });
                } else {
                  const nameOffset = rvaToOffset(val & 0x7fffffff);
                  if (nameOffset !== 0) {
                    const hint = this.view.getUint16(nameOffset, true);
                    const name = readString(nameOffset + 2);
                    importEntries.push({ hint, name });
                  }
                }
                thunkOffset += 4;
              }
            } else {
              while (thunkOffset + 8 <= this.view.byteLength) {
                const val = this.view.getBigUint64(thunkOffset, true);
                if (val === 0n) break;

                const isOrdinal = (val & 0x8000000000000000n) !== 0n;
                if (isOrdinal) {
                  importEntries.push({
                    ordinal: Number(val & 0xffffn),
                  });
                } else {
                  const nameOffset = rvaToOffset(Number(val & 0x7fffffffn));
                  if (nameOffset !== 0) {
                    const hint = this.view.getUint16(nameOffset, true);
                    const name = readString(nameOffset + 2);
                    importEntries.push({ hint, name });
                  }
                }
                thunkOffset += 8;
              }
            }
          }

          imports.push({
            dllName,
            imports: importEntries,
          });

          importDirOffset += 20;
        }
      }
    }

    // 8. Parse Resources (Directory 2)
    const RESOURCE_TYPES: Record<number, string> = {
      1: 'Cursor',
      2: 'Bitmap',
      3: 'Icon',
      4: 'Menu',
      5: 'Dialog',
      6: 'String Table',
      7: 'Font Directory',
      8: 'Font',
      9: 'Accelerator Table',
      10: 'Raw Data (RCDATA)',
      11: 'Message Table',
      12: 'Group Cursor',
      14: 'Group Icon',
      16: 'Version Info',
      19: 'Plug and Play',
      20: 'VXD',
      21: 'Animated Cursor',
      22: 'Animated Icon',
      23: 'HTML',
      24: 'Manifest'
    };

    const getResourceTypeName = (type: number | string): string => {
      if (typeof type === 'number') {
        return RESOURCE_TYPES[type] || `Unknown (${type})`;
      }
      return type;
    };

    let resources: ParsedPE['resources'];

    if (dataDirectories.length > 2 && dataDirectories[2].virtualAddress !== 0) {
      const resourceDirRva = dataDirectories[2].virtualAddress;
      const resourceStartOffset = rvaToOffset(resourceDirRva);

      if (resourceStartOffset !== 0) {
        const parseDirectory = (dirOffset: number, level: number, path: (string | number)[]): ParsedResource[] => {
          const absoluteDirOffset = resourceStartOffset + dirOffset;
          if (absoluteDirOffset + 16 > this.view.byteLength) {
            return [];
          }

          const numberOfNamedEntries = this.view.getUint16(absoluteDirOffset + 12, true);
          const numberOfIdEntries = this.view.getUint16(absoluteDirOffset + 14, true);
          const totalEntries = numberOfNamedEntries + numberOfIdEntries;

          const results: ParsedResource[] = [];
          let entryOffset = dirOffset + 16;

          for (let i = 0; i < totalEntries; i++) {
            const absoluteEntryOffset = resourceStartOffset + entryOffset;
            if (absoluteEntryOffset + 8 > this.view.byteLength) {
              break;
            }

            const nameOffsetOrId = this.view.getUint32(absoluteEntryOffset, true);
            const offsetToDataOrDirectory = this.view.getUint32(absoluteEntryOffset + 4, true);

            // Parse Name/ID
            let nameOrId: string | number;
            if ((nameOffsetOrId & 0x80000000) !== 0) {
              const stringOffset = nameOffsetOrId & 0x7fffffff;
              const absoluteStrOffset = resourceStartOffset + stringOffset;
              if (absoluteStrOffset + 2 <= this.view.byteLength) {
                const length = this.view.getUint16(absoluteStrOffset, true);
                const chars: string[] = [];
                for (let j = 0; j < length; j++) {
                  const charOffset = absoluteStrOffset + 2 + j * 2;
                  if (charOffset + 2 <= this.view.byteLength) {
                    chars.push(String.fromCharCode(this.view.getUint16(charOffset, true)));
                  }
                }
                nameOrId = chars.join('');
              } else {
                nameOrId = `Offset_0x${stringOffset.toString(16)}`;
              }
            } else {
              nameOrId = nameOffsetOrId;
            }

            const isSubdir = (offsetToDataOrDirectory & 0x80000000) !== 0;
            const subOffset = offsetToDataOrDirectory & 0x7fffffff;

            if (isSubdir) {
              results.push(...parseDirectory(subOffset, level + 1, [...path, nameOrId]));
            } else {
              const absoluteDataEntryOffset = resourceStartOffset + subOffset;
              if (absoluteDataEntryOffset + 16 <= this.view.byteLength) {
                const dataRva = this.view.getUint32(absoluteDataEntryOffset, true);
                const size = this.view.getUint32(absoluteDataEntryOffset + 4, true);
                
                const fileOffset = rvaToOffset(dataRva);
                if (fileOffset !== 0 && fileOffset + size <= this.view.byteLength) {
                  const dataBytes = new Uint8Array(this.buffer, fileOffset, size);
                  const type = path[0] !== undefined ? path[0] : 'Unknown';
                  const name = path[1] !== undefined ? path[1] : nameOrId;
                  const language = path[2] !== undefined ? Number(nameOrId) : 0;
                  results.push({
                    type,
                    typeName: getResourceTypeName(type),
                    name,
                    language,
                    offset: fileOffset,
                    size,
                    data: dataBytes
                  });
                }
              }
            }

            entryOffset += 8;
          }

          return results;
        };

        const allResources = parseDirectory(0, 1, []);

        // Manifests (Type 24)
        const manifests: string[] = [];
        const manifestResources = allResources.filter(r => r.type === 24);
        for (const r of manifestResources) {
          try {
            const text = new TextDecoder('utf-8').decode(r.data);
            manifests.push(text);
          } catch (e) {
            const text = String.fromCharCode(...Array.from(r.data));
            manifests.push(text);
          }
        }

        // String Tables (Type 6)
        const strings: Record<number, string> = {};
        const stringResources = allResources.filter(r => r.type === 6);
        for (const r of stringResources) {
          if (typeof r.name === 'number') {
            const blockId = r.name;
            const stringIdBase = (blockId - 1) * 16;
            let offset = 0;
            for (let i = 0; i < 16; i++) {
              if (offset + 2 > r.data.length) break;
              const len = r.data[offset] | (r.data[offset + 1] << 8);
              offset += 2;
              if (len > 0) {
                if (offset + len * 2 > r.data.length) break;
                const chars: string[] = [];
                for (let j = 0; j < len; j++) {
                  const charVal = r.data[offset + j * 2] | (r.data[offset + j * 2 + 1] << 8);
                  chars.push(String.fromCharCode(charVal));
                }
                strings[stringIdBase + i] = chars.join('');
                offset += len * 2;
              }
            }
          }
        }

        // Icons (Type 3) and Group Icons (Type 14)
        const icons: { type: number | string; size: number; offset: number }[] = [];
        const iconResources = allResources.filter(r => r.type === 3 || r.type === 14);
        for (const r of iconResources) {
          icons.push({
            type: r.type === 3 ? 'Icon' : 'Group Icon',
            size: r.size,
            offset: r.offset
          });
        }

        resources = {
          manifests,
          strings,
          icons,
          all: allResources
        };
      }
    }

    return {
      is32Bit,
      dosHeader,
      coffHeader,
      optionalHeader,
      sections,
      imports,
      exports,
      resources
    };
  }
}
