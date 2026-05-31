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
  hintNameTableRva?: number;
  iltRva?: number;
  iatRva?: number;
}

export interface ImportTable {
  dllName: string;
  imports: ImportEntry[];
  importAddressTableRva?: number;
  importLookupTableRva?: number;
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

export interface ParsedTLS {
  callbacks: number[];
  rawAddressOfCallbacks: bigint | number;
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
  tls?: ParsedTLS;
}

export class PEParser {
  private view: DataView;
  private buffer: ArrayBuffer;
  private bytes: Uint8Array;
  private decoder = new TextDecoder();
  private utf16Decoder = new TextDecoder('utf-16le');

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
    this.bytes = new Uint8Array(buffer);
  }

  public parse(): ParsedPE {
    const bytes = this.bytes;
    const len = bytes.length;

    // Fast helper functions for reading little-endian values
    const readU8 = (offset: number): number => bytes[offset];
    const readU16 = (offset: number): number => bytes[offset] | (bytes[offset + 1] << 8);
    const readU32 = (offset: number): number =>
      (bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)) >>>
      0;
    const readU64 = (offset: number): bigint => {
      const low =
        (bytes[offset] |
          (bytes[offset + 1] << 8) |
          (bytes[offset + 2] << 16) |
          (bytes[offset + 3] << 24)) >>>
        0;
      const high =
        (bytes[offset + 4] |
          (bytes[offset + 5] << 8) |
          (bytes[offset + 6] << 16) |
          (bytes[offset + 7] << 24)) >>>
        0;
      return BigInt(low) | (BigInt(high) << 32n);
    };

    // 1. DOS Header
    if (len < 64) {
      throw new Error('File too small to contain a valid DOS header');
    }

    if (bytes[0] !== 0x4d || bytes[1] !== 0x5a) { // 'M', 'Z'
      throw new Error('Invalid DOS MZ header signature');
    }

    const e_lfanew = readU32(60);
    const dosHeader: DosHeader = { magic: 'MZ', e_lfanew };

    // 2. PE Signature
    if (e_lfanew + 4 > len) {
      throw new Error('PE header offset points outside of file limits');
    }

    const peSig = readU32(e_lfanew);
    if (peSig !== 0x00004550) {
      // "PE\0\0"
      throw new Error('Invalid PE signature');
    }

    // 3. COFF File Header
    const coffOffset = e_lfanew + 4;
    if (coffOffset + 20 > len) {
      throw new Error('COFF file header points outside of file limits');
    }

    const coffHeader: CoffHeader = {
      machine: readU16(coffOffset),
      numberOfSections: readU16(coffOffset + 2),
      timeDateStamp: readU32(coffOffset + 4),
      pointerToSymbolTable: readU32(coffOffset + 8),
      numberOfSymbols: readU32(coffOffset + 12),
      sizeOfOptionalHeader: readU16(coffOffset + 16),
      characteristics: readU16(coffOffset + 18),
    };

    // 4. Optional Header
    const optionalOffset = coffOffset + 20;
    if (optionalOffset + 2 > len) {
      throw new Error('Optional header magic points outside of file limits');
    }

    const magic = readU16(optionalOffset);
    const is32Bit = magic === 0x10b; // PE32: 0x10b, PE32+: 0x20b
    if (magic !== 0x10b && magic !== 0x20b) {
      throw new Error(
        `Unsupported PE optional header magic: 0x${magic.toString(16)}`
      );
    }

    // Parse Standard Fields
    const majorLinkerVersion = readU8(optionalOffset + 2);
    const minorLinkerVersion = readU8(optionalOffset + 3);
    const sizeOfCode = readU32(optionalOffset + 4);
    const sizeOfInitializedData = readU32(optionalOffset + 8);
    const sizeOfUninitializedData = readU32(optionalOffset + 12);
    const addressOfEntryPoint = readU32(optionalOffset + 16);
    const baseOfCode = readU32(optionalOffset + 20);

    let baseOfData: number | undefined;
    let nextOffset = optionalOffset + 24;

    if (is32Bit) {
      baseOfData = readU32(optionalOffset + 24);
      nextOffset = optionalOffset + 28;
    }

    // Parse Windows-Specific Fields
    let imageBase: bigint | number;
    if (is32Bit) {
      imageBase = readU32(nextOffset);
      nextOffset += 4;
    } else {
      imageBase = readU64(nextOffset);
      nextOffset += 8;
    }

    const sectionAlignment = readU32(nextOffset);
    const fileAlignment = readU32(nextOffset + 4);
    const majorOperatingSystemVersion = readU16(nextOffset + 8);
    const minorOperatingSystemVersion = readU16(nextOffset + 10);
    const majorImageVersion = readU16(nextOffset + 12);
    const minorImageVersion = readU16(nextOffset + 14);
    const majorSubsystemVersion = readU16(nextOffset + 16);
    const minorSubsystemVersion = readU16(nextOffset + 18);
    const win32VersionValue = readU32(nextOffset + 20);
    const sizeOfImage = readU32(nextOffset + 24);
    const sizeOfHeaders = readU32(nextOffset + 28);
    const checkSum = readU32(nextOffset + 32);
    const subsystem = readU16(nextOffset + 36);
    const dllCharacteristics = readU16(nextOffset + 38);
    nextOffset += 40;

    let sizeOfStackReserve: bigint | number;
    let sizeOfStackCommit: bigint | number;
    let sizeOfHeapReserve: bigint | number;
    let sizeOfHeapCommit: bigint | number;

    if (is32Bit) {
      sizeOfStackReserve = readU32(nextOffset);
      sizeOfStackCommit = readU32(nextOffset + 4);
      sizeOfHeapReserve = readU32(nextOffset + 8);
      sizeOfHeapCommit = readU32(nextOffset + 12);
      nextOffset += 16;
    } else {
      sizeOfStackReserve = readU64(nextOffset);
      sizeOfStackCommit = readU64(nextOffset + 8);
      sizeOfHeapReserve = readU64(nextOffset + 16);
      sizeOfHeapCommit = readU64(nextOffset + 24);
      nextOffset += 32;
    }

    const loaderFlags = readU32(nextOffset);
    const numberOfRvaAndSizes = readU32(nextOffset + 4);
    nextOffset += 8;

    // Parse Data Directories
    const dataDirectories: DataDirectory[] = [];
    const maxOptionalOffset = optionalOffset + coffHeader.sizeOfOptionalHeader;
    for (let i = 0; i < numberOfRvaAndSizes; i++) {
      if (nextOffset + 8 > maxOptionalOffset) {
        break;
      }
      dataDirectories.push({
        virtualAddress: readU32(nextOffset),
        size: readU32(nextOffset + 4),
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
    const sectionHeadersOffset = optionalOffset + coffHeader.sizeOfOptionalHeader;
    const sections: SectionHeader[] = [];
    const numSections = coffHeader.numberOfSections;

    for (let i = 0; i < numSections; i++) {
      const offset = sectionHeadersOffset + i * 40;
      if (offset + 40 > len) {
        break;
      }

      // Parse 8-byte name
      let name = '';
      for (let j = 0; j < 8; j++) {
        const b = bytes[offset + j];
        if (b === 0) break;
        name += String.fromCharCode(b);
      }

      sections.push({
        name,
        virtualSize: readU32(offset + 8),
        virtualAddress: readU32(offset + 12),
        sizeOfRawData: readU32(offset + 16),
        pointerToRawData: readU32(offset + 20),
        pointerToRelocations: readU32(offset + 24),
        pointerToLinenumbers: readU32(offset + 28),
        numberOfRelocations: readU16(offset + 32),
        numberOfLinenumbers: readU16(offset + 34),
        characteristics: readU32(offset + 36),
      });
    }

    // Helpers for RVA to Offset translation
    const rvaToOffset = (rva: number): number => {
      const sectLen = sections.length;
      for (let i = 0; i < sectLen; i++) {
        const section = sections[i];
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

    const readString = (offset: number): string => {
      let end = offset;
      while (end < len && bytes[end] !== 0) {
        end++;
      }
      if (end === offset) return '';
      return this.decoder.decode(bytes.subarray(offset, end));
    };

    // 6. Parse Exports (Directory 0)
    let exports: ExportTable | undefined;
    if (dataDirectories.length > 0 && dataDirectories[0].virtualAddress !== 0) {
      const exportDirRva = dataDirectories[0].virtualAddress;
      const exportDirOffset = rvaToOffset(exportDirRva);

      if (
        exportDirOffset !== 0 &&
        exportDirOffset + 40 <= len
      ) {
        const characteristics = readU32(exportDirOffset);
        const timeDateStamp = readU32(exportDirOffset + 4);
        const majorVersion = readU16(exportDirOffset + 8);
        const minorVersion = readU16(exportDirOffset + 10);
        const nameRva = readU32(exportDirOffset + 12);
        const ordinalBase = readU32(exportDirOffset + 16);
        const numberOfFunctions = readU32(exportDirOffset + 20);
        const numberOfNames = readU32(exportDirOffset + 24);
        const addressOfFunctions = readU32(exportDirOffset + 28);
        const addressOfNames = readU32(exportDirOffset + 32);
        const addressOfNameOrdinals = readU32(exportDirOffset + 36);

        const dllName = nameRva ? readString(rvaToOffset(nameRva)) : '';

        const funcOffset = rvaToOffset(addressOfFunctions);
        const nameTableOffset = rvaToOffset(addressOfNames);
        const ordinalTableOffset = rvaToOffset(addressOfNameOrdinals);

        const exportList: ExportEntry[] = [];

        // Parse functions first
        if (funcOffset !== 0) {
          for (let i = 0; i < numberOfFunctions; i++) {
            const funcRva = readU32(funcOffset + i * 4);
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
            const nameStringRva = readU32(nameTableOffset + i * 4);
            const ordinalIdx = readU16(ordinalTableOffset + i * 2);

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
        while (importDirOffset + 20 <= len) {
          const originalFirstThunk = readU32(importDirOffset);
          const nameRva = readU32(importDirOffset + 12);
          const firstThunk = readU32(importDirOffset + 16);

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
              let idx = 0;
              while (thunkOffset + 4 <= len) {
                const val = readU32(thunkOffset);
                if (val === 0) break;

                const iltRva = originalFirstThunk !== 0 ? originalFirstThunk + idx * 4 : undefined;
                const iatRva = firstThunk !== 0 ? firstThunk + idx * 4 : undefined;

                const isOrdinal = (val & 0x80000000) !== 0;
                if (isOrdinal) {
                  importEntries.push({
                    ordinal: val & 0xffff,
                    iltRva,
                    iatRva,
                  });
                } else {
                  const hntRva = val & 0x7fffffff;
                  const nameOffset = rvaToOffset(hntRva);
                  if (nameOffset !== 0) {
                    const hint = readU16(nameOffset);
                    const name = readString(nameOffset + 2);
                    importEntries.push({
                      hint,
                      name,
                      hintNameTableRva: hntRva,
                      iltRva,
                      iatRva,
                    });
                  }
                }
                thunkOffset += 4;
                idx++;
              }
            } else {
              let idx = 0;
              while (thunkOffset + 8 <= len) {
                const val = readU64(thunkOffset);
                if (val === 0n) break;

                const iltRva = originalFirstThunk !== 0 ? originalFirstThunk + idx * 8 : undefined;
                const iatRva = firstThunk !== 0 ? firstThunk + idx * 8 : undefined;

                const isOrdinal = (val & 0x8000000000000000n) !== 0n;
                if (isOrdinal) {
                  importEntries.push({
                    ordinal: Number(val & 0xffffn),
                    iltRva,
                    iatRva,
                  });
                } else {
                  const hntRva = Number(val & 0x7fffffffn);
                  const nameOffset = rvaToOffset(hntRva);
                  if (nameOffset !== 0) {
                    const hint = readU16(nameOffset);
                    const name = readString(nameOffset + 2);
                    importEntries.push({
                      hint,
                      name,
                      hintNameTableRva: hntRva,
                      iltRva,
                      iatRva,
                    });
                  }
                }
                thunkOffset += 8;
                idx++;
              }
            }
          }

          imports.push({
            dllName,
            imports: importEntries,
            importAddressTableRva: firstThunk !== 0 ? firstThunk : undefined,
            importLookupTableRva: originalFirstThunk !== 0 ? originalFirstThunk : undefined,
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
      24: 'Manifest',
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
        const parseDirectory = (
          dirOffset: number,
          level: number,
          path: (string | number)[]
        ): ParsedResource[] => {
          const absoluteDirOffset = resourceStartOffset + dirOffset;
          if (absoluteDirOffset + 16 > len) {
            return [];
          }

          const numberOfNamedEntries = readU16(absoluteDirOffset + 12);
          const numberOfIdEntries = readU16(absoluteDirOffset + 14);
          const totalEntries = numberOfNamedEntries + numberOfIdEntries;

          const results: ParsedResource[] = [];
          let entryOffset = dirOffset + 16;

          for (let i = 0; i < totalEntries; i++) {
            const absoluteEntryOffset = resourceStartOffset + entryOffset;
            if (absoluteEntryOffset + 8 > len) {
              break;
            }

            const nameOffsetOrId = readU32(absoluteEntryOffset);
            const offsetToDataOrDirectory = readU32(absoluteEntryOffset + 4);

            // Parse Name/ID
            let nameOrId: string | number;
            if ((nameOffsetOrId & 0x80000000) !== 0) {
              const stringOffset = nameOffsetOrId & 0x7fffffff;
              const absoluteStrOffset = resourceStartOffset + stringOffset;
              if (absoluteStrOffset + 2 <= len) {
                const length = readU16(absoluteStrOffset);
                const charOffset = absoluteStrOffset + 2;
                if (charOffset + length * 2 <= len) {
                  try {
                    nameOrId = this.utf16Decoder.decode(bytes.subarray(charOffset, charOffset + length * 2));
                  } catch {
                    const tempChars: string[] = [];
                    for (let j = 0; j < length; j++) {
                      tempChars.push(String.fromCharCode(readU16(charOffset + j * 2)));
                    }
                    nameOrId = tempChars.join('');
                  }
                } else {
                  nameOrId = `Offset_0x${stringOffset.toString(16)}`;
                }
              } else {
                nameOrId = `Offset_0x${stringOffset.toString(16)}`;
              }
            } else {
              nameOrId = nameOffsetOrId;
            }

            const isSubdir = (offsetToDataOrDirectory & 0x80000000) !== 0;
            const subOffset = offsetToDataOrDirectory & 0x7fffffff;

            if (isSubdir) {
              results.push(
                ...parseDirectory(subOffset, level + 1, [...path, nameOrId])
              );
            } else {
              const absoluteDataEntryOffset = resourceStartOffset + subOffset;
              if (absoluteDataEntryOffset + 16 <= len) {
                const dataRva = readU32(absoluteDataEntryOffset);
                const size = readU32(absoluteDataEntryOffset + 4);

                const fileOffset = rvaToOffset(dataRva);
                if (
                  fileOffset !== 0 &&
                  fileOffset + size <= len
                ) {
                  const dataBytes = new Uint8Array(
                    this.buffer,
                    fileOffset,
                    size
                  );
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
                    data: dataBytes,
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
        const manifestResources = allResources.filter((r) => r.type === 24);
        for (const r of manifestResources) {
          try {
            manifests.push(this.decoder.decode(r.data));
          } catch {
            const tempChars: string[] = [];
            const rDataLen = r.data.length;
            for (let k = 0; k < rDataLen; k++) {
              tempChars.push(String.fromCharCode(r.data[k]));
            }
            manifests.push(tempChars.join(''));
          }
        }

        // String Tables (Type 6)
        const strings: Record<number, string> = {};
        const stringResources = allResources.filter((r) => r.type === 6);
        for (const r of stringResources) {
          if (typeof r.name === 'number') {
            const blockId = r.name;
            const stringIdBase = (blockId - 1) * 16;
            let offset = 0;
            const rDataLen = r.data.length;
            for (let i = 0; i < 16; i++) {
              if (offset + 2 > rDataLen) break;
              const lenStr = r.data[offset] | (r.data[offset + 1] << 8);
              offset += 2;
              if (lenStr > 0) {
                if (offset + lenStr * 2 > rDataLen) break;
                strings[stringIdBase + i] = this.utf16Decoder.decode(r.data.subarray(offset, offset + lenStr * 2));
                offset += lenStr * 2;
              }
            }
          }
        }

        // Icons (Type 3) and Group Icons (Type 14)
        const icons: { type: number | string; size: number; offset: number }[] =
          [];
        const iconResources = allResources.filter(
          (r) => r.type === 3 || r.type === 14
        );
        for (const r of iconResources) {
          icons.push({
            type: r.type === 3 ? 'Icon' : 'Group Icon',
            size: r.size,
            offset: r.offset,
          });
        }

        resources = {
          manifests,
          strings,
          icons,
          all: allResources,
        };
      }
    }

    // 9. Parse TLS (Directory 9)
    let tls: ParsedTLS | undefined;
    if (dataDirectories.length > 9 && dataDirectories[9].virtualAddress !== 0) {
      const tlsDirRva = dataDirectories[9].virtualAddress;
      const tlsDirOffset = rvaToOffset(tlsDirRva);

      if (
        tlsDirOffset !== 0 &&
        tlsDirOffset + (is32Bit ? 24 : 40) <= len
      ) {
        let rawAddressOfCallbacks: bigint | number;
        if (is32Bit) {
          rawAddressOfCallbacks = readU32(tlsDirOffset + 12);
        } else {
          rawAddressOfCallbacks = readU64(tlsDirOffset + 24);
        }

        const callbacks: number[] = [];
        if (rawAddressOfCallbacks !== 0 && rawAddressOfCallbacks !== 0n) {
          const callbacksRva =
            typeof imageBase === 'bigint'
              ? Number(BigInt(rawAddressOfCallbacks) - imageBase)
              : Number(rawAddressOfCallbacks) - (imageBase as number);

          let thunkOffset = rvaToOffset(callbacksRva);
          if (thunkOffset !== 0) {
            if (is32Bit) {
              while (thunkOffset + 4 <= len) {
                const val = readU32(thunkOffset);
                if (val === 0) break;
                const callbackRva =
                  typeof imageBase === 'bigint'
                    ? Number(BigInt(val) - imageBase)
                    : Number(val) - (imageBase as number);
                callbacks.push(callbackRva);
                thunkOffset += 4;
              }
            } else {
              while (thunkOffset + 8 <= len) {
                const val = readU64(thunkOffset);
                if (val === 0n) break;
                const callbackRva =
                  typeof imageBase === 'bigint'
                    ? Number(val - imageBase)
                    : Number(val) - (imageBase as number);
                callbacks.push(callbackRva);
                thunkOffset += 8;
              }
            }
          }
        }

        tls = {
          callbacks,
          rawAddressOfCallbacks,
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
      resources,
      tls,
    };
  }
}
