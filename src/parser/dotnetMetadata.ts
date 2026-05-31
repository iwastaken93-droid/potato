/**
 * .NET CLI Metadata Parser
 * Parses CLI Headers, Metadata Root, Metadata Streams, and Metadata Tables (ECMA-335).
 */

import { PEParser, SectionHeader } from './pe.js';

export interface CliHeader {
  cb: number;
  majorRuntimeVersion: number;
  minorRuntimeVersion: number;
  metaData: { virtualAddress: number; size: number };
  flags: number;
  entryPointTokenOrRva: number;
  resources: { virtualAddress: number; size: number };
  strongNameSignature: { virtualAddress: number; size: number };
  codeManagerTable: { virtualAddress: number; size: number };
  vtableFixups: { virtualAddress: number; size: number };
  exportAddressTableJumps: { virtualAddress: number; size: number };
  managedNativeHeader: { virtualAddress: number; size: number };
}

export interface StreamHeader {
  offset: number;
  size: number;
  name: string;
}

export interface MetadataRoot {
  signature: number; // 0x424A5342 (BSJB)
  majorVersion: number;
  minorVersion: number;
  reserved: number;
  versionString: string;
  flags: number;
  streams: StreamHeader[];
}

export interface TablesHeader {
  reserved: number;
  majorVersion: number;
  minorVersion: number;
  heapSizes: number;
  reserved2: number;
  valid: bigint;
  sorted: bigint;
  rows: Record<number, number>;
}

export interface ParsedDotNetMetadata {
  cliHeader: CliHeader | null;
  metadataRoot: MetadataRoot;
  tablesHeader: TablesHeader | null;
  tables: Record<string, unknown[]>;
  heaps: {
    strings: string[];
    userStrings: string[];
    blobs: Uint8Array[];
    guids: string[];
  };
}

export function readCompressedUint32(
  view: DataView,
  offset: number
): { value: number; bytesRead: number } {
  if (offset >= view.byteLength) {
    return { value: 0, bytesRead: 0 };
  }
  const b1 = view.getUint8(offset);
  if ((b1 & 0x80) === 0) {
    return { value: b1, bytesRead: 1 };
  } else if ((b1 & 0xc0) === 0x80) {
    if (offset + 1 >= view.byteLength)
      return { value: b1 & 0x3f, bytesRead: 1 };
    const b2 = view.getUint8(offset + 1);
    return { value: ((b1 & 0x3f) << 8) | b2, bytesRead: 2 };
  } else {
    if (offset + 3 >= view.byteLength) return { value: 0, bytesRead: 0 };
    const b2 = view.getUint8(offset + 1);
    const b3 = view.getUint8(offset + 2);
    const b4 = view.getUint8(offset + 3);
    return {
      value: ((b1 & 0x1f) << 24) | (b2 << 16) | (b3 << 8) | b4,
      bytesRead: 4,
    };
  }
}

const CODED_INDEX_SCHEMAS: Record<
  string,
  { tagBits: number; tables: number[] }
> = {
  TypeDefOrRef: {
    tagBits: 2,
    tables: [0x02, 0x01, 0x1c], // TypeDef, TypeRef, TypeSpec
  },
  HasConstant: {
    tagBits: 2,
    tables: [0x04, 0x08, 0x18], // Field, Param, Property
  },
  HasCustomAttribute: {
    tagBits: 5,
    tables: [
      0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x11, 0x1a, 0x12, 0x1b,
      0x1c, 0x1f, 0x23, 0x25, 0x26, 0x27, 0x2a, 0x2c, 0x2b,
    ],
  },
  HasFieldMarshal: {
    tagBits: 1,
    tables: [0x04, 0x08],
  },
  HasDeclSecurity: {
    tagBits: 2,
    tables: [0x02, 0x06, 0x1f],
  },
  MemberRefParent: {
    tagBits: 3,
    tables: [0x02, 0x01, 0x1b, 0x06, 0x1c],
  },
  HasSemantics: {
    tagBits: 1,
    tables: [0x16, 0x18],
  },
  MethodDefOrRef: {
    tagBits: 1,
    tables: [0x06, 0x0a],
  },
  MemberForwarded: {
    tagBits: 1,
    tables: [0x04, 0x06],
  },
  Implementation: {
    tagBits: 2,
    tables: [0x25, 0x23, 0x26],
  },
  CustomAttributeType: {
    tagBits: 3,
    tables: [0, 0, 0x06, 0x0a, 0],
  },
  ResolutionScope: {
    tagBits: 2,
    tables: [0x00, 0x1b, 0x23, 0x01],
  },
  TypeOrMethodDef: {
    tagBits: 1,
    tables: [0x02, 0x06],
  },
};

interface ColumnSchema {
  name: string;
  type:
    | 'u8'
    | 'u16'
    | 'u32'
    | 'string'
    | 'guid'
    | 'blob'
    | { table: number }
    | { coded: string };
}

const TABLE_SCHEMAS: Record<number, { name: string; columns: ColumnSchema[] }> =
  {
    0x00: {
      name: 'Module',
      columns: [
        { name: 'Generation', type: 'u16' },
        { name: 'Name', type: 'string' },
        { name: 'Mvid', type: 'guid' },
        { name: 'EncId', type: 'guid' },
        { name: 'EncBaseId', type: 'guid' },
      ],
    },
    0x01: {
      name: 'TypeRef',
      columns: [
        { name: 'ResolutionScope', type: { coded: 'ResolutionScope' } },
        { name: 'TypeName', type: 'string' },
        { name: 'TypeNamespace', type: 'string' },
      ],
    },
    0x02: {
      name: 'TypeDef',
      columns: [
        { name: 'Flags', type: 'u32' },
        { name: 'TypeName', type: 'string' },
        { name: 'TypeNamespace', type: 'string' },
        { name: 'Extends', type: { coded: 'TypeDefOrRef' } },
        { name: 'FieldList', type: { table: 0x04 } },
        { name: 'MethodList', type: { table: 0x06 } },
      ],
    },
    0x04: {
      name: 'Field',
      columns: [
        { name: 'Flags', type: 'u16' },
        { name: 'Name', type: 'string' },
        { name: 'Signature', type: 'blob' },
      ],
    },
    0x06: {
      name: 'MethodDef',
      columns: [
        { name: 'RVA', type: 'u32' },
        { name: 'ImplFlags', type: 'u16' },
        { name: 'Flags', type: 'u16' },
        { name: 'Name', type: 'string' },
        { name: 'Signature', type: 'blob' },
        { name: 'ParamList', type: { table: 0x08 } },
      ],
    },
    0x08: {
      name: 'Param',
      columns: [
        { name: 'Flags', type: 'u16' },
        { name: 'Sequence', type: 'u16' },
        { name: 'Name', type: 'string' },
      ],
    },
    0x09: {
      name: 'InterfaceImpl',
      columns: [
        { name: 'Class', type: { table: 0x02 } },
        { name: 'Interface', type: { coded: 'TypeDefOrRef' } },
      ],
    },
    0x0a: {
      name: 'MemberRef',
      columns: [
        { name: 'Class', type: { coded: 'MemberRefParent' } },
        { name: 'Name', type: 'string' },
        { name: 'Signature', type: 'blob' },
      ],
    },
    0x0c: {
      name: 'Constant',
      columns: [
        { name: 'Type', type: 'u8' },
        { name: 'Padding', type: 'u8' },
        { name: 'Parent', type: { coded: 'HasConstant' } },
        { name: 'Value', type: 'blob' },
      ],
    },
    0x0e: {
      name: 'CustomAttribute',
      columns: [
        { name: 'Parent', type: { coded: 'HasCustomAttribute' } },
        { name: 'Type', type: { coded: 'CustomAttributeType' } },
        { name: 'Value', type: 'blob' },
      ],
    },
    0x11: {
      name: 'FieldLayout',
      columns: [
        { name: 'Offset', type: 'u32' },
        { name: 'Field', type: { table: 0x04 } },
      ],
    },
    0x12: {
      name: 'StandAloneSig',
      columns: [{ name: 'Signature', type: 'blob' }],
    },
    0x14: {
      name: 'EventMap',
      columns: [
        { name: 'Parent', type: { table: 0x02 } },
        { name: 'EventList', type: { table: 0x16 } },
      ],
    },
    0x16: {
      name: 'Event',
      columns: [
        { name: 'EventFlags', type: 'u16' },
        { name: 'Name', type: 'string' },
        { name: 'EventType', type: { coded: 'TypeDefOrRef' } },
      ],
    },
    0x17: {
      name: 'PropertyMap',
      columns: [
        { name: 'Parent', type: { table: 0x02 } },
        { name: 'PropertyList', type: { table: 0x18 } },
      ],
    },
    0x18: {
      name: 'Property',
      columns: [
        { name: 'Flags', type: 'u16' },
        { name: 'Name', type: 'string' },
        { name: 'Type', type: 'blob' },
      ],
    },
    0x19: {
      name: 'MethodSemantics',
      columns: [
        { name: 'Semantics', type: 'u16' },
        { name: 'Method', type: { table: 0x06 } },
        { name: 'Association', type: { coded: 'HasSemantics' } },
      ],
    },
    0x1a: {
      name: 'MethodImpl',
      columns: [
        { name: 'Class', type: { table: 0x02 } },
        { name: 'MethodBody', type: { coded: 'MethodDefOrRef' } },
        { name: 'MethodDeclaration', type: { coded: 'MethodDefOrRef' } },
      ],
    },
    0x1b: {
      name: 'ModuleRef',
      columns: [{ name: 'Name', type: 'string' }],
    },
    0x1c: {
      name: 'TypeSpec',
      columns: [{ name: 'Signature', type: 'blob' }],
    },
    0x1f: {
      name: 'Assembly',
      columns: [
        { name: 'HashAlgId', type: 'u32' },
        { name: 'MajorVersion', type: 'u16' },
        { name: 'MinorVersion', type: 'u16' },
        { name: 'BuildNumber', type: 'u16' },
        { name: 'RevisionNumber', type: 'u16' },
        { name: 'Flags', type: 'u32' },
        { name: 'PublicKey', type: 'blob' },
        { name: 'Name', type: 'string' },
        { name: 'Culture', type: 'string' },
      ],
    },
    0x23: {
      name: 'AssemblyRef',
      columns: [
        { name: 'MajorVersion', type: 'u16' },
        { name: 'MinorVersion', type: 'u16' },
        { name: 'BuildNumber', type: 'u16' },
        { name: 'RevisionNumber', type: 'u16' },
        { name: 'Flags', type: 'u32' },
        { name: 'PublicKeyOrToken', type: 'blob' },
        { name: 'Name', type: 'string' },
        { name: 'Culture', type: 'string' },
        { name: 'HashValue', type: 'blob' },
      ],
    },
    0x29: {
      name: 'NestedClass',
      columns: [
        { name: 'NestedClass', type: { table: 0x02 } },
        { name: 'EnclosingClass', type: { table: 0x02 } },
      ],
    },
    0x2a: {
      name: 'GenericParam',
      columns: [
        { name: 'Number', type: 'u16' },
        { name: 'Flags', type: 'u16' },
        { name: 'Owner', type: { coded: 'TypeOrMethodDef' } },
        { name: 'Name', type: 'string' },
      ],
    },
    0x2b: {
      name: 'MethodSpec',
      columns: [
        { name: 'Method', type: { coded: 'MethodDefOrRef' } },
        { name: 'Instantiation', type: 'blob' },
      ],
    },
  };

export class DotNetMetadataParser {
  private view: DataView;
  private buffer: ArrayBuffer;

  constructor(buffer: ArrayBuffer) {
    this.buffer = buffer;
    this.view = new DataView(buffer);
  }

  public parse(): ParsedDotNetMetadata {
    let cliHeader: CliHeader | null = null;
    let metadataRootOffset: number;

    // Detect if we are parsing raw BSJB metadata root or a full PE file
    if (
      this.view.byteLength >= 4 &&
      this.view.getUint32(0, true) === 0x424a5342
    ) {
      metadataRootOffset = 0;
    } else {
      // Treat as PE
      const peParser = new PEParser(this.buffer);
      const parsedPe = peParser.parse();

      // Find CLI Data Directory (Index 14)
      const dataDirs = parsedPe.optionalHeader.dataDirectories;
      if (dataDirs.length <= 14 || dataDirs[14].virtualAddress === 0) {
        throw new Error('No CLI Header found in the PE binary');
      }

      const cliHeaderRva = dataDirs[14].virtualAddress;
      const cliHeaderOffset = this.rvaToOffset(cliHeaderRva, parsedPe.sections);
      if (
        cliHeaderOffset === 0 ||
        cliHeaderOffset + 72 > this.view.byteLength
      ) {
        throw new Error('CLI Header RVA points outside the file bounds');
      }

      cliHeader = {
        cb: this.view.getUint32(cliHeaderOffset, true),
        majorRuntimeVersion: this.view.getUint16(cliHeaderOffset + 4, true),
        minorRuntimeVersion: this.view.getUint16(cliHeaderOffset + 6, true),
        metaData: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 8, true),
          size: this.view.getUint32(cliHeaderOffset + 12, true),
        },
        flags: this.view.getUint32(cliHeaderOffset + 16, true),
        entryPointTokenOrRva: this.view.getUint32(cliHeaderOffset + 20, true),
        resources: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 24, true),
          size: this.view.getUint32(cliHeaderOffset + 28, true),
        },
        strongNameSignature: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 32, true),
          size: this.view.getUint32(cliHeaderOffset + 36, true),
        },
        codeManagerTable: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 40, true),
          size: this.view.getUint32(cliHeaderOffset + 44, true),
        },
        vtableFixups: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 48, true),
          size: this.view.getUint32(cliHeaderOffset + 52, true),
        },
        exportAddressTableJumps: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 56, true),
          size: this.view.getUint32(cliHeaderOffset + 60, true),
        },
        managedNativeHeader: {
          virtualAddress: this.view.getUint32(cliHeaderOffset + 64, true),
          size: this.view.getUint32(cliHeaderOffset + 68, true),
        },
      };

      metadataRootOffset = this.rvaToOffset(
        cliHeader.metaData.virtualAddress,
        parsedPe.sections
      );
      if (metadataRootOffset === 0) {
        throw new Error('Metadata Root RVA points outside the file bounds');
      }
    }

    // Parse Metadata Root
    if (metadataRootOffset + 16 > this.view.byteLength) {
      throw new Error('Metadata Root header points outside the file bounds');
    }

    const signature = this.view.getUint32(metadataRootOffset, true);
    if (signature !== 0x424a5342) {
      throw new Error(
        `Invalid Metadata Root signature: 0x${signature.toString(16)} (expected BSJB)`
      );
    }

    const majorVersion = this.view.getUint16(metadataRootOffset + 4, true);
    const minorVersion = this.view.getUint16(metadataRootOffset + 6, true);
    const reserved = this.view.getUint32(metadataRootOffset + 8, true);
    const versionLength = this.view.getUint32(metadataRootOffset + 12, true);

    if (metadataRootOffset + 16 + versionLength > this.view.byteLength) {
      throw new Error('Metadata version string points outside the file bounds');
    }

    const versionBytes = new Uint8Array(
      this.buffer,
      metadataRootOffset + 16,
      versionLength
    );
    // Find the first null character to truncate the version string
    let versionStrLength = 0;
    while (
      versionStrLength < versionLength &&
      versionBytes[versionStrLength] !== 0
    ) {
      versionStrLength++;
    }
    const versionString = new TextDecoder('utf-8').decode(
      versionBytes.subarray(0, versionStrLength)
    );

    let streamOffset = metadataRootOffset + 16 + versionLength;
    // Align version offset if necessary
    // streamOffset is relative to start, already aligned because versionLength is padded to multiple of 4

    const flags = this.view.getUint16(streamOffset, true);
    const numberOfStreams = this.view.getUint16(streamOffset + 2, true);
    streamOffset += 4;

    const streams: StreamHeader[] = [];
    for (let i = 0; i < numberOfStreams; i++) {
      if (streamOffset + 8 > this.view.byteLength) {
        throw new Error('Stream Header points outside the file bounds');
      }
      const offset = this.view.getUint32(streamOffset, true);
      const size = this.view.getUint32(streamOffset + 4, true);
      streamOffset += 8;

      // Read null-terminated string padded to 4-byte alignment
      let name = '';
      while (streamOffset < this.view.byteLength) {
        const char = this.view.getUint8(streamOffset++);
        if (char === 0) {
          break;
        }
        name += String.fromCharCode(char);
      }
      // Skip padding to 4-byte boundary
      const nameLength = name.length + 1; // including null terminator
      const paddedLength = (nameLength + 3) & ~3;
      streamOffset += paddedLength - nameLength;

      streams.push({ offset, size, name });
    }

    // Locate Heaps and Tables Streams
    let tablesStream: { offset: number; size: number } | null = null;
    let stringsStream: { offset: number; size: number } | null = null;
    let usStream: { offset: number; size: number } | null = null;
    let guidStream: { offset: number; size: number } | null = null;
    let blobStream: { offset: number; size: number } | null = null;

    for (const s of streams) {
      if (s.name === '#~' || s.name === '#-') {
        tablesStream = s;
      } else if (s.name === '#Strings') {
        stringsStream = s;
      } else if (s.name === '#US') {
        usStream = s;
      } else if (s.name === '#GUID') {
        guidStream = s;
      } else if (s.name === '#Blob') {
        blobStream = s;
      }
    }

    // Extract Heaps
    const decodedStrings: string[] = [];
    if (stringsStream) {
      const start = metadataRootOffset + stringsStream.offset;
      const end = start + stringsStream.size;
      let curr = start;
      while (curr < end) {
        let str = '';
        while (curr < end) {
          const char = this.view.getUint8(curr++);
          if (char === 0) break;
          str += String.fromCharCode(char);
        }
        decodedStrings.push(str);
      }
    }

    const decodedUserStrings: string[] = [];
    if (usStream) {
      const start = metadataRootOffset + usStream.offset;
      const end = start + usStream.size;
      let curr = start;
      // Skip the 0-byte at start of US heap if it exists
      if (curr < end && this.view.getUint8(curr) === 0) {
        curr++;
      }
      while (curr < end) {
        const { value: len, bytesRead } = readCompressedUint32(this.view, curr);
        curr += bytesRead;
        if (len === 0 || curr + len > end) {
          continue;
        }
        // US heap contains UTF-16LE, and the last byte is a signature byte indicating whether any chars > 0x7F
        const strBytes = new Uint16Array(this.buffer, curr, (len - 1) >> 1);
        let str = '';
        for (let j = 0; j < strBytes.length; j++) {
          str += String.fromCharCode(strBytes[j]);
        }
        decodedUserStrings.push(str);
        curr += len;
      }
    }

    const decodedBlobs: Uint8Array[] = [];
    if (blobStream) {
      const start = metadataRootOffset + blobStream.offset;
      const end = start + blobStream.size;
      let curr = start;
      if (curr < end && this.view.getUint8(curr) === 0) {
        curr++;
      }
      while (curr < end) {
        const { value: len, bytesRead } = readCompressedUint32(this.view, curr);
        curr += bytesRead;
        if (len === 0 || curr + len > end) {
          continue;
        }
        decodedBlobs.push(new Uint8Array(this.buffer, curr, len));
        curr += len;
      }
    }

    const decodedGuids: string[] = [];
    if (guidStream) {
      const start = metadataRootOffset + guidStream.offset;
      const end = start + guidStream.size;
      let curr = start;
      while (curr + 16 <= end) {
        // Format as standard GUID: 8-4-4-4-12
        const p1 = this.view
          .getUint32(curr, true)
          .toString(16)
          .padStart(8, '0');
        const p2 = this.view
          .getUint16(curr + 4, true)
          .toString(16)
          .padStart(4, '0');
        const p3 = this.view
          .getUint16(curr + 6, true)
          .toString(16)
          .padStart(4, '0');
        const p4_1 = this.view
          .getUint8(curr + 8)
          .toString(16)
          .padStart(2, '0');
        const p4_2 = this.view
          .getUint8(curr + 9)
          .toString(16)
          .padStart(2, '0');
        let p5 = '';
        for (let j = 10; j < 16; j++) {
          p5 += this.view
            .getUint8(curr + j)
            .toString(16)
            .padStart(2, '0');
        }
        decodedGuids.push(`${p1}-${p2}-${p3}-${p4_1}${p4_2}-${p5}`);
        curr += 16;
      }
    }

    // Parse Tables
    let tablesHeader: TablesHeader | null = null;
    const parsedTables: Record<string, unknown[]> = {};

    if (tablesStream) {
      const start = metadataRootOffset + tablesStream.offset;
      if (start + 24 <= this.view.byteLength) {
        const reservedTables = this.view.getUint32(start, true);
        const majorVersionTables = this.view.getUint8(start + 4);
        const minorVersionTables = this.view.getUint8(start + 5);
        const heapSizes = this.view.getUint8(start + 6);
        const reserved2 = this.view.getUint8(start + 7);
        const valid = this.view.getBigUint64(start + 8, true);
        const sorted = this.view.getBigUint64(start + 16, true);

        let tableHeaderOffset = start + 24;
        const rows: Record<number, number> = {};

        // Read row counts for each present table
        for (let i = 0; i < 64; i++) {
          if ((valid & (1n << BigInt(i))) !== 0n) {
            rows[i] = this.view.getUint32(tableHeaderOffset, true);
            tableHeaderOffset += 4;
          }
        }

        tablesHeader = {
          reserved: reservedTables,
          majorVersion: majorVersionTables,
          minorVersion: minorVersionTables,
          heapSizes,
          reserved2,
          valid,
          sorted,
          rows,
        };

        // Parse individual tables sequentially
        let currOffset = tableHeaderOffset;

        // Pre-calculate index sizes
        const stringIndexSize = heapSizes & 0x01 ? 4 : 2;
        const guidIndexSize = heapSizes & 0x02 ? 4 : 2;
        const blobIndexSize = heapSizes & 0x04 ? 4 : 2;

        const getTableIndexSize = (tableId: number): number => {
          const count = rows[tableId] || 0;
          return count >= 65536 ? 4 : 2;
        };

        const getCodedIndexSize = (codedName: string): number => {
          const schema = CODED_INDEX_SCHEMAS[codedName];
          if (!schema) return 2;
          let maxRows = 0;
          for (const tbl of schema.tables) {
            const count = rows[tbl] || 0;
            if (count > maxRows) maxRows = count;
          }
          return maxRows >= 1 << (16 - schema.tagBits) ? 4 : 2;
        };

        const readValue = (offset: number, size: number): number => {
          if (size === 1) return this.view.getUint8(offset);
          if (size === 2) return this.view.getUint16(offset, true);
          if (size === 4) return this.view.getUint32(offset, true);
          return 0;
        };

        // For each table in order
        for (let tableId = 0; tableId < 64; tableId++) {
          if ((valid & (1n << BigInt(tableId))) === 0n) {
            continue;
          }
          const rowCount = rows[tableId] || 0;
          const schema = TABLE_SCHEMAS[tableId];

          if (!schema) {
            // Unhandled table. Let's calculate its row size to skip it, or throw.
            // Since we want to be robust, we'll try to guess row size or parse what we know.
            // If we don't have schema, we skip. But for ECMA standard, we support almost all!
            continue;
          }

          const rowsList: Record<string, unknown>[] = [];
          for (let r = 0; r < rowCount; r++) {
            const rowData: Record<string, unknown> = { _rowIndex: r + 1 };
            for (const col of schema.columns) {
              let colSize = 0;
              let resolvedVal: unknown = null;

              if (col.type === 'u8') {
                colSize = 1;
                resolvedVal = readValue(currOffset, 1);
              } else if (col.type === 'u16') {
                colSize = 2;
                resolvedVal = readValue(currOffset, 2);
              } else if (col.type === 'u32') {
                colSize = 4;
                resolvedVal = readValue(currOffset, 4);
              } else if (col.type === 'string') {
                colSize = stringIndexSize;
                const index = readValue(currOffset, stringIndexSize);
                resolvedVal = this.getString(
                  index,
                  metadataRootOffset + (stringsStream?.offset || 0),
                  stringsStream?.size || 0
                );
              } else if (col.type === 'guid') {
                colSize = guidIndexSize;
                const index = readValue(currOffset, guidIndexSize);
                resolvedVal = this.getGuid(index, decodedGuids);
              } else if (col.type === 'blob') {
                colSize = blobIndexSize;
                const index = readValue(currOffset, blobIndexSize);
                resolvedVal = this.getBlob(
                  index,
                  metadataRootOffset + (blobStream?.offset || 0),
                  blobStream?.size || 0
                );
              } else if (typeof col.type === 'object' && 'table' in col.type) {
                colSize = getTableIndexSize(col.type.table);
                resolvedVal = readValue(currOffset, colSize);
              } else if (typeof col.type === 'object' && 'coded' in col.type) {
                colSize = getCodedIndexSize(col.type.coded);
                const rawVal = readValue(currOffset, colSize);
                resolvedVal = this.decodeCodedIndex(rawVal, col.type.coded);
              }

              rowData[col.name] = resolvedVal;
              currOffset += colSize;
            }
            rowsList.push(rowData);
          }
          parsedTables[schema.name] = rowsList;
        }
      }
    }

    return {
      cliHeader,
      metadataRoot: {
        signature,
        majorVersion,
        minorVersion,
        reserved,
        versionString,
        flags,
        streams,
      },
      tablesHeader,
      tables: parsedTables,
      heaps: {
        strings: decodedStrings,
        userStrings: decodedUserStrings,
        blobs: decodedBlobs,
        guids: decodedGuids,
      },
    };
  }

  private rvaToOffset(rva: number, sections: SectionHeader[]): number {
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
  }

  private getString(
    index: number,
    streamOffset: number,
    streamSize: number
  ): string {
    if (index === 0 || index >= streamSize) {
      return '';
    }
    let offset = streamOffset + index;
    let str = '';
    while (offset < this.view.byteLength) {
      const char = this.view.getUint8(offset++);
      if (char === 0) break;
      str += String.fromCharCode(char);
    }
    return str;
  }

  private getGuid(index: number, guids: string[]): string {
    if (index === 0 || index - 1 >= guids.length) {
      return '';
    }
    return guids[index - 1];
  }

  private getBlob(
    index: number,
    streamOffset: number,
    streamSize: number
  ): Uint8Array {
    if (index === 0 || index >= streamSize) {
      return new Uint8Array(0);
    }
    const offset = streamOffset + index;
    const { value: len, bytesRead } = readCompressedUint32(this.view, offset);
    if (len === 0 || offset + bytesRead + len > this.view.byteLength) {
      return new Uint8Array(0);
    }
    return new Uint8Array(this.buffer, offset + bytesRead, len);
  }

  private decodeCodedIndex(
    value: number,
    codedName: string
  ): { tableName: string; rowIndex: number } | null {
    const schema = CODED_INDEX_SCHEMAS[codedName];
    if (!schema) return null;

    const mask = (1 << schema.tagBits) - 1;
    const tag = value & mask;
    const rowIndex = value >> schema.tagBits;

    if (rowIndex === 0) {
      return null;
    }

    const tableId = schema.tables[tag];
    const tableSchema = TABLE_SCHEMAS[tableId];

    return {
      tableName: tableSchema
        ? tableSchema.name
        : `Table_0x${tableId.toString(16)}`,
      rowIndex,
    };
  }
}
