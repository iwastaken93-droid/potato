import { describe, it, expect } from 'vitest';
import { DotNetMetadataParser, readCompressedUint32 } from '../src/parser/dotnetMetadata.js';

describe('.NET Metadata Parser Unit Tests', () => {
  it('should parse compressed uint32 correctly', () => {
    // 1-byte encoding: values 0 to 127
    const buffer1 = new Uint8Array([0x3F]);
    const view1 = new DataView(buffer1.buffer);
    expect(readCompressedUint32(view1, 0)).toEqual({ value: 0x3F, bytesRead: 1 });

    // 2-byte encoding: values 128 to 16383
    const buffer2 = new Uint8Array([0x80 | 0x1F, 0x90]);
    const view2 = new DataView(buffer2.buffer);
    expect(readCompressedUint32(view2, 0)).toEqual({ value: (0x1F << 8) | 0x90, bytesRead: 2 });

    // 4-byte encoding
    const buffer3 = new Uint8Array([0xC0 | 0x0A, 0x1B, 0x2C, 0x3D]);
    const view3 = new DataView(buffer3.buffer);
    expect(readCompressedUint32(view3, 0)).toEqual({ value: (0x0A << 24) | (0x1B << 16) | (0x2C << 8) | 0x3D, bytesRead: 4 });
  });

  it('should parse a raw metadata root with signature and streams', () => {
    // Construct a mock Metadata Root buffer starting with BSJB
    // Header size = 4 (sig) + 2 (maj) + 2 (min) + 4 (res) + 4 (len) = 16 bytes
    // version = "v4.0.30319\0\0" (12 bytes)
    // flags = 0 (2 bytes)
    // numStreams = 2 (2 bytes)
    // Streams:
    // Stream 1: Offset=100, Size=50, Name="#Strings\0\0\0\0" (padded to 12)
    // Stream 2: Offset=200, Size=20, Name="#Blob\0\0\0" (padded to 8)
    const buffer = new ArrayBuffer(256);
    const view = new DataView(buffer);

    // 1. Signature 'BSJB'
    view.setUint32(0, 0x424A5342, true);
    // 2. Version
    view.setUint16(4, 1, true);
    view.setUint16(6, 1, true);
    view.setUint32(8, 0, true);
    view.setUint32(12, 12, true); // Version string length

    const versionStr = 'v4.0.30319';
    for (let i = 0; i < versionStr.length; i++) {
      view.setUint8(16 + i, versionStr.charCodeAt(i));
    }
    // padding bytes already 0

    // Offset of next fields: 16 + 12 = 28
    view.setUint16(28, 0, true); // flags
    view.setUint16(30, 2, true); // numberOfStreams = 2

    // Stream 1 Header: offset=32
    view.setUint32(32, 100, true); // offset
    view.setUint32(36, 50, true);  // size
    // Name: "#Strings" (8 chars) + null terminator = 9. Padded to 12.
    const name1 = '#Strings';
    for (let i = 0; i < name1.length; i++) {
      view.setUint8(40 + i, name1.charCodeAt(i));
    }

    // Stream 2 Header: offset=40+12 = 52
    view.setUint32(52, 200, true); // offset
    view.setUint32(56, 20, true);  // size
    // Name: "#Blob" (5 chars) + null terminator = 6. Padded to 8.
    const name2 = '#Blob';
    for (let i = 0; i < name2.length; i++) {
      view.setUint8(60 + i, name2.charCodeAt(i));
    }

    // Add mock heap data inside buffer
    // #Strings heap at metadataRootOffset + 100
    // We put: "\0Hello\0World\0"
    const stringsOffset = 100;
    view.setUint8(stringsOffset, 0);
    const s1 = 'Hello';
    for (let i = 0; i < s1.length; i++) {
      view.setUint8(stringsOffset + 1 + i, s1.charCodeAt(i));
    }
    view.setUint8(stringsOffset + 1 + s1.length, 0);

    const s2 = 'World';
    for (let i = 0; i < s2.length; i++) {
      view.setUint8(stringsOffset + 1 + s1.length + 1 + i, s2.charCodeAt(i));
    }
    view.setUint8(stringsOffset + 1 + s1.length + 1 + s2.length, 0);

    const parser = new DotNetMetadataParser(buffer);
    const parsed = parser.parse();

    expect(parsed.cliHeader).toBeNull();
    expect(parsed.metadataRoot.signature).toBe(0x424A5342);
    expect(parsed.metadataRoot.versionString).toBe('v4.0.30319');
    expect(parsed.metadataRoot.streams.length).toBe(2);
    expect(parsed.metadataRoot.streams[0].name).toBe('#Strings');
    expect(parsed.metadataRoot.streams[0].size).toBe(50);
    expect(parsed.metadataRoot.streams[1].name).toBe('#Blob');
    expect(parsed.metadataRoot.streams[1].offset).toBe(200);

    expect(parsed.heaps.strings).toContain('Hello');
    expect(parsed.heaps.strings).toContain('World');
  });

  it('should parse metadata tables correctly from #~ stream', () => {
    // Table Header size = 4 (reserved) + 1 (major) + 1 (minor) + 1 (heapSizes) + 1 (reserved2)
    //                     + 8 (valid) + 8 (sorted) = 24 bytes
    // Plus 4 bytes for each present table's row count.
    const buffer = new ArrayBuffer(512);
    const view = new DataView(buffer);

    // Metadata Root Header
    view.setUint32(0, 0x424A5342, true);
    view.setUint32(12, 12, true); // version string length
    view.setUint16(28, 0, true);  // flags
    view.setUint16(30, 2, true);  // 2 streams: #Strings and #~

    // Stream headers
    // Stream 1: #Strings
    view.setUint32(32, 120, true); // offset
    view.setUint32(36, 40, true);  // size
    const strName = '#Strings';
    for (let i = 0; i < strName.length; i++) view.setUint8(40 + i, strName.charCodeAt(i));

    // Stream 2: #~ at offset 200
    view.setUint32(52, 200, true); // offset
    view.setUint32(56, 100, true); // size
    const tablesName = '#~';
    for (let i = 0; i < tablesName.length; i++) view.setUint8(60 + i, tablesName.charCodeAt(i));

    // Write some strings to #Strings heap at 120
    const stringsBase = 120;
    // index 0 is empty
    // index 1: "MyClass"
    const classStr = 'MyClass';
    for (let i = 0; i < classStr.length; i++) view.setUint8(stringsBase + 1 + i, classStr.charCodeAt(i));
    view.setUint8(stringsBase + 1 + classStr.length, 0);

    // Table stream at 200
    const tblBase = 200;
    view.setUint32(tblBase, 0, true); // reserved
    view.setUint8(tblBase + 4, 2);    // major version
    view.setUint8(tblBase + 5, 0);    // minor version
    view.setUint8(tblBase + 6, 0);    // heapSizes (all 2-byte indexes)
    view.setUint8(tblBase + 7, 0);    // reserved2

    // Set bit 0 (Module: 0x00) and bit 2 (TypeDef: 0x02) in valid mask
    const validMask = (1n << 0n) | (1n << 2n);
    view.setBigUint64(tblBase + 8, validMask, true);
    view.setBigUint64(tblBase + 16, 0n, true); // sorted

    // Row counts (each 4 bytes)
    view.setUint32(tblBase + 24, 1, true); // 1 row for Module (0x00)
    view.setUint32(tblBase + 28, 1, true); // 1 row for TypeDef (0x02)

    // Table rows start at tblBase + 32
    let rowOffset = tblBase + 32;

    // Module row: Generation (u16), Name (String), Mvid (Guid), EncId (Guid), EncBaseId (Guid)
    // Sizes: 2 + 2 + 2 + 2 + 2 = 10 bytes
    view.setUint16(rowOffset, 1, true);     // Generation
    view.setUint16(rowOffset + 2, 0, true); // Name index (null)
    view.setUint16(rowOffset + 4, 0, true); // Mvid
    view.setUint16(rowOffset + 6, 0, true); // EncId
    view.setUint16(rowOffset + 8, 0, true); // EncBaseId
    rowOffset += 10;

    // TypeDef row: Flags (u32), TypeName (String), TypeNamespace (String), Extends (TypeDefOrRef coded index),
    //              FieldList (Field table index), MethodList (MethodDef table index)
    // Sizes: 4 + 2 + 2 + 2 + 2 + 2 = 14 bytes
    view.setUint32(rowOffset, 0x00100000, true); // Flags (Public)
    view.setUint16(rowOffset + 4, 1, true);      // TypeName index (points to "MyClass" at offset 1)
    view.setUint16(rowOffset + 6, 0, true);      // TypeNamespace (null)
    view.setUint16(rowOffset + 8, 0, true);      // Extends coded index (0)
    view.setUint16(rowOffset + 10, 1, true);     // FieldList (1)
    view.setUint16(rowOffset + 12, 1, true);     // MethodList (1)

    const parser = new DotNetMetadataParser(buffer);
    const parsed = parser.parse();

    expect(parsed.tablesHeader).toBeDefined();
    expect(parsed.tablesHeader?.valid).toBe(validMask);
    expect(parsed.tablesHeader?.rows[2]).toBe(1);

    expect(parsed.tables.TypeDef).toBeDefined();
    expect(parsed.tables.TypeDef.length).toBe(1);
    expect(parsed.tables.TypeDef[0].TypeName).toBe('MyClass');
    expect(parsed.tables.TypeDef[0].Flags).toBe(0x00100000);
    expect(parsed.tables.TypeDef[0].Extends).toBeNull();
  });
});
