import { describe, it, expect } from 'vitest';
import { PEParser } from '../src/parser/pe.js';

describe('PE Resource Section Parser Unit Tests', () => {
  it('should parse manifests, strings, and icons from a mock PE binary', () => {
    // We construct a mock PE buffer with:
    // DOS header (64) + PE signature (4) + COFF header (20) + Optional header (240) + 1 Section (40) = 368 bytes headers
    // Let's place the resource section at file offset 512, virtualAddress 0x2000.
    // Total size of buffer = 1024 bytes.
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. DOS Header
    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);

    // 2. PE Signature
    view.setUint32(e_lfanew, 0x00004550, true);

    // 3. COFF File Header
    const coffOffset = e_lfanew + 4; // 68
    view.setUint16(coffOffset, 0x8664, true); // AMD64
    view.setUint16(coffOffset + 2, 1, true); // 1 Section
    view.setUint32(coffOffset + 4, 12345, true);
    const sizeOfOptionalHeader = 240;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);

    // 4. Optional Header (PE32+: Magic = 0x20b)
    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x20b, true);
    view.setUint32(optionalOffset + 16, 0x1000, true); // Entry point

    const winOffset = optionalOffset + 24; // 112
    view.setBigUint64(winOffset, 0x140000000n, true); // ImageBase
    // Stack and Heap (PE32+: 32 bytes starting at winOffset + 48)
    const stackHeapOffset = winOffset + 48; // 160
    view.setBigUint64(stackHeapOffset, 0x100000n, true);
    view.setBigUint64(stackHeapOffset + 8, 0x1000n, true);
    view.setBigUint64(stackHeapOffset + 16, 0x100000n, true);
    view.setBigUint64(stackHeapOffset + 24, 0x1000n, true);

    const afterStackHeapOffset = stackHeapOffset + 32; // 192
    view.setUint32(afterStackHeapOffset, 0, true);
    view.setUint32(afterStackHeapOffset + 4, 3, true); // NumberOfRvaAndSizes (3 directories)

    // Data Directories starting at afterStackHeapOffset + 8 (200)
    const dirOffset = afterStackHeapOffset + 8; // 200
    // Export (200) - empty
    view.setUint32(dirOffset, 0, true);
    view.setUint32(dirOffset + 4, 0, true);
    // Import (208) - empty
    view.setUint32(dirOffset + 8, 0, true);
    view.setUint32(dirOffset + 12, 0, true);
    // Resource (216)
    view.setUint32(dirOffset + 16, 0x2000, true); // Resource VirtualAddress
    view.setUint32(dirOffset + 20, 512, true); // Resource Size

    // 5. Section Header for ".rsrc" (offset = optionalOffset + 240 = 328)
    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 328
    // ".rsrc\0\0"
    bytes[sectionOffset] = 0x2e; bytes[sectionOffset + 1] = 0x72;
    bytes[sectionOffset + 2] = 0x73; bytes[sectionOffset + 3] = 0x72;
    bytes[sectionOffset + 4] = 0x63;
    view.setUint32(sectionOffset + 8, 0x1000, true); // VirtualSize
    view.setUint32(sectionOffset + 12, 0x2000, true); // VirtualAddress (matches directory)
    view.setUint32(sectionOffset + 16, 512, true); // SizeOfRawData
    view.setUint32(sectionOffset + 20, 512, true); // PointerToRawData (file offset 512)
    view.setUint32(sectionOffset + 36, 0x40000040, true); // INITIALIZED_DATA, READ

    // 6. Build the Resource Section at offset 512
    // We will build a tree:
    // Level 1 (Type): Type 24 (Manifest, ID 24)
    //   Level 2 (Name): Name 1 (ID 1)
    //     Level 3 (Language): Language 1033 (ID 1033)
    //       Data Entry -> points to RVA 0x2100 (file offset 512 + 256) containing manifest text.
    // AND
    // Level 1 (Type): Type 6 (String Table, ID 6)
    //   Level 2 (Name): Name 1 (ID 1)
    //     Level 3 (Language): Language 1033 (ID 1033)
    //       Data Entry -> points to RVA 0x2180 (file offset 512 + 384) containing string table bytes.
    // AND
    // Level 1 (Type): Type 3 (Icon, ID 3)
    //   Level 2 (Name): Name 1 (ID 1)
    //     Level 3 (Language): Language 1033 (ID 1033)
    //       Data Entry -> points to RVA 0x21A0 (file offset 512 + 416) containing icon data.

    const rsrcFileOffset = 512;

    // Root directory table (offset 0 relative to resource section)
    // Number of Named entries = 0, Number of Id entries = 3 (Type 3, Type 6, Type 24)
    view.setUint16(rsrcFileOffset + 12, 0, true);
    view.setUint16(rsrcFileOffset + 14, 3, true);

    // Entries start at offset 16
    // Entry 1: Type 3 (Icon). Subdirectory offset 48
    view.setUint32(rsrcFileOffset + 16, 3, true);
    view.setUint32(rsrcFileOffset + 20, 0x80000000 | 48, true);

    // Entry 2: Type 6 (String Table). Subdirectory offset 80
    view.setUint32(rsrcFileOffset + 24, 6, true);
    view.setUint32(rsrcFileOffset + 28, 0x80000000 | 80, true);

    // Entry 3: Type 24 (Manifest). Subdirectory offset 112
    view.setUint32(rsrcFileOffset + 32, 24, true);
    view.setUint32(rsrcFileOffset + 36, 0x80000000 | 112, true);

    // Subdirectory for Type 3 (offset 48)
    // ID entry for Name 1 -> Subdirectory offset 144
    view.setUint16(rsrcFileOffset + 48 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 48 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 48 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 48 + 20, 0x80000000 | 144, true);

    // Subdirectory for Type 6 (offset 80)
    // ID entry for Name 1 -> Subdirectory offset 176
    view.setUint16(rsrcFileOffset + 80 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 80 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 80 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 80 + 20, 0x80000000 | 176, true);

    // Subdirectory for Type 24 (offset 112)
    // ID entry for Name 1 -> Subdirectory offset 208
    view.setUint16(rsrcFileOffset + 112 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 112 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 112 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 112 + 20, 0x80000000 | 208, true);

    // Subdirectory for Type 3 Name 1 (offset 144)
    // Language 1033 -> Data Entry offset 240
    view.setUint16(rsrcFileOffset + 144 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 144 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 144 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 144 + 20, 240, true);

    // Subdirectory for Type 6 Name 1 (offset 176)
    // Language 1033 -> Data Entry offset 256
    view.setUint16(rsrcFileOffset + 176 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 176 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 176 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 176 + 20, 256, true);

    // Subdirectory for Type 24 Name 1 (offset 208)
    // Language 1033 -> Data Entry offset 272
    view.setUint16(rsrcFileOffset + 208 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 208 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 208 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 208 + 20, 272, true);

    // Data Entry for Type 3 (Icon) (offset 240)
    // RVA = 0x21C0 (file offset 512 + 448 = 960), Size = 10
    view.setUint32(rsrcFileOffset + 240, 0x21C0, true);
    view.setUint32(rsrcFileOffset + 240 + 4, 10, true);

    // Data Entry for Type 6 (String Table) (offset 256)
    // RVA = 0x2170 (file offset 512 + 368 = 880), Size = 48
    view.setUint32(rsrcFileOffset + 256, 0x2170, true);
    view.setUint32(rsrcFileOffset + 256 + 4, 48, true);

    // Data Entry for Type 24 (Manifest) (offset 272)
    // RVA = 0x2140 (file offset 512 + 320 = 832), Size = 32
    view.setUint32(rsrcFileOffset + 272, 0x2140, true);
    view.setUint32(rsrcFileOffset + 272 + 4, 32, true);

    // Raw manifest data at RVA 0x2140 (file offset 832)
    const manifestText = '<assembly>MockManifest</assembly>';
    for (let i = 0; i < manifestText.length; i++) {
      bytes[832 + i] = manifestText.charCodeAt(i);
    }

    // Raw string table data at RVA 0x2170 (file offset 880)
    // String Table Block contains 16 strings.
    // Let's set index 0 string: length = 4, value = "Test" (UTF-16LE)
    // Let's set index 1 string: length = 0 (empty)
    // Let's set index 2 string: length = 5, value = "Hello" (UTF-16LE)
    let sOffset = 880;
    // Index 0
    view.setUint16(sOffset, 4, true);
    sOffset += 2;
    const str1 = 'Test';
    for (let i = 0; i < str1.length; i++) {
      view.setUint16(sOffset + i * 2, str1.charCodeAt(i), true);
    }
    sOffset += 8;

    // Index 1
    view.setUint16(sOffset, 0, true);
    sOffset += 2;

    // Index 2
    view.setUint16(sOffset, 5, true);
    sOffset += 2;
    const str2 = 'Hello';
    for (let i = 0; i < str2.length; i++) {
      view.setUint16(sOffset + i * 2, str2.charCodeAt(i), true);
    }

    // Parse the file
    const parser = new PEParser(buffer);
    const parsed = parser.parse();

    // Verify resources
    expect(parsed.resources).toBeDefined();
    expect(parsed.resources?.manifests.length).toBe(1);
    expect(parsed.resources?.manifests[0]).toContain('MockManifest');

    expect(parsed.resources?.strings).toBeDefined();
    expect(parsed.resources?.strings[0]).toBe('Test');
    expect(parsed.resources?.strings[2]).toBe('Hello');

    expect(parsed.resources?.icons.length).toBe(1);
    expect(parsed.resources?.icons[0].type).toBe('Icon');
  });
});
