import { describe, it, expect } from 'vitest';
import {
  parseDex,
  readUleb128,
  readSleb128,
  decodeMutf8,
  parseAccessFlags,
} from '../src/parser/dex.js';

describe('DEX Parser Helpers', () => {
  it('should parse ULEB128 correctly', () => {
    const bytes = new Uint8Array([0x80, 0x7f, 0x01]);
    const ref1 = { offset: 0 };
    expect(readUleb128(bytes, ref1)).toBe(16256); // (0x00 & 0x7f) | ((0x7f & 0x7f) << 7)
    expect(ref1.offset).toBe(2);

    const ref2 = { offset: 2 };
    expect(readUleb128(bytes, ref2)).toBe(1);
    expect(ref2.offset).toBe(3);
  });

  it('should parse SLEB128 correctly', () => {
    // -1 in SLEB128 is 0x7f
    const bytes1 = new Uint8Array([0x7f]);
    const ref1 = { offset: 0 };
    expect(readSleb128(bytes1, ref1)).toBe(-1);

    // -128 in SLEB128 is 0x80, 0x7f
    const bytes2 = new Uint8Array([0x80, 0x7f]);
    const ref2 = { offset: 0 };
    expect(readSleb128(bytes2, ref2)).toBe(-128);

    // Positive number 128 is 0x80, 0x01
    const bytes3 = new Uint8Array([0x80, 0x01]);
    const ref3 = { offset: 0 };
    expect(readSleb128(bytes3, ref3)).toBe(128);
  });

  it('should decode MUTF-8 correctly', () => {
    // 1-byte ASCII
    expect(decodeMutf8(new Uint8Array([0x61, 0x62, 0x63]))).toBe('abc');

    // 2-byte UTF-8 / MUTF-8
    expect(decodeMutf8(new Uint8Array([0xc3, 0xa9]))).toBe('é');

    // Embedded Null (0xc0, 0x80)
    expect(decodeMutf8(new Uint8Array([0x61, 0xc0, 0x80, 0x62]))).toBe('a\0b');

    // 3-byte character
    expect(decodeMutf8(new Uint8Array([0xe2, 0x82, 0xac]))).toBe('€');
  });

  it('should parse access flags correctly', () => {
    expect(parseAccessFlags(0x0001 | 0x0008 | 0x0010)).toContain('public');
    expect(parseAccessFlags(0x0001 | 0x0008 | 0x0010)).toContain('static');
    expect(parseAccessFlags(0x0001 | 0x0008 | 0x0010)).toContain('final');
  });
});

describe('DEX Parser Core', () => {
  it('should fail with invalid magic', () => {
    const buffer = new ArrayBuffer(112);
    const bytes = new Uint8Array(buffer);
    bytes.set([0, 1, 2, 3]);
    expect(() => parseDex(buffer)).toThrow('Invalid DEX Magic header');
  });

  it('should parse a minimal mock DEX file successfully', () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // --- Header Setup ---
    // Magic: "dex\n035\0"
    bytes.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00], 0);

    // Endian Tag: Little Endian
    view.setUint32(40, 0x12345678, true);

    // File size
    view.setUint32(32, 1024, true);

    // Header size
    view.setUint32(36, 112, true);

    // Layout offsets and counts
    let currentOffset = 112;

    // We will store 4 strings:
    // Index 0: "LMyClass;" (Class descriptor)
    // Index 1: "Ljava/lang/Object;" (Superclass descriptor)
    // Index 2: "myMethod" (Method name)
    // Index 3: "V" (Void type descriptor)
    const stringsData = [
      'LMyClass;',
      'Ljava/lang/Object;',
      'myMethod',
      'V',
    ];

    const stringIdsOff = currentOffset;
    const stringIdsSize = stringsData.length;
    view.setUint32(56, stringIdsSize, true);
    view.setUint32(60, stringIdsOff, true);
    currentOffset += stringIdsSize * 4;

    // Type IDs (points to string ID descriptors)
    // Index 0 -> "LMyClass;" (String ID 0)
    // Index 1 -> "Ljava/lang/Object;" (String ID 1)
    // Index 2 -> "V" (String ID 3)
    const typeIdsSize = 3;
    const typeIdsOff = currentOffset;
    view.setUint32(64, typeIdsSize, true);
    view.setUint32(68, typeIdsOff, true);
    view.setUint32(typeIdsOff, 0, true); // class MyClass
    view.setUint32(typeIdsOff + 4, 1, true); // class java/lang/Object
    view.setUint32(typeIdsOff + 8, 3, true); // void
    currentOffset += typeIdsSize * 4;

    // Proto IDs
    // We have 1 proto: return type Void, no parameters
    // protoId: shorty_idx (String ID 3), return_type_idx (Type ID 2), parameters_off (0)
    const protoIdsSize = 1;
    const protoIdsOff = currentOffset;
    view.setUint32(72, protoIdsSize, true);
    view.setUint32(76, protoIdsOff, true);
    view.setUint32(protoIdsOff, 3, true); // Shorty
    view.setUint32(protoIdsOff + 4, 2, true); // Return type
    view.setUint32(protoIdsOff + 8, 0, true); // No parameters
    currentOffset += 12;

    // Field IDs: None (0 size, 0 offset)
    view.setUint32(80, 0, true);
    view.setUint32(84, 0, true);

    // Method IDs
    // Method 0: Class "LMyClass;" (Type ID 0), Proto 0, Name "myMethod" (String ID 2)
    const methodIdsSize = 1;
    const methodIdsOff = currentOffset;
    view.setUint32(88, methodIdsSize, true);
    view.setUint32(92, methodIdsOff, true);
    view.setUint16(methodIdsOff, 0, true); // Class Index
    view.setUint16(methodIdsOff + 2, 0, true); // Proto Index
    view.setUint32(methodIdsOff + 4, 2, true); // Name Index
    currentOffset += 8;

    // Class Defs
    // Class 0: Class ID 0, access flags public (0x1), superclass ID 1, interfaces_off 0,
    // source_file_idx -1 (0xffffffff), annotations_off 0, class_data_off, static_values_off 0
    const classDefsSize = 1;
    const classDefsOff = currentOffset;
    view.setUint32(96, classDefsSize, true);
    view.setUint32(100, classDefsOff, true);

    const classDataOff = 600; // Place class data at offset 600
    view.setUint32(classDefsOff, 0, true); // Class Index
    view.setUint32(classDefsOff + 4, 1, true); // Access Flags
    view.setUint32(classDefsOff + 8, 1, true); // Superclass Index
    view.setUint32(classDefsOff + 12, 0, true); // Interfaces Off
    view.setUint32(classDefsOff + 16, 0xffffffff, true); // Source File Index
    view.setUint32(classDefsOff + 20, 0, true); // Annotations Off
    view.setUint32(classDefsOff + 24, classDataOff, true); // Class Data Off
    view.setUint32(classDefsOff + 28, 0, true); // Static Values Off
    currentOffset += 32;

    // Set up String Data items
    const stringDataOffsets: number[] = [];
    stringsData.forEach((str) => {
      stringDataOffsets.push(currentOffset);
      // Write length as ULEB128
      const lenOffsetRef = { offset: currentOffset };
      // For simple ASCII strings, length in code units is string length
      const lenBytes: number[] = [];
      let tempLen = str.length;
      do {
        let b = tempLen & 0x7f;
        tempLen >>= 7;
        if (tempLen > 0) {
          b |= 0x80;
        }
        lenBytes.push(b);
      } while (tempLen > 0);

      bytes.set(lenBytes, currentOffset);
      currentOffset += lenBytes.length;

      // Write string bytes
      const encoder = new TextEncoder();
      const encoded = encoder.encode(str);
      bytes.set(encoded, currentOffset);
      currentOffset += encoded.length;

      // Write null terminator
      bytes[currentOffset] = 0;
      currentOffset++;
    });

    // Populate String IDs offset table
    stringDataOffsets.forEach((off, idx) => {
      view.setUint32(stringIdsOff + idx * 4, off, true);
    });

    // Write Class Data at offset 600
    // class_data_item:
    // static_fields_size: 0
    // instance_fields_size: 0
    // direct_methods_size: 1
    // virtual_methods_size: 0
    let dataOffset = classDataOff;
    bytes[dataOffset++] = 0; // static_fields
    bytes[dataOffset++] = 0; // instance_fields
    bytes[dataOffset++] = 1; // direct_methods
    bytes[dataOffset++] = 0; // virtual_methods

    // direct_methods[0]:
    // method_idx_diff: 0 (since it's the first method, index is 0)
    // access_flags: 1 (public)
    // code_off: 700 (offset to code item)
    const codeOff = 700;
    // Write method_idx_diff as ULEB128 (0 -> 0x00)
    bytes[dataOffset++] = 0;
    // Write access_flags as ULEB128 (1 -> 0x01)
    bytes[dataOffset++] = 1;
    // Write code_off as ULEB128 (700 -> 0xbc, 0x05)
    bytes[dataOffset++] = 0xbc;
    bytes[dataOffset++] = 0x05;

    // Write Code Item at offset 700
    // code_item:
    // registers_size: 2 (uint16)
    // ins_size: 1 (uint16)
    // outs_size: 0 (uint16)
    // tries_size: 1 (uint16)
    // debug_info_off: 0 (uint32)
    // insns_size: 3 (uint32)
    // insns: [0x000e, 0x0000, 0x0000] (return-void is 0x000e)
    view.setUint16(codeOff, 2, true);
    view.setUint16(codeOff + 2, 1, true);
    view.setUint16(codeOff + 4, 0, true);
    view.setUint16(codeOff + 6, 1, true); // 1 try block
    view.setUint32(codeOff + 8, 0, true);
    view.setUint32(codeOff + 12, 3, true); // insns_size = 3 (odd, so we need padding)

    view.setUint16(codeOff + 16, 0x000e, true);
    view.setUint16(codeOff + 18, 0x0000, true);
    view.setUint16(codeOff + 20, 0x0000, true);

    // Padding + TriesOffset:
    // codeOff + 16 + insns_size * 2 = 700 + 16 + 6 = 722.
    // insns_size is 3 (odd), so add 2 bytes of padding. Tries starts at 724.
    const triesOffset = codeOff + 24; // 724
    // try_item:
    // start_addr: 0 (uint32)
    // insn_count: 3 (uint16)
    // handler_off: 1 (uint16) - offset 0 contains the list size (1)
    view.setUint32(triesOffset, 0, true);
    view.setUint16(triesOffset + 4, 3, true);
    view.setUint16(triesOffset + 6, 1, true);

    // Catch Handlers starts immediately after tries (size 1 * 8 = 8 bytes).
    // handlersStartOff = 724 + 8 = 732.
    // At handlersStartOff + handler_off (732 + 1):
    // catch_handler_list:
    // size (uleb128): 1
    // At handler offset 1:
    // size (sleb128): -1 (indicates 1 catch type + catch-all)
    // type_idx (uleb128): 1 (Ljava/lang/Object;)
    // addr (uleb128): 2 (handler address)
    // catch_all_addr (uleb128): 3 (catch-all address)
    const handlersStartOff = triesOffset + 8; // 732
    let handlersOffset = handlersStartOff;

    // list size (uleb128)
    bytes[handlersOffset++] = 1;

    // catch handler size: -1 in sleb128 is 0x7f
    bytes[handlersOffset++] = 0x7f;
    // type_idx: 1
    bytes[handlersOffset++] = 1;
    // addr: 2
    bytes[handlersOffset++] = 2;
    // catch_all_addr: 3
    bytes[handlersOffset++] = 3;

    // Run Parser
    const parsed = parseDex(buffer);

    // Assertions
    expect(parsed.header.magic).toBe('dex\n035\0');
    expect(parsed.header.littleEndian).toBe(true);

    expect(parsed.strings).toHaveLength(4);
    expect(parsed.strings[0]).toBe('LMyClass;');
    expect(parsed.strings[1]).toBe('Ljava/lang/Object;');
    expect(parsed.strings[2]).toBe('myMethod');
    expect(parsed.strings[3]).toBe('V');

    expect(parsed.typeIds).toHaveLength(3);
    expect(parsed.typeIds[0].descriptor).toBe('LMyClass;');
    expect(parsed.typeIds[1].descriptor).toBe('Ljava/lang/Object;');

    expect(parsed.protoIds).toHaveLength(1);
    expect(parsed.protoIds[0].shorty).toBe('V');
    expect(parsed.protoIds[0].returnType).toBe('V');
    expect(parsed.protoIds[0].parameters).toEqual([]);

    expect(parsed.methodIds).toHaveLength(1);
    expect(parsed.methodIds[0].className).toBe('LMyClass;');
    expect(parsed.methodIds[0].methodName).toBe('myMethod');

    expect(parsed.classDefs).toHaveLength(1);
    const cls = parsed.classDefs[0];
    expect(cls.className).toBe('LMyClass;');
    expect(cls.superclassName).toBe('Ljava/lang/Object;');

    const data = cls.classData;
    expect(data).toBeDefined();
    expect(data!.directMethods).toHaveLength(1);
    const method = data!.directMethods[0];
    expect(method.method.methodName).toBe('myMethod');
    expect(method.codeItem).toBeDefined();

    const code = method.codeItem!;
    expect(code.registersSize).toBe(2);
    expect(code.insSize).toBe(1);
    expect(code.triesSize).toBe(1);
    expect(code.insnsSize).toBe(3);
    expect(code.insns[0]).toBe(0x000e);

    expect(code.tries).toHaveLength(1);
    const tryBlock = code.tries[0];
    expect(tryBlock.startAddr).toBe(0);
    expect(tryBlock.insnCount).toBe(3);
    expect(tryBlock.handler).toBeDefined();

    const handler = tryBlock.handler!;
    expect(handler.handlers).toHaveLength(1);
    expect(handler.handlers[0].typeName).toBe('Ljava/lang/Object;');
    expect(handler.handlers[0].addr).toBe(2);
    expect(handler.catchAllAddr).toBe(3);
  });
});

import { DisassemblerRouter } from '../src/disassembler/router.js';

describe('DEX Router Integration', () => {
  it('should detect DEX magic bytes correctly', () => {
    const bytes = new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]);
    const arch = DisassemblerRouter.detectArchitecture(bytes);
    expect(arch).toBe('dex');
  });

  it('should route DEX disassembly correctly', () => {
    const bytes = new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x0e, 0x00]);
    const router = new DisassemblerRouter();
    const insts = router.disassemble(bytes);
    expect(insts).toBeDefined();
    expect(insts.length).toBeGreaterThan(0);
    // Address 0,1,2,3 are the magic bytes, 4 is 0x0e (return-void)
    expect(insts.some(i => i.mnemonic === 'return-void')).toBe(true);
  });
});
