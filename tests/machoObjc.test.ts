import { describe, it, expect } from 'vitest';
import { parseMacho } from '../src/parser/macho.js';
import { parseObjcMetadata } from '../src/parser/machoObjc.js';

describe('Mach-O Objective-C Metadata Parser Unit Tests', () => {
  it('should parse class, superclass, methods, properties, and ivars correctly', () => {
    // We will create a buffer representing a 64-bit Mach-O binary
    // Segment vmaddr = 0x1000. fileoff = 0.
    // Therefore, VM address targetVm resolves to file offset (targetVm - 0x1000).
    const totalSize = 2048;
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    // 1. Write Mach-O 64-bit Header (32 bytes)
    view.setUint32(0, 0xfeedfacf, true); // magic LE 64
    view.setInt32(4, 0x01000007, true); // cputype X86_64
    view.setUint32(16, 1, true); // ncmds = 1
    view.setUint32(20, 232, true); // sizeofcmds = 232

    // 2. Write LC_SEGMENT_64 Command (72 bytes info + 160 bytes for 2 sections)
    const cmdOffset = 32;
    view.setUint32(cmdOffset, 0x19, true); // cmd: LC_SEGMENT_64
    view.setUint32(cmdOffset + 4, 232, true); // cmdsize: 232

    // Segment name: "__DATA"
    const segName = '__DATA';
    for (let i = 0; i < segName.length; i++) {
      view.setUint8(cmdOffset + 8 + i, segName.charCodeAt(i));
    }
    view.setBigUint64(cmdOffset + 24, 0x1000n, true); // vmaddr = 0x1000
    view.setBigUint64(cmdOffset + 32, 0x1000n, true); // vmsize = 0x1000
    view.setBigUint64(cmdOffset + 40, 0n, true); // fileoff = 0
    view.setBigUint64(cmdOffset + 48, BigInt(totalSize), true); // filesize
    view.setUint32(cmdOffset + 64, 2, true); // nsects = 2

    // Section 1: __objc_classlist
    const sect1Offset = cmdOffset + 72;
    const sect1Name = '__objc_classlist';
    for (let i = 0; i < sect1Name.length; i++) {
      view.setUint8(sect1Offset + i, sect1Name.charCodeAt(i));
    }
    for (let i = 0; i < segName.length; i++) {
      view.setUint8(sect1Offset + 16 + i, segName.charCodeAt(i));
    }
    view.setBigUint64(sect1Offset + 32, 0x1100n, true); // addr = 0x1100
    view.setBigUint64(sect1Offset + 40, 8n, true); // size = 8
    view.setUint32(sect1Offset + 48, 0x100, true); // file offset = 0x100 (256)

    // Section 2: __objc_const
    const sect2Offset = sect1Offset + 80;
    const sect2Name = '__objc_const';
    for (let i = 0; i < sect2Name.length; i++) {
      view.setUint8(sect2Offset + i, sect2Name.charCodeAt(i));
    }
    for (let i = 0; i < segName.length; i++) {
      view.setUint8(sect2Offset + 16 + i, segName.charCodeAt(i));
    }
    view.setBigUint64(sect2Offset + 32, 0x1200n, true); // addr = 0x1200
    view.setBigUint64(sect2Offset + 40, 500n, true); // size = 500
    view.setUint32(sect2Offset + 48, 0x200, true); // file offset = 0x200 (512)

    // 3. Write ObjC Structures

    // classList at 0x1100 (offset 256) points to class_t at 0x1300 (offset 768)
    view.setBigUint64(256, 0x1300n, true);

    // class_t (at 0x1300 / offset 768):
    // isa (8 bytes): 0
    // superclass (8 bytes): 0
    // cache (16 bytes): 0
    // vtable (8 bytes): 0
    // data (8 bytes): points to class_ro_t at 0x1400 (offset 1024)
    view.setBigUint64(768 + 32, 0x1400n, true);

    // class_ro_t (at 0x1400 / offset 1024):
    // flags (4 bytes): 0
    // instanceStart (4 bytes): 8
    // instanceSize (4 bytes): 32
    // reserved (4 bytes): 0
    // ivarLayout (8 bytes): 0
    // name (8 bytes): C-string at 0x1500 (offset 1280)
    // baseMethods (8 bytes): method_list_t at 0x1600 (offset 1536)
    // baseProtocols (8 bytes): 0
    // ivars (8 bytes): ivar_list_t at 0x1700 (offset 1792)
    // weakIvarLayout (8 bytes): 0
    // baseProperties (8 bytes): property_list_t at 0x1800 (offset 2048 - wait, 2048 is size, let's put it at 0x1780 / offset 1920)
    view.setUint32(1024, 0, true);
    view.setUint32(1024 + 4, 8, true);
    view.setUint32(1024 + 8, 32, true);
    view.setBigUint64(1024 + 24, 0x1500n, true); // name
    view.setBigUint64(1024 + 32, 0x1600n, true); // baseMethods
    view.setBigUint64(1024 + 48, 0x1700n, true); // ivars
    view.setBigUint64(1024 + 64, 0x1780n, true); // baseProperties

    // Class Name at 0x1500 / offset 1280: "MyTestClass"
    const nameStr = 'MyTestClass';
    for (let i = 0; i < nameStr.length; i++) {
      bytes[1280 + i] = nameStr.charCodeAt(i);
    }

    // method_list_t (at 0x1600 / offset 1536):
    // entsizeAndFlags (4) = 24
    // count (4) = 1
    // method_t:
    //   name (8) = 0x1550 (offset 1360)
    //   types (8) = 0x1560 (offset 1376)
    //   imp (8) = 0x5000n
    view.setUint32(1536, 24, true);
    view.setUint32(1536 + 4, 1, true);
    view.setBigUint64(1536 + 8, 0x1550n, true);
    view.setBigUint64(1536 + 16, 0x1560n, true);
    view.setBigUint64(1536 + 24, 0x5000n, true);

    // Method Name at 0x1550 / offset 1360: "doSomething"
    const methName = 'doSomething';
    for (let i = 0; i < methName.length; i++) {
      bytes[1360 + i] = methName.charCodeAt(i);
    }

    // Method Types at 0x1560 / offset 1376: "v@:"
    const typesStr = 'v@:';
    for (let i = 0; i < typesStr.length; i++) {
      bytes[1376 + i] = typesStr.charCodeAt(i);
    }

    // ivar_list_t (at 0x1700 / offset 1792):
    // entsize (4) = 32
    // count (4) = 1
    // ivar_t:
    //   offsetPtr (8) = 0x1570 (offset 1392)
    //   name (8) = 0x1580 (offset 1408)
    //   type (8) = 0x1590 (offset 1424)
    //   alignment (4) = 3
    //   size (4) = 8
    view.setUint32(1792, 32, true);
    view.setUint32(1792 + 4, 1, true);
    view.setBigUint64(1792 + 8, 0x1570n, true);
    view.setBigUint64(1792 + 16, 0x1580n, true);
    view.setBigUint64(1792 + 24, 0x1590n, true);
    view.setUint32(1792 + 32, 3, true);
    view.setUint32(1792 + 36, 8, true);

    // offset value at 0x1570 (offset 1392) = 8
    view.setUint32(1392, 8, true);

    // Ivar Name at 0x1580 / offset 1408: "_myIvar"
    const ivarName = '_myIvar';
    for (let i = 0; i < ivarName.length; i++) {
      bytes[1408 + i] = ivarName.charCodeAt(i);
    }

    // Ivar Type at 0x1590 / offset 1424: "NSString"
    const ivarType = 'NSString';
    for (let i = 0; i < ivarType.length; i++) {
      bytes[1424 + i] = ivarType.charCodeAt(i);
    }

    // property_list_t (at 0x1780 / offset 1920):
    // entsize (4) = 16
    // count (4) = 1
    // property_t:
    //   name (8) = 0x15a0 (offset 1440)
    //   attributes (8) = 0x15b0 (offset 1456)
    view.setUint32(1920, 16, true);
    view.setUint32(1920 + 4, 1, true);
    view.setBigUint64(1920 + 8, 0x15a0n, true);
    view.setBigUint64(1920 + 16, 0x15b0n, true);

    // Property Name at 0x15a0 / offset 1440: "myProp"
    const propName = 'myProp';
    for (let i = 0; i < propName.length; i++) {
      bytes[1440 + i] = propName.charCodeAt(i);
    }

    // Property Attributes at 0x15b0 / offset 1456: "T@\"NSString\",C,N,V_myIvar"
    const propAttr = 'T@"NSString",C,N,V_myIvar';
    for (let i = 0; i < propAttr.length; i++) {
      bytes[1456 + i] = propAttr.charCodeAt(i);
    }

    const macho = parseMacho(buffer);
    const objc = parseObjcMetadata(macho, buffer);

    expect(objc.classes.length).toBe(1);
    const cls = objc.classes[0];
    expect(cls.name).toBe('MyTestClass');
    expect(cls.methods.length).toBe(1);
    expect(cls.methods[0].name).toBe('doSomething');
    expect(cls.methods[0].types).toBe('v@:');
    expect(cls.methods[0].imp).toBe(0x5000n);

    expect(cls.ivars.length).toBe(1);
    expect(cls.ivars[0].name).toBe('_myIvar');
    expect(cls.ivars[0].type).toBe('NSString');
    expect(cls.ivars[0].offset).toBe(8);
    expect(cls.ivars[0].size).toBe(8);

    expect(cls.properties.length).toBe(1);
    expect(cls.properties[0].name).toBe('myProp');
    expect(cls.properties[0].attributes).toBe('T@"NSString",C,N,V_myIvar');
  });
});
