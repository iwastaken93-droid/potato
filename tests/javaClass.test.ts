import { describe, it, expect } from 'vitest';
import { parseJavaClass, formatAccessFlags } from '../src/parser/javaClass.js';

describe('Java Class Parser Unit Tests', () => {
  it('should successfully parse a basic valid Java class header', () => {
    // Basic class buffer
    // Magic (4 bytes): CAFEBABE
    // Minor version (2 bytes): 0
    // Major version (2 bytes): 61 (Java 17)
    // Constant pool count (2 bytes): 5
    // Constant pool entries:
    // 1. Utf8 "MyClass" (tag 1, len 7, value "MyClass")
    // 2. Class index 1 (tag 7, nameIndex 1)
    // 3. Utf8 "java/lang/Object" (tag 1, len 16, value "java/lang/Object")
    // 4. Class index 3 (tag 7, nameIndex 3)
    // Access flags (2 bytes): 0x0021 (PUBLIC | SUPER)
    // This Class (2 bytes): 2
    // Super Class (2 bytes): 4
    // Interfaces count (2 bytes): 0
    // Fields count (2 bytes): 0
    // Methods count (2 bytes): 0
    // Attributes count (2 bytes): 0

    const buffer = new ArrayBuffer(100);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    let offset = 0;
    view.setUint32(offset, 0xcafebabe, false); offset += 4;
    view.setUint16(offset, 0, false); offset += 2; // minor
    view.setUint16(offset, 61, false); offset += 2; // major
    view.setUint16(offset, 5, false); offset += 2; // cp count

    // CP[1]: Utf8 "MyClass"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 7, false); offset += 2;
    const myClassStr = 'MyClass';
    for (let i = 0; i < myClassStr.length; i++) {
      bytes[offset + i] = myClassStr.charCodeAt(i);
    }
    offset += 7;

    // CP[2]: Class MyClass (CP[1])
    bytes[offset] = 7; offset += 1;
    view.setUint16(offset, 1, false); offset += 2;

    // CP[3]: Utf8 "java/lang/Object"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 16, false); offset += 2;
    const objectStr = 'java/lang/Object';
    for (let i = 0; i < objectStr.length; i++) {
      bytes[offset + i] = objectStr.charCodeAt(i);
    }
    offset += 16;

    // CP[4]: Class java/lang/Object (CP[3])
    bytes[offset] = 7; offset += 1;
    view.setUint16(offset, 3, false); offset += 2;

    // Access flags: 0x0021
    view.setUint16(offset, 0x0021, false); offset += 2;
    // This Class: 2
    view.setUint16(offset, 2, false); offset += 2;
    // Super Class: 4
    view.setUint16(offset, 4, false); offset += 2;
    // Interfaces count: 0
    view.setUint16(offset, 0, false); offset += 2;
    // Fields count: 0
    view.setUint16(offset, 0, false); offset += 2;
    // Methods count: 0
    view.setUint16(offset, 0, false); offset += 2;
    // Attributes count: 0
    view.setUint16(offset, 0, false); offset += 2;

    // slice the buffer to actual length
    const slicedBuffer = buffer.slice(0, offset);
    const parsed = parseJavaClass(slicedBuffer);

    expect(parsed.magic).toBe(0xcafebabe);
    expect(parsed.minorVersion).toBe(0);
    expect(parsed.majorVersion).toBe(61);
    expect(parsed.thisClass).toBe('MyClass');
    expect(parsed.superClass).toBe('java/lang/Object');
    expect(parsed.accessFlagsList).toContain('PUBLIC');
    expect(parsed.accessFlagsList).toContain('SUPER');
    expect(parsed.fields.length).toBe(0);
    expect(parsed.methods.length).toBe(0);
  });

  it('should throw an error for invalid magic number', () => {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setUint32(0, 0xdeadbeef, false);
    view.setUint16(4, 0, false);
    view.setUint16(6, 61, false);

    expect(() => parseJavaClass(buffer)).toThrow('Invalid Java Class Magic: 0xDEADBEEF');
  });

  it('should parse constant pool entries including Long and Double double-slot tags', () => {
    const buffer = new ArrayBuffer(150);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    let offset = 0;
    view.setUint32(offset, 0xcafebabe, false); offset += 4;
    view.setUint16(offset, 0, false); offset += 2;
    view.setUint16(offset, 61, false); offset += 2;
    view.setUint16(offset, 8, false); offset += 2; // cp count is 8

    // CP[1]: Integer (value 123456)
    bytes[offset] = 3; offset += 1;
    view.setUint32(offset, 123456, false); offset += 4;

    // CP[2]: Float (value 1.25)
    bytes[offset] = 4; offset += 1;
    view.setFloat32(offset, 1.25, false); offset += 4;

    // CP[3]: Long (value 0x1122334455667788n) - takes 2 slots (CP[3], CP[4])
    bytes[offset] = 5; offset += 1;
    view.setBigUint64(offset, 0x1122334455667788n, false); offset += 8;

    // CP[5]: Double (value 3.14159) - takes 2 slots (CP[5], CP[6])
    bytes[offset] = 6; offset += 1;
    view.setFloat64(offset, 3.14159, false); offset += 8;

    // CP[7]: String index 1 (points to Integer CP[1] but JVM would check it)
    bytes[offset] = 8; offset += 1;
    view.setUint16(offset, 1, false); offset += 2;

    // Header info (dummy)
    view.setUint16(offset, 0, false); offset += 2; // access flags
    view.setUint16(offset, 0, false); offset += 2; // this class
    view.setUint16(offset, 0, false); offset += 2; // super class
    view.setUint16(offset, 0, false); offset += 2; // interfaces count
    view.setUint16(offset, 0, false); offset += 2; // fields count
    view.setUint16(offset, 0, false); offset += 2; // methods count
    view.setUint16(offset, 0, false); offset += 2; // attributes count

    const sliced = buffer.slice(0, offset);
    const parsed = parseJavaClass(sliced);

    expect(parsed.constantPool[1]?.tagName).toBe('Integer');
    expect(parsed.constantPool[1]?.value).toBe(123456);

    expect(parsed.constantPool[2]?.tagName).toBe('Float');
    expect(parsed.constantPool[2]?.value).toBe(1.25);

    expect(parsed.constantPool[3]?.tagName).toBe('Long');
    expect(parsed.constantPool[3]?.value).toBe(0x1122334455667788n);
    expect(parsed.constantPool[4]).toBeNull(); // Second slot must be null

    expect(parsed.constantPool[5]?.tagName).toBe('Double');
    expect(parsed.constantPool[5]?.value).toBe(3.14159);
    expect(parsed.constantPool[6]).toBeNull(); // Second slot must be null

    expect(parsed.constantPool[7]?.tagName).toBe('String');
    expect(parsed.constantPool[7]?.stringIndex).toBe(1);
  });

  it('should successfully parse fields, methods, and bytecode attributes', () => {
    // Let's create a class structure with:
    // - Constant Pool count: 12
    //   1: Utf8 "ClassA"
    //   2: Class (1)
    //   3: Utf8 "java/lang/Object"
    //   4: Class (3)
    //   5: Utf8 "myField"
    //   6: Utf8 "I" (int descriptor)
    //   7: Utf8 "myMethod"
    //   8: Utf8 "()V" (void method descriptor)
    //   9: Utf8 "Code"
    //   10: Utf8 "LineNumberTable"
    //   11: Utf8 "SourceFile"
    // - Fields count: 1 (myField)
    // - Methods count: 1 (myMethod)
    //   - Code attribute (contains bytecode, LineNumberTable)
    // - Class level attributes: 1 (SourceFile)

    const buffer = new ArrayBuffer(300);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    let offset = 0;
    view.setUint32(offset, 0xcafebabe, false); offset += 4;
    view.setUint16(offset, 0, false); offset += 2;
    view.setUint16(offset, 61, false); offset += 2;
    view.setUint16(offset, 12, false); offset += 2; // cp count

    const strings = [
      '', // index 0 unused
      'ClassA', // 1
      'java/lang/Object', // 2 (used as CP[3])
      'myField', // 3 (used as CP[5])
      'I', // 4 (used as CP[6])
      'myMethod', // 5 (used as CP[7])
      '()V', // 6 (used as CP[8])
      'Code', // 7 (used as CP[9])
      'LineNumberTable', // 8 (used as CP[10])
      'SourceFile', // 9 (used as CP[11])
    ];

    // Write UTF8 strings at CP[1], Class[2], UTF8[3], Class[4], UTF8[5]...
    // Let's explicitly write them to the exact indexes to be safe.
    
    // CP[1]: Utf8 "ClassA"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 6, false); offset += 2;
    for (let j = 0; j < 6; j++) bytes[offset++] = 'ClassA'.charCodeAt(j);

    // CP[2]: Class index 1
    bytes[offset] = 7; offset += 1;
    view.setUint16(offset, 1, false); offset += 2;

    // CP[3]: Utf8 "java/lang/Object"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 16, false); offset += 2;
    for (let j = 0; j < 16; j++) bytes[offset++] = 'java/lang/Object'.charCodeAt(j);

    // CP[4]: Class index 3
    bytes[offset] = 7; offset += 1;
    view.setUint16(offset, 3, false); offset += 2;

    // CP[5]: Utf8 "myField"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 7, false); offset += 2;
    for (let j = 0; j < 7; j++) bytes[offset++] = 'myField'.charCodeAt(j);

    // CP[6]: Utf8 "I"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 1, false); offset += 2;
    bytes[offset++] = 'I'.charCodeAt(0);

    // CP[7]: Utf8 "myMethod"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 8, false); offset += 2;
    for (let j = 0; j < 8; j++) bytes[offset++] = 'myMethod'.charCodeAt(j);

    // CP[8]: Utf8 "()V"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 3, false); offset += 2;
    for (let j = 0; j < 3; j++) bytes[offset++] = '()V'.charCodeAt(j);

    // CP[9]: Utf8 "Code"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 4, false); offset += 2;
    for (let j = 0; j < 4; j++) bytes[offset++] = 'Code'.charCodeAt(j);

    // CP[10]: Utf8 "LineNumberTable"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 15, false); offset += 2;
    for (let j = 0; j < 15; j++) bytes[offset++] = 'LineNumberTable'.charCodeAt(j);

    // CP[11]: Utf8 "SourceFile"
    bytes[offset] = 1; offset += 1;
    view.setUint16(offset, 10, false); offset += 2;
    for (let j = 0; j < 10; j++) bytes[offset++] = 'SourceFile'.charCodeAt(j);

    // Access Flags: 0x0021
    view.setUint16(offset, 0x0021, false); offset += 2;
    // This class: 2 (ClassA)
    view.setUint16(offset, 2, false); offset += 2;
    // Super class: 4 (java/lang/Object)
    view.setUint16(offset, 4, false); offset += 2;

    // Interfaces count: 0
    view.setUint16(offset, 0, false); offset += 2;

    // Fields count: 1
    view.setUint16(offset, 1, false); offset += 2;
    // field info: access_flags (0x0002 = PRIVATE), name_index (5), descriptor_index (6), attributes_count (0)
    view.setUint16(offset, 0x0002, false); offset += 2;
    view.setUint16(offset, 5, false); offset += 2;
    view.setUint16(offset, 6, false); offset += 2;
    view.setUint16(offset, 0, false); offset += 2;

    // Methods count: 1
    view.setUint16(offset, 1, false); offset += 2;
    // method info: access_flags (0x0001 = PUBLIC), name_index (7), descriptor_index (8), attributes_count (1)
    view.setUint16(offset, 0x0001, false); offset += 2;
    view.setUint16(offset, 7, false); offset += 2;
    view.setUint16(offset, 8, false); offset += 2;
    view.setUint16(offset, 1, false); offset += 2; // 1 attribute: Code

    // Method Attribute: Code (CP[9])
    view.setUint16(offset, 9, false); offset += 2;
    // Length of Code attribute info: 2 + 2 + 4 + code_len(2) + 2 (exception table) + 2 (nested attributes count) + nested attributes length
    // Let's compute it:
    // max_stack (2) = 2
    // max_locals (2) = 1
    // code_length (4) = 2 bytes (0x00, 0x01)
    // exception_table_length (2) = 0
    // attributes_count (2) = 1 (LineNumberTable)
    // LineNumberTable attribute: name_index (10), length (6), line_number_table_length (1), start_pc (0), line_number (10)
    // Total nested Code info length: 2 + 2 + 4 + 2 + 2 + 2 + (2 + 4 + 6) = 14 + 12 = 26 bytes.
    view.setUint32(offset, 26, false); offset += 4;
    view.setUint16(offset, 2, false); offset += 2; // max_stack
    view.setUint16(offset, 1, false); offset += 2; // max_locals
    view.setUint32(offset, 2, false); offset += 4; // code_length
    bytes[offset++] = 0x2A; // aload_0
    bytes[offset++] = 0xB1; // return
    view.setUint16(offset, 0, false); offset += 2; // exception_table_length
    view.setUint16(offset, 1, false); offset += 2; // nested attributes_count

    // Nested attribute: LineNumberTable (CP[10])
    view.setUint16(offset, 10, false); offset += 2;
    view.setUint32(offset, 6, false); offset += 4;
    view.setUint16(offset, 1, false); offset += 2; // table length
    view.setUint16(offset, 0, false); offset += 2; // start_pc
    view.setUint16(offset, 10, false); offset += 2; // line_number

    // Class level attributes count: 1 (SourceFile CP[11])
    view.setUint16(offset, 1, false); offset += 2;
    // SourceFile attribute
    view.setUint16(offset, 11, false); offset += 2;
    view.setUint32(offset, 2, false); offset += 4; // length
    view.setUint16(offset, 1, false); offset += 2; // sourcefile_index CP[1] -> "ClassA"

    const sliced = buffer.slice(0, offset);
    const parsed = parseJavaClass(sliced);

    expect(parsed.fields.length).toBe(1);
    expect(parsed.fields[0].name).toBe('myField');
    expect(parsed.fields[0].descriptor).toBe('I');
    expect(parsed.fields[0].accessFlagsList).toContain('PRIVATE');

    expect(parsed.methods.length).toBe(1);
    expect(parsed.methods[0].name).toBe('myMethod');
    expect(parsed.methods[0].descriptor).toBe('()V');
    expect(parsed.methods[0].accessFlagsList).toContain('PUBLIC');

    const codeAttr = parsed.methods[0].attributes.find(a => a.name === 'Code');
    expect(codeAttr).toBeDefined();
    expect(codeAttr?.decoded).toBeDefined();
    expect(codeAttr?.decoded.maxStack).toBe(2);
    expect(codeAttr?.decoded.maxLocals).toBe(1);
    expect(codeAttr?.decoded.code).toEqual(new Uint8Array([0x2A, 0xB1]));

    const lnTable = codeAttr?.decoded.attributes.find((a: any) => a.name === 'LineNumberTable');
    expect(lnTable).toBeDefined();
    expect(lnTable?.decoded).toEqual([{ startPc: 0, lineNumber: 10 }]);

    const sfAttr = parsed.attributes.find(a => a.name === 'SourceFile');
    expect(sfAttr).toBeDefined();
    expect(sfAttr?.decoded).toBe('ClassA');
  });

  it('should correctly format access flags for classes, fields, and methods', () => {
    const classFlags = formatAccessFlags(0x0001 | 0x0010 | 0x0400 | 0x0200, 'class');
    expect(classFlags).toContain('PUBLIC');
    expect(classFlags).toContain('FINAL');
    expect(classFlags).toContain('ABSTRACT');
    expect(classFlags).toContain('INTERFACE');

    const fieldFlags = formatAccessFlags(0x0002 | 0x0008 | 0x0040 | 0x0080, 'field');
    expect(fieldFlags).toContain('PRIVATE');
    expect(fieldFlags).toContain('STATIC');
    expect(fieldFlags).toContain('VOLATILE');
    expect(fieldFlags).toContain('TRANSIENT');

    const methodFlags = formatAccessFlags(0x0004 | 0x0020 | 0x0100 | 0x0800, 'method');
    expect(methodFlags).toContain('PROTECTED');
    expect(methodFlags).toContain('SYNCHRONIZED');
    expect(methodFlags).toContain('NATIVE');
    expect(methodFlags).toContain('STRICT');
  });
});
