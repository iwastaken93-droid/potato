/**
 * Java Class File Format Parser
 * Decodes magic bytes, constant pool, fields, methods, and bytecode attributes.
 */

export interface ConstantPoolEntry {
  tag: number;
  tagName: string;
  value?: string | number | bigint;
  nameIndex?: number;
  stringIndex?: number;
  classIndex?: number;
  nameAndTypeIndex?: number;
  descriptorIndex?: number;
  referenceKind?: number;
  referenceIndex?: number;
  bootstrapMethodAttrIndex?: number;
}

export interface AttributeInfo {
  name: string;
  length: number;
  info: Uint8Array;
  decoded?: any;
}

export interface ExceptionTableEntry {
  startPc: number;
  endPc: number;
  handlerPc: number;
  catchType: number;
  catchTypeName?: string;
}

export interface CodeAttribute {
  maxStack: number;
  maxLocals: number;
  code: Uint8Array;
  exceptionTable: ExceptionTableEntry[];
  attributes: AttributeInfo[];
}

export interface JavaField {
  accessFlags: number;
  accessFlagsList: string[];
  name: string;
  descriptor: string;
  attributes: AttributeInfo[];
}

export interface JavaMethod {
  accessFlags: number;
  accessFlagsList: string[];
  name: string;
  descriptor: string;
  attributes: AttributeInfo[];
}

export interface ParsedJavaClass {
  magic: number;
  minorVersion: number;
  majorVersion: number;
  constantPool: (ConstantPoolEntry | null)[];
  accessFlags: number;
  accessFlagsList: string[];
  thisClass: string;
  superClass: string;
  interfaces: string[];
  fields: JavaField[];
  methods: JavaMethod[];
  attributes: AttributeInfo[];
}

const tagNames: Record<number, string> = {
  1: 'Utf8',
  3: 'Integer',
  4: 'Float',
  5: 'Long',
  6: 'Double',
  7: 'Class',
  8: 'String',
  9: 'Fieldref',
  10: 'Methodref',
  11: 'InterfaceMethodref',
  12: 'NameAndType',
  15: 'MethodHandle',
  16: 'MethodType',
  17: 'Dynamic',
  18: 'InvokeDynamic',
  19: 'Module',
  20: 'Package',
};

class BufferReader {
  private view: DataView;
  private bytes: Uint8Array;
  public offset: number = 0;

  constructor(buffer: ArrayBuffer) {
    this.view = new DataView(buffer);
    this.bytes = new Uint8Array(buffer);
  }

  readU1(): number {
    if (this.offset + 1 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.bytes[this.offset];
    this.offset += 1;
    return val;
  }

  readU2(): number {
    if (this.offset + 2 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.view.getUint16(this.offset, false);
    this.offset += 2;
    return val;
  }

  readU4(): number {
    if (this.offset + 4 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.view.getUint32(this.offset, false);
    this.offset += 4;
    return val;
  }

  readU8(): bigint {
    if (this.offset + 8 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.view.getBigUint64(this.offset, false);
    this.offset += 8;
    return val;
  }

  readFloat(): number {
    if (this.offset + 4 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.view.getFloat32(this.offset, false);
    this.offset += 4;
    return val;
  }

  readDouble(): number {
    if (this.offset + 8 > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.view.getFloat64(this.offset, false);
    this.offset += 8;
    return val;
  }

  readBytes(length: number): Uint8Array {
    if (this.offset + length > this.view.byteLength)
      throw new Error('Unexpected EOF');
    const val = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return val;
  }
}

export function formatAccessFlags(
  flags: number,
  type: 'class' | 'field' | 'method'
): string[] {
  const result: string[] = [];
  if (flags & 0x0001) result.push('PUBLIC');
  if (flags & 0x0002) result.push('PRIVATE');
  if (flags & 0x0004) result.push('PROTECTED');
  if (flags & 0x0008) result.push('STATIC');
  if (flags & 0x0010) result.push('FINAL');
  if (type === 'class') {
    if (flags & 0x0020) result.push('SUPER');
    if (flags & 0x0200) result.push('INTERFACE');
    if (flags & 0x0400) result.push('ABSTRACT');
    if (flags & 0x1000) result.push('SYNTHETIC');
    if (flags & 0x2000) result.push('ANNOTATION');
    if (flags & 0x4000) result.push('ENUM');
    if (flags & 0x8000) result.push('MODULE');
  } else if (type === 'field') {
    if (flags & 0x0040) result.push('VOLATILE');
    if (flags & 0x0080) result.push('TRANSIENT');
    if (flags & 0x1000) result.push('SYNTHETIC');
    if (flags & 0x4000) result.push('ENUM');
  } else if (type === 'method') {
    if (flags & 0x0020) result.push('SYNCHRONIZED');
    if (flags & 0x0040) result.push('BRIDGE');
    if (flags & 0x0080) result.push('VARARGS');
    if (flags & 0x0100) result.push('NATIVE');
    if (flags & 0x0400) result.push('ABSTRACT');
    if (flags & 0x0800) result.push('STRICT');
    if (flags & 0x1000) result.push('SYNTHETIC');
  }
  return result;
}

export function parseJavaClass(arrayBuffer: ArrayBuffer): ParsedJavaClass {
  const reader = new BufferReader(arrayBuffer);

  // Validate Magic: 0xCAFEBABE
  const magic = reader.readU4();
  if (magic !== 0xcafebabe) {
    throw new Error(
      `Invalid Java Class Magic: 0x${magic.toString(16).toUpperCase()}`
    );
  }

  const minorVersion = reader.readU2();
  const majorVersion = reader.readU2();

  // Read Constant Pool
  const constantPoolCount = reader.readU2();
  const constantPool: (ConstantPoolEntry | null)[] = [null]; // 1-indexed

  for (let i = 1; i < constantPoolCount; i++) {
    const tag = reader.readU1();
    const tagName = tagNames[tag] || `Unknown (${tag})`;
    const entry: ConstantPoolEntry = { tag, tagName };

    switch (tag) {
      case 1: {
        // Utf8
        const length = reader.readU2();
        const bytes = reader.readBytes(length);
        entry.value = new TextDecoder('utf-8').decode(bytes);
        break;
      }
      case 3: {
        // Integer
        entry.value = reader.readU4();
        break;
      }
      case 4: {
        // Float
        entry.value = reader.readFloat();
        break;
      }
      case 5: {
        // Long
        entry.value = reader.readU8();
        constantPool.push(entry);
        constantPool.push(null); // Second slot is empty/unused in JVM spec
        i++;
        continue;
      }
      case 6: {
        // Double
        entry.value = reader.readDouble();
        constantPool.push(entry);
        constantPool.push(null); // Second slot is empty/unused in JVM spec
        i++;
        continue;
      }
      case 7: {
        // Class
        entry.nameIndex = reader.readU2();
        break;
      }
      case 8: {
        // String
        entry.stringIndex = reader.readU2();
        break;
      }
      case 9: // Fieldref
      case 10: // Methodref
      case 11: {
        // InterfaceMethodref
        entry.classIndex = reader.readU2();
        entry.nameAndTypeIndex = reader.readU2();
        break;
      }
      case 12: {
        // NameAndType
        entry.nameIndex = reader.readU2();
        entry.descriptorIndex = reader.readU2();
        break;
      }
      case 15: {
        // MethodHandle
        entry.referenceKind = reader.readU1();
        entry.referenceIndex = reader.readU2();
        break;
      }
      case 16: {
        // MethodType
        entry.descriptorIndex = reader.readU2();
        break;
      }
      case 17: // Dynamic
      case 18: {
        // InvokeDynamic
        entry.bootstrapMethodAttrIndex = reader.readU2();
        entry.nameAndTypeIndex = reader.readU2();
        break;
      }
      case 19: {
        // Module
        entry.nameIndex = reader.readU2();
        break;
      }
      case 20: {
        // Package
        entry.nameIndex = reader.readU2();
        break;
      }
      default:
        throw new Error(`Unsupported constant pool tag: ${tag} at index ${i}`);
    }

    constantPool.push(entry);
  }

  // Helper functions for resolution
  function getUtf8(index: number): string {
    const entry = constantPool[index];
    if (entry && entry.tag === 1 && typeof entry.value === 'string') {
      return entry.value;
    }
    return '';
  }

  function getClassName(index: number): string {
    const entry = constantPool[index];
    if (entry && entry.tag === 7 && entry.nameIndex !== undefined) {
      return getUtf8(entry.nameIndex);
    }
    return '';
  }

  function parseAttributesList(attrReader: BufferReader): AttributeInfo[] {
    const attrCount = attrReader.readU2();
    const attributes: AttributeInfo[] = [];

    for (let i = 0; i < attrCount; i++) {
      const nameIndex = attrReader.readU2();
      const length = attrReader.readU4();
      const info = attrReader.readBytes(length);
      const name = getUtf8(nameIndex);

      const attribute: AttributeInfo = {
        name,
        length,
        info,
      };

      try {
        if (name === 'Code') {
          const codeReader = new BufferReader(
            info.buffer.slice(
              info.byteOffset,
              info.byteOffset + info.byteLength
            ) as ArrayBuffer
          );
          const maxStack = codeReader.readU2();
          const maxLocals = codeReader.readU2();
          const codeLength = codeReader.readU4();
          const codeBytes = codeReader.readBytes(codeLength);

          const exceptionTableLength = codeReader.readU2();
          const exceptionTable: ExceptionTableEntry[] = [];
          for (let j = 0; j < exceptionTableLength; j++) {
            const startPc = codeReader.readU2();
            const endPc = codeReader.readU2();
            const handlerPc = codeReader.readU2();
            const catchType = codeReader.readU2();
            exceptionTable.push({
              startPc,
              endPc,
              handlerPc,
              catchType,
              catchTypeName: catchType > 0 ? getClassName(catchType) : 'any',
            });
          }

          const nestedAttributes = parseAttributesList(codeReader);

          attribute.decoded = {
            maxStack,
            maxLocals,
            code: codeBytes,
            exceptionTable,
            attributes: nestedAttributes,
          } as CodeAttribute;
        } else if (name === 'LineNumberTable') {
          const lnReader = new BufferReader(
            info.buffer.slice(
              info.byteOffset,
              info.byteOffset + info.byteLength
            ) as ArrayBuffer
          );
          const tableLength = lnReader.readU2();
          const lines: { startPc: number; lineNumber: number }[] = [];
          for (let j = 0; j < tableLength; j++) {
            lines.push({
              startPc: lnReader.readU2(),
              lineNumber: lnReader.readU2(),
            });
          }
          attribute.decoded = lines;
        } else if (name === 'LocalVariableTable') {
          const lvReader = new BufferReader(
            info.buffer.slice(
              info.byteOffset,
              info.byteOffset + info.byteLength
            ) as ArrayBuffer
          );
          const tableLength = lvReader.readU2();
          const variables: {
            startPc: number;
            length: number;
            name: string;
            descriptor: string;
            index: number;
          }[] = [];
          for (let j = 0; j < tableLength; j++) {
            const startPc = lvReader.readU2();
            const len = lvReader.readU2();
            const nameIdx = lvReader.readU2();
            const descIdx = lvReader.readU2();
            const idx = lvReader.readU2();
            variables.push({
              startPc,
              length: len,
              name: getUtf8(nameIdx),
              descriptor: getUtf8(descIdx),
              index: idx,
            });
          }
          attribute.decoded = variables;
        } else if (name === 'SourceFile') {
          const sfReader = new BufferReader(
            info.buffer.slice(
              info.byteOffset,
              info.byteOffset + info.byteLength
            ) as ArrayBuffer
          );
          if (info.byteLength >= 2) {
            const sfIdx = sfReader.readU2();
            attribute.decoded = getUtf8(sfIdx);
          }
        } else if (name === 'ConstantValue') {
          const cvReader = new BufferReader(
            info.buffer.slice(
              info.byteOffset,
              info.byteOffset + info.byteLength
            ) as ArrayBuffer
          );
          if (info.byteLength >= 2) {
            const cvIdx = cvReader.readU2();
            const entry = constantPool[cvIdx];
            attribute.decoded = entry ? entry.value : undefined;
          }
        }
      } catch (err) {
        // Fallback if decoding nested attributes fails (e.g. malformed or partial buffers in tests)
        attribute.decoded = null;
      }

      attributes.push(attribute);
    }

    return attributes;
  }

  const accessFlags = reader.readU2();
  const accessFlagsList = formatAccessFlags(accessFlags, 'class');

  const thisClassIdx = reader.readU2();
  const thisClass = getClassName(thisClassIdx);

  const superClassIdx = reader.readU2();
  const superClass = superClassIdx > 0 ? getClassName(superClassIdx) : '';

  // Interfaces
  const interfacesCount = reader.readU2();
  const interfaces: string[] = [];
  for (let i = 0; i < interfacesCount; i++) {
    const interIdx = reader.readU2();
    interfaces.push(getClassName(interIdx));
  }

  // Fields
  const fieldsCount = reader.readU2();
  const fields: JavaField[] = [];
  for (let i = 0; i < fieldsCount; i++) {
    const fAccessFlags = reader.readU2();
    const fNameIdx = reader.readU2();
    const fDescriptorIdx = reader.readU2();
    const fAttributes = parseAttributesList(reader);

    fields.push({
      accessFlags: fAccessFlags,
      accessFlagsList: formatAccessFlags(fAccessFlags, 'field'),
      name: getUtf8(fNameIdx),
      descriptor: getUtf8(fDescriptorIdx),
      attributes: fAttributes,
    });
  }

  // Methods
  const methodsCount = reader.readU2();
  const methods: JavaMethod[] = [];
  for (let i = 0; i < methodsCount; i++) {
    const mAccessFlags = reader.readU2();
    const mNameIdx = reader.readU2();
    const mDescriptorIdx = reader.readU2();
    const mAttributes = parseAttributesList(reader);

    methods.push({
      accessFlags: mAccessFlags,
      accessFlagsList: formatAccessFlags(mAccessFlags, 'method'),
      name: getUtf8(mNameIdx),
      descriptor: getUtf8(mDescriptorIdx),
      attributes: mAttributes,
    });
  }

  // Class level attributes
  const attributes = parseAttributesList(reader);

  return {
    magic,
    minorVersion,
    majorVersion,
    constantPool,
    accessFlags,
    accessFlagsList,
    thisClass,
    superClass,
    interfaces,
    fields,
    methods,
    attributes,
  };
}
