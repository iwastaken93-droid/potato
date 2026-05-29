/**
 * DEX (Dalvik Executable) File Parser
 * Supports DEX magic detection, class defs, string IDs, type IDs, method IDs, and mock assembly generation for Android bytecode.
 */

export interface DexHeader {
  magic: string;
  checksum: number;
  signature: Uint8Array;
  fileSize: number;
  headerSize: number;
  endianTag: number;
  linkSize: number;
  linkOff: number;
  mapOff: number;
  stringIdsSize: number;
  stringIdsOff: number;
  typeIdsSize: number;
  typeIdsOff: number;
  protoIdsSize: number;
  protoIdsOff: number;
  fieldIdsSize: number;
  fieldIdsOff: number;
  methodIdsSize: number;
  methodIdsOff: number;
  classDefsSize: number;
  classDefsOff: number;
  dataSize: number;
  dataOff: number;
  isBigEndian: boolean;
  littleEndian: boolean;
}

export interface DexClass {
  classIdx: number;
  name: string;
  accessFlags: number;
  superclassIdx: number;
  interfacesOff: number;
  sourceFileIdx: number;
  annotationsOff: number;
  classDataOff: number;
  staticValuesOff: number;
}

export interface TypeId {
  descriptor: string;
}

export interface ProtoId {
  shorty: string;
  returnType: string;
  parameters: string[];
}

export interface MethodId {
  className: string;
  methodName: string;
}

export interface TryItem {
  startAddr: number;
  insnCount: number;
  handler: CatchHandler;
}

export interface CatchHandler {
  handlers: { typeName: string; addr: number }[];
  catchAllAddr?: number;
}

export interface CodeItem {
  registersSize: number;
  insSize: number;
  triesSize: number;
  insnsSize: number;
  insns: number[];
  tries: TryItem[];
}

export interface ClassMethod {
  method: MethodId;
  accessFlags: number;
  codeItem: CodeItem | null;
}

export interface ClassData {
  directMethods: ClassMethod[];
  virtualMethods: ClassMethod[];
}

export interface ClassDef {
  className: string;
  superclassName: string;
  classData: ClassData | null;
}

export interface ParsedDex {
  header: DexHeader;
  classes: DexClass[];
  strings: string[];
  methods: string[];
  typeIds: TypeId[];
  protoIds: ProtoId[];
  methodIds: MethodId[];
  classDefs: ClassDef[];
  entryPoint: number;
}

export class DexParser {
  private data: Uint8Array;
  private view: DataView;

  constructor(buffer: ArrayBuffer | Uint8Array) {
    this.data = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    this.view = new DataView(
      this.data.buffer,
      this.data.byteOffset,
      this.data.byteLength
    );
  }

  public parse(): ParsedDex {
    if (this.data.length < 0x70) {
      throw new Error('Buffer too small to be a DEX file');
    }

    // Parse Magic: 'dex\n035\0' etc.
    let magic = '';
    for (let i = 0; i < 8; i++) {
      magic += String.fromCharCode(this.data[i]);
    }
    if (!magic.startsWith('dex\n')) {
      throw new Error('Invalid DEX Magic header');
    }

    const checksum = this.view.getUint32(8, true);
    const signature = this.data.slice(12, 32);
    const fileSize = this.view.getUint32(32, true);
    const headerSize = this.view.getUint32(36, true);
    const endianTag = this.view.getUint32(40, true);

    const isBigEndian = endianTag === 0x78563412;
    const le = !isBigEndian;

    const linkSize = this.view.getUint32(44, le);
    const linkOff = this.view.getUint32(48, le);
    const mapOff = this.view.getUint32(52, le);
    const stringIdsSize = this.view.getUint32(56, le);
    const stringIdsOff = this.view.getUint32(60, le);
    const typeIdsSize = this.view.getUint32(64, le);
    const typeIdsOff = this.view.getUint32(68, le);
    const protoIdsSize = this.view.getUint32(72, le);
    const protoIdsOff = this.view.getUint32(76, le);
    const fieldIdsSize = this.view.getUint32(80, le);
    const fieldIdsOff = this.view.getUint32(84, le);
    const methodIdsSize = this.view.getUint32(88, le);
    const methodIdsOff = this.view.getUint32(92, le);
    const classDefsSize = this.view.getUint32(96, le);
    const classDefsOff = this.view.getUint32(100, le);
    const dataSize = this.view.getUint32(104, le);
    const dataOff = this.view.getUint32(108, le);

    const header: DexHeader = {
      magic,
      checksum,
      signature,
      fileSize,
      headerSize,
      endianTag,
      linkSize,
      linkOff,
      mapOff,
      stringIdsSize,
      stringIdsOff,
      typeIdsSize,
      typeIdsOff,
      protoIdsSize,
      protoIdsOff,
      fieldIdsSize,
      fieldIdsOff,
      methodIdsSize,
      methodIdsOff,
      classDefsSize,
      classDefsOff,
      dataSize,
      dataOff,
      isBigEndian,
      littleEndian: le,
    };

    // Parse Strings
    const strings: string[] = [];
    for (let i = 0; i < stringIdsSize; i++) {
      const offsetPos = stringIdsOff + i * 4;
      if (offsetPos + 4 > this.data.length) break;
      const stringDataOff = this.view.getUint32(offsetPos, le);

      // Dex strings are MUTF-8. First byte is ULEB128 string length.
      if (stringDataOff < this.data.length) {
        const ref = { offset: stringDataOff };
        const strLen = readUleb128(this.data, ref);
        const remainingBytes = this.data.slice(ref.offset);
        const strVal = decodeMutf8(remainingBytes);
        strings.push(strVal);
      }
    }

    // Parse Types (indexes into string IDs)
    const types: string[] = [];
    const typeIds: TypeId[] = [];
    for (let i = 0; i < typeIdsSize; i++) {
      const typePos = typeIdsOff + i * 4;
      if (typePos + 4 > this.data.length) break;
      const stringIdx = this.view.getUint32(typePos, le);
      const desc = strings[stringIdx] || `Type_${stringIdx}`;
      types.push(desc);
      typeIds.push({ descriptor: desc });
    }

    // Parse Proto IDs
    const protoIds: ProtoId[] = [];
    for (let i = 0; i < protoIdsSize; i++) {
      const protoPos = protoIdsOff + i * 12;
      if (protoPos + 12 > this.data.length) break;
      const shortyIdx = this.view.getUint32(protoPos, le);
      const returnTypeIdx = this.view.getUint32(protoPos + 4, le);
      const parametersOff = this.view.getUint32(protoPos + 8, le);

      const parameters: string[] = [];
      if (parametersOff !== 0 && parametersOff < this.data.length) {
        const paramSize = this.view.getUint32(parametersOff, le);
        for (let p = 0; p < paramSize; p++) {
          const typeIdx = this.view.getUint16(parametersOff + 4 + p * 2, le);
          parameters.push(types[typeIdx] || `Type_${typeIdx}`);
        }
      }

      protoIds.push({
        shorty: strings[shortyIdx] || '',
        returnType: types[returnTypeIdx] || '',
        parameters,
      });
    }

    // Parse Methods
    const methods: string[] = [];
    const methodIds: MethodId[] = [];
    for (let i = 0; i < methodIdsSize; i++) {
      const methodPos = methodIdsOff + i * 8;
      if (methodPos + 8 > this.data.length) break;
      const classIdx = this.view.getUint16(methodPos, le);
      const nameIdx = this.view.getUint32(methodPos + 4, le);

      const className = types[classIdx] || `Class_${classIdx}`;
      const methodName = strings[nameIdx] || `method_${nameIdx}`;
      methods.push(`${className}->${methodName}`);
      methodIds.push({ className, methodName });
    }

    // Parse Classes
    const classes: DexClass[] = [];
    const classDefs: ClassDef[] = [];
    for (let i = 0; i < classDefsSize; i++) {
      const classDefPos = classDefsOff + i * 32;
      if (classDefPos + 32 > this.data.length) break;

      const classIdx = this.view.getUint32(classDefPos, le);
      const accessFlags = this.view.getUint32(classDefPos + 4, le);
      const superclassIdx = this.view.getUint32(classDefPos + 8, le);
      const interfacesOff = this.view.getUint32(classDefPos + 12, le);
      const sourceFileIdx = this.view.getUint32(classDefPos + 16, le);
      const annotationsOff = this.view.getUint32(classDefPos + 20, le);
      const classDataOff = this.view.getUint32(classDefPos + 24, le);
      const staticValuesOff = this.view.getUint32(classDefPos + 28, le);

      const className = types[classIdx] || `Class_${classIdx}`;
      const superclassName = types[superclassIdx] || `Class_${superclassIdx}`;

      classes.push({
        classIdx,
        name: className,
        accessFlags,
        superclassIdx,
        interfacesOff,
        sourceFileIdx,
        annotationsOff,
        classDataOff,
        staticValuesOff,
      });

      let classData: ClassData | null = null;
      if (classDataOff !== 0 && classDataOff < this.data.length) {
        const ref = { offset: classDataOff };
        const staticFieldsSize = readUleb128(this.data, ref);
        const instanceFieldsSize = readUleb128(this.data, ref);
        const directMethodsSize = readUleb128(this.data, ref);
        const virtualMethodsSize = readUleb128(this.data, ref);

        // Skip static fields
        for (let f = 0; f < staticFieldsSize; f++) {
          readUleb128(this.data, ref); // field_idx_diff
          readUleb128(this.data, ref); // access_flags
        }
        // Skip instance fields
        for (let f = 0; f < instanceFieldsSize; f++) {
          readUleb128(this.data, ref); // field_idx_diff
          readUleb128(this.data, ref); // access_flags
        }

        const parseMethodsList = (size: number): ClassMethod[] => {
          const list: ClassMethod[] = [];
          let methodIdx = 0;
          for (let m = 0; m < size; m++) {
            const methodIdxDiff = readUleb128(this.data, ref);
            const mAccessFlags = readUleb128(this.data, ref);
            const codeOff = readUleb128(this.data, ref);
            methodIdx += methodIdxDiff;

            let codeItem: CodeItem | null = null;
            if (codeOff !== 0 && codeOff < this.data.length) {
              const regSize = this.view.getUint16(codeOff, le);
              const insSize = this.view.getUint16(codeOff + 2, le);
              const outsSize = this.view.getUint16(codeOff + 4, le);
              const triesSize = this.view.getUint16(codeOff + 6, le);
              const debugInfoOff = this.view.getUint32(codeOff + 8, le);
              const insnsSize = this.view.getUint32(codeOff + 12, le);

              const insns: number[] = [];
              for (let insIdx = 0; insIdx < insnsSize; insIdx++) {
                insns.push(this.view.getUint16(codeOff + 16 + insIdx * 2, le));
              }

              const tries: TryItem[] = [];
              if (triesSize > 0) {
                const triesStartOff =
                  codeOff + 16 + insnsSize * 2 + (insnsSize % 2 !== 0 ? 2 : 0);
                const handlersStartOff = triesStartOff + triesSize * 8;

                // Decode list size to find where handlers actually start
                const listSizeRef = { offset: handlersStartOff };
                readUleb128(this.data, listSizeRef);
                const listSizeSize = listSizeRef.offset - handlersStartOff;

                for (let t = 0; t < triesSize; t++) {
                  const tryItemOff = triesStartOff + t * 8;
                  const startAddr = this.view.getUint32(tryItemOff, le);
                  const insnCount = this.view.getUint16(tryItemOff + 4, le);
                  const handlerOff = this.view.getUint16(tryItemOff + 6, le);

                  const handlerRef = { offset: handlersStartOff + handlerOff };
                  const sizeRaw = readSleb128(this.data, handlerRef);
                  const handlersCount = Math.abs(sizeRaw);

                  const handlersList: { typeName: string; addr: number }[] = [];
                  for (let h = 0; h < handlersCount; h++) {
                    const tIdx = readUleb128(this.data, handlerRef);
                    const addr = readUleb128(this.data, handlerRef);
                    handlersList.push({
                      typeName: types[tIdx] || `Type_${tIdx}`,
                      addr,
                    });
                  }

                  let catchAllAddr: number | undefined = undefined;
                  if (sizeRaw <= 0) {
                    catchAllAddr = readUleb128(this.data, handlerRef);
                  }

                  tries.push({
                    startAddr,
                    insnCount,
                    handler: {
                      handlers: handlersList,
                      catchAllAddr,
                    },
                  });
                }
              }

              codeItem = {
                registersSize: regSize,
                insSize,
                triesSize,
                insnsSize,
                insns,
                tries,
              };
            }

            list.push({
              method: methodIds[methodIdx],
              accessFlags: mAccessFlags,
              codeItem,
            });
          }
          return list;
        };

        const directMethods = parseMethodsList(directMethodsSize);
        const virtualMethods = parseMethodsList(virtualMethodsSize);
        classData = { directMethods, virtualMethods };
      }

      classDefs.push({
        className,
        superclassName,
        classData,
      });
    }

    return {
      header,
      classes,
      strings,
      methods,
      typeIds,
      protoIds,
      methodIds,
      classDefs,
      entryPoint: 0,
    };
  }
}

export function parseDex(buffer: ArrayBuffer | Uint8Array): ParsedDex {
  return new DexParser(buffer).parse();
}

export function readUleb128(
  bytes: Uint8Array,
  ref: { offset: number }
): number {
  let result = 0;
  let shift = 0;
  while (ref.offset < bytes.length) {
    const byte = bytes[ref.offset++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7;
  }
  return result;
}

export function readSleb128(
  bytes: Uint8Array,
  ref: { offset: number }
): number {
  let result = 0;
  let shift = 0;
  let byte = 0;
  while (ref.offset < bytes.length) {
    byte = bytes[ref.offset++];
    result |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) {
      break;
    }
  }
  if (shift < 32 && (byte & 0x40) !== 0) {
    result |= -(1 << shift);
  }
  return result;
}

export function decodeMutf8(bytes: Uint8Array): string {
  let result = '';
  let i = 0;
  while (i < bytes.length) {
    const b1 = bytes[i++];
    if (b1 === 0) {
      break;
    }
    if ((b1 & 0x80) === 0) {
      result += String.fromCharCode(b1);
    } else if ((b1 & 0xe0) === 0xc0) {
      const b2 = bytes[i++];
      if (b1 === 0xc0 && b2 === 0x80) {
        result += '\0';
      } else {
        result += String.fromCharCode(((b1 & 0x1f) << 6) | (b2 & 0x3f));
      }
    } else if ((b1 & 0xf0) === 0xe0) {
      const b2 = bytes[i++];
      const b3 = bytes[i++];
      result += String.fromCharCode(
        ((b1 & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f)
      );
    }
  }
  return result;
}

export function parseAccessFlags(flags: number): string[] {
  const list: string[] = [];
  if (flags & 0x0001) list.push('public');
  if (flags & 0x0002) list.push('private');
  if (flags & 0x0004) list.push('protected');
  if (flags & 0x0008) list.push('static');
  if (flags & 0x0010) list.push('final');
  if (flags & 0x0020) list.push('synchronized');
  if (flags & 0x0040) list.push('bridge');
  if (flags & 0x0080) list.push('varargs');
  if (flags & 0x00100) list.push('native');
  if (flags & 0x00200) list.push('interface');
  if (flags & 0x00400) list.push('abstract');
  if (flags & 0x00800) list.push('strictfp');
  if (flags & 0x001000) list.push('synthetic');
  if (flags & 0x002000) list.push('annotation');
  if (flags & 0x004000) list.push('enum');
  return list;
}
