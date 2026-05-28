import { ParsedMacho, MachoSegment, MachoSection } from './macho.js';

export interface ObjcMethod {
  name: string;
  types: string;
  imp: bigint | number;
}

export interface ObjcProperty {
  name: string;
  attributes: string;
}

export interface ObjcIvar {
  name: string;
  type: string;
  offset: number;
  size: number;
}

export interface ObjcClass {
  name: string;
  superclassName: string | null;
  methods: ObjcMethod[];
  properties: ObjcProperty[];
  protocols: string[];
  ivars: ObjcIvar[];
}

export interface ObjcProtocol {
  name: string;
  instanceMethods: ObjcMethod[];
  classMethods: ObjcMethod[];
  properties: ObjcProperty[];
}

export interface ParsedObjcMetadata {
  classes: ObjcClass[];
  protocols: ObjcProtocol[];
}

/**
 * Maps a VM address to a file offset within the Mach-O binary.
 */
export function vmToOffset(vmAddr: bigint | number, segments: MachoSegment[]): number | null {
  const addr = BigInt(vmAddr);
  for (const seg of segments) {
    const vmStart = BigInt(seg.vmaddr);
    const vmSize = BigInt(seg.vmsize);
    if (addr >= vmStart && addr < vmStart + vmSize) {
      const fileoff = BigInt(seg.fileoff);
      return Number(fileoff + (addr - vmStart));
    }
  }
  return null;
}

/**
 * Safely reads a pointer value (4 or 8 bytes) from a VM address.
 */
export function readPointer(
  view: DataView,
  vmAddr: bigint | number,
  segments: MachoSegment[],
  is64Bit: boolean,
  isLittleEndian: boolean
): bigint | null {
  const offset = vmToOffset(vmAddr, segments);
  if (offset === null) return null;

  if (is64Bit) {
    if (offset + 8 > view.byteLength) return null;
    return view.getBigUint64(offset, isLittleEndian);
  } else {
    if (offset + 4 > view.byteLength) return null;
    return BigInt(view.getUint32(offset, isLittleEndian));
  }
}

/**
 * Safely reads a null-terminated C-string from a VM address, resolved via either absolute
 * pointer or a relative offset.
 */
export function readCString(
  view: DataView,
  bytes: Uint8Array,
  vmAddr: bigint | number,
  segments: MachoSegment[]
): string | null {
  let offset = vmToOffset(vmAddr, segments);
  if (offset === null || offset >= bytes.length) return null;

  // Let's check if the target has a pointer to a string instead of string itself
  // (e.g. selector refs). If the first 4/8 bytes form a valid VM address that resolves
  // to an offset, let's dereference it first.
  const possiblePtr = bytes.length - offset >= 8 
    ? view.getBigUint64(offset, true) 
    : (bytes.length - offset >= 4 ? BigInt(view.getUint32(offset, true)) : 0n);
  
  if (possiblePtr !== 0n) {
    const derefOffset = vmToOffset(possiblePtr, segments);
    if (derefOffset !== null && derefOffset < bytes.length && bytes[derefOffset] !== 0) {
      offset = derefOffset;
    }
  }

  let str = '';
  for (let i = offset; i < bytes.length; i++) {
    if (bytes[i] === 0) break;
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}

/**
 * Resolves relative references which are common in modern Mach-O Objective-C binaries.
 */
export function resolveRelativeOffset(
  view: DataView,
  baseVmAddr: bigint,
  offsetInStruct: number,
  segments: MachoSegment[],
  isLittleEndian: boolean
): bigint | null {
  const structOffset = vmToOffset(baseVmAddr, segments);
  if (structOffset === null) return null;

  const fieldOffset = structOffset + offsetInStruct;
  if (fieldOffset + 4 > view.byteLength) return null;

  const relVal = view.getInt32(fieldOffset, isLittleEndian);
  const fieldVmAddr = baseVmAddr + BigInt(offsetInStruct);
  return fieldVmAddr + BigInt(relVal);
}

/**
 * Parses Objective-C metadata from a parsed Mach-O structure and its raw binary buffer.
 */
export function parseObjcMetadata(
  macho: ParsedMacho,
  buffer: ArrayBuffer
): ParsedObjcMetadata {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const is64Bit = macho.is64Bit;
  const isLittleEndian = macho.isLittleEndian;
  const segments = macho.segments;

  const classes: ObjcClass[] = [];
  const protocols: ObjcProtocol[] = [];
  const protocolCache = new Map<string, ObjcProtocol>();

  // Helper to parse a method list
  const parseMethodList = (methodListVmAddr: bigint): ObjcMethod[] => {
    if (methodListVmAddr === 0n) return [];
    const listOffset = vmToOffset(methodListVmAddr, segments);
    if (listOffset === null || listOffset + 8 > view.byteLength) return [];

    const entsizeAndFlags = view.getUint32(listOffset, isLittleEndian);
    const count = view.getUint32(listOffset + 4, isLittleEndian);
    const entsize = entsizeAndFlags & 0xffff;
    const isRelative = (entsizeAndFlags & 0x80000000) !== 0;

    const methods: ObjcMethod[] = [];
    let methodOffset = listOffset + 8;

    for (let i = 0; i < count; i++) {
      if (methodOffset + entsize > view.byteLength) break;

      let name = '';
      let types = '';
      let imp: bigint | number = 0n;

      const currentMethodVmAddr = methodListVmAddr + 8n + BigInt(i * entsize);

      if (isRelative) {
        // Relative method_t (offsets are 32-bit signed integers)
        const nameVm = resolveRelativeOffset(view, currentMethodVmAddr, 0, segments, isLittleEndian);
        const typesVm = resolveRelativeOffset(view, currentMethodVmAddr, 4, segments, isLittleEndian);
        const impVm = resolveRelativeOffset(view, currentMethodVmAddr, 8, segments, isLittleEndian);

        if (nameVm) name = readCString(view, bytes, nameVm, segments) || '';
        if (typesVm) types = readCString(view, bytes, typesVm, segments) || '';
        if (impVm) imp = is64Bit ? impVm : Number(impVm);
      } else {
        // Absolute method_t
        if (is64Bit) {
          const nameVm = view.getBigUint64(methodOffset, isLittleEndian);
          const typesVm = view.getBigUint64(methodOffset + 8, isLittleEndian);
          const impVm = view.getBigUint64(methodOffset + 16, isLittleEndian);

          name = readCString(view, bytes, nameVm, segments) || '';
          types = readCString(view, bytes, typesVm, segments) || '';
          imp = impVm;
        } else {
          const nameVm = BigInt(view.getUint32(methodOffset, isLittleEndian));
          const typesVm = BigInt(view.getUint32(methodOffset + 4, isLittleEndian));
          const impVm = BigInt(view.getUint32(methodOffset + 8, isLittleEndian));

          name = readCString(view, bytes, nameVm, segments) || '';
          types = readCString(view, bytes, typesVm, segments) || '';
          imp = Number(impVm);
        }
      }

      methods.push({ name, types, imp });
      methodOffset += entsize;
    }

    return methods;
  };

  // Helper to parse a property list
  const parsePropertyList = (propListVmAddr: bigint): ObjcProperty[] => {
    if (propListVmAddr === 0n) return [];
    const listOffset = vmToOffset(propListVmAddr, segments);
    if (listOffset === null || listOffset + 8 > view.byteLength) return [];

    const entsize = view.getUint32(listOffset, isLittleEndian);
    const count = view.getUint32(listOffset + 4, isLittleEndian);

    const properties: ObjcProperty[] = [];
    let propOffset = listOffset + 8;

    for (let i = 0; i < count; i++) {
      if (propOffset + entsize > view.byteLength) break;

      let name = '';
      let attributes = '';

      if (is64Bit) {
        const nameVm = view.getBigUint64(propOffset, isLittleEndian);
        const attrVm = view.getBigUint64(propOffset + 8, isLittleEndian);
        name = readCString(view, bytes, nameVm, segments) || '';
        attributes = readCString(view, bytes, attrVm, segments) || '';
      } else {
        const nameVm = BigInt(view.getUint32(propOffset, isLittleEndian));
        const attrVm = BigInt(view.getUint32(propOffset + 4, isLittleEndian));
        name = readCString(view, bytes, nameVm, segments) || '';
        attributes = readCString(view, bytes, attrVm, segments) || '';
      }

      properties.push({ name, attributes });
      propOffset += entsize;
    }

    return properties;
  };

  // Helper to parse an ivar list
  const parseIvarList = (ivarListVmAddr: bigint): ObjcIvar[] => {
    if (ivarListVmAddr === 0n) return [];
    const listOffset = vmToOffset(ivarListVmAddr, segments);
    if (listOffset === null || listOffset + 8 > view.byteLength) return [];

    const entsize = view.getUint32(listOffset, isLittleEndian);
    const count = view.getUint32(listOffset + 4, isLittleEndian);

    const ivars: ObjcIvar[] = [];
    let ivarOffset = listOffset + 8;

    for (let i = 0; i < count; i++) {
      if (ivarOffset + entsize > view.byteLength) break;

      let name = '';
      let type = '';
      let offset = 0;
      let size = 0;

      if (is64Bit) {
        const offsetPtr = view.getBigUint64(ivarOffset, isLittleEndian);
        const nameVm = view.getBigUint64(ivarOffset + 8, isLittleEndian);
        const typeVm = view.getBigUint64(ivarOffset + 16, isLittleEndian);
        size = view.getUint32(ivarOffset + 28, isLittleEndian);

        name = readCString(view, bytes, nameVm, segments) || '';
        type = readCString(view, bytes, typeVm, segments) || '';

        const valOffset = vmToOffset(offsetPtr, segments);
        if (valOffset !== null && valOffset + 4 <= view.byteLength) {
          offset = view.getUint32(valOffset, isLittleEndian);
        }
      } else {
        const offsetPtr = BigInt(view.getUint32(ivarOffset, isLittleEndian));
        const nameVm = BigInt(view.getUint32(ivarOffset + 4, isLittleEndian));
        const typeVm = BigInt(view.getUint32(ivarOffset + 8, isLittleEndian));
        size = view.getUint32(ivarOffset + 16, isLittleEndian);

        name = readCString(view, bytes, nameVm, segments) || '';
        type = readCString(view, bytes, typeVm, segments) || '';

        const valOffset = vmToOffset(offsetPtr, segments);
        if (valOffset !== null && valOffset + 4 <= view.byteLength) {
          offset = view.getUint32(valOffset, isLittleEndian);
        }
      }

      ivars.push({ name, type, offset, size });
      ivarOffset += entsize;
    }

    return ivars;
  };

  // Helper to parse protocol list from a pointer
  const parseProtocolList = (protoListVmAddr: bigint): string[] => {
    if (protoListVmAddr === 0n) return [];
    const listOffset = vmToOffset(protoListVmAddr, segments);
    if (listOffset === null || listOffset + 8 > view.byteLength) return [];

    const pointerSize = is64Bit ? 8 : 4;
    const count = is64Bit 
      ? Number(view.getBigUint64(listOffset, isLittleEndian))
      : view.getUint32(listOffset, isLittleEndian);

    const protoNames: string[] = [];

    for (let i = 0; i < count; i++) {
      const fieldOffset = listOffset + pointerSize + (i * pointerSize);
      if (fieldOffset + pointerSize > view.byteLength) break;

      const protoVm = is64Bit 
        ? view.getBigUint64(fieldOffset, isLittleEndian)
        : BigInt(view.getUint32(fieldOffset, isLittleEndian));

      const protoStruct = parseProtocolStruct(protoVm);
      if (protoStruct) {
        protoNames.push(protoStruct.name);
      }
    }

    return protoNames;
  };

  // Helper to parse protocol_t structure
  const parseProtocolStruct = (protoVm: bigint): ObjcProtocol | null => {
    if (protoVm === 0n) return null;

    // We can extract a unique protocol by checking its name
    // Let's resolve the offset of name (isa is first pointer, name is second pointer)
    const namePtrOffset = protoVm + BigInt(is64Bit ? 8 : 4);
    const nameVm = readPointer(view, namePtrOffset, segments, is64Bit, isLittleEndian);
    if (!nameVm) return null;

    const name = readCString(view, bytes, nameVm, segments);
    if (!name) return null;

    if (protocolCache.has(name)) {
      return protocolCache.get(name)!;
    }

    // Resolve pointers based on protocol_t offsets (64-bit offsets)
    // isa (8), name (8), protocols (8), instanceMethods (8), classMethods (8), optionalInstanceMethods (8), optionalClassMethods (8), instanceProperties (8)
    const pointerSize = BigInt(is64Bit ? 8 : 4);
    
    const protocolsPtr = readPointer(view, protoVm + 2n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;
    const instMethodsPtr = readPointer(view, protoVm + 3n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;
    const classMethodsPtr = readPointer(view, protoVm + 4n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;
    const optInstMethodsPtr = readPointer(view, protoVm + 5n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;
    const optClassMethodsPtr = readPointer(view, protoVm + 6n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;
    const instPropertiesPtr = readPointer(view, protoVm + 7n * pointerSize, segments, is64Bit, isLittleEndian) || 0n;

    const instanceMethods = [
      ...parseMethodList(instMethodsPtr),
      ...parseMethodList(optInstMethodsPtr)
    ];

    const classMethods = [
      ...parseMethodList(classMethodsPtr),
      ...parseMethodList(optClassMethodsPtr)
    ];

    const properties = parsePropertyList(instPropertiesPtr);

    const protocol: ObjcProtocol = {
      name,
      instanceMethods,
      classMethods,
      properties
    };

    protocolCache.set(name, protocol);
    protocols.push(protocol);
    return protocol;
  };

  // Find classes section: typically __objc_classlist
  const classListSection = macho.sections.find(s => s.sectname === '__objc_classlist');
  if (classListSection) {
    const listOffset = classListSection.offset;
    const listSize = Number(classListSection.size);
    const ptrSize = is64Bit ? 8 : 4;
    const count = Math.floor(listSize / ptrSize);

    for (let i = 0; i < count; i++) {
      const fieldOffset = listOffset + (i * ptrSize);
      if (fieldOffset + ptrSize > view.byteLength) break;

      const classVm = is64Bit 
        ? view.getBigUint64(fieldOffset, isLittleEndian)
        : BigInt(view.getUint32(fieldOffset, isLittleEndian));

      if (classVm === 0n) continue;

      // Parse class_t
      // isa (8), superclass (8), cache (16), vtable (8), data (8)
      const dataPtrOffset = classVm + BigInt(is64Bit ? 32 : 16);
      const dataVm = readPointer(view, dataPtrOffset, segments, is64Bit, isLittleEndian);
      if (!dataVm) continue;

      // Mask out swift bits
      const cleanDataVm = dataVm & (is64Bit ? ~7n : ~3n);

      // Parse class_ro_t
      // flags (4), instanceStart (4), instanceSize (4), [if 64bit: reserved (4)], ivarLayout (8), name (8), baseMethods (8), baseProtocols (8), ivars (8), weakIvarLayout (8), baseProperties (8)
      const nameFieldOffset = cleanDataVm + BigInt(is64Bit ? 24 : 12);
      const nameVm = readPointer(view, nameFieldOffset, segments, is64Bit, isLittleEndian);
      if (!nameVm) continue;

      const name = readCString(view, bytes, nameVm, segments);
      if (!name) continue;

      // Resolve superclass name
      let superclassName: string | null = null;
      const superclassPtrOffset = classVm + BigInt(is64Bit ? 8 : 4);
      const superclassVm = readPointer(view, superclassPtrOffset, segments, is64Bit, isLittleEndian);
      if (superclassVm && superclassVm !== 0n) {
        // Superclass might be defined in this binary, so we can try to resolve its name
        const superDataVm = readPointer(view, superclassVm + BigInt(is64Bit ? 32 : 16), segments, is64Bit, isLittleEndian);
        if (superDataVm) {
          const cleanSuperDataVm = superDataVm & (is64Bit ? ~7n : ~3n);
          const superNameVm = readPointer(view, cleanSuperDataVm + BigInt(is64Bit ? 24 : 12), segments, is64Bit, isLittleEndian);
          if (superNameVm) {
            superclassName = readCString(view, bytes, superNameVm, segments);
          }
        }
      }

      // Read remaining class_ro_t fields
      const pSize = BigInt(is64Bit ? 8 : 4);
      const methodsFieldOffset = cleanDataVm + BigInt(is64Bit ? 32 : 16);
      const protocolsFieldOffset = cleanDataVm + BigInt(is64Bit ? 40 : 20);
      const ivarsFieldOffset = cleanDataVm + BigInt(is64Bit ? 48 : 24);
      const propertiesFieldOffset = cleanDataVm + BigInt(is64Bit ? 64 : 32);

      const baseMethodsVm = readPointer(view, methodsFieldOffset, segments, is64Bit, isLittleEndian) || 0n;
      const baseProtocolsVm = readPointer(view, protocolsFieldOffset, segments, is64Bit, isLittleEndian) || 0n;
      const ivarsVm = readPointer(view, ivarsFieldOffset, segments, is64Bit, isLittleEndian) || 0n;
      const basePropertiesVm = readPointer(view, propertiesFieldOffset, segments, is64Bit, isLittleEndian) || 0n;

      const methods = parseMethodList(baseMethodsVm);
      const properties = parsePropertyList(basePropertiesVm);
      const ivars = parseIvarList(ivarsVm);
      const classProtos = parseProtocolList(baseProtocolsVm);

      classes.push({
        name,
        superclassName,
        methods,
        properties,
        protocols: classProtos,
        ivars
      });
    }
  }

  // Also search for standalone protocol list: __objc_protolist
  const protolistSection = macho.sections.find(s => s.sectname === '__objc_protolist');
  if (protolistSection) {
    const listOffset = protolistSection.offset;
    const listSize = Number(protolistSection.size);
    const ptrSize = is64Bit ? 8 : 4;
    const count = Math.floor(listSize / ptrSize);

    for (let i = 0; i < count; i++) {
      const fieldOffset = listOffset + (i * ptrSize);
      if (fieldOffset + ptrSize > view.byteLength) break;

      const protoVm = is64Bit
        ? view.getBigUint64(fieldOffset, isLittleEndian)
        : BigInt(view.getUint32(fieldOffset, isLittleEndian));

      parseProtocolStruct(protoVm);
    }
  }

  return {
    classes,
    protocols
  };
}
