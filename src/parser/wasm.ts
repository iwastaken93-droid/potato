/**
 * WebAssembly Binary Format (.wasm) Parser
 *
 * Implements parsing of WebAssembly modules according to the WASM 1.0/2.0 binary specifications.
 * Decodes magic numbers, versions, types, imports, functions, exports, and instructions in the code section.
 */

// WASM Section Codes
export enum SectionId {
  Custom = 0,
  Type = 1,
  Import = 2,
  Function = 3,
  Table = 4,
  Memory = 5,
  Global = 6,
  Export = 7,
  Start = 8,
  Element = 9,
  Code = 10,
  Data = 11,
  DataCount = 12,
}

// WASM Value Types
export enum ValueType {
  I32 = 0x7f,
  I64 = 0x7e,
  F32 = 0x7d,
  F64 = 0x7c,
  V128 = 0x7b,
  FuncRef = 0x70,
  ExternRef = 0x6f,
}

export const ValueTypeNames: Record<number, string> = {
  [ValueType.I32]: 'i32',
  [ValueType.I64]: 'i64',
  [ValueType.F32]: 'f32',
  [ValueType.F64]: 'f64',
  [ValueType.V128]: 'v128',
  [ValueType.FuncRef]: 'funcref',
  [ValueType.ExternRef]: 'externref',
};

// WASM Export Kinds
export enum ExportKind {
  Func = 0,
  Table = 1,
  Mem = 2,
  Global = 3,
}

export const ExportKindNames: Record<number, string> = {
  [ExportKind.Func]: 'function',
  [ExportKind.Table]: 'table',
  [ExportKind.Mem]: 'memory',
  [ExportKind.Global]: 'global',
};

export interface FuncType {
  params: ValueType[];
  results: ValueType[];
}

export interface ImportEntry {
  module: string;
  field: string;
  kind: ExportKind;
  typeIndexOrDesc: number | object;
}

export interface ExportEntry {
  name: string;
  kind: ExportKind;
  index: number;
}

export interface LocalEntry {
  count: number;
  type: ValueType;
}

export interface Instruction {
  offset: number;
  opcode: number;
  mnemonic: string;
  args?: any;
}

export interface FunctionBody {
  locals: LocalEntry[];
  instructions: Instruction[];
  rawBytes: Uint8Array;
}

export interface WasmNames {
  module?: string;
  functions?: Record<number, string>;
  locals?: Record<number, Record<number, string>>;
  labels?: Record<number, Record<number, string>>;
  types?: Record<number, string>;
  tables?: Record<number, string>;
  memories?: Record<number, string>;
  globals?: Record<number, string>;
  elements?: Record<number, string>;
  data?: Record<number, string>;
}

export interface WasmModule {
  magic: number[];
  version: number;
  types: FuncType[];
  imports: ImportEntry[];
  functions: number[]; // indices into types
  exports: ExportEntry[];
  code: FunctionBody[];
  customSections: { name: string; size: number; payload?: Uint8Array }[];
  names?: WasmNames;
  metadata?: Record<string, any>;
}

export class WasmReader {
  private view: DataView;
  public bytes: Uint8Array;
  public pos: number = 0;

  constructor(buffer: ArrayBuffer | Uint8Array) {
    if (buffer instanceof Uint8Array) {
      this.bytes = buffer;
      this.view = new DataView(
        buffer.buffer as ArrayBuffer,
        buffer.byteOffset,
        buffer.byteLength
      );
    } else {
      this.bytes = new Uint8Array(buffer);
      this.view = new DataView(buffer);
    }
  }

  get remaining(): number {
    return this.bytes.length - this.pos;
  }

  readByte(): number {
    if (this.pos >= this.bytes.length) {
      throw new Error(`Unexpected EOF at offset ${this.pos}`);
    }
    return this.bytes[this.pos++];
  }

  readBytes(len: number): Uint8Array {
    if (this.pos + len > this.bytes.length) {
      throw new Error(
        `Unexpected EOF reading ${len} bytes at offset ${this.pos}`
      );
    }
    const slice = this.bytes.subarray(this.pos, this.pos + len);
    this.pos += len;
    return slice;
  }

  // LEB128 unsigned decoding
  readVarUint(): number {
    let result = 0;
    let shift = 0;
    while (true) {
      const byte = this.readByte();
      result |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        break;
      }
      shift += 7;
      if (shift >= 32) {
        // Handle numbers larger than 32-bit if needed, but for typical WASM values number fits in JS safe integer
        // Just return to avoid infinite loops on corrupt files
        break;
      }
    }
    return result;
  }

  // LEB128 signed decoding
  readVarInt(): number {
    let result = 0;
    let shift = 0;
    let byte = 0;
    while (true) {
      byte = this.readByte();
      result |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) {
        break;
      }
      if (shift >= 32) {
        break;
      }
    }
    if (shift < 32 && (byte & 0x40) !== 0) {
      result |= ~0 << shift;
    }
    return result;
  }

  // LEB128 signed 64-bit decoding returning bigint
  readVarInt64(): bigint {
    let result = 0n;
    let shift = 0n;
    let byte = 0;
    while (true) {
      byte = this.readByte();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) {
        break;
      }
    }
    if ((byte & 0x40) !== 0) {
      result |= ~0n << shift;
    }
    return result;
  }

  readF32(): number {
    if (this.pos + 4 > this.bytes.length) {
      throw new Error(`Unexpected EOF reading f32 at offset ${this.pos}`);
    }
    const val = this.view.getFloat32(this.pos, true);
    this.pos += 4;
    return val;
  }

  readF64(): number {
    if (this.pos + 8 > this.bytes.length) {
      throw new Error(`Unexpected EOF reading f64 at offset ${this.pos}`);
    }
    const val = this.view.getFloat64(this.pos, true);
    this.pos += 8;
    return val;
  }

  readString(): string {
    const len = this.readVarUint();
    const bytes = this.readBytes(len);
    return new TextDecoder('utf-8').decode(bytes);
  }

  readVector<T>(readerFn: () => T): T[] {
    const count = this.readVarUint();
    const vec: T[] = [];
    for (let i = 0; i < count; i++) {
      vec.push(readerFn());
    }
    return vec;
  }
}

// Opcode Mnemonic Mapping for standard WASM instructions
const opcodes: Record<number, { name: string; args?: string }> = {
  0x00: { name: 'unreachable' },
  0x01: { name: 'nop' },
  0x02: { name: 'block', args: 'blocktype' },
  0x03: { name: 'loop', args: 'blocktype' },
  0x04: { name: 'if', args: 'blocktype' },
  0x05: { name: 'else' },
  0x0b: { name: 'end' },
  0x0c: { name: 'br', args: 'labelidx' },
  0x0d: { name: 'br_if', args: 'labelidx' },
  0x0e: { name: 'br_table', args: 'br_table' },
  0x0f: { name: 'return' },
  0x10: { name: 'call', args: 'funcidx' },
  0x11: { name: 'call_indirect', args: 'call_indirect' },

  // Parametric instructions
  0x1a: { name: 'drop' },
  0x1b: { name: 'select' },
  0x1c: { name: 'select_t', args: 'valtype_vec' },

  // Variable instructions
  0x20: { name: 'local.get', args: 'localidx' },
  0x21: { name: 'local.set', args: 'localidx' },
  0x22: { name: 'local.tee', args: 'localidx' },
  0x23: { name: 'global.get', args: 'globalidx' },
  0x24: { name: 'global.set', args: 'globalidx' },
  0x25: { name: 'table.get', args: 'tableidx' },
  0x26: { name: 'table.set', args: 'tableidx' },

  // Memory instructions
  0x28: { name: 'i32.load', args: 'memarg' },
  0x29: { name: 'i64.load', args: 'memarg' },
  0x2a: { name: 'f32.load', args: 'memarg' },
  0x2b: { name: 'f64.load', args: 'memarg' },
  0x2c: { name: 'i32.load8_s', args: 'memarg' },
  0x2d: { name: 'i32.load8_u', args: 'memarg' },
  0x2e: { name: 'i32.load16_s', args: 'memarg' },
  0x2f: { name: 'i32.load16_u', args: 'memarg' },
  0x30: { name: 'i64.load8_s', args: 'memarg' },
  0x31: { name: 'i64.load8_u', args: 'memarg' },
  0x32: { name: 'i64.load16_s', args: 'memarg' },
  0x33: { name: 'i64.load16_u', args: 'memarg' },
  0x34: { name: 'i64.load32_s', args: 'memarg' },
  0x35: { name: 'i64.load32_u', args: 'memarg' },
  0x36: { name: 'i32.store', args: 'memarg' },
  0x37: { name: 'i64.store', args: 'memarg' },
  0x38: { name: 'f32.store', args: 'memarg' },
  0x39: { name: 'f64.store', args: 'memarg' },
  0x3a: { name: 'i32.store8', args: 'memarg' },
  0x3b: { name: 'i32.store16', args: 'memarg' },
  0x3c: { name: 'i64.store8', args: 'memarg' },
  0x3d: { name: 'i64.store16', args: 'memarg' },
  0x3e: { name: 'i64.store32', args: 'memarg' },
  0x3f: { name: 'memory.size', args: 'zero' },
  0x40: { name: 'memory.grow', args: 'zero' },

  // Constants
  0x41: { name: 'i32.const', args: 'i32' },
  0x42: { name: 'i64.const', args: 'i64' },
  0x43: { name: 'f32.const', args: 'f32' },
  0x44: { name: 'f64.const', args: 'f64' },

  // Comparison
  0x45: { name: 'i32.eqz' },
  0x46: { name: 'i32.eq' },
  0x47: { name: 'i32.ne' },
  0x48: { name: 'i32.lt_s' },
  0x49: { name: 'i32.lt_u' },
  0x4a: { name: 'i32.gt_s' },
  0x4b: { name: 'i32.gt_u' },
  0x4c: { name: 'i32.le_s' },
  0x4d: { name: 'i32.le_u' },
  0x4e: { name: 'i32.ge_s' },
  0x4f: { name: 'i32.ge_u' },

  0x50: { name: 'i64.eqz' },
  0x51: { name: 'i64.eq' },
  0x52: { name: 'i64.ne' },
  0x53: { name: 'i64.lt_s' },
  0x54: { name: 'i64.lt_u' },
  0x55: { name: 'i64.gt_s' },
  0x56: { name: 'i64.gt_u' },
  0x57: { name: 'i64.le_s' },
  0x58: { name: 'i64.le_u' },
  0x59: { name: 'i64.ge_s' },
  0x5a: { name: 'i64.ge_u' },

  0x5b: { name: 'f32.eq' },
  0x5c: { name: 'f32.ne' },
  0x5d: { name: 'f32.lt' },
  0x5e: { name: 'f32.gt' },
  0x5f: { name: 'f32.le' },
  0x60: { name: 'f32.ge' },

  0x61: { name: 'f64.eq' },
  0x62: { name: 'f64.ne' },
  0x63: { name: 'f64.lt' },
  0x64: { name: 'f64.gt' },
  0x65: { name: 'f64.le' },
  0x66: { name: 'f64.ge' },

  // Numeric
  0x67: { name: 'i32.clz' },
  0x68: { name: 'i32.ctz' },
  0x69: { name: 'i32.popcnt' },
  0x6a: { name: 'i32.add' },
  0x6b: { name: 'i32.sub' },
  0x6c: { name: 'i32.mul' },
  0x6d: { name: 'i32.div_s' },
  0x6e: { name: 'i32.div_u' },
  0x6f: { name: 'i32.rem_s' },
  0x70: { name: 'i32.rem_u' },
  0x71: { name: 'i32.and' },
  0x72: { name: 'i32.or' },
  0x73: { name: 'i32.xor' },
  0x74: { name: 'i32.shl' },
  0x75: { name: 'i32.shr_s' },
  0x76: { name: 'i32.shr_u' },
  0x77: { name: 'i32.rotl' },
  0x78: { name: 'i32.rotr' },

  0x79: { name: 'i64.clz' },
  0x7a: { name: 'i64.ctz' },
  0x7b: { name: 'i64.popcnt' },
  0x7c: { name: 'i64.add' },
  0x7d: { name: 'i64.sub' },
  0x7e: { name: 'i64.mul' },
  0x7f: { name: 'i64.div_s' },
  0x80: { name: 'i64.div_u' },
  0x81: { name: 'i64.rem_s' },
  0x82: { name: 'i64.rem_u' },
  0x83: { name: 'i64.and' },
  0x84: { name: 'i64.or' },
  0x85: { name: 'i64.xor' },
  0x86: { name: 'i64.shl' },
  0x87: { name: 'i64.shr_s' },
  0x88: { name: 'i64.shr_u' },
  0x89: { name: 'i64.rotl' },
  0x8a: { name: 'i64.rotr' },

  0x8b: { name: 'f32.abs' },
  0x8c: { name: 'f32.neg' },
  0x8d: { name: 'f32.ceil' },
  0x8e: { name: 'f32.floor' },
  0x8f: { name: 'f32.trunc' },
  0x90: { name: 'f32.nearest' },
  0x91: { name: 'f32.sqrt' },
  0x92: { name: 'f32.add' },
  0x93: { name: 'f32.sub' },
  0x94: { name: 'f32.mul' },
  0x95: { name: 'f32.div' },
  0x96: { name: 'f32.min' },
  0x97: { name: 'f32.max' },
  0x98: { name: 'f32.copysign' },

  0x99: { name: 'f64.abs' },
  0x9a: { name: 'f64.neg' },
  0x9b: { name: 'f64.ceil' },
  0x9c: { name: 'f64.floor' },
  0x9d: { name: 'f64.trunc' },
  0x9e: { name: 'f64.nearest' },
  0x9f: { name: 'f64.sqrt' },
  0xa0: { name: 'f64.add' },
  0xa1: { name: 'f64.sub' },
  0xa2: { name: 'f64.mul' },
  0xa3: { name: 'f64.div' },
  0xa4: { name: 'f64.min' },
  0xa5: { name: 'f64.max' },
  0xa6: { name: 'f64.copysign' },

  // Conversions
  0xa7: { name: 'i32.wrap_i64' },
  0xa8: { name: 'i32.trunc_f32_s' },
  0xa9: { name: 'i32.trunc_f32_u' },
  0xaa: { name: 'i32.trunc_f64_s' },
  0xab: { name: 'i32.trunc_f64_u' },
  0xac: { name: 'i64.extend_i32_s' },
  0xad: { name: 'i64.extend_i32_u' },
  0xae: { name: 'i64.trunc_f32_s' },
  0xaf: { name: 'i64.trunc_f32_u' },
  0xb0: { name: 'i64.trunc_f64_s' },
  0xb1: { name: 'i64.trunc_f64_u' },
  0xb2: { name: 'f32.convert_i32_s' },
  0xb3: { name: 'f32.convert_i32_u' },
  0xb4: { name: 'f32.convert_i64_s' },
  0xb5: { name: 'f32.convert_i64_u' },
  0xb6: { name: 'f32.demote_f64' },
  0xb7: { name: 'f64.convert_i32_s' },
  0xb8: { name: 'f64.convert_i32_u' },
  0xb9: { name: 'f64.convert_i64_s' },
  0xba: { name: 'f64.convert_i64_u' },
  0xbb: { name: 'f64.promote_f32' },
  0xbc: { name: 'i32.reinterpret_f32' },
  0xbd: { name: 'i64.reinterpret_f64' },
  0xbe: { name: 'f32.reinterpret_i32' },
  0xbf: { name: 'f64.reinterpret_i64' },
};

/**
 * Parses instructions from WebAssembly bytecode stream.
 */
export function parseInstructions(
  reader: WasmReader,
  endOffset: number
): Instruction[] {
  if (endOffset > reader.bytes.length) {
    throw new Error(`endOffset ${endOffset} extends beyond EOF`);
  }
  const instructions: Instruction[] = [];

  while (reader.pos < endOffset) {
    const offset = reader.pos;
    const opcode = reader.readByte();

    // Check if opcode exists in map
    const op = opcodes[opcode];
    const mnemonic = op ? op.name : `unknown_0x${opcode.toString(16)}`;
    const argsType = op ? op.args : undefined;
    let args: any = undefined;

    if (argsType) {
      switch (argsType) {
        case 'blocktype': {
          const typeVal = reader.readVarInt();
          args = { blockType: typeVal };
          break;
        }
        case 'labelidx':
        case 'funcidx':
        case 'localidx':
        case 'globalidx':
        case 'tableidx': {
          args = reader.readVarUint();
          break;
        }
        case 'br_table': {
          const targets = reader.readVector(() => reader.readVarUint());
          const defaultTarget = reader.readVarUint();
          args = { targets, defaultTarget };
          break;
        }
        case 'call_indirect': {
          const typeIdx = reader.readVarUint();
          const tableIdx = reader.readVarUint();
          args = { typeIdx, tableIdx };
          break;
        }
        case 'memarg': {
          const align = reader.readVarUint();
          const memOffset = reader.readVarUint();
          args = { align, offset: memOffset };
          break;
        }
        case 'zero': {
          args = reader.readByte(); // usually 0x00 reserved byte
          break;
        }
        case 'i32': {
          args = reader.readVarInt();
          break;
        }
        case 'i64': {
          args = reader.readVarInt64();
          break;
        }
        case 'f32': {
          args = reader.readF32();
          break;
        }
        case 'f64': {
          args = reader.readF64();
          break;
        }
        case 'valtype_vec': {
          args = reader.readVector(() => reader.readByte());
          break;
        }
      }
    }

    instructions.push({ offset, opcode, mnemonic, args });

    // Stop parsing if we reach the end of the block/function (which is marked by end code 0x0f or 0x0b in some contexts,
    // but code section functions end with 0x0b).
    // Note: We parse up to the defined size in code section, so this loop terminates naturally at endOffset.
  }

  return instructions;
}

/**
 * Parses a complete WebAssembly binary module.
 */
export function parseWasm(binary: ArrayBuffer | Uint8Array): WasmModule {
  const reader = new WasmReader(binary);

  // Magic number verification
  const magic = [
    reader.readByte(),
    reader.readByte(),
    reader.readByte(),
    reader.readByte(),
  ];

  if (
    magic[0] !== 0x00 ||
    magic[1] !== 0x61 ||
    magic[2] !== 0x73 ||
    magic[3] !== 0x6d
  ) {
    throw new Error(
      `Invalid WebAssembly magic number: ${magic.map((b) => b.toString(16).padStart(2, '0')).join(' ')}`
    );
  }

  // Version verification
  const version =
    reader.readByte() |
    (reader.readByte() << 8) |
    (reader.readByte() << 16) |
    (reader.readByte() << 24);

  if (version !== 1) {
    // WASM specification standard version is 1
    console.warn(`WASM version is ${version}, expected 1.`);
  }

  const module: WasmModule = {
    magic,
    version,
    types: [],
    imports: [],
    functions: [],
    exports: [],
    code: [],
    customSections: [],
  };

  while (reader.remaining > 0) {
    const sectionId = reader.readByte() as SectionId;
    const sectionSize = reader.readVarUint();
    const sectionEnd = reader.pos + sectionSize;

    if (sectionEnd > reader.bytes.length) {
      throw new Error(`Section size ${sectionSize} extends beyond EOF`);
    }

    switch (sectionId) {
      case SectionId.Type: {
        module.types = reader.readVector(() => {
          const form = reader.readByte();
          if (form !== 0x60) {
            throw new Error(
              `Invalid function type form: 0x${form.toString(16)}, expected 0x60`
            );
          }
          const params = reader.readVector(
            () => reader.readByte() as ValueType
          );
          const results = reader.readVector(
            () => reader.readByte() as ValueType
          );
          return { params, results };
        });
        break;
      }

      case SectionId.Import: {
        module.imports = reader.readVector(() => {
          const modName = reader.readString();
          const fieldName = reader.readString();
          const kind = reader.readByte() as ExportKind;
          let typeIndexOrDesc: number | object;

          if (kind === ExportKind.Func) {
            typeIndexOrDesc = reader.readVarUint();
          } else if (kind === ExportKind.Table) {
            const refType = reader.readByte();
            const hasMax = reader.readByte();
            const min = reader.readVarUint();
            const max = hasMax ? reader.readVarUint() : undefined;
            typeIndexOrDesc = { refType, min, max };
          } else if (kind === ExportKind.Mem) {
            const hasMax = reader.readByte();
            const min = reader.readVarUint();
            const max = hasMax ? reader.readVarUint() : undefined;
            typeIndexOrDesc = { min, max };
          } else if (kind === ExportKind.Global) {
            const valType = reader.readByte() as ValueType;
            const mutable = reader.readByte() !== 0;
            typeIndexOrDesc = { valType, mutable };
          } else {
            throw new Error(`Unknown import kind: ${kind}`);
          }

          return {
            module: modName,
            field: fieldName,
            kind,
            typeIndexOrDesc,
          };
        });
        break;
      }

      case SectionId.Function: {
        module.functions = reader.readVector(() => reader.readVarUint());
        break;
      }

      case SectionId.Export: {
        module.exports = reader.readVector(() => {
          const name = reader.readString();
          const kind = reader.readByte() as ExportKind;
          const index = reader.readVarUint();
          return { name, kind, index };
        });
        break;
      }

      case SectionId.Code: {
        module.code = reader.readVector(() => {
          const bodySize = reader.readVarUint();
          const bodyEnd = reader.pos + bodySize;

          // Read local variables declarations
          const locals = reader.readVector(() => {
            const count = reader.readVarUint();
            const type = reader.readByte() as ValueType;
            return { count, type };
          });

          // Read raw body bytes
          const instStart = reader.pos;
          const rawBytes = reader.bytes.slice(instStart, bodyEnd);

          // Parse standard instructions
          const bodyReader = new WasmReader(rawBytes);
          const instructions = parseInstructions(bodyReader, rawBytes.length);

          // Advance global reader pos to bodyEnd
          reader.pos = bodyEnd;

          return {
            locals,
            instructions,
            rawBytes,
          };
        });
        break;
      }

      case SectionId.Custom: {
        const name = reader.readString();
        const customPayloadSize = sectionEnd - reader.pos;
        const payload = reader.readBytes(customPayloadSize);
        module.customSections.push({
          name,
          size: customPayloadSize,
          payload,
        });

        if (name === 'name') {
          module.names = parseNameSection(payload);
        } else {
          if (!module.metadata) {
            module.metadata = {};
          }
          const parsed = parseMetadataSection(name, payload);
          if (parsed !== undefined) {
            module.metadata[name] = parsed;
          }
        }

        reader.pos = sectionEnd; // Skip the rest of the custom section
        break;
      }

      default: {
        // Skip unhandled section
        reader.pos = sectionEnd;
        break;
      }
    }

    // Guard to ensure reader alignment matches the section sizes
    if (reader.pos !== sectionEnd) {
      console.warn(
        `Section boundary mismatch. Aligning pos from ${reader.pos} to ${sectionEnd}`
      );
      reader.pos = sectionEnd;
    }
  }

  return module;
}

/**
 * Parses the 'name' custom section payload.
 */
export function parseNameSection(payload: Uint8Array): WasmNames {
  const reader = new WasmReader(payload);
  const names: WasmNames = {};

  while (reader.remaining > 0) {
    try {
      const subId = reader.readByte();
      const subSize = reader.readVarUint();
      const subEnd = reader.pos + subSize;

      if (subEnd > reader.bytes.length) {
        throw new Error(`Sub-section size ${subSize} extends beyond EOF`);
      }

      if (subId === 0) {
        // Module name
        names.module = reader.readString();
      } else if (subId === 1) {
        // Function names
        names.functions = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.functions[idx] = name;
        }
      } else if (subId === 2) {
        // Local names
        names.locals = {};
        const funcCount = reader.readVarUint();
        for (let i = 0; i < funcCount; i++) {
          const funcIdx = reader.readVarUint();
          const localMap: Record<number, string> = {};
          const localCount = reader.readVarUint();
          for (let j = 0; j < localCount; j++) {
            const localIdx = reader.readVarUint();
            const name = reader.readString();
            localMap[localIdx] = name;
          }
          names.locals[funcIdx] = localMap;
        }
      } else if (subId === 3) {
        // Label names
        names.labels = {};
        const funcCount = reader.readVarUint();
        for (let i = 0; i < funcCount; i++) {
          const funcIdx = reader.readVarUint();
          const labelMap: Record<number, string> = {};
          const labelCount = reader.readVarUint();
          for (let j = 0; j < labelCount; j++) {
            const labelIdx = reader.readVarUint();
            const name = reader.readString();
            labelMap[labelIdx] = name;
          }
          names.labels[funcIdx] = labelMap;
        }
      } else if (subId === 4) {
        // Type names
        names.types = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.types[idx] = name;
        }
      } else if (subId === 5) {
        // Table names
        names.tables = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.tables[idx] = name;
        }
      } else if (subId === 6) {
        // Memory names
        names.memories = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.memories[idx] = name;
        }
      } else if (subId === 7) {
        // Global names
        names.globals = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.globals[idx] = name;
        }
      } else if (subId === 8) {
        // Element names
        names.elements = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.elements[idx] = name;
        }
      } else if (subId === 9) {
        // Data names
        names.data = {};
        const count = reader.readVarUint();
        for (let i = 0; i < count; i++) {
          const idx = reader.readVarUint();
          const name = reader.readString();
          names.data[idx] = name;
        }
      }

      reader.pos = subEnd;
    } catch (e) {
      console.warn(`Error parsing name subsection:`, e);
      break;
    }
  }

  return names;
}

/**
 * Parses other custom metadata sections (e.g., 'producers', 'target_features', etc.).
 */
export function parseMetadataSection(name: string, payload: Uint8Array): any {
  const reader = new WasmReader(payload);
  try {
    if (name === 'producers') {
      const fields: Record<string, Record<string, string>> = {};
      const fieldCount = reader.readVarUint();
      for (let i = 0; i < fieldCount; i++) {
        const fieldName = reader.readString();
        const values: Record<string, string> = {};
        const valueCount = reader.readVarUint();
        for (let j = 0; j < valueCount; j++) {
          const valName = reader.readString();
          const valVersion = reader.readString();
          values[valName] = valVersion;
        }
        fields[fieldName] = values;
      }
      return fields;
    }

    if (name === 'target_features') {
      const features: string[] = [];
      const count = reader.readVarUint();
      for (let i = 0; i < count; i++) {
        const prefixByte = reader.readByte();
        const prefix =
          prefixByte === 0x2b ? '+' : prefixByte === 0x2d ? '-' : '';
        const featureName = reader.readString();
        features.push(`${prefix}${featureName}`);
      }
      return features;
    }

    if (name === 'sourceMappingURL') {
      return new TextDecoder('utf-8').decode(payload);
    }

    // Attempt text decode; if invalid UTF-8, fall back to number array
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      return decoder.decode(payload);
    } catch {
      return Array.from(payload);
    }
  } catch (e) {
    console.warn(`Error parsing custom section ${name}:`, e);
    return Array.from(payload);
  }
}
