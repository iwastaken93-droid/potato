import { Instruction, Operand } from './types.js';
import { parseWasm } from '../parser/wasm.js';

/**
 * WebAssembly Disassembly.
 */
export function disassembleWasm(data: Uint8Array): Instruction[] {
  try {
    const wasmModule = parseWasm(data);
    const instructions: Instruction[] = [];

    for (let i = 0; i < wasmModule.code.length; i++) {
      const body = wasmModule.code[i];

      for (let j = 0; j < body.instructions.length; j++) {
        const wasmInst = body.instructions[j];
        const nextInst = body.instructions[j + 1];
        const instSize = nextInst ? nextInst.offset - wasmInst.offset : 1;

        // Extract instruction bytes if available
        const instBytes = body.rawBytes.subarray(
          wasmInst.offset,
          Math.min(wasmInst.offset + instSize, body.rawBytes.length)
        );

        // Convert WASM operands
        const operands: Operand[] = [];
        let opStr = '';

        if (wasmInst.args !== undefined) {
          if (
            typeof wasmInst.args === 'number' ||
            typeof wasmInst.args === 'bigint'
          ) {
            operands.push({
              type: 'imm',
              imm: Number(wasmInst.args),
            });
            opStr = wasmInst.args.toString();
          } else if (Array.isArray(wasmInst.args)) {
            opStr = wasmInst.args.join(', ');
            wasmInst.args.forEach((arg: any) => {
              if (typeof arg === 'number') {
                operands.push({ type: 'imm', imm: arg });
              }
            });
          } else if (
            typeof wasmInst.args === 'object' &&
            wasmInst.args !== null
          ) {
            opStr = JSON.stringify(wasmInst.args);
          } else {
            opStr = String(wasmInst.args);
          }
        }

        instructions.push({
          address: wasmInst.offset,
          bytes:
            instBytes.length > 0
              ? instBytes
              : new Uint8Array([wasmInst.opcode]),
          mnemonic: wasmInst.mnemonic,
          opStr,
          operands,
          size: instSize,
        });
      }
    }

    return instructions;
  } catch (e) {
    console.error(
      'Failed to parse WASM binary, falling back to mock WASM stream:',
      e
    );
    return generateFallbackWasm(data);
  }
}

/**
 * Fallback mock WASM generator for partial WASM binaries.
 */
function generateFallbackWasm(data: Uint8Array): Instruction[] {
  const instructions: Instruction[] = [];
  let pos = 0;
  while (pos < data.length) {
    const opcode = data[pos];
    let mnemonic = 'unsupported';
    let size = 1;
    let opStr = '';
    let operands: Operand[] = [];

    // WASM Opcode Map Extension
    if (opcode === 0x00) {
      mnemonic = 'unreachable';
    } else if (opcode === 0x01) {
      mnemonic = 'nop';
    } else if (opcode === 0x02) {
      mnemonic = 'block';
      size = 2;
      opStr = `type: ${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x03) {
      mnemonic = 'loop';
      size = 2;
      opStr = `type: ${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x04) {
      mnemonic = 'if';
      size = 2;
      opStr = `type: ${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x05) {
      mnemonic = 'else';
    } else if (opcode === 0x0b) {
      mnemonic = 'end';
    } else if (opcode === 0x0c) {
      mnemonic = 'br';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x0d) {
      mnemonic = 'br_if';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x0f) {
      mnemonic = 'return';
    } else if (opcode === 0x10) {
      mnemonic = 'call';
      size = 2;
      opStr = `func_${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x11) {
      mnemonic = 'call_indirect';
      size = 3;
      opStr = `type_${data[pos + 1] || 0}, table_${data[pos + 2] || 0}`;
      operands = [
        { type: 'imm', imm: data[pos + 1] || 0 },
        { type: 'imm', imm: data[pos + 2] || 0 },
      ];
    } else if (opcode === 0x1a) {
      mnemonic = 'drop';
    } else if (opcode === 0x1b) {
      mnemonic = 'select';
    } else if (opcode === 0x20) {
      mnemonic = 'local.get';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x21) {
      mnemonic = 'local.set';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x22) {
      mnemonic = 'local.tee';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x23) {
      mnemonic = 'global.get';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x24) {
      mnemonic = 'global.set';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode >= 0x28 && opcode <= 0x3e) {
      // Loads and Stores
      const mnemonics: Record<number, string> = {
        0x28: 'i32.load',
        0x29: 'i64.load',
        0x2a: 'f32.load',
        0x2b: 'f64.load',
        0x2c: 'i32.load8_s',
        0x2d: 'i32.load8_u',
        0x2e: 'i32.load16_s',
        0x2f: 'i32.load16_u',
        0x30: 'i64.load8_s',
        0x31: 'i64.load8_u',
        0x32: 'i64.load16_s',
        0x33: 'i64.load16_u',
        0x34: 'i64.load32_s',
        0x35: 'i64.load32_u',
        0x36: 'i32.store',
        0x37: 'i64.store',
        0x38: 'f32.store',
        0x39: 'f64.store',
        0x3a: 'i32.store8',
        0x3b: 'i32.store16',
        0x3c: 'i64.store8',
        0x3d: 'i64.store16',
        0x3e: 'i64.store32',
      };
      mnemonic = mnemonics[opcode] || 'load_store';
      size = 3;
      const align = data[pos + 1] || 0;
      const offset = data[pos + 2] || 0;
      opStr = `align=${align} offset=${offset}`;
      operands = [
        { type: 'imm', imm: align },
        { type: 'imm', imm: offset },
      ];
    } else if (opcode === 0x41) {
      mnemonic = 'i32.const';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x42) {
      mnemonic = 'i64.const';
      size = 2;
      opStr = `${data[pos + 1] || 0}`;
      operands = [{ type: 'imm', imm: data[pos + 1] || 0 }];
    } else if (opcode === 0x43) {
      mnemonic = 'f32.const';
      size = 5;
      opStr = 'float';
    } else if (opcode === 0x44) {
      mnemonic = 'f64.const';
      size = 9;
      opStr = 'double';
    } else if (opcode >= 0x45 && opcode <= 0x66) {
      // Comparisons
      const cmpOps: Record<number, string> = {
        0x45: 'i32.eqz',
        0x46: 'i32.eq',
        0x47: 'i32.ne',
        0x48: 'i32.lt_s',
        0x49: 'i32.lt_u',
        0x4a: 'i32.gt_s',
        0x4b: 'i32.gt_u',
        0x4c: 'i32.le_s',
        0x4d: 'i32.le_u',
        0x4e: 'i32.ge_s',
        0x4f: 'i32.ge_u',
        0x50: 'i64.eqz',
        0x51: 'i64.eq',
        0x52: 'i64.ne',
        0x53: 'i64.lt_s',
        0x54: 'i64.lt_u',
        0x55: 'i64.gt_s',
        0x56: 'i64.gt_u',
        0x57: 'i64.le_s',
        0x58: 'i64.le_u',
        0x59: 'i64.ge_s',
        0x5a: 'i64.ge_u',
        0x5b: 'f32.eq',
        0x5c: 'f32.ne',
        0x5d: 'f32.lt',
        0x5e: 'f32.gt',
        0x5f: 'f32.le',
        0x60: 'f32.ge',
        0x61: 'f64.eq',
        0x62: 'f64.ne',
        0x63: 'f64.lt',
        0x64: 'f64.gt',
        0x65: 'f64.le',
        0x66: 'f64.ge',
      };
      mnemonic = cmpOps[opcode] || 'cmp';
    } else if (opcode >= 0x67 && opcode <= 0x78) {
      // i32 numeric
      const i32Ops: Record<number, string> = {
        0x67: 'i32.clz',
        0x68: 'i32.ctz',
        0x69: 'i32.popcnt',
        0x6a: 'i32.add',
        0x6b: 'i32.sub',
        0x6c: 'i32.mul',
        0x6d: 'i32.div_s',
        0x6e: 'i32.div_u',
        0x6f: 'i32.rem_s',
        0x70: 'i32.rem_u',
        0x71: 'i32.and',
        0x72: 'i32.or',
        0x73: 'i32.xor',
        0x74: 'i32.shl',
        0x75: 'i32.shr_s',
        0x76: 'i32.shr_u',
        0x77: 'i32.rotl',
        0x78: 'i32.rotr',
      };
      mnemonic = i32Ops[opcode] || 'i32.numeric';
    } else if (opcode === 0x7c) {
      mnemonic = 'f32.add';
    }

    if (pos + size > data.length) size = data.length - pos;

    const bytes = data.slice(pos, pos + size);
    instructions.push({
      address: pos,
      bytes,
      mnemonic,
      opStr,
      operands,
      size,
    });

    pos += size;
  }
  return instructions;
}
