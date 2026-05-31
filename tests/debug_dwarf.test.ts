import { describe, it, expect } from 'vitest';
import { parseDwarfLine } from '../src/parser/dwarfParser.js';

function writeULEB128(value: number): number[] {
  const bytes: number[] = [];
  let temp = value;
  while (true) {
    let byte = temp & 0x7f;
    temp >>>= 7;
    if (temp !== 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
    if (temp === 0) {
      break;
    }
  }
  return bytes;
}

function writeSLEB128(value: number): number[] {
  const bytes: number[] = [];
  let temp = value;
  let hasMore = true;
  while (hasMore) {
    let byte = temp & 0x7f;
    temp >>= 7;
    if ((temp === 0 && (byte & 0x40) === 0) || (temp === -1 && (byte & 0x40) !== 0)) {
      hasMore = false;
    } else {
      byte |= 0x80;
    }
    bytes.push(byte);
  }
  return bytes;
}

describe('debug dwarf test', () => {
  it('debugs', () => {
    const bytes: number[] = [];

    // 1. unit_length = 0xffffffff (indicates DWARF64)
    bytes.push(0xff, 0xff, 0xff, 0xff);
    const startOfUnit = bytes.length;
    bytes.push(0, 0, 0, 0, 0, 0, 0, 0); // Filled later

    // 2. version (2 bytes) = 4
    bytes.push(4, 0);

    // 3. header_length (8 bytes for DWARF64)
    bytes.push(0, 0, 0, 0, 0, 0, 0, 0); // Filled later
    const startOfHeader = bytes.length;

    // min_instruction_length(1), max_ops(1), default_is_stmt(1), line_base(1), line_range(1), opcode_base(1)
    bytes.push(1, 1, 1, -5 & 0xff, 14, 13);
    // standard_opcode_lengths
    bytes.push(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1);

    // directories (null-terminated)
    bytes.push(0); // empty directory
    // files
    const file1 = 'test.c';
    for (let i = 0; i < file1.length; i++) bytes.push(file1.charCodeAt(i));
    bytes.push(0);
    bytes.push(...writeULEB128(0)); // dir index
    bytes.push(...writeULEB128(0));
    bytes.push(...writeULEB128(0));
    bytes.push(0); // end of files

    const endOfHeader = bytes.length;
    const headerLength = endOfHeader - startOfHeader;
    // Write header_length (starts at index 14)
    bytes[14] = headerLength & 0xff;
    bytes[15] = (headerLength >> 8) & 0xff;

    // Line Program instructions:
    bytes.push(0);
    bytes.push(...writeULEB128(5)); // size (1 subopcode + 4 address bytes)
    bytes.push(2); // DW_LNE_set_address
    bytes.push(0x00, 0x20, 0x00, 0x00); // Address 0x2000

    bytes.push(2);
    bytes.push(...writeULEB128(10)); // PC += 10

    bytes.push(3);
    bytes.push(...writeSLEB128(5)); // line += 5

    bytes.push(4);
    bytes.push(...writeULEB128(1));

    bytes.push(5);
    bytes.push(...writeULEB128(4));

    bytes.push(6);
    bytes.push(7);
    bytes.push(8); // PC += constant (255 - 13)/14 = 17

    bytes.push(9);
    bytes.push(0x04, 0x00); // PC += 4

    bytes.push(10);
    bytes.push(11);
    bytes.push(12);
    bytes.push(...writeULEB128(2));

    bytes.push(0);
    bytes.push(...writeULEB128(2)); // size = 2
    bytes.push(4); // DW_LNE_set_discriminator
    bytes.push(...writeULEB128(1));

    bytes.push(1);

    bytes.push(0);
    bytes.push(...writeULEB128(1));
    bytes.push(1);

    const endOfUnit = bytes.length;
    const unitLength = endOfUnit - 12; // 12 bytes unit length fields prefix in DWARF64
    bytes[startOfUnit] = unitLength & 0xff;
    bytes[startOfUnit + 1] = (unitLength >> 8) & 0xff;
    bytes[startOfUnit + 2] = (unitLength >> 16) & 0xff;
    bytes[startOfUnit + 3] = (unitLength >> 24) & 0xff;

    const buffer = new Uint8Array(bytes).buffer;
    console.log('Byte length:', buffer.byteLength);
    console.log('Unit length:', unitLength);
    console.log('Header length:', headerLength);

    const lines = parseDwarfLine(buffer);
    console.log('Parsed lines count:', lines.length);
    console.log('Lines:', JSON.stringify(lines, null, 2));
  });
});
