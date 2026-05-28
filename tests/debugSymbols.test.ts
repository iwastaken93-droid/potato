import { describe, it, expect } from 'vitest';
import {
  DebugSymbolsParser,
  readULEB128,
  readSLEB128,
  parseDwarfLine,
  parseDwarfInfo,
  parseMsfHeader,
  readMsfStream,
  parsePdbSymbols,
} from '../src/parser/debugSymbols.js';

// Helper to write ULEB128 to a Uint8Array
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

// Helper to write SLEB128 to a Uint8Array
function writeSLEB128(value: number): number[] {
  const bytes: number[] = [];
  let temp = value;
  let hasMore = true;
  while (hasMore) {
    let byte = temp & 0x7f;
    temp >>= 7; // Arithmetic shift
    if (
      (temp === 0 && (byte & 0x40) === 0) ||
      (temp === -1 && (byte & 0x40) !== 0)
    ) {
      hasMore = false;
    } else {
      byte |= 0x80;
    }
    bytes.push(byte);
  }
  return bytes;
}

describe('Debug Symbols Parser Framework Tests', () => {
  describe('LEB128 Utility Tests', () => {
    it('should correctly decode ULEB128 values', () => {
      const cases = [0, 1, 127, 128, 624485];
      for (const val of cases) {
        const bytes = writeULEB128(val);
        const buffer = new Uint8Array(bytes).buffer;
        const view = new DataView(buffer);
        const result = readULEB128(view, 0);
        expect(result.value).toBe(val);
        expect(result.bytesRead).toBe(bytes.length);
      }
    });

    it('should correctly decode SLEB128 values', () => {
      const cases = [0, 1, -1, 63, -64, 127, -128, 128, -129, 624485, -624485];
      for (const val of cases) {
        const bytes = writeSLEB128(val);
        const buffer = new Uint8Array(bytes).buffer;
        const view = new DataView(buffer);
        const result = readSLEB128(view, 0);
        expect(result.value).toBe(val);
        expect(result.bytesRead).toBe(bytes.length);
      }
    });

    it('should throw error on ULEB128 out of bounds', () => {
      const buffer = new Uint8Array([0x80, 0x80]).buffer;
      const view = new DataView(buffer);
      expect(() => readULEB128(view, 0)).toThrow();
    });

    it('should throw error on SLEB128 out of bounds', () => {
      const buffer = new Uint8Array([0x80, 0x80]).buffer;
      const view = new DataView(buffer);
      expect(() => readSLEB128(view, 0)).toThrow();
    });
  });

  describe('DWARF Line Number Program Parser Tests', () => {
    it('should parse a mock DWARF line number program', () => {
      const bytes: number[] = [];

      // 1. unit_length (4 bytes) - populated later
      bytes.push(0, 0, 0, 0);
      const startOfUnit = bytes.length;

      // 2. version (2 bytes)
      bytes.push(4, 0);

      // 3. header_length (4 bytes) - populated later
      bytes.push(0, 0, 0, 0);
      const startOfHeader = bytes.length;

      // 4. min_instruction_length (1)
      bytes.push(1);
      // 5. max_ops_per_instruction (1)
      bytes.push(1);
      // 6. default_is_stmt (1)
      bytes.push(1);
      // 7. line_base (1) - signed -5
      bytes.push(-5 & 0xff);
      // 8. line_range (1)
      bytes.push(14);
      // 9. opcode_base (1)
      bytes.push(13);

      // 10. standard_opcode_lengths
      // opcodes 1..12 lengths
      bytes.push(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1);

      // 11. include_directories (null-terminated strings, finished by 0)
      const dir1 = '/usr/src/app';
      for (let i = 0; i < dir1.length; i++) bytes.push(dir1.charCodeAt(i));
      bytes.push(0);
      bytes.push(0); // End of directories

      // 12. file_names (null-terminated string, dir_idx (uleb), mod_time (uleb), length (uleb))
      const file1 = 'main.cpp';
      for (let i = 0; i < file1.length; i++) bytes.push(file1.charCodeAt(i));
      bytes.push(0);
      bytes.push(...writeULEB128(1)); // dir_idx
      bytes.push(...writeULEB128(0)); // mod_time
      bytes.push(...writeULEB128(0)); // length
      bytes.push(0); // End of files

      const endOfHeader = bytes.length;
      const headerLength = endOfHeader - startOfHeader;

      // Fill in header length
      bytes[startOfUnit + 2] = headerLength & 0xff;
      bytes[startOfUnit + 3] = (headerLength >> 8) & 0xff;
      bytes[startOfUnit + 4] = (headerLength >> 16) & 0xff;
      bytes[startOfUnit + 5] = (headerLength >> 24) & 0xff;

      // Line Program Instructions
      // - DW_LNE_set_address (Extended subopcode 2, size 8)
      bytes.push(0); // Extended prefix
      bytes.push(...writeULEB128(9)); // length: 1 (subopcode) + 8 (addr)
      bytes.push(2); // DW_LNE_set_address
      // Address: 0x1000 (8 bytes)
      bytes.push(0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

      // - DW_LNS_advance_line (signed advance by 4)
      bytes.push(3);
      bytes.push(...writeSLEB128(4)); // line = 1 + 4 = 5

      // - DW_LNS_copy (append row)
      bytes.push(1);

      // - Special opcode: adjusted opcode = 20
      // opcode_base is 13. opcode = 20 + 13 = 33
      // address_advance = Math.floor(20 / 14) * 1 = 1
      // line_advance = -5 + (20 % 14) = -5 + 6 = 1
      bytes.push(33); // Address + 1 (0x1001), Line + 1 (6), append row

      // - DW_LNE_end_sequence (Extended subopcode 1, size 1)
      bytes.push(0);
      bytes.push(...writeULEB128(1));
      bytes.push(1); // end_sequence

      const endOfUnit = bytes.length;
      const unitLength = endOfUnit - startOfUnit;

      // Fill in unit length
      bytes[0] = unitLength & 0xff;
      bytes[1] = (unitLength >> 8) & 0xff;
      bytes[2] = (unitLength >> 16) & 0xff;
      bytes[3] = (unitLength >> 24) & 0xff;

      const buffer = new Uint8Array(bytes).buffer;
      const lines = parseDwarfLine(buffer);

      expect(lines.length).toBe(3);
      expect(lines[0].address).toBe(0x1000);
      expect(lines[0].file).toBe('/usr/src/app/main.cpp');
      expect(lines[0].line).toBe(5);

      expect(lines[1].address).toBe(0x1001);
      expect(lines[1].file).toBe('/usr/src/app/main.cpp');
      expect(lines[1].line).toBe(6);
    });
  });

  describe('DWARF Info Parser Tests', () => {
    it('should parse mock DWARF info and resolve strings', () => {
      const infoBytes: number[] = [];
      const strBytes: number[] = [];

      // Create debug_str content: "main" at 0, "helper" at 5
      strBytes.push(...[...'main'].map(c => c.charCodeAt(0)), 0);
      strBytes.push(...[...'helper'].map(c => c.charCodeAt(0)), 0);

      // debug_info unit header
      infoBytes.push(0, 0, 0, 0); // unit_length placeholder
      const startOfUnit = infoBytes.length;
      infoBytes.push(4, 0); // version 4
      infoBytes.push(0, 0, 0, 0); // abbrev offset
      infoBytes.push(8); // address size: 8

      // DIE 1: Code 1, Tag 0x2e (DW_TAG_subprogram)
      infoBytes.push(...writeULEB128(1)); // code
      infoBytes.push(0x2e); // tag
      infoBytes.push(2); // form: strp
      infoBytes.push(0, 0, 0, 0); // string offset 0 ("main")
      // Low PC: 0x1000 (8 bytes)
      infoBytes.push(0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
      // High PC: 0x1050 (8 bytes)
      infoBytes.push(0x50, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

      // DIE 2: Code 2, Tag 0x2e (DW_TAG_subprogram)
      infoBytes.push(...writeULEB128(2)); // code
      infoBytes.push(0x2e); // tag
      infoBytes.push(1); // form: inline string
      infoBytes.push(...[...'inline_func'].map(c => c.charCodeAt(0)), 0);
      // Low PC: 0x2000 (8 bytes)
      infoBytes.push(0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
      // High PC: 0x2020 (8 bytes)
      infoBytes.push(0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

      const endOfUnit = infoBytes.length;
      const unitLength = endOfUnit - startOfUnit;

      infoBytes[0] = unitLength & 0xff;
      infoBytes[1] = (unitLength >> 8) & 0xff;
      infoBytes[2] = (unitLength >> 16) & 0xff;
      infoBytes[3] = (unitLength >> 24) & 0xff;

      const infoBuffer = new Uint8Array(infoBytes).buffer;
      const strBuffer = new Uint8Array(strBytes).buffer;

      const symbols = parseDwarfInfo(infoBuffer, strBuffer);
      expect(symbols.length).toBe(2);
      expect(symbols[0].name).toBe('main');
      expect(symbols[0].address).toBe(0x1000);
      expect(symbols[0].size).toBe(0x50);
      expect(symbols[0].type).toBe('function');

      expect(symbols[1].name).toBe('inline_func');
      expect(symbols[1].address).toBe(0x2000);
      expect(symbols[1].size).toBe(0x20);
    });
  });

  describe('PDB MSF & Symbol Parser Tests', () => {
    it('should fail parsing PDB if magic is invalid', () => {
      const buffer = new ArrayBuffer(64);
      expect(() => parseMsfHeader(buffer)).toThrow('Invalid MSF magic signature');
    });

    it('should parse a valid MSF header', () => {
      const magic = 'Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00';
      const buffer = new ArrayBuffer(64);
      const bytes = new Uint8Array(buffer);
      for (let i = 0; i < magic.length; i++) {
        bytes[i] = magic.charCodeAt(i);
      }

      const view = new DataView(buffer);
      view.setUint32(32, 512, true); // pageSize
      view.setUint32(40, 10, true); // numPages
      view.setUint32(44, 2048, true); // directorySize
      view.setUint32(52, 2, true); // blockMapAddress

      const header = parseMsfHeader(buffer);
      expect(header.pageSize).toBe(512);
      expect(header.numPages).toBe(10);
      expect(header.directorySize).toBe(2048);
      expect(header.blockMapAddress).toBe(2);
    });

    it('should copy streams using readMsfStream', () => {
      const header = {
        pageSize: 64,
        numPages: 10,
        directorySize: 128,
        blockMapAddress: 1,
      };

      const buffer = new ArrayBuffer(640);
      const bytes = new Uint8Array(buffer);
      // Fill page 2 with 'A's, page 4 with 'B's
      bytes.fill(0x41, 2 * 64, 3 * 64);
      bytes.fill(0x42, 4 * 64, 5 * 64);

      const streamBuffer = readMsfStream(buffer, header, [1], 100, [2, 4]);
      const streamBytes = new Uint8Array(streamBuffer);

      // Verify page 2 copied (first 64 bytes)
      expect(streamBytes[0]).toBe(0x41);
      expect(streamBytes[63]).toBe(0x41);
      // Verify page 4 copied (remaining 36 bytes)
      expect(streamBytes[64]).toBe(0x42);
      expect(streamBytes[99]).toBe(0x42);
    });

    it('should parse PDB symbol records', () => {
      const bytes: number[] = [];

      // Record 1: S_PUB32 (0x110e)
      // len(2) = 18
      bytes.push(18, 0);
      // type(2) = 0x110e
      bytes.push(0x0e, 0x11);
      // flags(4)
      bytes.push(0, 0, 0, 0);
      // offset(4) = 0x100
      bytes.push(0x00, 0x01, 0x00, 0x00);
      // segment(2) = 1
      bytes.push(1, 0);
      // name = "func1\0"
      bytes.push(...[...'func1'].map(c => c.charCodeAt(0)), 0);

      // Record 2: S_DEFSYM_LINE (0x1015)
      // len(2) = 23
      bytes.push(23, 0);
      // type(2) = 0x1015
      bytes.push(0x15, 0x10);
      // addrOffset(4) = 0x100
      bytes.push(0x00, 0x01, 0x00, 0x00);
      // segment(2) = 1
      bytes.push(1, 0);
      // line(4) = 42
      bytes.push(42, 0, 0, 0);
      // filename = "source.cpp\0"
      bytes.push(...[...'source.cpp'].map(c => c.charCodeAt(0)), 0);

      const buffer = new Uint8Array(bytes).buffer;
      const res = parsePdbSymbols(buffer);

      expect(res.symbols.length).toBe(1);
      expect(res.symbols[0].name).toBe('func1');
      expect(res.symbols[0].address).toBe(0x10000 + 0x100);

      expect(res.lines.length).toBe(1);
      expect(res.lines[0].address).toBe(0x10000 + 0x100);
      expect(res.lines[0].file).toBe('source.cpp');
      expect(res.lines[0].line).toBe(42);
    });
  });

  describe('DebugSymbolsParser Framework API Tests', () => {
    it('should resolve address to line and symbol names', () => {
      const parser = new DebugSymbolsParser();
      parser.loadRaw(
        'DWARF',
        [
          { name: 'main', address: 0x1000, size: 0x50, type: 'function' },
          { name: 'helper', address: 0x2000, size: 0x20, type: 'function' },
        ],
        [
          { address: 0x1000, file: 'main.cpp', line: 10, column: 0 },
          { address: 0x1010, file: 'main.cpp', line: 15, column: 4 },
          { address: 0x2000, file: 'helper.cpp', line: 5, column: 0 },
        ]
      );

      // Address resolution
      expect(parser.resolveAddress(0x1000)).toEqual({
        address: 0x1000,
        file: 'main.cpp',
        line: 10,
        column: 0,
      });
      expect(parser.resolveAddress(0x1005)).toEqual({
        address: 0x1000,
        file: 'main.cpp',
        line: 10,
        column: 0,
      });
      expect(parser.resolveAddress(0x1015)).toEqual({
        address: 0x1010,
        file: 'main.cpp',
        line: 15,
        column: 4,
      });
      expect(parser.resolveAddress(0x500)).toBeNull();

      // Symbol name resolution
      expect(parser.getSymbolName(0x1000)).toBe('main');
      expect(parser.getSymbolName(0x1020)).toBe('main'); // inside main's size 0x50
      expect(parser.getSymbolName(0x1055)).toBe('main'); // closest start address <= target
      expect(parser.getSymbolName(0x2000)).toBe('helper');
      expect(parser.getSymbolName(0x500)).toBeNull();
    });
  });
});
