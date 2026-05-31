import { describe, it, expect } from 'vitest';
import {
  DebugSymbolsParser,
  readULEB128,
  readSLEB128,
  parseFormValue,
  parseDwarfLine,
  parseDwarfInfo,
  parseMsfHeader,
  readMsfStream,
  parsePdbSymbols,
} from '../src/parser/debugSymbols.js';
import { resolveStrX } from '../src/parser/dwarfParser.js';

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

    it('should parse a mock DWARF v5 line number program with MD5 and directories', () => {
      const bytes: number[] = [];

      // 1. unit_length (4 bytes) - populated later
      bytes.push(0, 0, 0, 0);
      const startOfUnit = bytes.length;

      // 2. version (2 bytes) = 5
      bytes.push(5, 0);

      // 3. address_size (1 byte) = 8
      bytes.push(8);

      // 4. segment_selector_size (1 byte) = 0
      bytes.push(0);

      // 5. header_length (4 bytes) - populated later
      bytes.push(0, 0, 0, 0);
      const startOfHeader = bytes.length;

      // 6. min_instruction_length (1)
      bytes.push(1);
      // 7. max_ops_per_instruction (1)
      bytes.push(1);
      // 8. default_is_stmt (1)
      bytes.push(1);
      // 9. line_base (1) - signed -5
      bytes.push(-5 & 0xff);
      // 10. line_range (1)
      bytes.push(14);
      // 11. opcode_base (1)
      bytes.push(13);

      // 12. standard_opcode_lengths
      bytes.push(0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1);

      // 13. DWARF v5 Directory Entry Format Count
      bytes.push(1);
      // Format 0: content_type = 1 (DW_LNCT_path), form = 0x08 (DW_FORM_string)
      bytes.push(...writeULEB128(1));
      bytes.push(...writeULEB128(0x08));

      // Directories count (ULEB128)
      bytes.push(...writeULEB128(1));
      // Directory 0: path = "/usr/src/app"
      const dir1 = '/usr/src/app';
      for (let i = 0; i < dir1.length; i++) bytes.push(dir1.charCodeAt(i));
      bytes.push(0);

      // 14. DWARF v5 File Entry Format Count
      bytes.push(3);
      // Format 0: content_type = 1 (DW_LNCT_path), form = 0x08 (DW_FORM_string)
      bytes.push(...writeULEB128(1));
      bytes.push(...writeULEB128(0x08));
      // Format 1: content_type = 2 (DW_LNCT_directory_index), form = 0x0f (DW_FORM_udata)
      bytes.push(...writeULEB128(2));
      bytes.push(...writeULEB128(0x0f));
      // Format 2: content_type = 5 (DW_LNCT_MD5), form = 0x1e (DW_FORM_data16)
      bytes.push(...writeULEB128(5));
      bytes.push(...writeULEB128(0x1e));

      // Files count (ULEB128)
      bytes.push(...writeULEB128(1));
      // File 0: name = "main.cpp", dir_idx = 0, MD5 = 16 bytes
      const file1 = 'main.cpp';
      for (let i = 0; i < file1.length; i++) bytes.push(file1.charCodeAt(i));
      bytes.push(0);
      bytes.push(...writeULEB128(0)); // dir index 0
      // 16 bytes MD5: 0102030405060708090a0b0c0d0e0f10
      for (let i = 1; i <= 16; i++) bytes.push(i);

      const endOfHeader = bytes.length;
      const headerLength = endOfHeader - startOfHeader;

      // Fill in header length
      bytes[startOfUnit + 4] = headerLength & 0xff;
      bytes[startOfUnit + 5] = (headerLength >> 8) & 0xff;
      bytes[startOfUnit + 6] = (headerLength >> 16) & 0xff;
      bytes[startOfUnit + 7] = (headerLength >> 24) & 0xff;

      // Line Program Instructions
      // - DW_LNE_set_address (Extended subopcode 2, size 8)
      bytes.push(0); // Extended prefix
      bytes.push(...writeULEB128(9)); // length: 1 (subopcode) + 8 (addr)
      bytes.push(2); // DW_LNE_set_address
      bytes.push(0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

      // - DW_LNS_advance_line (signed advance by 4)
      bytes.push(3);
      bytes.push(...writeSLEB128(4)); // line = 1 + 4 = 5

      // - DW_LNS_copy (append row)
      bytes.push(1);

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

      expect(lines.length).toBe(2);
      expect(lines[0].address).toBe(0x1000);
      expect(lines[0].file).toBe('/usr/src/app/main.cpp');
      expect(lines[0].line).toBe(5);
    });
  });

  describe('DWARF Info Parser Tests', () => {
    it('should parse mock DWARF info and resolve strings', () => {
      const infoBytes: number[] = [];
      const strBytes: number[] = [];

      // Create debug_str content: "main" at 0, "helper" at 5
      strBytes.push(...[...'main'].map((c) => c.charCodeAt(0)), 0);
      strBytes.push(...[...'helper'].map((c) => c.charCodeAt(0)), 0);

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
      infoBytes.push(...[...'inline_func'].map((c) => c.charCodeAt(0)), 0);
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
      expect(() => parseMsfHeader(buffer)).toThrow(
        'Invalid MSF magic signature'
      );
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
      bytes.push(...[...'func1'].map((c) => c.charCodeAt(0)), 0);

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
      bytes.push(...[...'source.cpp'].map((c) => c.charCodeAt(0)), 0);

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

  describe('dwarfParser form parsing edge cases', () => {
    it('should correctly parse DWARF v5 form values', () => {
      const buffer = new Uint8Array([
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sec_offset (64-bit) / data8
        0x01, // flag
        0x12, // strx1
        0x34, 0x12, // strx2
        0x12, 0x34, 0x56, // strx3 (0x563412 = 5649426)
        0x78, 0x56, 0x34, 0x12, // strx4 (0x12345678 = 305419896)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // data16 (MD5)
      ]);
      const view = new DataView(buffer.buffer);

      // sec_offset 32-bit (uses size = 4)
      let res = parseFormValue(view, 0, 0x17, false); // DW_FORM_sec_offset
      expect(res.value).toBe(5);
      expect(res.bytesRead).toBe(4);

      // sec_offset 64-bit (uses size = 8)
      res = parseFormValue(view, 0, 0x17, true);
      expect(res.value).toBe(5);
      expect(res.bytesRead).toBe(8);

      // DW_FORM_flag (offset 8)
      res = parseFormValue(view, 8, 0x0c, false);
      expect(res.value).toBe(true);
      expect(res.bytesRead).toBe(1);

      // DW_FORM_flag_present
      res = parseFormValue(view, 0, 0x19, false);
      expect(res.value).toBe(true);
      expect(res.bytesRead).toBe(0);

      // DW_FORM_strx1 (offset 9)
      res = parseFormValue(view, 9, 0x25, false);
      expect(res.value).toBe('strx_18');
      expect(res.bytesRead).toBe(1);

      // DW_FORM_strx2 (offset 10)
      res = parseFormValue(view, 10, 0x26, false);
      expect(res.value).toBe('strx_4660');
      expect(res.bytesRead).toBe(2);

      // DW_FORM_strx3 (offset 12)
      res = parseFormValue(view, 12, 0x27, false);
      expect(res.value).toBe('strx_5649426');
      expect(res.bytesRead).toBe(3);

      // DW_FORM_strx4 (offset 15)
      res = parseFormValue(view, 15, 0x28, false);
      expect(res.value).toBe('strx_305419896');
      expect(res.bytesRead).toBe(4);

      // DW_FORM_data16 (offset 19)
      res = parseFormValue(view, 19, 0x1e, false);
      expect(res.value).toBe('0102030405060708090a0b0c0d0e0f10');
      expect(res.bytesRead).toBe(16);
    });

    it('should throw on unsupported DWARF form', () => {
      const buffer = new Uint8Array([0x01, 0x02]);
      const view = new DataView(buffer.buffer);
      expect(() => parseFormValue(view, 0, 0x99, false)).toThrow('Unsupported DW_FORM: 0x99');
    });

    it('should throw out of bounds on DWARF forms', () => {
      const buffer = new Uint8Array([0x01]);
      const view = new DataView(buffer.buffer);
      expect(() => parseFormValue(view, 0, 0x05, false)).toThrow(); // DW_FORM_data2 requires 2 bytes
      expect(() => parseFormValue(view, 0, 0x1f, false)).toThrow(); // DW_FORM_line_strp requires 4 bytes
      expect(() => parseFormValue(view, 0, 0x0e, true)).toThrow(); // DW_FORM_strp in 64-bit requires 8 bytes
    });
  });

  describe('dwarfParser DWARF64 and advanced line program opcodes', () => {
    it('should parse DWARF64 line header and execute standard/extended opcodes', () => {
      const bytes: number[] = [];

      // 1. unit_length = 0xffffffff (indicates DWARF64)
      bytes.push(0xff, 0xff, 0xff, 0xff);
      // Actual 64-bit length (we just write 8 bytes, low 4 bytes for length, high 4 bytes 0)
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
      // - DW_LNE_set_address (Extended subopcode 2)
      bytes.push(0);
      bytes.push(...writeULEB128(5)); // size (1 subopcode + 4 address bytes)
      bytes.push(2); // DW_LNE_set_address
      bytes.push(0x00, 0x20, 0x00, 0x00); // Address 0x2000

      // - DW_LNS_advance_pc
      bytes.push(2);
      bytes.push(...writeULEB128(10)); // PC += 10

      // - DW_LNS_advance_line
      bytes.push(3);
      bytes.push(...writeSLEB128(5)); // line += 5

      // - DW_LNS_set_file
      bytes.push(4);
      bytes.push(...writeULEB128(1));

      // - DW_LNS_set_column
      bytes.push(5);
      bytes.push(...writeULEB128(4));

      // - DW_LNS_negate_stmt
      bytes.push(6);

      // - DW_LNS_set_basic_block
      bytes.push(7);

      // - DW_LNS_const_add_pc
      bytes.push(8); // PC += constant (255 - 13)/14 = 17

      // - DW_LNS_fixed_advance_pc
      bytes.push(9);
      bytes.push(0x04, 0x00); // PC += 4

      // - DW_LNS_set_prologue_end
      bytes.push(10);

      // - DW_LNS_set_epilogue_begin
      bytes.push(11);

      // - DW_LNS_set_isa
      bytes.push(12);
      bytes.push(...writeULEB128(2));

      // - DW_LNE_set_discriminator
      bytes.push(0);
      bytes.push(...writeULEB128(2)); // size = 2
      bytes.push(4); // DW_LNE_set_discriminator
      bytes.push(...writeULEB128(1));

      // - DW_LNS_copy
      bytes.push(1);

      // - DW_LNE_end_sequence
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
      const lines = parseDwarfLine(buffer);

      expect(lines.length).toBe(2);
      expect(lines[0].address).toBe(0x2000 + 10 + 17 + 4);
      expect(lines[0].line).toBe(6);
      expect(lines[0].file).toBe('test.c');
    });
  });

  describe('PDB MSF & symbols parser edge cases', () => {
    it('should throw error when block read is out of bounds in readMsfStream', () => {
      const header = {
        pageSize: 64,
        numPages: 2,
        directorySize: 128,
        blockMapAddress: 1,
      };
      const buffer = new ArrayBuffer(64); // Only 1 page large
      expect(() => readMsfStream(buffer, header, [1], 128, [0, 5])).toThrow('MSF stream block read out of bounds');
    });

    it('should parse PDB symbols S_GPROC32 and S_LPROC32 correctly', () => {
      const bytes: number[] = [];

      // S_GPROC32 (0x1110)
      bytes.push(20, 0); // len = 20
      bytes.push(0x10, 0x11); // type = 0x1110
      bytes.push(0, 0, 0, 0); // flags
      bytes.push(0x00, 0x20, 0x00, 0x00); // offset = 0x2000
      bytes.push(2, 0); // segment = 2
      bytes.push(0, 0); // symtype
      bytes.push(...[...'gfunc'].map((c) => c.charCodeAt(0)), 0);

      // S_LPROC32 (0x110f)
      bytes.push(20, 0); // len = 20
      bytes.push(0x0f, 0x11); // type = 0x110f
      bytes.push(0, 0, 0, 0); // flags
      bytes.push(0x00, 0x30, 0x00, 0x00); // offset = 0x3000
      bytes.push(3, 0); // segment = 3
      bytes.push(0, 0); // symtype
      bytes.push(...[...'lfunc'].map((c) => c.charCodeAt(0)), 0);

      const buffer = new Uint8Array(bytes).buffer;
      const res = parsePdbSymbols(buffer);

      expect(res.symbols).toHaveLength(2);
      expect(res.symbols[0].name).toBe('gfunc');
      expect(res.symbols[0].address).toBe(2 * 0x10000 + 0x2000);
      expect(res.symbols[0].type).toBe('function');

      expect(res.symbols[1].name).toBe('lfunc');
      expect(res.symbols[1].address).toBe(3 * 0x10000 + 0x3000);
      expect(res.symbols[1].type).toBe('function');
    });

    it('should throw error when calling parse on invalid PDB file', () => {
      const parser = new DebugSymbolsParser();
      expect(() => parser.parse({ pdbFile: new ArrayBuffer(10) })).toThrow('Failed parsing PDB file: Invalid MSF magic signature');
    });
  });

  describe('DWARF v5 debug_str_offsets resolving', () => {
    it('should resolve strx forms to strings using debugStrOffsets section', () => {
      // Create debugStr: "hello" at offset 0, "world" at offset 6
      const strBytes: number[] = [];
      strBytes.push(...[...'hello'].map((c) => c.charCodeAt(0)), 0);
      strBytes.push(...[...'world'].map((c) => c.charCodeAt(0)), 0);

      // Create debugStrOffsets contribution (DWARF32)
      // unit_length (4 bytes): 12 bytes follows
      // version (2 bytes): 5
      // padding (2 bytes): 0
      // offset array:
      // index 0: offset 0 ("hello")
      // index 1: offset 6 ("world")
      const offsetBytes: number[] = [
        0x0c, 0x00, 0x00, 0x00, // unit_length = 12 (2 version + 2 padding + 8 offsets)
        0x05, 0x00,             // version = 5
        0x00, 0x00,             // padding = 0
        0x00, 0x00, 0x00, 0x00, // index 0 offset = 0
        0x06, 0x00, 0x00, 0x00, // index 1 offset = 6
      ];

      const strBuffer = new Uint8Array(strBytes).buffer;
      const offsetBuffer = new Uint8Array(offsetBytes).buffer;

      // Now call parseFormValue for DW_FORM_strx (0x1a) with index 1
      const view = new DataView(new Uint8Array(writeULEB128(1)).buffer);
      const res = parseFormValue(
        view,
        0,
        0x1a, // DW_FORM_strx
        false, // is64Bit
        new DataView(strBuffer),
        null,
        new DataView(offsetBuffer)
      );

      expect(res.value).toBe('world');
      expect(res.bytesRead).toBe(1);
    });

    it('should handle resolveStrX edge cases correctly', () => {
      // 1. null views
      expect(resolveStrX(0, null, null)).toBeNull();

      // 2. strOffsetsBase out of bounds (32-bit: strOffsetsBase + 4 > size)
      const emptyView = new DataView(new ArrayBuffer(2));
      const strView = new DataView(new ArrayBuffer(10));
      expect(resolveStrX(0, emptyView, strView)).toBeNull();

      // 3. strOffsetsBase out of bounds (64-bit: strOffsetsBase + 12 > size)
      const dwarf64Empty = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
      expect(resolveStrX(0, new DataView(dwarf64Empty.buffer), strView)).toBeNull();

      // 4. versionOffset + 2 out of bounds (32-bit: needs version 2 bytes at offset 4)
      const dwarf32Trunc = new Uint8Array([8, 0, 0, 0, 5]); // only 1 byte of version
      expect(resolveStrX(0, new DataView(dwarf32Trunc.buffer), strView)).toBeNull();

      // 5. entryOffset + offsetSize out of bounds
      const dwarf32NoEntries = new Uint8Array([8, 0, 0, 0, 5, 0, 0, 0]); // length = 8, no entries
      expect(resolveStrX(0, new DataView(dwarf32NoEntries.buffer), strView)).toBeNull();

      // 6. strOffset out of bounds of debugStrView
      const dwarf32BadOffset = new Uint8Array([12, 0, 0, 0, 5, 0, 0, 0, 100, 0, 0, 0]); // offset 100
      expect(resolveStrX(0, new DataView(dwarf32BadOffset.buffer), strView)).toBeNull();
    });

    it('should parse DWARF forms with missing views or truncated buffers', () => {
      // 1. DW_FORM_string without null terminator
      const strView = new DataView(new Uint8Array([0x61, 0x62, 0x63]).buffer); // "abc"
      let res = parseFormValue(strView, 0, 0x08, false);
      expect(res.value).toBe('abc');
      expect(res.bytesRead).toBe(3);

      // 2. DW_FORM_line_strp (0x1f) with missing view
      const lineStrpView = new DataView(new Uint8Array([10, 0, 0, 0]).buffer); // offset 10
      res = parseFormValue(lineStrpView, 0, 0x1f, false, null, null);
      expect(res.value).toBe('line_strp_10');
      expect(res.bytesRead).toBe(4);

      // 3. DW_FORM_strp (0x0e) with missing view
      const strpView = new DataView(new Uint8Array([20, 0, 0, 0]).buffer); // offset 20
      res = parseFormValue(strpView, 0, 0x0e, false, null);
      expect(res.value).toBe('strp_20');
      expect(res.bytesRead).toBe(4);

      // 4. DW_FORM_strx (0x1a) with missing debugStrOffsetsView
      const strxView = new DataView(new Uint8Array([5]).buffer); // index 5
      res = parseFormValue(strxView, 0, 0x1a, false, null, null, null);
      expect(res.value).toBe('strx_5');
      expect(res.bytesRead).toBe(1);
    });

    it('should skip zero-length or unrecognized type records in parsePdbSymbols', () => {
      const bytes: number[] = [];
      // 1. zero length record (len = 0 -> skips 2 bytes and continues)
      bytes.push(0, 0);
      // 2. unrecognized type record (len = 4, type = 0x9999)
      bytes.push(4, 0);
      bytes.push(0x99, 0x99);
      bytes.push(0, 0);
      // 3. S_PUB32 (type 0x110e) record with empty name
      bytes.push(14, 0);
      bytes.push(0x0e, 0x11);
      bytes.push(0, 0, 0, 0); // flags
      bytes.push(0x00, 0x10, 0x00, 0x00); // offset
      bytes.push(1, 0); // segment
      bytes.push(0, 0); // empty name string (null terminator only)

      const buffer = new Uint8Array(bytes).buffer;
      const res = parsePdbSymbols(buffer);
      expect(res.symbols).toHaveLength(0);
      expect(res.lines).toHaveLength(0);
    });
  });
});
