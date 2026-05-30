import { describe, it, expect } from 'vitest';
import { Emulator } from '../src/emulator/emulator.js';
import {
  calculateChecksum,
  escapeData,
  unescapeData,
  formatPacket,
  toLittleEndianHex,
  fromLittleEndianHex,
  GDBProtocolParser,
  handleGDBCommand,
  X86_64_REGISTERS,
  GDBPacket,
} from '../src/emulator/gdbProtocol.js';

describe('GDB/LLDB RSP Protocol Tests', () => {
  describe('Checksum & Escaping Utilities', () => {
    it('should calculate correct 8-bit checksum', () => {
      expect(calculateChecksum('OK')).toBe((79 + 75) % 256);
      expect(calculateChecksum('')).toBe(0);
    });

    it('should escape special characters correctly', () => {
      // '$', '#', '}', and '*' should be escaped with '}' and XORed with 0x20
      expect(escapeData('$')).toBe('}\x04'); // 0x24 ^ 0x20 = 0x04
      expect(escapeData('#')).toBe('}\x03'); // 0x23 ^ 0x20 = 0x03
      expect(escapeData('}')).toBe('}]'); // 0x7d ^ 0x20 = 0x5d (']')
      expect(escapeData('*')).toBe('}\x0a'); // 0x2a ^ 0x20 = 0x0a ('\n')
      expect(escapeData('abc')).toBe('abc');
    });

    it('should unescape special characters correctly', () => {
      expect(unescapeData('}\x04')).toBe('$');
      expect(unescapeData('}\x03')).toBe('#');
      expect(unescapeData('}]')).toBe('}');
      expect(unescapeData('}\x0a')).toBe('*');
      expect(unescapeData('abc')).toBe('abc');
    });

    it('should format a packet correctly', () => {
      // $OK#9a (79 + 75 = 154 = 0x9a)
      expect(formatPacket('OK')).toBe('$OK#9a');
    });

    it('should handle BigInt endianness conversion correctly', () => {
      const val = 0x1234567890abcdefn;
      const hex = toLittleEndianHex(val, 8);
      expect(hex).toBe('efcdab9078563412');
      expect(fromLittleEndianHex(hex)).toBe(val);
    });
  });

  describe('GDBProtocolParser', () => {
    it('should parse ACKs and NAKs', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      parser.feed('+');
      parser.feed('-');
      expect(packets).toEqual([{ type: 'ack' }, { type: 'nak' }]);
    });

    it('should parse valid packets with correct checksum', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      parser.feed('$OK#9a');
      expect(packets).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);
    });

    it('should parse packet with escaped characters', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      // Escaped '$' is '}\x04'
      const data = 'a}\x04b';
      const chk = calculateChecksum(data).toString(16).padStart(2, '0');
      parser.feed(`$${data}#${chk}`);

      expect(packets).toEqual([{ type: 'packet', data: 'a$b', raw: data }]);
    });

    it('should fail packet with invalid checksum', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      parser.feed('$OK#00'); // incorrect checksum
      expect(packets).toEqual([{ type: 'packet', data: undefined, raw: 'OK' }]);
    });

    it('should handle streaming data fed in chunks', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      parser.feed('$O');
      parser.feed('K#9');
      parser.feed('a');

      expect(packets).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);
    });
  });

  describe('handleGDBCommand Emulator Queries', () => {
    it('should handle "?" (stop reason)', () => {
      const emulator = new Emulator();
      expect(handleGDBCommand('?', emulator)).toBe('S05');
    });

    it('should handle register reading and writing ("g", "G", "p", "P")', () => {
      const emulator = new Emulator();
      emulator.reset();

      // Write RAX (index 0) and RIP (index 16) using P
      expect(handleGDBCommand('P0=1122334455667788', emulator)).toBe('OK');
      expect(handleGDBCommand('P10=abcdef0000000000', emulator)).toBe('OK'); // hex 10 is 16

      expect(emulator.cpu.read('rax')).toBe(0x8877665544332211n);
      expect(emulator.cpu.read('rip')).toBe(0x0000000000efcdabn);

      // Read single registers
      expect(handleGDBCommand('p0', emulator)).toBe('1122334455667788');
      expect(handleGDBCommand('p10', emulator)).toBe('abcdef0000000000');

      // Read all registers via g
      const gOutput = handleGDBCommand('g', emulator);
      expect(gOutput.startsWith('1122334455667788')).toBe(true);

      // Write all registers via G
      const customG = ''.padEnd(
        X86_64_REGISTERS.reduce((acc, r) => acc + r.size * 2, 0),
        'f'
      );
      expect(handleGDBCommand('G' + customG, emulator)).toBe('OK');
      expect(emulator.cpu.read('rax')).toBe(0xffffffffffffffffn);
    });

    it('should handle memory reading and writing ("m", "M")', () => {
      const emulator = new Emulator();
      emulator.reset();
      emulator.memory.strictMode = true;

      // Map a memory region for testing
      emulator.memory.map(0x1000n, 0x100);

      // Write memory via M: M addr,length:XX...
      expect(handleGDBCommand('M1000,4:aabbccdd', emulator)).toBe('OK');

      // Read memory via m: m addr,length
      expect(handleGDBCommand('m1000,4', emulator)).toBe('aabbccdd');

      // Read out of bounds memory should fail with E03
      expect(handleGDBCommand('m9999,4', emulator)).toBe('E03');
    });

    it('should handle stepping and continuing ("s", "c")', () => {
      const emulator = new Emulator();
      emulator.reset(0x1000);
      emulator.memory.map(0x1000n, 0x10);

      // Mock a 'mov rax, rax' instruction
      emulator.instructions.set(0x1000, {
        address: 0x1000,
        mnemonic: 'mov',
        opStr: 'rax, rax',
        bytes: new Uint8Array([0x48, 0x89, 0xc0]),
        size: 3,
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'reg', reg: 'rax' },
        ],
      });

      // Step should succeed and return stop reply S05
      const stepResponse = handleGDBCommand('s', emulator);
      expect(stepResponse).toBe('S05');
      expect(emulator.cpu.read('rip')).toBe(0x1003n);

      // Reset RIP to 0x1000 for continue test
      emulator.cpu.write('rip', 0x1000n);

      // Continue should execute and halt (since there is nothing at 0x1003)
      const continueResponse = handleGDBCommand('c', emulator);
      expect(continueResponse).toBe('W00');
    });

    it('should handle qSupported', () => {
      const emulator = new Emulator();
      expect(handleGDBCommand('qSupported', emulator)).toBe('PacketSize=1024');
    });

    it('should return empty string for unrecognized commands', () => {
      const emulator = new Emulator();
      expect(handleGDBCommand('unknownCommand', emulator)).toBe('');
    });

    it('should handle edge cases in register read/write ("p", "P", "g", "G")', () => {
      const emulator = new Emulator();
      emulator.reset();

      // Invalid register indices
      expect(handleGDBCommand('p-1', emulator)).toBe('E01');
      expect(handleGDBCommand('p99', emulator)).toBe('E01');
      expect(handleGDBCommand('pXYZ', emulator)).toBe('E01');
      expect(handleGDBCommand('P-1=123', emulator)).toBe('E01');
      expect(handleGDBCommand('P99=123', emulator)).toBe('E01');
      expect(handleGDBCommand('P0=', emulator)).toBe('OK');
      expect(handleGDBCommand('P0', emulator)).toBe('E01');

      // Writing/reading RAX (index 0) with boundary/large values
      expect(handleGDBCommand('P0=ffffffffffffffff', emulator)).toBe('OK');
      expect(emulator.cpu.read('rax')).toBe(0xffffffffffffffffn);
      expect(handleGDBCommand('p0', emulator)).toBe('ffffffffffffffff');

      // G command with short hexData
      emulator.cpu.write('rax', 0n);
      expect(handleGDBCommand('G112233', emulator)).toBe('OK');
      // Should have parsed only what was available (rax has 8 bytes, so 112233 is 3 bytes, leaving rax partially modified or unwritten depending on implementation details)
      // Actually writeGeneralRegisters loops through X86_64_REGISTERS:
      // if (offset + charsNeeded > hexData.length) break;
      // Since rax needs 16 hex characters and we passed '112233' (6 chars), it breaks immediately. RAX should remain unchanged.
      expect(emulator.cpu.read('rax')).toBe(0n);
    });

    it('should handle edge cases in memory read/write ("m", "M")', () => {
      const emulator = new Emulator();
      emulator.reset();
      emulator.memory.strictMode = true;
      emulator.memory.map(0x1000n, 0x100);

      // Malformed memory read commands
      expect(handleGDBCommand('m1000', emulator)).toBe('E01');
      expect(handleGDBCommand('m1000,', emulator)).toBe('E01');
      expect(handleGDBCommand('m,4', emulator)).toBe('E01');
      expect(handleGDBCommand('m-1000,4', emulator)).toBe('E03'); // parsing error or unmapped
      expect(handleGDBCommand('m1000,-4', emulator)).toBe('E01');

      // Map, write and verify boundaries
      expect(handleGDBCommand('M1000,2:ff00', emulator)).toBe('OK');
      expect(handleGDBCommand('m1000,2', emulator)).toBe('ff00');

      // Mismatched length and payload on M command
      // Length is 4, but only 2 bytes provided
      expect(handleGDBCommand('M1000,4:aabb', emulator)).toBe('OK'); // parses what it can, might fill rest with NaN -> 0
      expect(handleGDBCommand('m1000,4', emulator)).toBe('aabb0000');

      // Writing/reading out of bounds memory
      expect(handleGDBCommand('M0fff,2:1122', emulator)).toBe('E03');
      expect(handleGDBCommand('m0fff,2', emulator)).toBe('E03');
      expect(handleGDBCommand('M10ff,2:1122', emulator)).toBe('E03'); // overflows map
      expect(handleGDBCommand('m10ff,2', emulator)).toBe('E03');
    });

    it('should handle breakpoints and control flow during continue ("c" and "s")', () => {
      const emulator = new Emulator();

      // Mock consecutive valid instructions
      // Instruction 1: RIP 0x1000 (size 2)
      emulator.instructions.set(0x1000, {
        address: 0x1000,
        mnemonic: 'nop',
        opStr: '',
        bytes: new Uint8Array([0x90, 0x90]),
        size: 2,
        operands: [],
      });
      // Instruction 2: RIP 0x1002 (size 2)
      emulator.instructions.set(0x1002, {
        address: 0x1002,
        mnemonic: 'nop',
        opStr: '',
        bytes: new Uint8Array([0x90, 0x90]),
        size: 2,
        operands: [],
      });
      // Instruction 3: RIP 0x1004 (size 2)
      emulator.instructions.set(0x1004, {
        address: 0x1004,
        mnemonic: 'nop',
        opStr: '',
        bytes: new Uint8Array([0x90, 0x90]),
        size: 2,
        operands: [],
      });

      // Call reset after instructions are registered so that they are mapped into memory
      emulator.reset(0x1000);

      // Step with address argument: s1002 should set RIP to 0x1002, step, and stop at 0x1004
      expect(handleGDBCommand('s1002', emulator)).toBe('S05');
      expect(emulator.cpu.read('rip')).toBe(0x1004n);

      // Continue with address argument and breakpoint
      emulator.cpu.write('rip', 0x1000n);
      emulator.addBreakpoint(0x1002);

      // c1000 should set RIP to 0x1000, step over, then hit breakpoint at 0x1002
      expect(handleGDBCommand('c1000', emulator)).toBe('S05');
      expect(emulator.cpu.read('rip')).toBe(0x1002n);

      // If we continue again from 0x1002 (where breakpoint is), it should step past it first and then halt/run
      expect(handleGDBCommand('c', emulator)).toBe('S05'); // hits next breakpoint or end of instruction list (halts at 0x1006 after max steps / unmapped)
    });

    it('should handle escaping/checksum edge cases', () => {
      // Checksum wrapping (> 255)
      // 'A' is 65. 5 * 65 = 325. 325 % 256 = 69.
      expect(calculateChecksum('AAAAA')).toBe(69);

      // Sequential escapes
      const escaped = escapeData('$}#*');
      expect(escaped).toBe('}\x04' + '}]' + '}\x03' + '}\x0a');
      expect(unescapeData(escaped)).toBe('$}#*');
    });

    it('should handle parser streaming and corruption', () => {
      const packets: GDBPacket[] = [];
      const parser = new GDBProtocolParser((p) => packets.push(p));

      // Junk before packet should be ignored
      parser.feed('junk$OK#9a');
      expect(packets).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);
      packets.length = 0;

      // Interrupted packet followed by valid packet
      parser.feed('$OK#00$OK#9a');
      expect(packets).toEqual([
        { type: 'packet', data: undefined, raw: 'OK' },
        { type: 'packet', data: 'OK', raw: 'OK' },
      ]);
    });
  });
});
