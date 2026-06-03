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
} from '../src/emulator/gdbProtocol.js';

function assert(condition, message) {
  if (!condition) {
    throw new Error('Assertion failed: ' + message);
  }
}

function expect(val) {
  return {
    toBe(expected) {
      assert(val === expected, `Expected ${val} to be ${expected}`);
    },
    toEqual(expected) {
      assert(JSON.stringify(val) === JSON.stringify(expected), `Expected ${JSON.stringify(val)} to equal ${JSON.stringify(expected)}`);
    },
    toBeGreaterThan(expected) {
      assert(val > expected, `Expected ${val} to be > ${expected}`);
    },
    not: {
      toBeNull() {
        assert(val !== null, `Expected ${val} not to be null`);
      },
      toContain(sub) {
        assert(!val.includes(sub), `Expected ${val} not to contain ${sub}`);
      }
    },
    toContain(sub) {
      assert(val.includes(sub), `Expected ${val} to contain ${sub}`);
    }
  };
}

async function run() {
  console.log("Starting tests...");

  // Test 1
  console.log("Running: should calculate correct 8-bit checksum");
  expect(calculateChecksum('OK')).toBe((79 + 75) % 256);
  expect(calculateChecksum('')).toBe(0);

  // Test 2
  console.log("Running: should escape special characters correctly");
  expect(escapeData('$')).toBe('}\x04'); // 0x24 ^ 0x20 = 0x04
  expect(escapeData('#')).toBe('}\x03'); // 0x23 ^ 0x20 = 0x03
  expect(escapeData('}')).toBe('}]'); // 0x7d ^ 0x20 = 0x5d (']')
  expect(escapeData('*')).toBe('}\x0a'); // 0x2a ^ 0x20 = 0x0a ('\n')
  expect(escapeData('abc')).toBe('abc');

  // Test 3
  console.log("Running: should unescape special characters correctly");
  expect(unescapeData('}\x04')).toBe('$');
  expect(unescapeData('}\x03')).toBe('#');
  expect(unescapeData('}]')).toBe('}');
  expect(unescapeData('}\x0a')).toBe('*');
  expect(unescapeData('abc')).toBe('abc');

  // Test 4
  console.log("Running: should format a packet correctly");
  expect(formatPacket('OK')).toBe('$OK#9a');

  // Test 5
  console.log("Running: should handle BigInt endianness conversion correctly");
  const val = 0x1234567890abcdefn;
  const hex = toLittleEndianHex(val, 8);
  expect(hex).toBe('efcdab9078563412');
  expect(fromLittleEndianHex(hex)).toBe(val);

  // Test 6
  console.log("Running: should parse ACKs and NAKs");
  const packets = [];
  const parser = new GDBProtocolParser((p) => packets.push(p));
  parser.feed('+');
  parser.feed('-');
  expect(packets).toEqual([{ type: 'ack' }, { type: 'nak' }]);

  // Test 7
  console.log("Running: should parse valid packets with correct checksum");
  packets.length = 0;
  parser.feed('$OK#9a');
  expect(packets).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);

  // Test 8
  console.log("Running: should parse packet with escaped characters");
  packets.length = 0;
  const data = 'a}\x04b';
  const chk = calculateChecksum(data).toString(16).padStart(2, '0');
  parser.feed(`$${data}#${chk}`);
  expect(packets).toEqual([{ type: 'packet', data: 'a$b', raw: data }]);

  // Test 9
  console.log("Running: should fail packet with invalid checksum");
  packets.length = 0;
  parser.feed('$OK#00'); // incorrect checksum
  expect(packets).toEqual([{ type: 'packet', data: undefined, raw: 'OK' }]);

  // Test 10
  console.log("Running: should handle streaming data fed in chunks");
  packets.length = 0;
  parser.feed('$O');
  parser.feed('K#9');
  parser.feed('a');
  expect(packets).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);

  // Test 11
  console.log("Running: should handle \"?\" (stop reason)");
  const emulator = new Emulator();
  expect(handleGDBCommand('?', emulator)).toBe('S05');

  // Test 12
  console.log("Running: should handle register reading and writing");
  emulator.reset();
  expect(handleGDBCommand('P0=1122334455667788', emulator)).toBe('OK');
  expect(handleGDBCommand('P10=abcdef0000000000', emulator)).toBe('OK');
  expect(emulator.cpu.read('rax')).toBe(0x8877665544332211n);
  expect(emulator.cpu.read('rip')).toBe(0x0000000000efcdabn);
  expect(handleGDBCommand('p0', emulator)).toBe('1122334455667788');
  expect(handleGDBCommand('p10', emulator)).toBe('abcdef0000000000');
  const gOutput = handleGDBCommand('g', emulator);
  expect(gOutput.startsWith('1122334455667788')).toBe(true);
  const customG = ''.padEnd(
    X86_64_REGISTERS.reduce((acc, r) => acc + r.size * 2, 0),
    'f'
  );
  expect(handleGDBCommand('G' + customG, emulator)).toBe('OK');
  expect(emulator.cpu.read('rax')).toBe(0xffffffffffffffffn);

  // Test 13
  console.log("Running: should handle memory reading and writing");
  emulator.reset();
  emulator.memory.strictMode = true;
  emulator.memory.map(0x1000n, 0x100);
  expect(handleGDBCommand('M1000,4:aabbccdd', emulator)).toBe('OK');
  expect(handleGDBCommand('m1000,4', emulator)).toBe('aabbccdd');
  expect(handleGDBCommand('m9999,4', emulator)).toBe('E03');

  // Test 14
  console.log("Running: should handle stepping and continuing");
  emulator.reset(0x1000);
  emulator.memory.map(0x1000n, 0x10);
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
  expect(handleGDBCommand('s', emulator)).toBe('S05');
  expect(emulator.cpu.read('rip')).toBe(0x1003n);
  emulator.cpu.write('rip', 0x1000n);
  expect(handleGDBCommand('c', emulator)).toBe('W00');

  // Test 15
  console.log("Running: should handle qSupported");
  expect(handleGDBCommand('qSupported', emulator)).toBe('PacketSize=1024');

  // Test 16
  console.log("Running: should return empty string for unrecognized commands");
  expect(handleGDBCommand('unknownCommand', emulator)).toBe('');

  // Test 17
  console.log("Running: should handle edge cases in register read/write");
  emulator.reset();
  expect(handleGDBCommand('p-1', emulator)).toBe('E01');
  expect(handleGDBCommand('p99', emulator)).toBe('E01');
  expect(handleGDBCommand('pXYZ', emulator)).toBe('E01');
  expect(handleGDBCommand('P-1=123', emulator)).toBe('E01');
  expect(handleGDBCommand('P99=123', emulator)).toBe('E01');
  expect(handleGDBCommand('P0=', emulator)).toBe('OK');
  expect(handleGDBCommand('P0', emulator)).toBe('E01');
  expect(handleGDBCommand('P0=ffffffffffffffff', emulator)).toBe('OK');
  expect(emulator.cpu.read('rax')).toBe(0xffffffffffffffffn);
  expect(handleGDBCommand('p0', emulator)).toBe('ffffffffffffffff');
  emulator.cpu.write('rax', 0n);
  expect(handleGDBCommand('G112233', emulator)).toBe('OK');
  expect(emulator.cpu.read('rax')).toBe(0n);

  // Test 18
  console.log("Running: should handle edge cases in memory read/write");
  emulator.reset();
  emulator.memory.strictMode = true;
  emulator.memory.map(0x1000n, 0x100);
  expect(handleGDBCommand('m1000', emulator)).toBe('E01');
  expect(handleGDBCommand('m1000,', emulator)).toBe('E01');
  expect(handleGDBCommand('m,4', emulator)).toBe('E01');
  expect(handleGDBCommand('m-1000,4', emulator)).toBe('E03');
  expect(handleGDBCommand('m1000,-4', emulator)).toBe('E01');
  expect(handleGDBCommand('M1000,2:ff00', emulator)).toBe('OK');
  expect(handleGDBCommand('m1000,2', emulator)).toBe('ff00');
  expect(handleGDBCommand('M1000,4:aabb', emulator)).toBe('OK');
  expect(handleGDBCommand('m1000,4', emulator)).toBe('aabb0000');
  expect(handleGDBCommand('M0fff,2:1122', emulator)).toBe('E03');
  expect(handleGDBCommand('m0fff,2', emulator)).toBe('E03');
  expect(handleGDBCommand('M10ff,2:1122', emulator)).toBe('E03');
  expect(handleGDBCommand('m10ff,2', emulator)).toBe('E03');

  // Test 19
  console.log("Running: should handle breakpoints and control flow during continue");
  emulator.reset();
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
  emulator.instructions.set(0x1003, {
    address: 0x1003,
    mnemonic: 'mov',
    opStr: 'rax, rax',
    bytes: new Uint8Array([0x48, 0x89, 0xc0]),
    size: 3,
    operands: [
      { type: 'reg', reg: 'rax' },
      { type: 'reg', reg: 'rax' },
    ],
  });
  emulator.instructions.set(0x1006, {
    address: 0x1006,
    mnemonic: 'mov',
    opStr: 'rax, rax',
    bytes: new Uint8Array([0x48, 0x89, 0xc0]),
    size: 3,
    operands: [
      { type: 'reg', reg: 'rax' },
      { type: 'reg', reg: 'rax' },
    ],
  });
  emulator.reset(0x1000);
  expect(handleGDBCommand('s1003', emulator)).toBe('S05');
  expect(emulator.cpu.read('rip')).toBe(0x1006n);
  emulator.cpu.write('rip', 0x1000n);
  emulator.addBreakpoint(0x1003);
  emulator.addBreakpoint(0x1006);
  expect(handleGDBCommand('c1000', emulator)).toBe('S05');
  expect(emulator.cpu.read('rip')).toBe(0x1003n);
  expect(handleGDBCommand('c', emulator)).toBe('S05');
  expect(emulator.cpu.read('rip')).toBe(0x1006n);
  expect(handleGDBCommand('c', emulator)).toBe('W00');

  // Test 20
  console.log("Running: should handle escaping/checksum edge cases");
  expect(calculateChecksum('AAAAA')).toBe(69);
  const escaped = escapeData('$}#*');
  expect(escaped).toBe('}\x04' + '}]' + '}\x03' + '}\x0a');
  expect(unescapeData(escaped)).toBe('$}#*');

  // Test 21
  console.log("Running: should handle parser streaming and corruption");
  const packetsStream = [];
  const parserStream = new GDBProtocolParser((p) => packetsStream.push(p));
  parserStream.feed('junk$OK#9a');
  expect(packetsStream).toEqual([{ type: 'packet', data: 'OK', raw: 'OK' }]);
  packetsStream.length = 0;
  parserStream.feed('$OK#00$OK#9a');
  expect(packetsStream).toEqual([
    { type: 'packet', data: undefined, raw: 'OK' },
    { type: 'packet', data: 'OK', raw: 'OK' },
  ]);

  console.log("All tests passed successfully!");
}

run().catch((e) => {
  console.error("Test failed with error:", e);
});
