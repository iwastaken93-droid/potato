import { describe, it, expect } from 'vitest';
import { CapstoneWasmEngine } from '../src/disassembler/capstoneWasm.js';
import { DisassemblerRouter } from '../src/disassembler/router.js';

describe('CapstoneWasmEngine Unit Tests', () => {
  it('should initialize with correct architecture and mode, and start unloaded', () => {
    const engine = new CapstoneWasmEngine('x86_64', '64');
    expect(engine.isEngineLoaded()).toBe(false);
  });

  it('should load asynchronously via load()', async () => {
    const engine = new CapstoneWasmEngine('x86_64', '64');
    const result = await engine.load();
    expect(result).toBe(true);
    expect(engine.isEngineLoaded()).toBe(true);
  });

  it('should load synchronously via loadSync()', () => {
    const engine = new CapstoneWasmEngine('x86_64', '64');
    engine.loadSync();
    expect(engine.isEngineLoaded()).toBe(true);
  });

  it('should throw an error when disassembling before loading', () => {
    const engine = new CapstoneWasmEngine('x86_64', '64');
    expect(() => engine.disassemble(new Uint8Array([0x90]), 0x1000)).toThrow(
      'Capstone WASM module is not loaded. Call load() or loadSync() first.'
    );
  });

  it('should disassemble x86_64 instructions correctly when loaded', () => {
    const engine = new CapstoneWasmEngine('x86_64', '64');
    engine.loadSync();

    // Bytes:
    // 0x90 (nop)
    // 0x55 (push rbp)
    // 0x48, 0x89, 0xe5 (mov rbp, rsp)
    // 0x48, 0x83, 0xec, 0x10 (sub rsp, 16)
    // 0xb8, 0xef, 0xbe, 0xad, 0xde (mov eax, 0xdeadbeef)
    // 0xc3 (ret)
    // 0xff (db 0xff)
    const data = new Uint8Array([
      0x90,
      0x55,
      0x48, 0x89, 0xe5,
      0x48, 0x83, 0xec, 0x10,
      0xb8, 0xef, 0xbe, 0xad, 0xde,
      0xc3,
      0xff,
    ]);

    const insts = engine.disassemble(data, 0x1000);
    expect(insts.length).toBe(7);

    expect(insts[0].address).toBe(0x1000);
    expect(insts[0].mnemonic).toBe('nop');
    expect(insts[0].size).toBe(1);

    expect(insts[1].address).toBe(0x1001);
    expect(insts[1].mnemonic).toBe('push');
    expect(insts[1].opStr).toBe('rbp');
    expect(insts[1].size).toBe(1);

    expect(insts[2].address).toBe(0x1002);
    expect(insts[2].mnemonic).toBe('mov');
    expect(insts[2].opStr).toBe('rbp, rsp');
    expect(insts[2].size).toBe(3);

    expect(insts[3].address).toBe(0x1005);
    expect(insts[3].mnemonic).toBe('sub');
    expect(insts[3].opStr).toBe('rsp, 16');
    expect(insts[3].size).toBe(4);

    expect(insts[4].address).toBe(0x1009);
    expect(insts[4].mnemonic).toBe('mov');
    expect(insts[4].opStr).toBe('eax, 0xdeadbeef');
    expect(insts[4].size).toBe(5);

    expect(insts[5].address).toBe(0x100e);
    expect(insts[5].mnemonic).toBe('ret');
    expect(insts[5].size).toBe(1);

    expect(insts[6].address).toBe(0x100f);
    expect(insts[6].mnemonic).toBe('db');
    expect(insts[6].opStr).toBe('0xff');
    expect(insts[6].size).toBe(1);
  });

  it('should disassemble arm instructions correctly when loaded', () => {
    const engine = new CapstoneWasmEngine('arm', 'arm');
    engine.loadSync();

    // 0xd503201f (nop)
    // 0xd65f03c0 (ret)
    // 0xe1a00000 (mov x0, x1)
    const data = new Uint8Array([
      0x1f, 0x20, 0x03, 0xd5,
      0xc0, 0x03, 0x5f, 0xd6,
      0x00, 0x00, 0xa0, 0xe1,
    ]);

    const insts = engine.disassemble(data, 0x2000);
    console.log("DEBUG arm instructions disassemble output:", insts);
    expect(insts.length).toBe(3);

    expect(insts[0].address).toBe(0x2000);
    expect(insts[0].mnemonic).toBe('nop');
    expect(insts[0].size).toBe(4);

    expect(insts[1].address).toBe(0x2004);
    expect(insts[1].mnemonic).toBe('ret');
    expect(insts[1].size).toBe(4);

    expect(insts[2].address).toBe(0x2008);
    expect(insts[2].mnemonic).toBe('mov');
    expect(insts[2].opStr).toBe('x0, x1');
    expect(insts[2].size).toBe(4);
  });

  it('should fallback for other architectures', () => {
    const engine = new CapstoneWasmEngine('mips', '32');
    engine.loadSync();

    const data = new Uint8Array([0x12, 0x34]);
    const insts = engine.disassemble(data, 0x3000);

    expect(insts.length).toBe(2);
    expect(insts[0].mnemonic).toBe('db');
    expect(insts[0].size).toBe(1);
  });
});

describe('DisassemblerRouter Integration with CapstoneWasmEngine', () => {
  it('should routing and use Capstone WASM if enabled via metadata', () => {
    const router = new DisassemblerRouter();
    const data = new Uint8Array([0x90, 0x55]); // x86_64 bytes

    // Without Capstone
    const normalInsts = router.disassemble(data, { arch: 'x86_64', baseAddress: 0x1000 });
    // With Capstone enabled via metadata
    const capstoneInsts = router.disassemble(data, {
      arch: 'x86_64',
      baseAddress: 0x1000,
      useCapstoneWasm: true,
    });

    expect(capstoneInsts.length).toBe(2);
    expect(capstoneInsts[0].mnemonic).toBe('nop');
    expect(capstoneInsts[1].mnemonic).toBe('push');
  });

  it('should routing and use Capstone WASM if enabled via router configuration', () => {
    const router = new DisassemblerRouter({ useCapstoneWasm: true });
    expect(router.isUsingCapstoneWasm()).toBe(true);

    const data = new Uint8Array([0x90, 0x55]);
    const capstoneInsts = router.disassemble(data, { arch: 'x86_64', baseAddress: 0x1000 });

    expect(capstoneInsts.length).toBe(2);
    expect(capstoneInsts[0].mnemonic).toBe('nop');
    expect(capstoneInsts[1].mnemonic).toBe('push');

    router.setUseCapstoneWasm(false);
    expect(router.isUsingCapstoneWasm()).toBe(false);
  });
});
