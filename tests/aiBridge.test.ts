import { describe, it, expect } from 'vitest';
import { AIBridge, toUint8Array, toHex } from '../src/analyzer/aiBridge.js';

describe('AI Query Bridge & Tool System Tests', () => {
  it('should successfully convert hex strings and base64 strings to Uint8Array', () => {
    const hex = '4d5a9000';
    const decodedHex = toUint8Array(hex);
    expect(toHex(decodedHex)).toBe(hex);

    const b64 = 'UklGRg==';
    const decodedB64 = toUint8Array(b64);
    expect(decodedB64[0]).toBe(0x52); // 'R'
    expect(decodedB64[1]).toBe(0x49); // 'I'
  });

  it('should disassemble binary data via the bridge', async () => {
    // Simple 6502 NOP: EA
    const result = await AIBridge.executeQuery({
      action: 'disassemble',
      params: {
        data: 'ea',
        arch: 'm6502'
      }
    });

    expect(result.success).toBe(true);
    expect(result.instructions.length).toBeGreaterThan(0);
    expect(result.instructions[0].op.toUpperCase()).toBe('NOP');
  });

  it('should decompile instructions via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'decompile',
      params: {
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rax', 'rbx'] },
          { address: 0x1004, op: 'ret', args: [] }
        ]
      }
    });

    expect(result.success).toBe(true);
    expect(result.decompiled.pseudocode).toContain('rax');
  });

  it('should parse PE headers via the bridge', async () => {
    const buffer = new ArrayBuffer(352);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 64, true); // e_lfanew
    view.setUint32(64, 0x00004550, true); // PE signature
    view.setUint16(68, 0x14c, true); // Machine: Intel 386
    view.setUint16(70, 1, true); // Number of Sections
    view.setUint16(84, 224, true); // SizeOfOptionalHeader
    view.setUint16(88, 0x10b, true); // Magic (PE32)

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'parseBinary',
      params: {
        data: hex,
        format: 'pe'
      }
    });

    expect(result.success).toBe(true);
    expect(result.format).toBe('pe');
    expect(result.header.machine).toBe(0x14c);
  });

  it('should apply binary patches via the bridge', async () => {
    const initialHex = '11223344';
    const result = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        data: initialHex,
        patches: [
          { offset: 1, patchedBytes: 'ff', address: 0x1001, description: 'patch test' }
        ]
      }
    });

    expect(result.success).toBe(true);
    expect(result.patchedData).toBe('11ff3344');
    expect(result.records.length).toBe(1);
    expect(result.records[0].description).toBe('patch test');
  });

  it('should execute scripts with scripting context via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'executeScript',
      params: {
        data: 'aabbcc',
        script: `
          console.log("data size: " + data.length);
          helpers.result = data[0];
        `
      }
    });

    expect(result.success).toBe(true);
    expect(result.logs).toContain('data size: 3');
  });

  it('should run YARA scans via the bridge', async () => {
    const data = 'test_yara_rule_trigger_value';
    const rules = `
      rule TestRule {
        strings:
          $str = "yara_rule_trigger"
        condition:
          $str
      }
    `;

    const result = await AIBridge.executeQuery({
      action: 'yaraScan',
      params: {
        data: toHex(new TextEncoder().encode(data)),
        rules
      }
    });

    expect(result.success).toBe(true);
    expect(result.matches.length).toBe(1);
    expect(result.matches[0].ruleName).toBe('TestRule');
  });

  it('should scan for vulnerabilities via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'vulnScan',
      params: {
        importNames: ['strcpy', 'gets']
      }
    });

    expect(result.success).toBe(true);
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.vulnerabilities.map(v => v.evidence)).toContain('strcpy');
  });

  it('should perform binary diffing via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'diffBinaries',
      params: {
        dataA: '112233',
        dataB: '114433',
        type: 'bytes'
      }
    });

    expect(result.success).toBe(true);
    expect(result.diffs.length).toBeGreaterThan(0);
  });

  it('should analyze assembly patterns via AI engine in bridge', async () => {
    const code = `
      void decrypt(uint8_t *buffer, int size) {
        uint8_t s[256];
        int i, j = 0;
        for (i = 0; i < 256; i++) s[i] = i;
        swap(&s[i], &s[j]);
      }
    `;
    const result = await AIBridge.executeQuery({
      action: 'analyzeCodeAI',
      params: {
        code,
        functionName: 'rc4_decrypt'
      }
    });

    expect(result.success).toBe(true);
    expect(result.analysis.summary).toContain('RC4');
  });

  it('should symbolically execute instructions and solve path constraints', async () => {
    const result = await AIBridge.executeQuery({
      action: 'symbolicExecute',
      params: {
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rax', 'x'] },
          { address: 0x1004, op: 'add', args: ['rax', '10'] },
          { address: 0x1008, op: 'cmp', args: ['rax', '25'] },
          { address: 0x100c, op: 'je', args: ['0x2000'] }
        ],
        inputs: [
          { name: 'x', min: 0, max: 100 }
        ],
        targetAddress: 0x2000
      }
    });

    expect(result.success).toBe(true);
    expect(result.pathFound).toBe(true);
    expect(result.constraints).toContain('(x + 10) === 25');
    expect(result.solutions).toBeDefined();
    expect(result.solutions!.x).toBe(15);
  });

  it('should explore multiple paths and solve branch constraints', async () => {
    const result = await AIBridge.executeQuery({
      action: 'symbolicExecute',
      params: {
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rax', 'x'] },
          { address: 0x1004, op: 'cmp', args: ['rax', '50'] },
          { address: 0x1008, op: 'jl', args: ['0x1018'] },
          // Path 1: x >= 50
          { address: 0x100c, op: 'cmp', args: ['rax', '70'] },
          { address: 0x1010, op: 'je', args: ['0x2000'] },
          { address: 0x1014, op: 'jmp', args: ['0x3000'] },
          // Path 2: x < 50
          { address: 0x1018, op: 'cmp', args: ['rax', '20'] },
          { address: 0x101c, op: 'je', args: ['0x2000'] }
        ],
        inputs: [
          { name: 'x', min: 0, max: 100 }
        ],
        targetAddress: 0x2000
      }
    });

    expect(result.success).toBe(true);
    expect(result.pathFound).toBe(true);
    // Should find solutions for x = 70 or x = 20 depending on which path is evaluated first
    expect(result.solutions).toBeDefined();
    expect([20, 70]).toContain(result.solutions!.x);
  });

  it('should control emulator via the bridge', async () => {
    // Reset and load instructions
    const resetResult = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'reset',
        entryPoint: 0x1000,
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rax', '0x42'], bytes: new Uint8Array([0xb8, 0x42, 0x00, 0x00, 0x00]) }
        ]
      }
    });

    expect(resetResult.success).toBe(true);
    expect(resetResult.cpuState.rip).toBe('4096'); // 0x1000

    // Step execution
    const stepResult = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'step',
        steps: 1
      }
    });

    expect(stepResult.success).toBe(true);
    expect(stepResult.cpuState.rax).toBe('66'); // 0x42
  });

  it('should extract strings via the bridge', async () => {
    const raw = 'Hello\x00World\x00\x00\x00';
    const hex = toHex(new TextEncoder().encode(raw));
    const result = await AIBridge.executeQuery({
      action: 'extractStrings',
      params: {
        data: hex,
        minLength: 4
      }
    });

    expect(result.success).toBe(true);
    expect(result.strings.map((s: any) => s.value)).toContain('Hello');
    expect(result.strings.map((s: any) => s.value)).toContain('World');
  });

  it('should get sections from PE via the bridge', async () => {
    const buffer = new ArrayBuffer(352);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 64, true); // e_lfanew
    view.setUint32(64, 0x00004550, true); // PE signature
    view.setUint16(68, 0x14c, true); // Machine: Intel 386
    view.setUint16(70, 1, true); // Number of Sections
    view.setUint16(84, 224, true); // SizeOfOptionalHeader
    view.setUint16(88, 0x10b, true); // Magic (PE32)

    // Setup section table
    const secOffset = 64 + 24 + 224; // PE signature + COFF header + Optional header
    // Section name ".text"
    bytes[secOffset] = 0x2e; bytes[secOffset + 1] = 0x74; bytes[secOffset + 2] = 0x65; bytes[secOffset + 3] = 0x78; bytes[secOffset + 4] = 0x74;
    view.setUint32(secOffset + 8, 0x1000, true); // VirtualSize
    view.setUint32(secOffset + 12, 0x1000, true); // VirtualAddress
    view.setUint32(secOffset + 16, 0x200, true); // SizeOfRawData
    view.setUint32(secOffset + 20, 0x200, true); // PointerToRawData

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'getSections',
      params: {
        data: hex,
        format: 'pe'
      }
    });

    expect(result.success).toBe(true);
    expect(result.format).toBe('pe');
    expect(result.sections.length).toBe(1);
    expect(result.sections[0].name).toBe('.text');
  });

  it('should run entropy analysis via the bridge', async () => {
    // 256 random-ish bytes
    const randomBytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      randomBytes[i] = Math.floor(Math.random() * 256);
    }
    const hex = toHex(randomBytes);
    const result = await AIBridge.executeQuery({
      action: 'entropyAnalysis',
      params: {
        data: hex,
        blockSize: 64,
        stride: 32,
        threshold: 5.0
      }
    });

    expect(result.success).toBe(true);
    expect(result.overall).toBeGreaterThan(4.0);
    expect(result.highEntropyBlocks.length).toBeGreaterThan(0);
  });

  it('should generate a hex dump via the bridge', async () => {
    const raw = 'ABCDEF1234567890';
    const hex = toHex(new TextEncoder().encode(raw));
    const result = await AIBridge.executeQuery({
      action: 'hexDump',
      params: {
        data: hex,
        bytesPerLine: 8
      }
    });

    expect(result.success).toBe(true);
    expect(result.lines.length).toBe(2);
    expect(result.formatted).toContain('ABCDEF12');
  });
});
