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

  it('should decompile instructions starting at a specific entry point and preserve complex args', async () => {
    const result = await AIBridge.executeQuery({
      action: 'decompile',
      params: {
        entryPoint: 0x1008,
        instructions: [
          { address: 0x1000, op: 'mov', args: ['[rax, rcx, 8]', 'rbx'] },
          { address: 0x1004, op: 'jmp', args: ['0x1008'] },
          { address: 0x1008, op: 'RET', args: [] }
        ]
      }
    });

    expect(result.success).toBe(true);
    expect(result.decompiled.pseudocode).not.toContain('[rax, rcx, 8]');
    expect(result.decompiled.pseudocode).toContain('return');
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

  it('should support session-persistent patch tracking and undo/redo', async () => {
    const initialHex = '11223344';

    // Reset the persistent patcherInstance state
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: {
        data: initialHex
      }
    });

    // 1. Initial patch
    const patchResult = await AIBridge.executeQuery({

      action: 'patchBinary',
      params: {
        data: initialHex,
        action: 'patch',
        patches: [
          { offset: 1, patchedBytes: 'ff', address: 0x1001, description: 'patch 1' }
        ]
      }
    });
    expect(patchResult.success).toBe(true);
    expect(patchResult.patchedData).toBe('11ff3344');
    expect(patchResult.records.length).toBe(1);

    // 2. Second patch (reuses the session-persistent patcherInstance)
    const secondResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        data: initialHex,
        action: 'patch',
        patches: [
          { offset: 2, patchedBytes: 'ee', address: 0x1002, description: 'patch 2' }
        ]
      }
    });
    expect(secondResult.success).toBe(true);
    expect(secondResult.patchedData).toBe('11ffee44');
    expect(secondResult.records.length).toBe(2);

    // 3. Undo patch
    const undoResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        action: 'undo'
      }
    });
    expect(undoResult.success).toBe(true);
    expect(undoResult.patchedData).toBe('11ff3344');
    expect(undoResult.records.length).toBe(1);
    expect(undoResult.records[0].description).toBe('patch 1');

    // 4. Redo patch
    const redoResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        action: 'redo'
      }
    });
    expect(redoResult.success).toBe(true);
    expect(redoResult.patchedData).toBe('11ffee44');
    expect(redoResult.records.length).toBe(2);

    // 5. loadBinary should reset patcherInstance
    const loadResult = await AIBridge.executeQuery({
      action: 'loadBinary',
      params: {
        data: initialHex
      }
    });
    expect(loadResult.success).toBe(true);

    // Now undo should do nothing (patcherInstance is null)
    const undoAfterReset = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        action: 'undo'
      }
    });
    expect(undoAfterReset.success).toBe(true);
    expect(undoAfterReset.patchedData).toBe('');
    expect(undoAfterReset.records.length).toBe(0);
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

  it('should analyze and categorize strings via the bridge', async () => {
    const encoder = new TextEncoder();
    const url = encoder.encode("https://example.com/test");
    const path = encoder.encode("C:\\Windows\\System32\\cmd.exe");
    const regKey = encoder.encode("HKEY_LOCAL_MACHINE\\Software\\Test");
    const format = encoder.encode("Error count: %d, Message: %s");
    const base64Str = encoder.encode("aGVsbG93b3JsZDEyMzQ1Ng==");
    const pgpKey = encoder.encode("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    const jwt = encoder.encode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    const apiKey = encoder.encode("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q");
    const oauth = encoder.encode("ya29.a0AfB_byE8L1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z");

    const buffer = new Uint8Array(1000);
    let offset = 0;

    buffer.set(url, offset);
    offset += url.length + 1;

    buffer.set(path, offset);
    offset += path.length + 1;

    buffer.set(regKey, offset);
    offset += regKey.length + 1;

    buffer.set(format, offset);
    offset += format.length + 1;

    buffer.set(base64Str, offset);
    offset += base64Str.length + 1;

    buffer.set(pgpKey, offset);
    offset += pgpKey.length + 1;

    buffer.set(jwt, offset);
    offset += jwt.length + 1;

    buffer.set(apiKey, offset);
    offset += apiKey.length + 1;

    buffer.set(oauth, offset);

    const hex = toHex(buffer);

    const result = await AIBridge.executeQuery({
      action: 'analyzeStrings',
      params: {
        data: hex,
        minLength: 4
      }
    });

    expect(result.success).toBe(true);
    expect(result.urls.map((s: any) => s.value)).toContain("https://example.com/test");
    expect(result.paths.map((s: any) => s.value)).toContain("C:\\Windows\\System32\\cmd.exe");
    expect(result.registryKeys.map((s: any) => s.value)).toContain("HKEY_LOCAL_MACHINE\\Software\\Test");
    expect(result.formatStrings.map((s: any) => s.value)).toContain("Error count: %d, Message: %s");
    expect(result.highEntropy.map((s: any) => s.value)).toContain("aGVsbG93b3JsZDEyMzQ1Ng==");
    expect(result.pgpKeys.map((s: any) => s.value)).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    expect(result.jwts.map((s: any) => s.value)).toContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    expect(result.apiKeys.map((s: any) => s.value)).toContain("AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q");
    expect(result.oauthTokens.map((s: any) => s.value)).toContain("ya29.a0AfB_byE8L1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z");
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

  it('should find cross-references via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'findXRefs',
      params: {
        data: 'e8fa0f0000',
        address: 0x1000,
        baseAddress: 0x1000
      }
    });

    expect(result.success).toBe(true);
    expect(result.incoming).toBeDefined();
    expect(result.outgoing).toBeDefined();
  });

  it('should build control flow graph via the bridge', async () => {
    const result = await AIBridge.executeQuery({
      action: 'buildCFG',
      params: {
        instructions: [
          { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx', size: 3 },
          { address: 0x1003, mnemonic: 'jmp', opStr: '0x100a', operands: [{ type: 'imm', imm: 0x100a }], size: 5 },
          { address: 0x1008, mnemonic: 'nop', size: 1 },
          { address: 0x100a, mnemonic: 'ret', size: 1 }
        ]
      }
    });

    expect(result.success).toBe(true);
    expect(result.blocks.length).toBeGreaterThan(0);
    const entryBlock = result.blocks.find((b: any) => b.startAddress === 0x1000);
    expect(entryBlock).toBeDefined();
    expect(entryBlock.successors).toContain('block_0x100a');
  });

  it('should build control flow graph from session binary with fallback to entryPoint/startVA', async () => {
    const buffer = new ArrayBuffer(512);
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
    view.setUint32(104, 0x1000, true); // AddressOfEntryPoint
    view.setUint32(116, 0x400000, true); // ImageBase (PE32)

    const secOffset = 64 + 24 + 224;
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x74; bytes[secOffset+2] = 0x65; bytes[secOffset+3] = 0x78; bytes[secOffset+4] = 0x74;
    view.setUint32(secOffset + 8, 256, true);
    view.setUint32(secOffset + 12, 0x1000, true);
    view.setUint32(secOffset + 16, 256, true);
    view.setUint32(secOffset + 20, 256, true);
    view.setUint32(secOffset + 36, 0x60000020, true);

    bytes[256] = 0x90; // nop
    bytes[257] = 0xc3; // ret

    const hex = toHex(bytes);
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: hex }
    });

    const result = await AIBridge.executeQuery({
      action: 'buildCFG',
      params: {
        arch: 'x86_64'
      }
    });

    expect(result.success).toBe(true);
    expect(result.blocks.length).toBeGreaterThan(0);
    const block = result.blocks[0];
    expect(block.startAddress).toBe(0x401000);
    expect(block.instructions.length).toBe(2);
    expect(block.instructions[0].mnemonic).toBe('nop');
    expect(block.instructions[1].mnemonic).toBe('ret');
  });

  it('should support visual format outputs for CFG', async () => {
    const instructions = [
      { address: 0x1000, mnemonic: 'mov', opStr: 'rax, rbx', size: 3 },
      { address: 0x1003, mnemonic: 'jmp', opStr: '0x100a', operands: [{ type: 'imm', imm: 0x100a }], size: 5 },
      { address: 0x1008, mnemonic: 'nop', size: 1 },
      { address: 0x100a, mnemonic: 'ret', size: 1 }
    ];

    const dotResult = await AIBridge.executeQuery({
      action: 'buildCFG',
      params: {
        instructions,
        format: 'dot'
      }
    });
    expect(dotResult.success).toBe(true);
    expect(dotResult.format).toBe('dot');
    expect(dotResult.formatted).toContain('digraph CFG');
    expect(dotResult.formatted).toContain('block_0x1000 -> block_0x100a');

    const asciiResult = await AIBridge.executeQuery({
      action: 'buildCFG',
      params: {
        instructions,
        format: 'ascii'
      }
    });
    expect(asciiResult.success).toBe(true);
    expect(asciiResult.format).toBe('ascii');
    expect(asciiResult.formatted).toContain('block_0x1000');
    expect(asciiResult.formatted).toContain('└── block_0x100a');
  });

  it('should return entry point metadata in parseBinary', async () => {
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
    view.setUint32(104, 0x1000, true); // AddressOfEntryPoint
    view.setUint32(116, 0x400000, true); // ImageBase (PE32)

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'parseBinary',
      params: {
        data: hex,
        format: 'pe'
      }
    });

    expect(result.success).toBe(true);
    expect(result.entryPoint).toBe(0x1000);
    expect(result.entryPointAddress).toBe(0x401000);
    expect(result.entryPointRVA).toBe(0x1000);
    expect(result.imageBase.toString()).toBe('4194304');
  });

  it('should limit input sizes to 10MB to prevent memory OOM crashes', async () => {
    const hugeInput = 'A'.repeat(21 * 1024 * 1024); // 21MB, exceeds 20 million chars
    await expect(AIBridge.executeQuery({
      action: 'hexDump',
      params: { data: hugeInput }
    })).rejects.toThrow('Input size exceeds 10MB limit');
  });

  it('should support limit and offset in hexDump for paging', async () => {
    const data = '00112233445566778899aabbccddeeff';
    const result = await AIBridge.executeQuery({
      action: 'hexDump',
      params: {
        data,
        offset: 4,
        limit: 8
      }
    });

    expect(result.success).toBe(true);
    expect(result.formatted).toContain('44 55 66 77 88 99 aa bb');
    expect(result.lines.length).toBe(1);
  });

  it('should calculate section breakdown entropy in entropyAnalysis', async () => {
    const buffer = new ArrayBuffer(500);
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

    // Section header details for a single section
    const secOffset = 64 + 24 + 224; // PE signature + COFF header + Optional header
    // Section Name: ".text"
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x74; bytes[secOffset+2] = 0x65; bytes[secOffset+3] = 0x78; bytes[secOffset+4] = 0x74;
    view.setUint32(secOffset + 8, 32, true); // VirtualSize = 32
    view.setUint32(secOffset + 12, 0x1000, true); // VirtualAddress = 0x1000
    view.setUint32(secOffset + 16, 32, true); // SizeOfRawData = 32
    view.setUint32(secOffset + 20, 400, true); // PointerToRawData = 400

    // Fill some random bytes into the raw data section to have some entropy
    for (let i = 400; i < 432; i++) {
      bytes[i] = i % 256;
    }

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'entropyAnalysis',
      params: { data: hex }
    });

    expect(result.success).toBe(true);
    expect(result.sectionBreakdown).toBeDefined();
    expect(result.sectionBreakdown.length).toBe(1);
    expect(result.sectionBreakdown[0].name).toBe('.text');
    expect(result.sectionBreakdown[0].entropy).toBeGreaterThan(0);
  });

  it('should cross-reference vulnerable functions against imported library names in vulnScan', async () => {
    const buffer = new ArrayBuffer(500);
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

    // Data directories: Import table RVA (offset 64 + 24 + 96 + 8 = 192)
    view.setUint32(180, 16, true); // Number of RVA and Sizes
    view.setUint32(192, 0x2000, true); // Import directory RVA = 0x2000
    view.setUint32(196, 40, true); // Import directory size = 40

    // Section header
    const secOffset = 64 + 24 + 224; 
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x69; bytes[secOffset+2] = 0x64; bytes[secOffset+3] = 0x61; bytes[secOffset+4] = 0x74; bytes[secOffset+5] = 0x61; // ".idata"
    view.setUint32(secOffset + 8, 100, true); // VirtualSize = 100
    view.setUint32(secOffset + 12, 0x2000, true); // VirtualAddress = 0x2000
    view.setUint32(secOffset + 16, 100, true); // SizeOfRawData = 100
    view.setUint32(secOffset + 20, 300, true); // PointerToRawData = 300

    // 300 is our raw data start for .idata (corresponds to RVA 0x2000)
    // Import Directory Entry at RVA 0x2000 (offset 300):
    // Import Lookup Table RVA at 300
    view.setUint32(300, 0x2028, true); 
    // Time/Date stamp
    // Forwarder chain
    // Name RVA at 30c (offset 312) -> points to "KERNEL32.dll" at RVA 0x2050 (offset 380)
    view.setUint32(312, 0x2050, true);
    // Import Address Table RVA at 316 (offset 316) -> points to RVA 0x2038 (offset 356)
    view.setUint32(316, 0x2038, true);

    // Import Lookup Table at RVA 0x2028 (offset 340):
    // Import "strcpy" hint/name RVA = 0x2060 (offset 396)
    view.setUint32(340, 0x2060, true);
    // Null terminator for ILT
    view.setUint32(344, 0, true);

    // Import Address Table at RVA 0x2038 (offset 356):
    view.setUint32(356, 0x2060, true);
    view.setUint32(360, 0, true);

    // Write "KERNEL32.dll" string at RVA 0x2050 (offset 380)
    const nameStr = 'KERNEL32.dll';
    for (let i = 0; i < nameStr.length; i++) {
      bytes[380 + i] = nameStr.charCodeAt(i);
    }

    // Write "strcpy" string at RVA 0x2060 (offset 396)
    // Hint: 0 (2 bytes)
    view.setUint16(396, 0, true);
    const funcStr = 'strcpy';
    for (let i = 0; i < funcStr.length; i++) {
      bytes[398 + i] = funcStr.charCodeAt(i);
    }

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'vulnScan',
      params: {
        data: hex,
        symbols: [{ name: 'strcpy', address: 0x2038 }]
      }
    });

    expect(result.success).toBe(true);
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    const match = result.vulnerabilities.find((v: any) => v.evidence === 'strcpy');
    expect(match).toBeDefined();
    expect(match.library).toBe('KERNEL32.dll');
  });

  it('should support hex string address parsing in typeStructRecovery and emulatorHooks', async () => {
    // 1. typeStructRecovery with hex address
    const codeBytes = '488b4308c3';
    const resultRecovery = await AIBridge.executeQuery({
      action: 'typeStructRecovery',
      params: {
        data: codeBytes,
        address: '0x1000',
        baseAddress: '0x1000',
        arch: 'x86_64'
      }
    });
    expect(resultRecovery.success).toBe(true);
    expect(resultRecovery.recoveredStructs.rbx).toContain('field_8');

    // 2. emulatorHooks with hex breakpoints
    const resultHooks = await AIBridge.executeQuery({
      action: 'emulatorHooks',
      params: {
        action: 'setBreakpoints',
        breakpoints: ['0x1000', '0x1004']
      }
    });
    expect(resultHooks.success).toBe(true);
    expect(resultHooks.breakpointCount).toBe(2);
  });

  it('should filter out stack, frame, and instruction pointer references in typeStructRecovery', async () => {
    // mov rax, [rbx + 8]   -> 488b4308
    // mov rax, [rsp + 8]   -> 488b442408
    // mov rax, [rbp + 8]   -> 488b4508
    // mov rax, [rip + 8]   -> 488b0508000000
    // ret                  -> c3
    const codeBytes = '488b4308' + '488b442408' + '488b4508' + '488b0508000000' + 'c3';
    const result = await AIBridge.executeQuery({
      action: 'typeStructRecovery',
      params: {
        data: codeBytes,
        address: '0x1000',
        baseAddress: '0x1000',
        arch: 'x86_64'
      }
    });
    expect(result.success).toBe(true);
    expect(result.recoveredStructs.rbx).toBeDefined();
    expect(result.recoveredStructs.rbx).toContain('field_8');

    // Standard stack or instruction-relative pointer registers must be filtered out
    expect(result.recoveredStructs.rsp).toBeUndefined();
    expect(result.recoveredStructs.esp).toBeUndefined();
    expect(result.recoveredStructs.rbp).toBeUndefined();
    expect(result.recoveredStructs.ebp).toBeUndefined();
    expect(result.recoveredStructs.rip).toBeUndefined();
    expect(result.recoveredStructs.eip).toBeUndefined();
  });

  it('should resolve symbolic lookup for imports in callTree and findXRefs', async () => {
    // Build a mock PE binary with imports
    const buffer = new ArrayBuffer(500);
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
    view.setUint32(116, 0x400000, true); // ImageBase = 0x400000

    // Data directories: Import table RVA (offset 64 + 24 + 96 + 8 = 192)
    view.setUint32(180, 16, true); // Number of RVA and Sizes
    view.setUint32(192, 0x2000, true); // Import directory RVA = 0x2000
    view.setUint32(196, 40, true); // Import directory size = 40

    // Section header
    const secOffset = 64 + 24 + 224; 
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x69; bytes[secOffset+2] = 0x64; bytes[secOffset+3] = 0x61; bytes[secOffset+4] = 0x74; bytes[secOffset+5] = 0x61; // ".idata"
    view.setUint32(secOffset + 8, 100, true); // VirtualSize = 100
    view.setUint32(secOffset + 12, 0x2000, true); // VirtualAddress = 0x2000
    view.setUint32(secOffset + 16, 100, true); // SizeOfRawData = 100
    view.setUint32(secOffset + 20, 300, true); // PointerToRawData = 300

    // 300 is our raw data start for .idata (corresponds to RVA 0x2000)
    // Import Directory Entry at RVA 0x2000 (offset 300):
    // Import Lookup Table RVA at 300
    view.setUint32(300, 0x2028, true); 
    // Name RVA at 312 -> points to "KERNEL32.dll" at RVA 0x2050 (offset 380)
    view.setUint32(312, 0x2050, true);
    // Import Address Table RVA at 316 -> points to RVA 0x2038 (offset 356)
    view.setUint32(316, 0x2038, true);

    // Import Lookup Table at RVA 0x2028 (offset 340):
    // Import "VirtualAlloc" hint/name RVA = 0x2060 (offset 396)
    view.setUint32(340, 0x2060, true);
    // Null terminator for ILT
    view.setUint32(344, 0, true);

    // Import Address Table at RVA 0x2038 (offset 356):
    view.setUint32(356, 0x2060, true);
    view.setUint32(360, 0, true);

    // Write "KERNEL32.dll" string at RVA 0x2050 (offset 380)
    const nameStr = 'KERNEL32.dll';
    for (let i = 0; i < nameStr.length; i++) {
      bytes[380 + i] = nameStr.charCodeAt(i);
    }

    // Write "VirtualAlloc" string at RVA 0x2060 (offset 396)
    view.setUint16(396, 0, true);
    const funcStr = 'VirtualAlloc';
    for (let i = 0; i < funcStr.length; i++) {
      bytes[398 + i] = funcStr.charCodeAt(i);
    }

    const hex = toHex(bytes);

    // 1. callTree symbolic lookup
    const resultCallTree = await AIBridge.executeQuery({
      action: 'callTree',
      params: {
        data: hex,
        target: 'VirtualAlloc'
      }
    });
    expect(resultCallTree.success).toBe(true);
    // VirtualAlloc IAT entry address is imageBase (0x400000) + 0x2038 = 0x402038
    expect(resultCallTree.targetAddress).toBe(0x402038);

    // 2. findXRefs symbolic lookup
    const resultXRefs = await AIBridge.executeQuery({
      action: 'findXRefs',
      params: {
        data: hex,
        address: 'VirtualAlloc'
      }
    });
    expect(resultXRefs.success).toBe(true);
    expect(resultXRefs.incoming).toBeDefined();
    expect(resultXRefs.outgoing).toBeDefined();
  });

  it('should resolve PE ordinal-only imports in callTree and findXRefs', async () => {
    // Build a mock PE binary with ordinal imports
    const buffer = new ArrayBuffer(500);
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
    view.setUint32(116, 0x400000, true); // ImageBase = 0x400000

    // Data directories: Import table RVA (offset 64 + 24 + 96 + 8 = 192)
    view.setUint32(180, 16, true); // Number of RVA and Sizes
    view.setUint32(192, 0x2000, true); // Import directory RVA = 0x2000
    view.setUint32(196, 40, true); // Import directory size = 40

    // Section header
    const secOffset = 64 + 24 + 224; 
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x69; bytes[secOffset+2] = 0x64; bytes[secOffset+3] = 0x61; bytes[secOffset+4] = 0x74; bytes[secOffset+5] = 0x61; // ".idata"
    view.setUint32(secOffset + 8, 100, true); // VirtualSize = 100
    view.setUint32(secOffset + 12, 0x2000, true); // VirtualAddress = 0x2000
    view.setUint32(secOffset + 16, 100, true); // SizeOfRawData = 100
    view.setUint32(secOffset + 20, 300, true); // PointerToRawData = 300

    // 300 is our raw data start for .idata (corresponds to RVA 0x2000)
    // Import Directory Entry at RVA 0x2000 (offset 300):
    // Import Lookup Table RVA at 0x2028 (offset 340)
    view.setUint32(300, 0x2028, true); 
    // Name RVA at 312 -> points to "ws2_32.dll" at RVA 0x2050 (offset 380)
    view.setUint32(312, 0x2050, true);
    // Import Address Table RVA at 316 -> points to RVA 0x2038 (offset 356)
    view.setUint32(316, 0x2038, true);

    // Import Lookup Table at RVA 0x2028 (offset 340):
    // Import by ordinal 115 (0x73) -> bit 31 set: 0x80000073
    view.setUint32(340, 0x80000073, true);
    // Import by ordinal 99 (0x63) -> bit 31 set: 0x80000063
    view.setUint32(344, 0x80000063, true);
    // Null terminator for ILT
    view.setUint32(348, 0, true);

    // Import Address Table at RVA 0x2038 (offset 356):
    view.setUint32(356, 0x80000073, true);
    view.setUint32(360, 0x80000063, true);
    view.setUint32(364, 0, true);

    // Write "ws2_32.dll" string at RVA 0x2050 (offset 380)
    const nameStr = 'ws2_32.dll';
    for (let i = 0; i < nameStr.length; i++) {
      bytes[380 + i] = nameStr.charCodeAt(i);
    }

    const hex = toHex(bytes);

    // 1. callTree search by WSAStartup
    const resultCallTreeWSA = await AIBridge.executeQuery({
      action: 'callTree',
      params: {
        data: hex,
        target: 'WSAStartup'
      }
    });
    expect(resultCallTreeWSA.success).toBe(true);
    // WSAStartup IAT entry address is imageBase (0x400000) + 0x2038 = 0x402038
    expect(resultCallTreeWSA.targetAddress).toBe(0x402038);

    // 2. callTree search by Ordinal_115
    const resultCallTreeOrd115 = await AIBridge.executeQuery({
      action: 'callTree',
      params: {
        data: hex,
        target: 'Ordinal_115'
      }
    });
    expect(resultCallTreeOrd115.success).toBe(true);
    expect(resultCallTreeOrd115.targetAddress).toBe(0x402038);

    // 3. callTree search by Ordinal_99 (unmapped ordinal)
    const resultCallTreeOrd99 = await AIBridge.executeQuery({
      action: 'callTree',
      params: {
        data: hex,
        target: 'Ordinal_99'
      }
    });
    expect(resultCallTreeOrd99.success).toBe(true);
    // Ordinal_99 IAT entry address is imageBase (0x400000) + 0x203c = 0x40203c
    expect(resultCallTreeOrd99.targetAddress).toBe(0x40203c);

    // 4. findXRefs symbolic lookup for Ordinal_115
    const resultXRefs = await AIBridge.executeQuery({
      action: 'findXRefs',
      params: {
        data: hex,
        address: 'Ordinal_115'
      }
    });
    expect(resultXRefs.success).toBe(true);
    expect(resultXRefs.incoming).toBeDefined();
    expect(resultXRefs.outgoing).toBeDefined();
  });

  it('should verify and implement pipelineChainMode data chaining with placeholders', async () => {
    const buffer = new ArrayBuffer(500);
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
    view.setUint32(104, 0x1000, true); // AddressOfEntryPoint = 0x1000
    view.setUint32(116, 0x400000, true); // ImageBase (PE32) = 0x400000

    // Section header
    const secOffset = 64 + 24 + 224; 
    bytes[secOffset] = 0x2e; bytes[secOffset+1] = 0x74; bytes[secOffset+2] = 0x65; bytes[secOffset+3] = 0x78; bytes[secOffset+4] = 0x74; // ".text"
    view.setUint32(secOffset + 8, 100, true); // VirtualSize = 100
    view.setUint32(secOffset + 12, 0x1000, true); // VirtualAddress = 0x1000
    view.setUint32(secOffset + 16, 100, true); // SizeOfRawData = 100
    view.setUint32(secOffset + 20, 300, true); // PointerToRawData = 300
    view.setUint32(secOffset + 36, 0x60000020, true); // Section characteristics: executable & code

    // Write a call instruction to offset 300 (VA 0x401000)
    // mov rax, rbx (48 89 d8)
    bytes[300] = 0x48; bytes[301] = 0x89; bytes[302] = 0xd8;
    // call 0x401010 (e8 08 00 00 00)
    bytes[303] = 0xe8; bytes[304] = 0x08; bytes[305] = 0x00; bytes[306] = 0x00; bytes[307] = 0x00;
    // ret (c3)
    bytes[308] = 0xc3;
    // ret at 0x401010 (offset 316)
    bytes[316] = 0xc3;

    // Write some string for extractStrings at offset 350
    const helloStr = 'HelloChained';
    for (let i = 0; i < helloStr.length; i++) {
      bytes[350 + i] = helloStr.charCodeAt(i);
    }
    bytes[350 + helloStr.length] = 0;

    const mockPeHex = toHex(bytes);

    const result = await AIBridge.executeQuery({
      action: 'pipelineChainMode',
      params: {
        pipeline: [
          {
            tool: 'loadBinary',
            params: {
              data: mockPeHex
            }
          },
          {
            tool: 'parseBinary',
            params: {
              format: 'pe'
            }
          },
          {
            tool: 'extractStrings',
            params: {
              baseAddress: '$$prev.entryPointAddress$$',
              minLength: 4
            }
          },
          {
            tool: 'callTree',
            params: {
              target: '0x$$results[1].entryPointAddress.toString(16)$$'
            }
          }
        ]
      }
    });

    expect(result.success).toBe(true);
    expect(result.pipelineResults.length).toBe(4);

    // Verify step 0: loadBinary
    expect(result.pipelineResults[0].success).toBe(true);
    expect(result.pipelineResults[0].format).toBe('pe');

    // Verify step 1: parseBinary
    expect(result.pipelineResults[1].success).toBe(true);
    expect(result.pipelineResults[1].entryPointAddress).toBe(0x401000);
    expect(result.pipelineResults[1].imageBase.toString()).toBe('4194304'); // 0x400000

    // Verify step 2: extractStrings using baseAddress placeholder
    expect(result.pipelineResults[2].success).toBe(true);
    const extracted = result.pipelineResults[2].strings.find((s: any) => s.value === 'HelloChained');
    expect(extracted).toBeDefined();
    // 350 is offset. baseAddress is set to entryPointAddress (0x401000):
    // address of offset 350 is 0x401000 + 350 = 0x40115e (4198750)
    expect(extracted.virtualAddress).toBe(0x401000 + 350);

    // Verify step 3: callTree
    expect(result.pipelineResults[3].success).toBe(true);
    expect(result.pipelineResults[3].targetAddress).toBe(0x401000);
    expect(result.pipelineResults[3].callees.length).toBe(1);
    expect(result.pipelineResults[3].callees[0].calleeAddress).toBe(0x401010);
  });

  it('should successfully save and load emulator sessions via the bridge', async () => {
    // 1. Reset/load binary into the session
    const binaryDataHex = '48c7c037130000c3'; // mov rax, 0x1337; ret
    const loadResult = await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: binaryDataHex }
    });
    expect(loadResult.success).toBe(true);

    // Initialize emulator with instruction and entry point
    const resetResult = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'reset',
        entryPoint: 0x1000,
        instructions: [
          { address: 0x1000, mnemonic: 'mov', opStr: 'rax, 0x1337', bytes: toUint8Array('48c7c037130000'), size: 7 },
          { address: 0x1007, mnemonic: 'ret', opStr: '', bytes: toUint8Array('c3'), size: 1 }
        ]
      }
    });
    expect(resetResult.success).toBe(true);

    // Set registers and memory
    await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'writeReg',
        registers: {
          rbx: '5555',
          rcx: '9999'
        }
      }
    });

    await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'writeMem',
        memory: [
          { address: '0x2000', value: '41424344' } // "ABCD"
        ]
      }
    });

    // Set breakpoint
    await AIBridge.executeQuery({
      action: 'emulatorHooks',
      params: {
        action: 'setBreakpoints',
        breakpoints: [0x1007]
      }
    });

    // Execute one step to produce an execution trace
    const stepResult = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'step',
        steps: 1
      }
    });
    expect(stepResult.success).toBe(true);

    // 2. Save Session
    const tempSessionPath = './scratch/session_test.json';
    const saveResult = await AIBridge.executeQuery({
      action: 'sessionSave',
      params: { filePath: tempSessionPath }
    });
    expect(saveResult.success).toBe(true);

    // 3. Clear/Reset emulator to zero-out state
    const cleanReset = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'reset',
        entryPoint: 0
      }
    });
    expect(cleanReset.success).toBe(true);

    // Clear breakpoints
    await AIBridge.executeQuery({
      action: 'emulatorHooks',
      params: { action: 'clearBreakpoints' }
    });

    // Verify registers are reset and trace is empty
    const checkRegs = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: { action: 'readReg' }
    });
    expect(checkRegs.registers.rbx).toBe('0');
    expect(checkRegs.registers.rcx).toBe('0');

    // 4. Load Session
    const loadSessionResult = await AIBridge.executeQuery({
      action: 'sessionLoad',
      params: { filePath: tempSessionPath }
    });
    expect(loadSessionResult.success).toBe(true);

    // 5. Verify restored state
    // Verify registers
    const restoredRegs = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: { action: 'readReg' }
    });
    expect(restoredRegs.registers.rax).toBe('4919'); // 0x1337 in decimal (step completed executing mov rax, 0x1337)
    expect(restoredRegs.registers.rbx).toBe('5555');
    expect(restoredRegs.registers.rcx).toBe('9999');

    // Verify memory
    const restoredMem = await AIBridge.executeQuery({
      action: 'emulatorControl',
      params: {
        action: 'readMem',
        memory: [
          { address: '0x2000', size: 4 }
        ]
      }
    });
    expect(restoredMem.memory[0].hex).toBe('41424344');

    // Verify Breakpoints
    const restoredHooks = await AIBridge.executeQuery({
      action: 'emulatorHooks',
      params: {
        action: 'setBreakpoints',
        breakpoints: [] // get breakpoints count returned by setting empty (or we can query/check)
      }
    });
    // In emulatorHooks setBreakpoints action: returns breakpointCount. So we set it to empty and verify count is 0?
    // Wait, the setBreakpoints action clears and resets the breakpoints array.
    // If we call it with [0x1007] it should return 1.
    const restoredHooksCheck = await AIBridge.executeQuery({
      action: 'emulatorHooks',
      params: {
        action: 'setBreakpoints',
        breakpoints: [0x1007]
      }
    });
    expect(restoredHooksCheck.breakpointCount).toBe(1);

    // Let's verify trace log directly by calling saveSession again or inspecting emulator
    // Let's clean up file
    const fs = await import('fs');
    if (fs.existsSync(tempSessionPath)) {
      fs.unlinkSync(tempSessionPath);
    }
  });

  it('should detect function boundaries and estimate names using findFunctions', async () => {
    // Function 1: push rbp; mov rbp, rsp; mov eax, 1; pop rbp; ret (11 bytes)
    // padding: nop (1 byte)
    // Function 2: push rdi; push rsi; sub rsp, 8; add edi, esi; add rsp, 8; pop rsi; pop rdi; ret (15 bytes)
    const mockBinaryHex = '554889e5b8010000005dc39057564883ec0801f74883c4085e5fc3';

    const result = await AIBridge.executeQuery({
      action: 'findFunctions',
      params: {
        data: mockBinaryHex,
        arch: 'x86_64'
      }
    });

    expect(result.success).toBe(true);
    expect(result.boundaries).toBeDefined();
    expect(result.boundaries.length).toBe(2);

    const f1 = result.boundaries[0];
    expect(f1.startVA).toBe(0);
    expect(f1.endVA).toBe(11);
    expect(f1.estimatedName).toBe('func_0x0');

    const f2 = result.boundaries[1];
    expect(f2.startVA).toBe(12);
    expect(f2.endVA).toBe(27);
    expect(f2.estimatedName).toBe('func_0xc');
  });

  it('should successfully run generateReport and aggregate all outputs', async () => {
    const mockBinaryHex = '4d5a9000000000000000000000000000' +
                          '00000000000000000000000000000040' +
                          '00000000000000000000000000000000' +
                          '504500004c0101000000000000000000' +
                          '00000000e00000000b01000000000000' +
                          '00100000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000002e74657874000000' +
                          '00100000001000000010000000020000' +
                          '00000000000000000000000020000060';

    let fullHex = mockBinaryHex.padEnd(1024, '0');
    const payload = '9090909073747263707900' +
                    '636d642e65786500' +
                    'c3';
    fullHex = fullHex.substring(0, 1024) + payload + fullHex.substring(1024 + payload.length);

    const result = await AIBridge.executeQuery({
      action: 'generateReport',
      params: {
        data: fullHex,
        fileName: 'generate_report_test.exe'
      }
    });

    expect(result.success).toBe(true);
    expect(result.jsonReport).toBeDefined();
    expect(result.markdownReport).toBeDefined();

    expect(result.jsonReport.fileName).toBe('generate_report_test.exe');
    expect(result.jsonReport.fileSize).toBeGreaterThan(0);
    expect(result.jsonReport.architecture).toBeDefined();
    expect(result.jsonReport.entropy).toBeDefined();
    expect(result.jsonReport.strings.length).toBeGreaterThan(0);

    expect(result.jsonReport.yaraMatches).toBeDefined();
    const yaraMatch = result.jsonReport.yaraMatches.find((m: any) => m.ruleName === 'SuspiciousStrings');
    expect(yaraMatch).toBeDefined();

    expect(result.jsonReport.vulnerabilities).toBeDefined();
    const vuln = result.jsonReport.vulnerabilities.find((v: any) => v.evidence === 'strcpy');
    expect(vuln).toBeDefined();

    expect(result.jsonReport.idaScript).toBeDefined();

    expect(result.markdownReport).toContain('# Binary Analysis Report: generate_report_test.exe');
    expect(result.markdownReport).toContain('## 🛡️ YARA Scan Results');
    expect(result.markdownReport).toContain('## ⚠️ Vulnerability / Unsafe API Scan Results');
    expect(result.markdownReport).toContain('## 🔌 IDA Pro / Ghidra Export Script');
  });

  it('should fallback to session binary and disassemble starting at the .text entry point by default', async () => {
    // 1. Create a mock PE binary with a .text section
    const buffer = new ArrayBuffer(512);
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

    // Setup section table for .text
    const secOffset = 64 + 24 + 224; // PE signature + COFF header + Optional header
    // Section name ".text"
    bytes[secOffset] = 0x2e; bytes[secOffset + 1] = 0x74; bytes[secOffset + 2] = 0x65; bytes[secOffset + 3] = 0x78; bytes[secOffset + 4] = 0x74;
    view.setUint32(secOffset + 8, 0x10, true); // VirtualSize = 16
    view.setUint32(secOffset + 12, 0x1000, true); // VirtualAddress = 0x1000
    view.setUint32(secOffset + 16, 0x10, true); // SizeOfRawData = 16
    view.setUint32(secOffset + 20, 300, true); // PointerToRawData = 300

    // Fill some assembly instructions at PointerToRawData = 300
    // NOP (90)
    bytes[300] = 0x90;
    // RET (C3)
    bytes[301] = 0xc3;

    const hex = toHex(bytes);

    // 2. Load the binary into the session
    const loadResult = await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: hex }
    });
    expect(loadResult.success).toBe(true);

    // 3. Run disassemble with data parameter omitted
    const disasmResult = await AIBridge.executeQuery({
      action: 'disassemble',
      params: {
        arch: 'x86_64'
      }
    });

    expect(disasmResult.success).toBe(true);
    expect(disasmResult.instructions.length).toBeGreaterThan(0);
    // Should start at .text section entry point (virtual address 0x1000)
    expect(disasmResult.instructions[0].address).toBe(0x1000);
    expect(disasmResult.instructions[0].op.toUpperCase()).toBe('NOP');
    expect(disasmResult.instructions[1].op.toUpperCase()).toBe('RET');
  });

  it('should fallback to session binary and support section-name queries in hexDump', async () => {
    // 1. Create a mock PE binary with two sections (.text and .data)
    const buffer = new ArrayBuffer(600);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 64, true); // e_lfanew
    view.setUint32(64, 0x00004550, true); // PE signature
    view.setUint16(68, 0x14c, true); // Machine: Intel 386
    view.setUint16(70, 2, true); // Number of Sections: 2
    view.setUint16(84, 224, true); // SizeOfOptionalHeader
    view.setUint16(88, 0x10b, true); // Magic (PE32)

    // Setup section table
    const sec1Offset = 64 + 24 + 224; // PE signature + COFF header + Optional header
    // Section 1 name ".text"
    bytes[sec1Offset] = 0x2e; bytes[sec1Offset + 1] = 0x74; bytes[sec1Offset + 2] = 0x65; bytes[sec1Offset + 3] = 0x78; bytes[sec1Offset + 4] = 0x74;
    view.setUint32(sec1Offset + 8, 0x10, true); // VirtualSize = 16
    view.setUint32(sec1Offset + 12, 0x1000, true); // VirtualAddress = 0x1000
    view.setUint32(sec1Offset + 16, 0x10, true); // SizeOfRawData = 16
    view.setUint32(sec1Offset + 20, 300, true); // PointerToRawData = 300

    // Section 2 name ".data"
    const sec2Offset = sec1Offset + 40;
    bytes[sec2Offset] = 0x2e; bytes[sec2Offset + 1] = 0x64; bytes[sec2Offset + 2] = 0x61; bytes[sec2Offset + 3] = 0x74; bytes[sec2Offset + 4] = 0x61;
    view.setUint32(sec2Offset + 8, 0x10, true); // VirtualSize = 16
    view.setUint32(sec2Offset + 12, 0x2000, true); // VirtualAddress = 0x2000
    view.setUint32(sec2Offset + 16, 0x10, true); // SizeOfRawData = 16
    view.setUint32(sec2Offset + 20, 400, true); // PointerToRawData = 400

    // Fill some distinctive bytes in .data
    // 0xAA 0xBB 0xCC 0xDD
    bytes[400] = 0xaa;
    bytes[401] = 0xbb;
    bytes[402] = 0xcc;
    bytes[403] = 0xdd;

    const hex = toHex(bytes);

    // 2. Load the binary into the session
    const loadResult = await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: hex }
    });
    expect(loadResult.success).toBe(true);

    // 3. Run hexDump with data omitted but section: ".data"
    const dumpResult = await AIBridge.executeQuery({
      action: 'hexDump',
      params: {
        section: '.data',
        bytesPerLine: 8
      }
    });

    expect(dumpResult.success).toBe(true);
    expect(dumpResult.formatted.replace(/\s+/g, '')).toContain('aabbccdd');
    // Ensure the offset in the dump output corresponds to .data raw offset (400 = 0x00000190)
    expect(dumpResult.lines[0]).toContain('00000190');

    // 4. Run hexDump with data omitted (no section name, should dump everything from offset 0)
    const dumpAll = await AIBridge.executeQuery({
      action: 'hexDump',
      params: {
        bytesPerLine: 8
      }
    });
    expect(dumpAll.success).toBe(true);
    // Since offset is 0, the first line should be offset 0
    expect(dumpAll.lines[0]).toContain('00000000');
  });

  it('should detect XOR key-decryption loops, stack-string construction, and control flow flattening via deobfuscate tool', async () => {
    // 1. XOR loop
    const resultXor = await AIBridge.executeQuery({
      action: 'deobfuscate',
      params: {
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rcx', '0'] },
          { address: 0x1008, op: 'xor', args: ['BYTE PTR [rax + rcx]', '0x5A'] },
          { address: 0x100f, op: 'inc', args: ['rcx'] },
          { address: 0x1012, op: 'cmp', args: ['rcx', '10'] },
          { address: 0x1016, op: 'jl', args: ['0x1008'] }
        ]
      }
    });
    expect(resultXor.success).toBe(true);
    expect(resultXor.detected).toBe(true);
    const xorPattern = resultXor.patterns.find((p: any) => p.pattern === 'XOR key-decryption loop');
    expect(xorPattern).toBeDefined();
    expect(xorPattern.loopStart).toBe(0x1008);
    expect(xorPattern.key).toBe('0x5a');

    // 2. Stack-string
    const resultStackString = await AIBridge.executeQuery({
      action: 'deobfuscate',
      params: {
        instructions: [
          { address: 0x2000, op: 'mov', args: ['BYTE PTR [rsp + 8]', '0x48'] },
          { address: 0x2005, op: 'mov', args: ['BYTE PTR [rsp + 9]', '0x65'] },
          { address: 0x200a, op: 'mov', args: ['BYTE PTR [rsp + 10]', '0x6c'] },
          { address: 0x200f, op: 'mov', args: ['BYTE PTR [rsp + 11]', '0x6c'] },
          { address: 0x2014, op: 'mov', args: ['BYTE PTR [rsp + 12]', '0x6f'] },
          { address: 0x2019, op: 'mov', args: ['BYTE PTR [rsp + 13]', '0x00'] }
        ]
      }
    });
    expect(resultStackString.success).toBe(true);
    expect(resultStackString.detected).toBe(true);
    const ssPattern = resultStackString.patterns.find((p: any) => p.pattern === 'Stack-string construction');
    expect(ssPattern).toBeDefined();
    expect(ssPattern.reconstructedString).toBe('Hello\\0');

    // 3. Control Flow Flattening
    const resultCff = await AIBridge.executeQuery({
      action: 'deobfuscate',
      params: {
        instructions: [
          { address: 0x3000, op: 'cmp', args: ['eax', '0x1'] },
          { address: 0x3005, op: 'je', args: ['0x3020'] },
          { address: 0x300b, op: 'cmp', args: ['eax', '0x2'] },
          { address: 0x3010, op: 'je', args: ['0x3030'] },
          { address: 0x3016, op: 'jmp', args: ['0x3040'] },
          { address: 0x3020, op: 'mov', args: ['eax', '0x2'] },
          { address: 0x3025, op: 'jmp', args: ['0x3000'] },
          { address: 0x3030, op: 'mov', args: ['eax', '0x3'] },
          { address: 0x3035, op: 'jmp', args: ['0x3000'] },
          { address: 0x3040, op: 'mov', args: ['eax', '0x1'] },
          { address: 0x3045, op: 'jmp', args: ['0x3000'] }
        ]
      }
    });
    expect(resultCff.success).toBe(true);
    expect(resultCff.detected).toBe(true);
    const cffPattern = resultCff.patterns.find((p: any) => p.pattern === 'Control Flow Flattening');
    expect(cffPattern).toBeDefined();
  });

  it('should support patchAndRun execution with string addresses and breakpoints', async () => {
    const result = await AIBridge.executeQuery({
      action: 'patchAndRun',
      params: {
        data: '90909090', // 4 NOPs
        patches: [
          { offset: '0x1', patchedBytes: '90' }
        ],
        runUntil: '0x2',
        maxSteps: 10
      }
    });

    expect(result.success).toBe(true);
    expect(result.stepsRun).toBe(2);
    expect(result.hitBreakpoint).toBe(true);
    expect(result.cpuState.rip).toBe('2');
  });

  it('should parse PE exports via analyzeExports', async () => {
    const buffer = new ArrayBuffer(1024);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    view.setUint32(60, 64, true); // e_lfanew
    view.setUint32(64, 0x00004550, true); // PE signature
    view.setUint16(68, 0x8664, true); // AMD64
    view.setUint16(70, 1, true); // 1 Section
    view.setUint16(84, 240, true); // size of optional header

    const optionalOffset = 64 + 24; // 88
    view.setUint16(optionalOffset, 0x20b, true);

    const winOffset = optionalOffset + 24; // 112
    view.setBigUint64(winOffset, 0x10000000n, true); // ImageBase = 0x10000000

    const stackHeapOffset = winOffset + 48; // 160
    const afterStackHeapOffset = stackHeapOffset + 32; // 192
    view.setUint32(afterStackHeapOffset + 4, 1, true); // NumberOfRvaAndSizes = 1 (1 directory: Export)

    const dirOffset = afterStackHeapOffset + 8; // 200 (optionalOffset + 112)
    view.setUint32(dirOffset, 0x2000, true); // Export Directory VirtualAddress = 0x2000
    view.setUint32(dirOffset + 4, 100, true); // Size = 100

    const sectionOffset = optionalOffset + 240; // 328
    bytes[sectionOffset] = 0x2e; bytes[sectionOffset + 1] = 0x65; bytes[sectionOffset + 2] = 0x64; bytes[sectionOffset + 3] = 0x61; bytes[sectionOffset + 4] = 0x74; bytes[sectionOffset + 5] = 0x61;
    view.setUint32(sectionOffset + 8, 0x1000, true); // VirtualSize = 0x1000
    view.setUint32(sectionOffset + 12, 0x2000, true); // VirtualAddress = 0x2000 (matches export dir)
    view.setUint32(sectionOffset + 16, 512, true); // SizeOfRawData = 512
    view.setUint32(sectionOffset + 20, 512, true); // PointerToRawData = 512 (file offset 512)

    const expOffset = 512;
    view.setUint32(expOffset + 16, 1, true); // OrdinalBase = 1
    view.setUint32(expOffset + 20, 1, true); // NumberOfFunctions = 1
    view.setUint32(expOffset + 24, 1, true); // NumberOfNames = 1
    view.setUint32(expOffset + 28, 0x2028, true); // AddressOfFunctions RVA = 0x2028
    view.setUint32(expOffset + 32, 0x202c, true); // AddressOfNames RVA = 0x202c
    view.setUint32(expOffset + 36, 0x2030, true); // AddressOfNameOrdinals RVA = 0x2030

    view.setUint32(512 + 0x28, 0x1000, true); // Function RVA = 0x1000
    view.setUint32(512 + 0x2c, 0x2034, true); // Name RVA = 0x2034
    view.setUint16(512 + 0x30, 0, true); // Ordinal index = 0

    const nameStr = 'MyExportedFunc';
    for (let i = 0; i < nameStr.length; i++) {
      bytes[564 + i] = nameStr.charCodeAt(i);
    }

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'analyzeExports',
      params: {
        data: hex,
        format: 'pe'
      }
    });
    expect(result.success).toBe(true);
    expect(result.format).toBe('pe');
    expect(result.exports.length).toBe(1);
    expect(result.exports[0].name).toBe('MyExportedFunc');
    expect(result.exports[0].ordinal).toBe(1);
    expect(result.exports[0].address).toBe(0x10000000 + 0x1000);
  });

  it('should parse PE resources via analyzeResources', async () => {
    const buffer = new ArrayBuffer(2048);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);

    bytes[0] = 0x4d; // 'M'
    bytes[1] = 0x5a; // 'Z'
    const e_lfanew = 64;
    view.setUint32(60, e_lfanew, true);
    view.setUint32(e_lfanew, 0x00004550, true);

    const coffOffset = e_lfanew + 4; // 68
    view.setUint16(coffOffset, 0x8664, true); // AMD64
    view.setUint16(coffOffset + 2, 1, true); // 1 Section
    const sizeOfOptionalHeader = 240;
    view.setUint16(coffOffset + 16, sizeOfOptionalHeader, true);

    const optionalOffset = coffOffset + 20; // 88
    view.setUint16(optionalOffset, 0x20b, true);
    view.setBigUint64(optionalOffset + 24, 0x140000000n, true);

    const winOffset = optionalOffset + 24;
    const stackHeapOffset = winOffset + 48;
    const afterStackHeapOffset = stackHeapOffset + 32;
    view.setUint32(afterStackHeapOffset + 4, 3, true); // 3 directories

    const dirOffset = afterStackHeapOffset + 8;
    view.setUint32(dirOffset + 16, 0x2000, true); // Resource VirtualAddress
    view.setUint32(dirOffset + 20, 1024, true); // Resource Size

    const sectionOffset = optionalOffset + sizeOfOptionalHeader; // 328
    bytes[sectionOffset] = 0x2e; bytes[sectionOffset + 1] = 0x72; bytes[sectionOffset + 2] = 0x73; bytes[sectionOffset + 3] = 0x72; bytes[sectionOffset + 4] = 0x63;
    view.setUint32(sectionOffset + 8, 0x1000, true); // VirtualSize
    view.setUint32(sectionOffset + 12, 0x2000, true); // VirtualAddress
    view.setUint32(sectionOffset + 16, 1024, true); // SizeOfRawData
    view.setUint32(sectionOffset + 20, 512, true); // PointerToRawData

    const rsrcFileOffset = 512;
    view.setUint16(rsrcFileOffset + 12, 0, true);
    view.setUint16(rsrcFileOffset + 14, 3, true);

    // Type 6 (String Table) at offset 48
    view.setUint32(rsrcFileOffset + 16, 6, true);
    view.setUint32(rsrcFileOffset + 20, 0x80000000 | 48, true);

    // Type 16 (Version Info) at offset 80
    view.setUint32(rsrcFileOffset + 24, 16, true);
    view.setUint32(rsrcFileOffset + 28, 0x80000000 | 80, true);

    // Type 24 (Manifest) at offset 112
    view.setUint32(rsrcFileOffset + 32, 24, true);
    view.setUint32(rsrcFileOffset + 36, 0x80000000 | 112, true);

    // Type 6 Name subdirectory
    view.setUint16(rsrcFileOffset + 48 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 48 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 48 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 48 + 20, 0x80000000 | 144, true);

    // Type 16 Name subdirectory
    view.setUint16(rsrcFileOffset + 80 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 80 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 80 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 80 + 20, 0x80000000 | 176, true);

    // Type 24 Name subdirectory
    view.setUint16(rsrcFileOffset + 112 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 112 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 112 + 16, 1, true);
    view.setUint32(rsrcFileOffset + 112 + 20, 0x80000000 | 208, true);

    // Type 6 Lang -> data offset 240
    view.setUint16(rsrcFileOffset + 144 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 144 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 144 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 144 + 20, 240, true);

    // Type 16 Lang -> data offset 256
    view.setUint16(rsrcFileOffset + 176 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 176 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 176 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 176 + 20, 256, true);

    // Type 24 Lang -> data offset 272
    view.setUint16(rsrcFileOffset + 208 + 12, 0, true);
    view.setUint16(rsrcFileOffset + 208 + 14, 1, true);
    view.setUint32(rsrcFileOffset + 208 + 16, 1033, true);
    view.setUint32(rsrcFileOffset + 208 + 20, 272, true);

    // Data Entries:
    // Type 6 (String Table): RVA = 0x2170 (offset 880), Size = 48
    view.setUint32(rsrcFileOffset + 240, 0x2170, true);
    view.setUint32(rsrcFileOffset + 240 + 4, 48, true);

    // Type 16 (Version Info): RVA = 0x21C0 (offset 960), Size = 300
    view.setUint32(rsrcFileOffset + 256, 0x21c0, true);
    view.setUint32(rsrcFileOffset + 256 + 4, 300, true);

    // Type 24 (Manifest): RVA = 0x2140 (offset 832), Size = 33
    view.setUint32(rsrcFileOffset + 272, 0x2140, true);
    view.setUint32(rsrcFileOffset + 272 + 4, 33, true);

    // Manifest Text at 832
    const manifestText = '<assembly>MockManifest</assembly>';
    for (let i = 0; i < manifestText.length; i++) {
      bytes[832 + i] = manifestText.charCodeAt(i);
    }

    // String Table at 880
    view.setUint16(880, 4, true);
    const str1 = 'Test';
    for (let i = 0; i < str1.length; i++) {
      view.setUint16(882 + i * 2, str1.charCodeAt(i), true);
    }

    // Version Info at 960
    const vOffset = 960;
    view.setUint16(vOffset, 300, true);
    view.setUint16(vOffset + 2, 52, true);
    view.setUint16(vOffset + 4, 0, true);
    const keyStr = 'VS_VERSION_INFO';
    for (let i = 0; i < keyStr.length; i++) {
      view.setUint16(vOffset + 6 + i * 2, keyStr.charCodeAt(i), true);
    }
    view.setUint16(vOffset + 6 + keyStr.length * 2, 0, true);

    const fixedOffset = 1000;
    view.setUint32(fixedOffset, 0xFEEF04BD, true);
    view.setUint32(fixedOffset + 4, 0x00010000, true);
    view.setUint32(fixedOffset + 8, 0x00020003, true);
    view.setUint32(fixedOffset + 12, 0x00040005, true);
    view.setUint32(fixedOffset + 16, 0, true);
    view.setUint32(fixedOffset + 20, 0, true);

    const sfiOffset = 1052;
    view.setUint16(sfiOffset, 150, true);
    view.setUint16(sfiOffset + 2, 0, true);
    view.setUint16(sfiOffset + 4, 1, true);
    const sfiKey = 'StringFileInfo';
    for (let i = 0; i < sfiKey.length; i++) {
      view.setUint16(sfiOffset + 6 + i * 2, sfiKey.charCodeAt(i), true);
    }
    view.setUint16(sfiOffset + 6 + sfiKey.length * 2, 0, true);

    const stOffset = 1088;
    view.setUint16(stOffset, 110, true);
    view.setUint16(stOffset + 2, 0, true);
    view.setUint16(stOffset + 4, 1, true);
    const stKey = '040904b0';
    for (let i = 0; i < stKey.length; i++) {
      view.setUint16(stOffset + 6 + i * 2, stKey.charCodeAt(i), true);
    }
    view.setUint16(stOffset + 6 + stKey.length * 2, 0, true);

    const strOffset = 1112;
    view.setUint16(strOffset, 80, true);
    view.setUint16(strOffset + 2, 11, true);
    view.setUint16(strOffset + 4, 1, true);
    const sKey = 'CompanyName';
    for (let i = 0; i < sKey.length; i++) {
      view.setUint16(strOffset + 6 + i * 2, sKey.charCodeAt(i), true);
    }
    view.setUint16(strOffset + 6 + sKey.length * 2, 0, true);

    const valOffset = 1144;
    const sVal = 'TestCompany';
    for (let i = 0; i < sVal.length; i++) {
      view.setUint16(valOffset + i * 2, sVal.charCodeAt(i), true);
    }
    view.setUint16(valOffset + sVal.length * 2, 0, true);

    const hex = toHex(bytes);
    const result = await AIBridge.executeQuery({
      action: 'analyzeResources',
      params: {
        data: hex
      }
    });

    expect(result.success).toBe(true);
    expect(result.manifests.length).toBe(1);
    expect(result.manifests[0]).toBe('<assembly>MockManifest</assembly>');
    expect(result.strings['0']).toBe('Test');
    expect(result.versionHeaders.length).toBe(1);
    expect(result.versionHeaders[0].fixedFileInfo.fileVersion).toBe('2.3.4.5');
    expect(result.versionHeaders[0].stringFileInfo.CompanyName).toBe('TestCompany');
  });

  it('should run importRiskAnalyzer on provided data and return a risk score', async () => {
    // 9090 is nop nop in x86
    const result = await AIBridge.executeQuery({
      action: 'importRiskAnalyzer',
      params: {
        data: '9090'
      }
    });

    expect(result.success).toBe(true);
    expect(result.riskScore).toBeDefined();
    expect(typeof result.riskScore).toBe('number');
    expect(Array.isArray(result.combos)).toBe(true);
    expect(Array.isArray(result.evidence)).toBe(true);
  });

  it('should run importRiskAnalyzer against the session binary when data parameter is omitted', async () => {
    // First load binary into session
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: {
        data: '90909090'
      }
    });

    const result = await AIBridge.executeQuery({
      action: 'importRiskAnalyzer',
      params: {}
    });

    expect(result.success).toBe(true);
    expect(result.riskScore).toBeDefined();
    expect(typeof result.riskScore).toBe('number');
    expect(Array.isArray(result.combos)).toBe(true);
    expect(result.evidence.length).toBe(0); // No vulnerabilities in a NOP stream
  });

  it('should support patcher state and undo/redo persistence across session save and load', async () => {
    const initialHex = '11223344';
    const tempSessionPath = './scratch/persistent_patch_test.json';

    // 1. Load initial binary into session
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: initialHex }
    });

    // 2. Apply a patch
    const patchResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: {
        data: initialHex,
        action: 'patch',
        patches: [
          { offset: 1, patchedBytes: 'ff', address: 0x1001, description: 'persistent patch 1' }
        ]
      }
    });
    expect(patchResult.success).toBe(true);
    expect(patchResult.patchedData).toBe('11ff3344');

    // 3. Save the session
    const saveResult = await AIBridge.executeQuery({
      action: 'sessionSave',
      params: { filePath: tempSessionPath }
    });
    expect(saveResult.success).toBe(true);

    // 4. Reset the bridge session completely by loading a different binary
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: 'aabbccdd' }
    });
    // Patcher should be null now
    expect(AIBridge.patcherInstance).toBeNull();

    // 5. Load the session back
    const loadResult = await AIBridge.executeQuery({
      action: 'sessionLoad',
      params: { filePath: tempSessionPath }
    });
    expect(loadResult.success).toBe(true);

    // 6. Verify restored patcher state and history
    expect(AIBridge.patcherInstance).toBeDefined();
    expect(AIBridge.patcherInstance).not.toBeNull();
    const history = AIBridge.patcherInstance!.getHistory();
    expect(history.length).toBe(1);
    expect(history[0].description).toBe('persistent patch 1');

    // 7. Verify we can perform undo on the restored session
    const undoResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: { action: 'undo' }
    });
    expect(undoResult.success).toBe(true);
    expect(undoResult.patchedData).toBe('11223344');

    // 8. Verify we can perform redo on the restored session
    const redoResult = await AIBridge.executeQuery({
      action: 'patchBinary',
      params: { action: 'redo' }
    });
    expect(redoResult.success).toBe(true);
    expect(redoResult.patchedData).toBe('11ff3344');

    // Clean up
    const fs = await import('fs');
    if (fs.existsSync(tempSessionPath)) {
      fs.unlinkSync(tempSessionPath);
    }
  });

  it('should throw a detailed warning when JSON text is passed instead of raw binary', async () => {
    await expect(
      AIBridge.executeQuery({
        action: 'disassemble',
        params: {
          data: '{"filePath": "crackme.exe", "baseAddress": 4194304}'
        }
      })
    ).rejects.toThrow("Warning: data appears to be JSON text (starts with '{'), not binary. Expected PE magic 'MZ' or ELF magic '\\x7FELF'. Did you pass the parameter JSON instead of a file path? Use loadBinary({ filePath: '...' }) first.");
  });

  it('should return session status via getSessionStatus', async () => {
    // 1. Check status when no binary is loaded
    (AIBridge as any).loadedBinaryBytes = null;

    const status1 = await AIBridge.executeQuery({
      action: 'getSessionStatus',
      params: {}
    });
    expect(status1.success).toBe(true);
    expect(status1.loaded).toBe(false);

    // 2. Check status when a mock binary is loaded
    await AIBridge.executeQuery({
      action: 'loadBinary',
      params: { data: '4d5a90000300' } // MZ signature
    });

    const status2 = await AIBridge.executeQuery({
      action: 'getSessionStatus',
      params: {}
    });
    expect(status2.success).toBe(true);
    expect(status2.loaded).toBe(true);
    expect(status2.format).toBe('pe');
    expect(status2.size).toBe(6);
  });
});


