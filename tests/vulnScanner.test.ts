import { describe, test, expect } from 'vitest';
import { VulnScanner } from '../src/analyzer/vulnScanner.js';
import { Instruction, Section, Symbol } from '../src/disassembler/types.js';

describe('VulnScanner Core Tests', () => {
  const scanner = new VulnScanner();

  // Test 1: Unsafe C APIs in symbols list (original test)
  test('detects unsafe C API calls in symbols list', () => {
    const symbols: Symbol[] = [
      { name: 'strcpy', address: 0x1020, binding: 'global', type: 'function' },
      { name: 'sprintf', address: 0x1040, binding: 'global', type: 'function' },
      { name: 'memset', address: 0x1060, binding: 'global', type: 'function' }, // safe
    ];

    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(2);
    expect(matches[0].category).toBe('unsafe_api');
    expect(matches[0].evidence).toBe('strcpy');
    expect(matches[1].evidence).toBe('sprintf');
  });

  // Test 2: Unsafe APIs in instructions (original test)
  test('detects unsafe API calls inside instructions', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0xe8, 0x00, 0x00, 0x00, 0x00]),
        mnemonic: 'call',
        opStr: 'strcpy',
        operands: [],
        size: 5,
      },
      {
        address: 0x1005,
        bytes: new Uint8Array([0xe8, 0x00, 0x00, 0x00, 0x00]),
        mnemonic: 'call',
        opStr: 'printf', // not directly listed as high-severity unsafe API
        operands: [],
        size: 5,
      },
    ];

    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('unsafe_api');
    expect(matches[0].evidence).toBe('strcpy');
  });

  // Test 3: Buffer overflow rep movs (original test)
  test('detects buffer overflow indicators (rep movs & large stack allocations)', () => {
    const instructions: Instruction[] = [
      {
        address: 0x2000,
        bytes: new Uint8Array([0xf3, 0xa4]),
        mnemonic: 'rep movsb',
        opStr: '',
        operands: [],
        size: 2,
      },
      {
        address: 0x2002,
        bytes: new Uint8Array([0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00]),
        mnemonic: 'sub',
        opStr: 'rsp, 0x1000',
        operands: [
          { type: 'reg', reg: 'rsp' },
          { type: 'imm', imm: 4096 },
        ],
        size: 7,
      },
    ];

    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(2);
    expect(matches[0].category).toBe('buffer_overflow');
    expect(matches[1].category).toBe('buffer_overflow');
    expect(matches[1].evidence).toContain('rsp, 0x1000');
  });

  // Test 4: Integer overflow idiv & add (original test)
  test('detects integer overflow vulnerability patterns (idiv & unchecked loop/index arithmetic)', () => {
    const instructions: Instruction[] = [
      {
        address: 0x3000,
        bytes: new Uint8Array([0xf7, 0xf9]),
        mnemonic: 'idiv',
        opStr: 'ecx',
        operands: [{ type: 'reg', reg: 'ecx' }],
        size: 2,
      },
      {
        address: 0x3002,
        bytes: new Uint8Array([0x48, 0x01, 0xde]),
        mnemonic: 'add',
        opStr: 'rsi, rbx',
        operands: [
          { type: 'reg', reg: 'rsi' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 3,
      },
    ];

    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(2);
    expect(matches[0].category).toBe('integer_overflow');
    expect(matches[0].evidence).toBe('idiv ecx');
    expect(matches[1].category).toBe('integer_overflow');
    expect(matches[1].evidence).toBe('add rsi, rbx');
  });

  // Test 5: Detect gets() with high severity
  test('detects gets API with high severity', () => {
    const symbols: Symbol[] = [
      { name: 'gets', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('high');
  });

  // Test 6: Detect realpath() with medium severity
  test('detects realpath API with medium severity', () => {
    const symbols: Symbol[] = [
      {
        name: 'realpath',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Test 7: Clean symbol names test link decorations (e.g. imp__strcpy, strcpy@8)
  test('detects unsafe APIs with decorations', () => {
    const symbols: Symbol[] = [
      {
        name: '__imp_strcpy',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
      {
        name: '_sprintf@12',
        address: 0x1008,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(2);
    expect(matches[0].evidence).toBe('__imp_strcpy');
    expect(matches[1].evidence).toBe('_sprintf@12');
  });

  // Test 8: Instruction jmp to unsafe API
  test('detects jmp to unsafe API', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0xff, 0x25]),
        mnemonic: 'jmp',
        opStr: 'imp_strcpy',
        operands: [],
        size: 6,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('unsafe_api');
  });

  // Test 9: Unsafe API config option disabled
  test('skips unsafe API scanning if option is disabled', () => {
    const symbols: Symbol[] = [
      { name: 'strcpy', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: false,
    });
    expect(matches.length).toBe(0);
  });

  // Test 10: Buffer overflow config option disabled
  test('skips buffer overflow scanning if option is disabled', () => {
    const instructions: Instruction[] = [
      {
        address: 0x2000,
        bytes: new Uint8Array([0xf3, 0xa4]),
        mnemonic: 'rep movsb',
        opStr: '',
        operands: [],
        size: 2,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: false,
    });
    expect(matches.length).toBe(0);
  });

  // Test 11: Integer overflow config option disabled
  test('skips integer overflow scanning if option is disabled', () => {
    const instructions: Instruction[] = [
      {
        address: 0x3000,
        bytes: new Uint8Array([0xf7, 0xf9]),
        mnemonic: 'idiv',
        opStr: 'ecx',
        operands: [{ type: 'reg', reg: 'ecx' }],
        size: 2,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: false,
    });
    expect(matches.length).toBe(0);
  });

  // Test 12: Integer overflow arithmetic followed by conditional jump (should be skipped)
  test('skips reporting integer overflow if a checked pattern is present', () => {
    const instructions: Instruction[] = [
      {
        address: 0x4000,
        bytes: new Uint8Array([0x48, 0x01, 0xde]),
        mnemonic: 'add',
        opStr: 'rsi, rbx',
        operands: [
          { type: 'reg', reg: 'rsi' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 3,
      },
      {
        address: 0x4003,
        bytes: new Uint8Array([0x70, 0x05]),
        mnemonic: 'jo', // jump on overflow (check present)
        opStr: '0x400a',
        operands: [],
        size: 2,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Test 13: Repnz movs buffer overflow detection
  test('detects buffer overflow on repnz movs instruction', () => {
    const instructions: Instruction[] = [
      {
        address: 0x5000,
        bytes: new Uint8Array([0xf2, 0xa4]),
        mnemonic: 'repnz movs',
        opStr: '',
        operands: [],
        size: 2,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('buffer_overflow');
  });

  // Test 14: Unsafe C APIs wcscpy
  test('detects wcscpy as high severity unsafe wide-char api', () => {
    const symbols: Symbol[] = [
      { name: 'wcscpy', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('high');
    expect(matches[0].category).toBe('unsafe_api');
  });

  // Test 15: Unsafe C APIs wcscat
  test('detects wcscat as high severity unsafe wide-char api', () => {
    const symbols: Symbol[] = [
      { name: 'wcscat', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('high');
  });

  // Test 16: Unsafe C APIs tempnam
  test('detects tempnam with medium severity', () => {
    const symbols: Symbol[] = [
      { name: 'tempnam', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Test 17: Unsafe C APIs getwd
  test('detects getwd as high severity unsafe api', () => {
    const symbols: Symbol[] = [
      { name: 'getwd', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('high');
  });

  // Test 18: Stack allocation size below threshold
  test('skips stack buffer allocation match if size is under 1024 bytes', () => {
    const instructions: Instruction[] = [
      {
        address: 0x2000,
        bytes: new Uint8Array([0x48, 0x81, 0xec, 0xff, 0x03, 0x00, 0x00]),
        mnemonic: 'sub',
        opStr: 'rsp, 1023',
        operands: [
          { type: 'reg', reg: 'rsp' },
          { type: 'imm', imm: 1023 },
        ],
        size: 7,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Test 19: Stack allocation size at threshold
  test('detects stack buffer allocation match if size is exactly 1024 bytes', () => {
    const instructions: Instruction[] = [
      {
        address: 0x2000,
        bytes: new Uint8Array([0x48, 0x81, 0xec, 0x00, 0x04, 0x00, 0x00]),
        mnemonic: 'sub',
        opStr: 'rsp, 1024',
        operands: [
          { type: 'reg', reg: 'rsp' },
          { type: 'imm', imm: 1024 },
        ],
        size: 7,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('buffer_overflow');
  });

  // Test 20: Integer overflow register filtering
  test('skips integer overflow detection for non-index/non-counter registers', () => {
    const instructions: Instruction[] = [
      {
        address: 0x3000,
        bytes: new Uint8Array([0x48, 0x01, 0xd8]),
        mnemonic: 'add',
        opStr: 'rax, rbx',
        operands: [
          { type: 'reg', reg: 'rax' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 3,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Test 21: Integer overflow for register rcx
  test('detects integer overflow on register rcx', () => {
    const instructions: Instruction[] = [
      {
        address: 0x3000,
        bytes: new Uint8Array([0x48, 0x01, 0xd9]),
        mnemonic: 'add',
        opStr: 'rcx, rbx',
        operands: [
          { type: 'reg', reg: 'rcx' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 3,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('integer_overflow');
  });

  // Test 22: Integer overflow check skip with js jump
  test('skips integer overflow on rcx if followed by js jump instruction', () => {
    const instructions: Instruction[] = [
      {
        address: 0x3000,
        bytes: new Uint8Array([0x48, 0x01, 0xd9]),
        mnemonic: 'add',
        opStr: 'rcx, rbx',
        operands: [
          { type: 'reg', reg: 'rcx' },
          { type: 'reg', reg: 'rbx' },
        ],
        size: 3,
      },
      {
        address: 0x3003,
        bytes: new Uint8Array([0x78, 0x05]),
        mnemonic: 'js',
        opStr: '0x300a',
        operands: [],
        size: 2,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Test 23: cleanSymbolName helper regex test
  test('cleans custom mangled names correctly', () => {
    const symbols: Symbol[] = [
      {
        name: 'imp_strcpy',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
      {
        name: '__dl_strcpy',
        address: 0x1008,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(2);
    expect(matches[0].evidence).toBe('imp_strcpy');
    expect(matches[1].evidence).toBe('__dl_strcpy');
  });

  // Test 24: Unsafe C API scan with namespace/dot separator
  test('detects API with dot separator namespaces', () => {
    const symbols: Symbol[] = [
      {
        name: 'libc.strcpy',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].evidence).toBe('libc.strcpy');
  });

  // Extra Test 25: Scanf API detection
  test('detects scanf API with medium severity', () => {
    const symbols: Symbol[] = [
      { name: 'scanf', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Extra Test 26: Sscanf API detection
  test('detects sscanf API with medium severity', () => {
    const symbols: Symbol[] = [
      { name: 'sscanf', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Extra Test 27: Fscanf API detection
  test('detects fscanf API with medium severity', () => {
    const symbols: Symbol[] = [
      { name: 'fscanf', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Extra Test 28: Vsprintf API detection
  test('detects vsprintf API with high severity', () => {
    const symbols: Symbol[] = [
      {
        name: 'vsprintf',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('high');
  });

  // Extra Test 29: Tmpnam API detection
  test('detects tmpnam API with medium severity', () => {
    const symbols: Symbol[] = [
      { name: 'tmpnam', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].severity).toBe('medium');
  });

  // Extra Test 30: Integer overflow check with mul instruction
  test('detects integer overflow on mul instruction on index register', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'mul',
        opStr: 'rsi',
        operands: [{ type: 'reg', reg: 'rsi' }],
        size: 1,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('integer_overflow');
  });

  // Extra Test 31: Integer overflow check with imul instruction
  test('detects integer overflow on imul instruction on counter register', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'imul',
        opStr: 'rdi',
        operands: [{ type: 'reg', reg: 'rdi' }],
        size: 1,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].category).toBe('integer_overflow');
  });

  // Extra Test 32: cleanSymbolName with DLL prefix
  test('cleans symbols with DLL linkage prefix correctly', () => {
    const symbols: Symbol[] = [
      {
        name: '__imp_dll_strcpy',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].evidence).toBe('__imp_dll_strcpy');
  });

  // Extra Test 33: Unsafe API scan with call instruction containing no opStr
  test('does not crash when call instruction has empty opStr', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'call',
        opStr: '',
        operands: [],
        size: 1,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    expect(matches.length).toBe(0);
  });

  // Extra Test 34: Large stack frame allocation on non-rsp register
  test('skips large stack frame check for non-rsp registers', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'sub',
        opStr: 'rbp, 0x1000',
        operands: [
          { type: 'reg', reg: 'rbp' },
          { type: 'imm', imm: 4096 },
        ],
        size: 1,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Extra Test 35: Unsafe API with mixed calls
  test('detects only unsafe APIs in mixed instruction streams', () => {
    const instructions: Instruction[] = [
      { address: 0x1000, mnemonic: 'call', opStr: 'strcpy', size: 5 },
      { address: 0x1005, mnemonic: 'call', opStr: 'malloc', size: 5 },
      { address: 0x100a, mnemonic: 'call', opStr: 'strcat', size: 5 },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    expect(matches.length).toBe(2);
    expect(matches.map((m) => m.evidence)).toContain('strcpy');
    expect(matches.map((m) => m.evidence)).toContain('strcat');
  });

  // Extra Test 36: Scan with all configuration options disabled
  test('returns no matches when all scanner settings are disabled', () => {
    const symbols: Symbol[] = [
      { name: 'strcpy', address: 0x1000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(100), [], symbols, [], {
      unsafeApi: false,
      bufferOverflow: false,
      integerOverflow: false,
      cryptoWeakness: false,
      obfuscation: false,
      shellcode: false,
    });
    expect(matches.length).toBe(0);
  });

  // Extra Test 37: Positive add to rsp should not be considered stack allocation
  test('does not flag add to rsp as buffer overflow vulnerability', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'add',
        opStr: 'rsp, 0x1000',
        operands: [
          { type: 'reg', reg: 'rsp' },
          { type: 'imm', imm: 4096 },
        ],
        size: 7,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      bufferOverflow: true,
    });
    expect(matches.length).toBe(0);
  });

  // Extra Test 38: Integer overflow check with add instruction on non-pointer registers
  test('flags add with large values on generic registers as integer overflow', () => {
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        mnemonic: 'add',
        opStr: 'eax, 0x7fffffff',
        operands: [
          { type: 'reg', reg: 'eax' },
          { type: 'imm', imm: 2147483647 },
        ],
        size: 5,
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      integerOverflow: true,
    });
    expect(matches.length).toBeGreaterThan(0);
  });

  // Extra Test 39: Cryptographic check with no matches returns 0 findings
  test('does not flag any crypto weaknesses if no suspicious constants are present', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const matches = scanner.scan(data, [], [], [], { cryptoWeakness: true });
    expect(matches.length).toBe(0);
  });

  // Extra Test 40: Shellcode scan threshold handling
  test('skips shellcode scan if data size is below minimal threshold', () => {
    const data = new Uint8Array([0x90, 0x90]);
    const matches = scanner.scan(data, [], [], [], { shellcode: true });
    expect(matches.length).toBe(0);
  });

  // Extra Test 41: Format string vulnerability scan with valid formatting strings
  test('does not flag printf calls with literal/static formatting strings', () => {
    const instructions: Instruction[] = [
      { address: 0x1000, mnemonic: 'call', opStr: 'printf', size: 5 },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    // Assuming simple scanner does not alert on plain printf if it is not in the unsafe list
    expect(matches.filter((m) => m.evidence === 'printf').length).toBe(0);
  });

  // Extra Test 42: cleanSymbolName handling symbols with trailing compiler decoration
  test('cleans decorated C++ compiler symbols correctly', () => {
    const symbols: Symbol[] = [
      {
        name: '_strcpy@8',
        address: 0x1000,
        binding: 'global',
        type: 'function',
      },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].evidence).toBe('_strcpy@8');
  });

  // Extra Test 43: VulnScanner class with empty config options defaults
  test('uses default configuration if not provided', () => {
    const matches = scanner.scan(new Uint8Array(0), [], [], []);
    expect(matches).toBeDefined();
    expect(matches.length).toBe(0);
  });

  // Extra Test 44: Command injection detection on system call
  test('detects potential command injection on system calls', () => {
    const symbols: Symbol[] = [
      { name: 'system', address: 0x2000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    expect(matches.length).toBe(1);
    expect(matches[0].evidence).toBe('system');
  });

  // Extra Test 45: Process Injection combination (Critical)
  test('detects critical process injection combination (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)', () => {
    const symbols: Symbol[] = [
      { name: 'VirtualAlloc', address: 0x1000, binding: 'global', type: 'function' },
      { name: 'WriteProcessMemory', address: 0x2000, binding: 'global', type: 'function' },
      { name: 'CreateRemoteThread', address: 0x3000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    const combo = matches.find(m => m.severity === 'critical' && m.description.includes('Process Injection'));
    expect(combo).toBeDefined();
    expect(combo!.evidence).toContain('VirtualAlloc');
    expect(combo!.evidence).toContain('WriteProcessMemory');
    expect(combo!.evidence).toContain('CreateRemoteThread');
  });

  // Extra Test 46: Process Injection combination (High)
  test('detects high process injection combination (VirtualAlloc + WriteProcessMemory)', () => {
    const symbols: Symbol[] = [
      { name: 'VirtualAlloc', address: 0x1000, binding: 'global', type: 'function' },
      { name: 'WriteProcessMemory', address: 0x2000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    const combo = matches.find(m => m.severity === 'high' && m.description.includes('Memory Allocation/Protection API'));
    expect(combo).toBeDefined();
  });

  // Extra Test 47: Anti-debugging/evasion + Process termination (High)
  test('detects high severity anti-debugging evasion + process termination combination', () => {
    const symbols: Symbol[] = [
      { name: 'IsDebuggerPresent', address: 0x1000, binding: 'global', type: 'function' },
      { name: 'ExitProcess', address: 0x2000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    const combo = matches.find(m => m.severity === 'high' && m.description.includes('Anti-Debugging/Evasion'));
    expect(combo).toBeDefined();
    expect(combo!.evidence).toContain('IsDebuggerPresent');
    expect(combo!.evidence).toContain('ExitProcess');
  });

  // Extra Test 48: Dynamic library loading + Symbol resolution (High)
  test('detects high severity dynamic library loading + symbol resolution combination', () => {
    const symbols: Symbol[] = [
      { name: 'LoadLibraryA', address: 0x1000, binding: 'global', type: 'function' },
      { name: 'GetProcAddress', address: 0x2000, binding: 'global', type: 'function' },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], symbols, [], {
      unsafeApi: true,
    });
    const combo = matches.find(m => m.severity === 'high' && m.description.includes('Dynamic Library Loading'));
    expect(combo).toBeDefined();
    expect(combo!.evidence).toContain('LoadLibraryA');
    expect(combo!.evidence).toContain('GetProcAddress');
  });

  // Extra Test 49: Combo detection via instructions calls
  test('detects combinations when APIs are called within instructions', () => {
    const instructions: Instruction[] = [
      { address: 0x1000, mnemonic: 'call', opStr: 'VirtualAllocEx', size: 5 },
      { address: 0x1005, mnemonic: 'call', opStr: 'CreateRemoteThreadEx', size: 5 },
    ];
    const matches = scanner.scan(new Uint8Array(0), [], [], instructions, {
      unsafeApi: true,
    });
    const combo = matches.find(m => m.severity === 'critical' && m.description.includes('Process Injection'));
    expect(combo).toBeDefined();
    expect(combo!.evidence).toContain('VirtualAllocEx');
    expect(combo!.evidence).toContain('CreateRemoteThreadEx');
  });
});
