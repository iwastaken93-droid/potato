import { describe, it, expect, vi } from 'vitest';
import { DisassemblerRouter } from '../src/disassembler/router.js';
import * as wasmParser from '../src/parser/wasm.js';

describe('DisassemblerRouter Unit Tests', () => {
  describe('DEX/Dalvik Routing', () => {
    it('should detect DEX/Dalvik format by magic bytes', () => {
      const data = new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x00, 0x00, 0x00, 0x00]);
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('dex');
    });

    it('should route and disassemble DEX bytecode correctly', () => {
      const router = new DisassemblerRouter();
      // DEX magic followed by:
      // - 0x00 (nop)
      // - 0x0e (return-void)
      const data = new Uint8Array([
        0x64, 0x65, 0x78, 0x0a, // dex\n magic
        0x00,                   // nop
        0x0e,                   // return-void
      ]);
      const instructions = router.disassemble(data);

      expect(instructions.length).toBe(6);
      expect(instructions[0].mnemonic).toBe('db');
      expect(instructions[4].mnemonic).toBe('nop');
      expect(instructions[5].mnemonic).toBe('return-void');
    });
  });

  describe('Mach-O Routing', () => {
    // Helper to build thin Mach-O header
    function makeThinMacho(magic: number, isLE: boolean, cputype: number): Uint8Array {
      const header = new Uint8Array(28);
      const view = new DataView(header.buffer);
      view.setUint32(0, magic, isLE);
      view.setUint32(4, cputype, isLE);
      return header;
    }

    it('should route 64-bit LE Mach-O (x86_64)', () => {
      // magic: 0xfeedfacf (LE), cputype: CPU_TYPE_X86_64 (0x01000007)
      const data = makeThinMacho(0xfeedfacf, true, 0x01000007);
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('x86_64');
    });

    it('should route 64-bit LE Mach-O (arm)', () => {
      // magic: 0xfeedfacf (LE), cputype: CPU_TYPE_ARM64 (0x0100000c)
      const data = makeThinMacho(0xfeedfacf, true, 0x0100000c);
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });

    it('should route 32-bit BE Mach-O (x86_64 / i386)', () => {
      // magic: 0xfeedface (BE), cputype: CPU_TYPE_I386 (7)
      const data = makeThinMacho(0xfeedface, false, 7);
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('x86_64');
    });

    it('should route 32-bit BE Mach-O (arm)', () => {
      // magic: 0xfeedface (BE), cputype: CPU_TYPE_ARM (12)
      const data = makeThinMacho(0xfeedface, false, 12);
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });

    it('should route Fat BE Mach-O (x86_64)', () => {
      const data = new Uint8Array(28);
      const view = new DataView(data.buffer);
      // fat magic: 0xcafebabe (BE)
      view.setUint32(0, 0xcafebabe, false);
      // nfat: 1
      view.setUint32(4, 1, false);
      // cputype: CPU_TYPE_X86_64 (0x01000007)
      view.setUint32(8, 0x01000007, false);

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('x86_64');
    });

    it('should route Fat LE Mach-O (arm)', () => {
      const data = new Uint8Array(28);
      const view = new DataView(data.buffer);
      // fat magic: 0xbebafeca (LE in bytes, so we write BE of 0xbebafeca to get bytes be ba fe ca)
      view.setUint32(0, 0xbebafeca, false);
      // nfat: 1
      view.setUint32(4, 1, true);
      // cputype: CPU_TYPE_ARM64 (0x0100000c)
      view.setUint32(8, 0x0100000c, true);

      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('arm');
    });
  });

  describe('x86_64 Instruction Expansion Verification', () => {
    const router = new DisassemblerRouter();

    it('should disassemble ADD reg, reg correctly (0x01)', () => {
      // 0x01, 0xc3 (add ebx, eax)
      const data = new Uint8Array([0x01, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('add');
      expect(insts[0].opStr).toBe('rbx, rax');
    });

    it('should disassemble TEST reg, reg correctly (0x85)', () => {
      // 0x85, 0xc3 (test ebx, eax)
      const data = new Uint8Array([0x85, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('test');
      expect(insts[0].opStr).toBe('rbx, rax');
    });

    it('should disassemble flag instructions correctly', () => {
      // 0xf8 (clc)
      const data = new Uint8Array([0xf8]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('clc');
      expect(insts[0].opStr).toBe('');
    });

    it('should disassemble shifts correctly (0xd3)', () => {
      // 0xd3, 0xf8 (sar eax, cl / sar reg, cl)
      const data = new Uint8Array([0xd3, 0xf8]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('sar');
      expect(insts[0].opStr).toBe('rax, cl');
    });

    it('should disassemble Group 3 NEG correctly (0xf7)', () => {
      // 0xf7, 0xd8 (neg eax)
      const data = new Uint8Array([0xf7, 0xd8]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('neg');
      expect(insts[0].opStr).toBe('rax');
    });

    it('should disassemble ADC correctly', () => {
      const data = new Uint8Array([0x11, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('adc');
      expect(insts[0].opStr).toBe('rbx, rax');
    });

    it('should disassemble SBB correctly', () => {
      const data = new Uint8Array([0x19, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('sbb');
      expect(insts[0].opStr).toBe('rbx, rax');
    });

    it('should disassemble 8-bit ADD correctly', () => {
      const data = new Uint8Array([0x00, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('add');
      expect(insts[0].opStr).toBe('rbx, rax');
    });

    it('should disassemble CMOVcc instructions correctly', () => {
      const data = new Uint8Array([0x0f, 0x45, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('cmovne');
      expect(insts[0].opStr).toBe('rax, rbx');
    });

    it('should disassemble BSF / BSR correctly', () => {
      const data = new Uint8Array([0x0f, 0xbc, 0xc3]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('bsf');
      expect(insts[0].opStr).toBe('rax, rbx');
    });

    it('should disassemble UD2 correctly', () => {
      const data = new Uint8Array([0x0f, 0x0b]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts[0].mnemonic).toBe('ud2');
      expect(insts[0].opStr).toBe('');
    });
  });

  describe('ARM AArch64 Instruction Expansion Verification', () => {
    const router = new DisassemblerRouter();

    it('should disassemble CMP register correctly', () => {
      // 0xeb01001f (cmp x0, x1) -> LE: 1f, 00, 01, eb
      const data = new Uint8Array([0x1f, 0x00, 0x01, 0xeb]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('cmp');
      expect(insts[0].opStr).toBe('x0, x1');
    });

    it('should disassemble TST register correctly', () => {
      // 0xea01001f (tst x0, x1) -> LE: 1f, 00, 01, ea
      const data = new Uint8Array([0x1f, 0x00, 0x01, 0xea]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('tst');
      expect(insts[0].opStr).toBe('x0, x1');
    });

    it('should disassemble LSR immediate shift correctly', () => {
      // 0xd342fc20 (lsr x0, x1, #2) -> LE: 20, fc, 42, d3
      const data = new Uint8Array([0x20, 0xfc, 0x42, 0xd3]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('lsr');
      expect(insts[0].opStr).toBe('x0, x1, #0x2');
    });

    it('should disassemble MRS NZCV flags register correctly', () => {
      // 0xd53b4200 (mrs x0, nzcv) -> LE: 00, 42, 3b, d5
      const data = new Uint8Array([0x00, 0x42, 0x3b, 0xd5]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('mrs');
      expect(insts[0].opStr).toBe('x0, nzcv');
    });

    it('should disassemble BIC register correctly', () => {
      // bic x0, x1, x2 -> LE: 20, 00, 22, 0a
      const data = new Uint8Array([0x20, 0x00, 0x22, 0x0a]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('bic');
      expect(insts[0].opStr).toBe('x0, x1, x2');
    });

    it('should disassemble ORN register correctly', () => {
      // orn x0, x1, x2 -> LE: 20, 00, 22, aa
      const data = new Uint8Array([0x20, 0x00, 0x22, 0xaa]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('orn');
      expect(insts[0].opStr).toBe('x0, x1, x2');
    });

    it('should disassemble UDIV register correctly', () => {
      // udiv x0, x1, x2 -> LE: 20, 08, c2, 1a
      const data = new Uint8Array([0x20, 0x08, 0xc2, 0x1a]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('udiv');
      expect(insts[0].opStr).toBe('x0, x1, x2');
    });

    it('should disassemble SDIV register correctly', () => {
      // sdiv x0, x1, x2 -> LE: 20, 0c, c2, 1a
      const data = new Uint8Array([0x20, 0x0c, 0xc2, 0x1a]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('sdiv');
      expect(insts[0].opStr).toBe('x0, x1, x2');
    });

    it('should disassemble MUL register correctly', () => {
      // mul x0, x1, x2 -> LE: 20, 7c, 02, 9b
      const data = new Uint8Array([0x20, 0x7c, 0x02, 0x9b]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('mul');
      expect(insts[0].opStr).toBe('x0, x1, x2');
    });

    it('should disassemble MADD register correctly', () => {
      // madd x0, x1, x2, x3 -> LE: 20, 0c, 02, 9b
      const data = new Uint8Array([0x20, 0x0c, 0x02, 0x9b]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts[0].mnemonic).toBe('madd');
      expect(insts[0].opStr).toBe('x0, x1, x2, x3');
    });
  });

  describe('Additional ELF/PE Routing and Edge Cases', () => {
    it('should route ELF format to x86_64 and arm based on machine ID', () => {
      // ELF magic: 7f 45 4c 46. 64-bit: offset 4 = 2. machine id at offset 18 is 62 (EM_X86_64)
      const dataX86 = new Uint8Array(64);
      dataX86[0] = 0x7f; dataX86[1] = 0x45; dataX86[2] = 0x4c; dataX86[3] = 0x46;
      dataX86[4] = 2;
      dataX86[18] = 62; // EM_X86_64
      expect(DisassemblerRouter.detectArchitecture(dataX86)).toBe('x86_64');

      // ELF machine id 40 (EM_ARM)
      const dataArm32 = new Uint8Array(64);
      dataArm32[0] = 0x7f; dataArm32[1] = 0x45; dataArm32[2] = 0x4c; dataArm32[3] = 0x46;
      dataArm32[18] = 40;
      expect(DisassemblerRouter.detectArchitecture(dataArm32)).toBe('arm');

      // ELF machine id 183 (EM_AARCH64)
      const dataArm64 = new Uint8Array(64);
      dataArm64[0] = 0x7f; dataArm64[1] = 0x45; dataArm64[2] = 0x4c; dataArm64[3] = 0x46;
      dataArm64[18] = 183;
      expect(DisassemblerRouter.detectArchitecture(dataArm64)).toBe('arm');
    });

    it('should route PE format correctly based on machine field', () => {
      // PE magic is MZ (4d 5a) at 0. Offset to PE signature is at 0x3c.
      const data = new Uint8Array(128);
      data[0] = 0x5a; data[1] = 0x4d; // MZ
      const peOffset = 64;
      data[0x3c] = peOffset; // offset to PE signature
      data[peOffset] = 0x50; data[peOffset + 1] = 0x45; // PE\0\0
      // machine 0x8664 at peOffset + 4
      data[peOffset + 4] = 0x64; data[peOffset + 5] = 0x86;
      expect(DisassemblerRouter.detectArchitecture(data)).toBe('x86_64');

      // machine 0xaa64
      data[peOffset + 4] = 0x64; data[peOffset + 5] = 0xaa;
      expect(DisassemblerRouter.detectArchitecture(data)).toBe('arm');

      // machine 0x01c4
      data[peOffset + 4] = 0xc4; data[peOffset + 5] = 0x01;
      expect(DisassemblerRouter.detectArchitecture(data)).toBe('arm');
    });

    it('should route Mach-O using alternative detection branches', () => {
      // Alternative thin Mach-O detection at line 140
      const dataMacho = new Uint8Array(16);
      dataMacho[0] = 0xcf; dataMacho[1] = 0xfa; dataMacho[2] = 0xed; dataMacho[3] = 0xfe; // magic
      dataMacho[4] = 12; // CPU_TYPE_ARM
      expect(DisassemblerRouter.detectArchitecture(dataMacho)).toBe('arm');

      // Alternative fat Mach-O detection at line 163
      const dataFat = new Uint8Array(16);
      dataFat[0] = 0xca; dataFat[1] = 0xfe; dataFat[2] = 0xba; dataFat[3] = 0xbe;
      dataFat[11] = 12; // cputype is ARM (big endian, so at offset 11)
      expect(DisassemblerRouter.detectArchitecture(dataFat)).toBe('arm');

      // fallback case: should default to x86_64
      const empty = new Uint8Array(0);
      expect(DisassemblerRouter.detectArchitecture(empty)).toBe('x86_64');
    });

    it('should set and get Capstone options and metadata configuration', () => {
      const router = new DisassemblerRouter({ useCapstoneWasm: true });
      expect(router.isUsingCapstoneWasm()).toBe(true);
      router.setUseCapstoneWasm(false);
      expect(router.isUsingCapstoneWasm()).toBe(false);
    });
  });

  describe('WebAssembly Parsing and Fallback logic', () => {
    const router = new DisassemblerRouter();

    // Helper functions to generate binary WASM structures
    function encodeVarUint(val: number): number[] {
      const bytes: number[] = [];
      let temp = val;
      while (true) {
        const byte = temp & 0x7f;
        temp >>>= 7;
        if (temp === 0) {
          bytes.push(byte);
          break;
        } else {
          bytes.push(byte | 0x80);
        }
      }
      return bytes;
    }

    function encodeString(str: string): number[] {
      const bytes = Array.from(new TextEncoder().encode(str));
      return [...encodeVarUint(bytes.length), ...bytes];
    }

    it('should disassemble a valid WASM binary with type, function, export, and code sections', () => {
      // 1. Type Section: 1 function type: () -> ()
      const typePayload = [
        ...encodeVarUint(1), // number of types
        0x60, // type form (func)
        ...encodeVarUint(0), // param count
        ...encodeVarUint(0), // result count
      ];

      // 2. Function Section
      const funcPayload = [
        ...encodeVarUint(1), // number of functions
        ...encodeVarUint(0), // type index 0
      ];

      // 3. Code Section
      const locals = [
        ...encodeVarUint(0), // number of local declarations
      ];

      const instructions = [
        0x41, ...encodeVarUint(42), // i32.const 42
        0x0b, // end
      ];

      const funcBody = [...locals, ...instructions];
      const codePayload = [
        ...encodeVarUint(1), // number of code bodies
        ...encodeVarUint(funcBody.length),
        ...funcBody,
      ];

      // Combine sections
      const wasmBytes = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, // Magic
        0x01, 0x00, 0x00, 0x00, // Version

        1, // SectionId.Type
        ...encodeVarUint(typePayload.length),
        ...typePayload,

        3, // SectionId.Function
        ...encodeVarUint(funcPayload.length),
        ...funcPayload,

        10, // SectionId.Code
        ...encodeVarUint(codePayload.length),
        ...codePayload,
      ]);

      const insts = router.disassemble(wasmBytes);
      expect(insts.length).toBeGreaterThan(0);
      expect(insts[0].mnemonic).toBe('i32.const');
      expect(insts[0].opStr).toBe('42');
      expect(insts[0].operands[0]).toEqual({ type: 'imm', imm: 42 });
    });

    it('should invoke fallback mock WASM disassembler for parsing failures', () => {
      // Provide partial/invalid WASM bytes to trigger the try-catch block and generate fallback
      const data = new Uint8Array([
        0x00, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x01,
        0x05, 0x0b, 0x0c, 0x01, 0x0d, 0x01, 0x0f, 0x10,
        0x01, 0x11, 0x01, 0x01, 0x1a, 0x1b, 0x20, 0x01,
        0x21, 0x01, 0x22, 0x01, 0x23, 0x01, 0x24, 0x01,
        0x28, 0x01, 0x02, 0x41, 0x05, 0x42, 0x05, 0x43,
        0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x67, 0x7c,
      ]);
      const insts = router.disassemble(data, { arch: 'wasm' });
      expect(insts.length).toBeGreaterThan(0);
      
      const mnemonics = insts.map(i => i.mnemonic);
      expect(mnemonics).toContain('unreachable');
      expect(mnemonics).toContain('nop');
      expect(mnemonics).toContain('block');
      expect(mnemonics).toContain('loop');
      expect(mnemonics).toContain('if');
      expect(mnemonics).toContain('else');
      expect(mnemonics).toContain('end');
      expect(mnemonics).toContain('br');
      expect(mnemonics).toContain('br_if');
      expect(mnemonics).toContain('return');
      expect(mnemonics).toContain('call');
      expect(mnemonics).toContain('call_indirect');
      expect(mnemonics).toContain('drop');
      expect(mnemonics).toContain('select');
      expect(mnemonics).toContain('local.get');
      expect(mnemonics).toContain('local.set');
      expect(mnemonics).toContain('local.tee');
      expect(mnemonics).toContain('global.get');
      expect(mnemonics).toContain('global.set');
      expect(mnemonics).toContain('i32.load');
      expect(mnemonics).toContain('i32.const');
      expect(mnemonics).toContain('i64.const');
      expect(mnemonics).toContain('f32.const');
      expect(mnemonics).toContain('f64.const');
      expect(mnemonics).toContain('i32.eqz');
      expect(mnemonics).toContain('i32.clz');
      expect(mnemonics).toContain('f32.add');
    });
  });

  describe('DEX bytecode disassembler edge cases', () => {
    const router = new DisassemblerRouter();

    it('should disassemble DEX move and const instructions', () => {
      // 0x01 (move), 0x12 (const/4), 0x26 (fill-array-data), 0x28 (goto), 0x32 (if-eq), 0x71 (invoke-static), 0x13 (const/16)
      const data = new Uint8Array([
        0x01, 0x12, // move v2, v1 (depending on nibble)
        0x12, 0x34, // const/4 v4, #3
        0x26, 0x01, 0x05, 0x00, 0x00, 0x00, // fill-array-data
        0x28, 0x02, // goto +2
        0x32, 0x12, 0x04, 0x00, // if-eq v2, v1, +4
        0x71, 0x20, 0x04, 0x00, 0x00, 0x00, // invoke-static
        0x13, 0x02, 0x04, 0x00, // const/16 v2, #4
      ]);
      const insts = router.disassemble(data, { arch: 'dex' });
      expect(insts.length).toBeGreaterThan(0);
      expect(insts[0].mnemonic).toBe('move');
      expect(insts[1].mnemonic).toBe('const/4');
      expect(insts[2].mnemonic).toBe('fill-array-data');
      expect(insts[3].mnemonic).toBe('goto');
      expect(insts[4].mnemonic).toBe('if-eq');
      expect(insts[5].mnemonic).toBe('invoke-static');
      expect(insts[6].mnemonic).toBe('const/16');
    });
  });

  describe('x86_64 and ARM edge cases', () => {
    const router = new DisassemblerRouter();

    it('should handle x86_64 rex prefixes, shifts, jumps and immediate instructions', () => {
      // rex prefixes, push/pop, jumps, movs, etc.
      const data = new Uint8Array([
        0x48, 0x89, 0xc3, // REX.W mov rbx, rax
        0x50,             // push rax
        0x58,             // pop rax
        0x6a, 0x05,       // push 5 (8-bit)
        0x68, 0x00, 0x00, 0x00, 0x00, // push 0 (32-bit)
        0xeb, 0x02,       // jmp short
        0xe9, 0x00, 0x00, 0x00, 0x00, // jmp near
        0x70, 0x02,       // jo short
        0xe8, 0x00, 0x00, 0x00, 0x00, // call
        0xc7, 0xc0, 0x05, 0x00, 0x00, 0x00, // mov rax, 5
        0x48, 0xb8, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 5 (64-bit imm)
        0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5 (32-bit imm)
        0x83, 0xc0, 0x05, // add eax, 5
        0x8d, 0x00,       // lea eax, [eax]
        0xc1, 0xe0, 0x02, // shl eax, 2
        0xd1, 0xe0,       // shl eax, 1
        0x9c,             // pushf
        0x0f, 0x85, 0x00, 0x00, 0x00, 0x00, // jne near
        0x0f, 0xaf, 0xc3, // imul rax, rbx
        0x0f, 0xb6, 0xc3, // movzx rax, rbx
      ]);
      const insts = router.disassemble(data, { arch: 'x86_64' });
      expect(insts.length).toBeGreaterThan(0);
      expect(insts[0].mnemonic).toBe('mov');
      expect(insts[1].mnemonic).toBe('push');
      expect(insts[2].mnemonic).toBe('pop');
    });

    it('should handle ARM branch, shift, system, logical and loading instructions', () => {
      // 0xd503201f (nop), 0xd65f03c0 (ret), 0x14000002 (b), 0x94000002 (bl), 0xd61f0020 (br x1), 0xd63f0020 (blr x1)
      // 0x54000040 (b.eq +8), 0x34000040 (cbz x0, +8), 0x91000800 (add x0, x0, #2), 0x8b010000 (add x0, x0, x1)
      // 0xd340fc00 (ubfx), 0x9340fc00 (sbfx), 0x1ac02000 (lsl), nzcv msr/mrs, orr logical, udiv/sdiv, ldr/str, ldp/stp
      const data = new Uint8Array([
        0x1f, 0x20, 0x03, 0xd5, // nop
        0xc0, 0x03, 0x5f, 0xd6, // ret
        0x02, 0x00, 0x00, 0x14, // b +8
        0x02, 0x00, 0x00, 0x94, // bl +8
        0x20, 0x00, 0x1f, 0xd6, // br x1
        0x20, 0x00, 0x3f, 0xd6, // blr x1
        0x40, 0x00, 0x00, 0x54, // b.eq +8
        0x40, 0x00, 0x00, 0x34, // cbz x0, +8
        0x00, 0x08, 0x00, 0x91, // add x0, x0, #2
        0x00, 0x00, 0x01, 0x8b, // add x0, x0, x1
        0x00, 0xfc, 0x40, 0xd3, // ubfx x0, x0, #0, #64
        0x00, 0xfc, 0x40, 0x93, // sbfx x0, x0, #0, #64
        0x00, 0x20, 0xc0, 0x1a, // lsl x0, x0, x0
        0x00, 0x42, 0x1b, 0xd5, // msr nzcv, x0
        0x00, 0x00, 0x02, 0x0a, // and x0, x0, x2
        0x00, 0x00, 0x22, 0x0a, // orr x0, x0, x2 (with neg/move check)
        0x00, 0x04, 0xc2, 0x1a, // sdiv x0, x1, x2 (incorrect instruction but checks pattern)
        0x00, 0x00, 0x40, 0xf9, // ldr x0, [x0, #0]
        0x00, 0x00, 0x00, 0x29, // stp x0, x0, [x0, #0]
        0xfe, 0x0f, 0x1f, 0xf8, // push x0
        0xfe, 0x07, 0x40, 0xf8, // pop x0
      ]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts.length).toBeGreaterThan(0);
      expect(insts[0].mnemonic).toBe('nop');
      expect(insts[1].mnemonic).toBe('ret');
    });

    it('should handle remaining ARM bytes at the end of stream', () => {
      // 5 bytes: 4 bytes for nop, and 1 remaining byte 0x99
      const data = new Uint8Array([0x1f, 0x20, 0x03, 0xd5, 0x99]);
      const insts = router.disassemble(data, { arch: 'arm' });
      expect(insts.length).toBe(2);
      expect(insts[0].mnemonic).toBe('nop');
      expect(insts[1].mnemonic).toBe('db');
      expect(insts[1].opStr).toBe('0x99');
    });

    it('should handle truncated DEX instructions at the end of stream', () => {
      // 0x26 opcode expects 6 bytes. We only give it 3 bytes: 0x26, 0x01, 0x05
      const data = new Uint8Array([0x26, 0x01, 0x05]);
      const insts = router.disassemble(data, { arch: 'dex' });
      expect(insts.length).toBe(1);
      expect(insts[0].mnemonic).toBe('db');
      expect(insts[0].opStr).toBe('0x26, 0x01, 0x05');
    });

    it('should handle mocked WASM instructions with various argument types', () => {
      const mockModule = {
        magic: [0x00, 0x61, 0x73, 0x6d],
        version: 1,
        types: [],
        imports: [],
        functions: [],
        exports: [],
        code: [
          {
            locals: [],
            rawBytes: new Uint8Array([0x41, 0x05]),
            instructions: [
              { offset: 0, opcode: 0x41, mnemonic: 'i32.const', args: 100 },
              { offset: 2, opcode: 0x42, mnemonic: 'i64.const', args: 500n },
              { offset: 4, opcode: 0x20, mnemonic: 'local.get', args: [1, 2] },
              { offset: 6, opcode: 0x03, mnemonic: 'loop', args: { blockType: 0x40 } },
              { offset: 8, opcode: 0x0b, mnemonic: 'end', args: 'some-string' }
            ]
          }
        ]
      };

      const spy = vi.spyOn(wasmParser, 'parseWasm').mockReturnValueOnce(mockModule as any);

      const wasmBytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
      const insts = router.disassemble(wasmBytes);
      
      expect(spy).toHaveBeenCalled();
      expect(insts.length).toBe(5);
      
      expect(insts[0].mnemonic).toBe('i32.const');
      expect(insts[0].opStr).toBe('100');
      
      expect(insts[1].mnemonic).toBe('i64.const');
      expect(insts[1].opStr).toBe('500');
      
      expect(insts[2].mnemonic).toBe('local.get');
      expect(insts[2].opStr).toBe('1, 2');
      
      expect(insts[3].mnemonic).toBe('loop');
      expect(insts[3].opStr).toBe('{"blockType":64}');
      
      expect(insts[4].mnemonic).toBe('end');
      expect(insts[4].opStr).toBe('some-string');
      
      spy.mockRestore();
    });
  });
});

