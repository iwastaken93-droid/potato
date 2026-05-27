import { describe, it, expect } from 'vitest';
import { DisassemblerRouter } from '../src/disassembler/router.js';

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
});
