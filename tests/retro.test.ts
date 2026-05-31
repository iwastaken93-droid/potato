import { describe, it, expect } from 'vitest';
import { DisassemblerRouter } from '../src/disassembler/router.js';
import { disassembleZ80 } from '../src/disassembler/z80.js';
import { disassemble6502 } from '../src/disassembler/m6502.js';
import fs from 'fs';
import path from 'path';

describe('Retro Architecture Decoders', () => {
  describe('Z80 Decoder', () => {
    it('should decode basic instructions', () => {
      const data = new Uint8Array([0x00, 0x3e, 0x42, 0x06, 0x10, 0x04]);
      const insts = disassembleZ80(data, 0x1000);

      expect(insts.length).toBe(4);
      expect(insts[0].mnemonic).toBe('nop');
      expect(insts[0].size).toBe(1);

      expect(insts[1].mnemonic).toBe('ld');
      expect(insts[1].opStr).toBe('a, 0x42');
      expect(insts[1].operands).toEqual([
        { type: 'reg', reg: 'a' },
        { type: 'imm', imm: 0x42 },
      ]);
      expect(insts[1].size).toBe(2);

      expect(insts[2].mnemonic).toBe('ld');
      expect(insts[2].opStr).toBe('b, 0x10');
      expect(insts[2].size).toBe(2);

      expect(insts[3].mnemonic).toBe('inc');
      expect(insts[3].opStr).toBe('b');
      expect(insts[3].operands).toEqual([{ type: 'reg', reg: 'b' }]);
      expect(insts[3].size).toBe(1);
    });

    it('should decode CB prefix instructions', () => {
      const data = new Uint8Array([0xcb, 0x47, 0xcb, 0x86]);
      const insts = disassembleZ80(data, 0x0);

      expect(insts.length).toBe(2);
      expect(insts[0].mnemonic).toBe('bit');
      expect(insts[0].opStr).toBe('0, a');
      expect(insts[0].operands).toEqual([
        { type: 'imm', imm: 0 },
        { type: 'reg', reg: 'a' },
      ]);

      expect(insts[1].mnemonic).toBe('res');
      expect(insts[1].opStr).toBe('0, (hl)');
      expect(insts[1].operands).toEqual([
        { type: 'imm', imm: 0 },
        { type: 'mem', mem: { base: 'hl' } },
      ]);
    });

    it('should decode ED prefix instructions', () => {
      const data = new Uint8Array([0xed, 0xb0, 0xed, 0x56]);
      const insts = disassembleZ80(data, 0x0);

      expect(insts.length).toBe(2);
      expect(insts[0].mnemonic).toBe('ldir');
      expect(insts[1].mnemonic).toBe('im');
      expect(insts[1].opStr).toBe('1');
    });

    it('should decode DD/FD prefixed instructions with displacement', () => {
      const data = new Uint8Array([
        0xdd,
        0x7e,
        0x05,
        0xfd,
        0x70,
        0xfa,
        0xdd,
        0xcb,
        0x0a,
        0x46,
      ]);
      const insts = disassembleZ80(data, 0x0);

      expect(insts.length).toBe(3);
      expect(insts[0].mnemonic).toBe('ld');
      expect(insts[0].opStr).toBe('a, (ix+5)');
      expect(insts[0].operands).toEqual([
        { type: 'reg', reg: 'a' },
        { type: 'mem', mem: { base: 'ix', disp: 5 } },
      ]);

      expect(insts[1].mnemonic).toBe('ld');
      expect(insts[1].opStr).toBe('(iy-6), b');
      expect(insts[1].operands).toEqual([
        { type: 'mem', mem: { base: 'iy', disp: -6 } },
        { type: 'reg', reg: 'b' },
      ]);

      expect(insts[2].mnemonic).toBe('bit');
      expect(insts[2].opStr).toBe('0, (ix+10)');
      expect(insts[2].operands).toEqual([
        { type: 'imm', imm: 0 },
        { type: 'mem', mem: { base: 'ix', disp: 10 } },
      ]);
    });

    it('should compute relative jump targets', () => {
      const data = new Uint8Array([0x18, 0x05]);
      const insts = disassembleZ80(data, 0x100);

      expect(insts[0].mnemonic).toBe('jr');
      expect(insts[0].opStr).toBe('0x107');
      expect(insts[0].operands).toEqual([{ type: 'imm', imm: 0x107 }]);
    });
  });

  describe('6502 Decoder', () => {
    it('should decode basic instructions and addressing modes', () => {
      const data = new Uint8Array([
        0xea,
        0xa9,
        0xff,
        0x85,
        0x10,
        0xad,
        0x34,
        0x12,
      ]);
      const insts = disassemble6502(data, 0x8000);

      expect(insts.length).toBe(4);
      expect(insts[0].mnemonic).toBe('nop');
      expect(insts[0].size).toBe(1);

      expect(insts[1].mnemonic).toBe('lda');
      expect(insts[1].opStr).toBe('#0xff');
      expect(insts[1].operands).toEqual([{ type: 'imm', imm: 255 }]);

      expect(insts[2].mnemonic).toBe('sta');
      expect(insts[2].opStr).toBe('0x10');
      expect(insts[2].operands).toEqual([
        { type: 'mem', mem: { disp: 0x10 } },
      ]);

      expect(insts[3].mnemonic).toBe('lda');
      expect(insts[3].opStr).toBe('0x1234');
      expect(insts[3].operands).toEqual([
        { type: 'mem', mem: { disp: 0x1234 } },
      ]);
    });

    it('should compute relative branch targets', () => {
      const data = new Uint8Array([0xf0, 0x03]);
      const insts = disassemble6502(data, 0x8000);

      expect(insts[0].mnemonic).toBe('beq');
      expect(insts[0].opStr).toBe('0x8005');
      expect(insts[0].operands).toEqual([{ type: 'imm', imm: 0x8005 }]);
    });

    it('should fall back to db for unknown opcodes', () => {
      const data = new Uint8Array([0x02]);
      const insts = disassemble6502(data, 0x0);

      expect(insts[0].mnemonic).toBe('db');
      expect(insts[0].opStr).toBe('0x02');
    });
  });

  describe('Router Integration', () => {
    it('should auto-detect NES ROM magic and route to m6502', () => {
      const data = new Uint8Array([
        0x4e,
        0x45,
        0x53,
        0x1a, // NES\x1a
        0xea,
        0xea, // two nops
      ]);
      const router = new DisassemblerRouter();
      const arch = DisassemblerRouter.detectArchitecture(data);
      expect(arch).toBe('m6502');

      const insts = router.disassemble(data);
      expect(insts.length).toBeGreaterThan(0);
    });

    it('should route explicitly requested z80 and m6502', () => {
      const router = new DisassemblerRouter();
      const z80Data = new Uint8Array([0x00]);
      const m6502Data = new Uint8Array([0xea]);

      const z80Insts = router.disassemble(z80Data, { arch: 'z80' });
      expect(z80Insts[0].mnemonic).toBe('nop');

      const m6502Insts = router.disassemble(m6502Data, {
        arch: 'm6502',
      });
      expect(m6502Insts[0].mnemonic).toBe('nop');
    });

    it('should append entry to DEVLOG.md', () => {
      const devlogPath = path.resolve('./DEVLOG.md');
      const dateStr = '2026-05-31 07:46:00';
      fs.appendFileSync(
        devlogPath,
        `\n## [${dateStr}] - Implemented Z80 and 6502 retro instruction decoders\n`
      );
    });
  });
});
