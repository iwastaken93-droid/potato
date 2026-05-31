import { describe, it, expect } from 'vitest';
import { parseIntelHex, parseSRecord, detectFormat, mergeBlocks } from '../src/parser/hexLoader.js';
import { processBinaryData } from '../src/analyzer/binaryProcessor.js';

describe('hexLoader parser tests', () => {
  describe('detectFormat', () => {
    it('should detect Intel HEX format', () => {
      const data = new TextEncoder().encode(':10010000214601360121470136007EFE09D2190140\n');
      expect(detectFormat(data)).toBe('IntelHex');
    });

    it('should detect S-record format', () => {
      const data = new TextEncoder().encode('S00600004844521B\nS1130000285F245F2212226A000424290008237C2A\n');
      expect(detectFormat(data)).toBe('SRecord');
    });

    it('should handle whitespace before magic character', () => {
      const data = new TextEncoder().encode('\r\n  :10010000214601360121470136007EFE09D2190140\n');
      expect(detectFormat(data)).toBe('IntelHex');
    });

    it('should return null for unrecognized format', () => {
      const data = new Uint8Array([0x7f, 0x45, 0x4c, 0x46]);
      expect(detectFormat(data)).toBeNull();
    });
  });

  describe('mergeBlocks', () => {
    it('should merge contiguous memory blocks', () => {
      const blocks = [
        { address: 0x1000, data: new Uint8Array([1, 2]) },
        { address: 0x1002, data: new Uint8Array([3, 4]) },
        { address: 0x2000, data: new Uint8Array([5, 6]) }
      ];
      const merged = mergeBlocks(blocks);
      expect(merged.length).toBe(2);
      expect(merged[0].address).toBe(0x1000);
      expect(Array.from(merged[0].data)).toEqual([1, 2, 3, 4]);
      expect(merged[1].address).toBe(0x2000);
      expect(Array.from(merged[1].data)).toEqual([5, 6]);
    });
  });

  describe('parseIntelHex', () => {
    it('should parse valid Intel HEX with 16-bit addresses', () => {
      const hex = `
        :10010000214601360121470136007EFE09D2190140
        :00000001FF
      `;
      const parsed = parseIntelHex(hex);
      expect(parsed.format).toBe('IntelHex');
      expect(parsed.blocks.length).toBe(1);
      expect(parsed.blocks[0].address).toBe(0x0100);
      expect(parsed.blocks[0].data[0]).toBe(0x21);
      expect(parsed.blocks[0].data[15]).toBe(0x01);
    });

    it('should parse Intel HEX with Extended Linear Address (Type 04)', () => {
      const hex = `
        :020000041234B4
        :10010000214601360121470136007EFE09D2190140
        :00000001FF
      `;
      const parsed = parseIntelHex(hex);
      expect(parsed.format).toBe('IntelHex');
      expect(parsed.blocks.length).toBe(1);
      expect(parsed.blocks[0].address).toBe(0x12340100);
    });

    it('should parse Intel HEX with Start Linear Address (Type 05)', () => {
      const hex = `
        :0400000512345678E3
        :00000001FF
      `;
      const parsed = parseIntelHex(hex);
      expect(parsed.entryPoint).toBe(0x12345678);
    });

    it('should parse Intel HEX with Extended Segment Address (Type 02)', () => {
      const hex = `
        :020000021200EA
        :10010000214601360121470136007EFE09D2190140
        :00000001FF
      `;
      const parsed = parseIntelHex(hex);
      expect(parsed.format).toBe('IntelHex');
      expect(parsed.blocks[0].address).toBe((0x1200 << 4) + 0x0100);
    });

    it('should parse Intel HEX with Start Segment Address (Type 03)', () => {
      const hex = `
        :0400000312000034B3
        :00000001FF
      `;
      const parsed = parseIntelHex(hex);
      expect(parsed.entryPoint).toBe((0x1200 << 4) + 0x0034);
    });

    it('should throw on checksum failure', () => {
      const hex = ':10010000214601360121470136007EFE09D2190100'; // Bad checksum
      expect(() => parseIntelHex(hex)).toThrow('Checksum validation failed');
    });

    it('should throw on invalid line format', () => {
      const hex = '10010000214601360121470136007EFE09D2190140'; // Missing colon
      expect(() => parseIntelHex(hex)).toThrow('Invalid Intel HEX line prefix');
    });

    it('should throw on odd hex characters', () => {
      const hex = ':10010000214601360121470136007EFE09D219014'; // Odd length
      expect(() => parseIntelHex(hex)).toThrow('Odd number of hex characters');
    });
  });

  describe('parseSRecord', () => {
    it('should parse valid Motorola S19 (16-bit address)', () => {
      const srec = `
        S00600004844521B
        S1130000285F245F2212226A000424290008237C2A
        S9030000FC
      `;
      const parsed = parseSRecord(srec);
      expect(parsed.format).toBe('SRecord');
      expect(parsed.header).toBe('HDR');
      expect(parsed.entryPoint).toBe(0);
      expect(parsed.blocks.length).toBe(1);
      expect(parsed.blocks[0].address).toBe(0);
      expect(parsed.blocks[0].data.length).toBe(16);
      expect(parsed.blocks[0].data[0]).toBe(0x28);
    });

    it('should parse S28 (24-bit address) and S8 EOF', () => {
      const srec = `
        S2080102031122334447
        S804010203F5
      `;
      const parsed = parseSRecord(srec);
      expect(parsed.format).toBe('SRecord');
      expect(parsed.entryPoint).toBe(0x010203);
      expect(parsed.blocks.length).toBe(1);
      expect(parsed.blocks[0].address).toBe(0x010203);
      expect(Array.from(parsed.blocks[0].data)).toEqual([0x11, 0x22, 0x33, 0x44]);
    });

    it('should parse S37 (32-bit address) and S7 EOF', () => {
      const srec = `
        S309010203041122334442
        S70501020304F0
      `;
      const parsed = parseSRecord(srec);
      expect(parsed.format).toBe('SRecord');
      expect(parsed.entryPoint).toBe(0x01020304);
      expect(parsed.blocks[0].address).toBe(0x01020304);
    });

    it('should skip S5/S6 record count lines safely', () => {
      const srec = `
        S1070010112233443E
        S5030001FB
        S9030010EC
      `;
      const parsed = parseSRecord(srec);
      expect(parsed.blocks.length).toBe(1);
      expect(parsed.blocks[0].address).toBe(0x0010);
    });

    it('should throw on checksum mismatch', () => {
      const srec = 'S10700101122334400';
      expect(() => parseSRecord(srec)).toThrow('Checksum validation failed');
    });

    it('should throw on invalid format', () => {
      const srec = 'X1080010112233443D';
      expect(() => parseSRecord(srec)).toThrow('Invalid S-record line prefix');
    });
  });

  describe('binaryProcessor integration', () => {
    it('should parse and process Intel HEX binary contents', () => {
      const hexString = `
        :1010000090909090909090909090909090909090E0
        :00000001FF
      `;
      const data = new TextEncoder().encode(hexString);
      const res = processBinaryData('firmware.hex', data, data.buffer);

      expect(res).toBeDefined();
      expect(res.sections.length).toBe(1);
      expect(res.sections[0].virtualAddress).toBe(0x1000);
      expect(res.sections[0].virtualSize).toBe(16);
      expect(res.entryPoint).toBe(0x1000);
      expect(res.symbols[0].name).toBe('_start');
      expect(res.symbols[0].address).toBe(0x1000);
      
      expect(res.instructions.length).toBeGreaterThan(0);
      expect(res.instructions[0].mnemonic.toLowerCase()).toBe('nop');
    });

    it('should parse and process Motorola S-record firmware', () => {
      const srecString = `
        S113100090909090909090909090909090909090DC
        S9031000EC
      `;
      const data = new TextEncoder().encode(srecString);
      const res = processBinaryData('firmware.s19', data, data.buffer);

      expect(res).toBeDefined();
      expect(res.sections.length).toBe(1);
      expect(res.sections[0].virtualAddress).toBe(0x1000);
      expect(res.sections[0].virtualSize).toBe(16);
      expect(res.entryPoint).toBe(0x1000);
      
      expect(res.instructions.length).toBeGreaterThan(0);
      expect(res.instructions[0].mnemonic.toLowerCase()).toBe('nop');
    });
  });
});
