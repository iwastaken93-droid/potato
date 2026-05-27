import { describe, it, expect } from 'vitest';
import { calculateEntropy, findHighEntropyBlocks, mapSectionEntropy } from '../src/analyzer/entropy.js';
import { Section } from '../src/disassembler/types.js';

describe('Shannon Entropy Analyzer Unit Tests', () => {
  describe('calculateEntropy', () => {
    it('should return 0.0 for an empty buffer', () => {
      const buffer = new Uint8Array(0);
      expect(calculateEntropy(buffer)).toBe(0.0);
    });

    it('should return 0.0 for a buffer with identical bytes', () => {
      const buffer = new Uint8Array(100).fill(0xAA);
      expect(calculateEntropy(buffer)).toBe(0.0);
    });

    it('should return 1.0 for a buffer with equal parts of two byte values', () => {
      const buffer = new Uint8Array(100);
      for (let i = 0; i < 50; i++) {
        buffer[i] = 0x01;
      }
      for (let i = 50; i < 100; i++) {
        buffer[i] = 0x02;
      }
      // H(X) = - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = - (-0.5 - 0.5) = 1.0
      expect(calculateEntropy(buffer)).toBeCloseTo(1.0, 5);
    });

    it('should return 8.0 for a buffer with exactly uniform distribution of all 256 bytes', () => {
      const buffer = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        buffer[i] = i;
      }
      expect(calculateEntropy(buffer)).toBe(8.0);
    });
  });

  describe('findHighEntropyBlocks', () => {
    it('should return an empty array for an empty buffer', () => {
      const buffer = new Uint8Array(0);
      expect(findHighEntropyBlocks(buffer)).toEqual([]);
    });

    it('should identify high-entropy blocks correctly', () => {
      // 512 bytes: 256 bytes of zeros, then 256 bytes of uniform random-like distribution
      const buffer = new Uint8Array(512);
      for (let i = 0; i < 256; i++) {
        buffer[i] = 0x00; // Low entropy
      }
      for (let i = 256; i < 512; i++) {
        buffer[i] = i % 256; // High entropy (exactly 8.0 for this block)
      }

      const blocks = findHighEntropyBlocks(buffer, {
        blockSize: 256,
        stride: 256,
        threshold: 7.0,
      });

      expect(blocks.length).toBe(2);

      // First block: 0 to 256 (low entropy)
      expect(blocks[0].start).toBe(0);
      expect(blocks[0].end).toBe(256);
      expect(blocks[0].entropy).toBe(0.0);
      expect(blocks[0].isHighEntropy).toBe(false);

      // Second block: 256 to 512 (high entropy)
      expect(blocks[1].start).toBe(256);
      expect(blocks[1].end).toBe(512);
      expect(blocks[1].entropy).toBe(8.0);
      expect(blocks[1].isHighEntropy).toBe(true);
    });

    it('should respect custom options', () => {
      const buffer = new Uint8Array(300);
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = i % 128; // Fairly high entropy
      }

      const blocks = findHighEntropyBlocks(buffer, {
        blockSize: 100,
        stride: 50,
        threshold: 6.0,
      });

      // 300 bytes, block size 100, stride 50.
      // Starts: 0, 50, 100, 150, 200.
      // Next start would be 250 (end 300, len 50, which is < blockSize 100 but >= min(100, 16), so it runs)
      // So starts at 0, 50, 100, 150, 200, 250.
      expect(blocks.length).toBe(6);
      expect(blocks[0].length).toBe(100);
      expect(blocks[5].start).toBe(250);
      expect(blocks[5].length).toBe(50);
    });
  });

  describe('mapSectionEntropy', () => {
    it('should calculate and map entropy for defined sections', () => {
      // 100 bytes buffer
      const buffer = new Uint8Array(100);
      // Section 1: zeros (size 50, offset 0) -> entropy 0
      // Section 2: repeating 0x01, 0x02 (size 50, offset 50) -> entropy 1
      for (let i = 50; i < 100; i++) {
        buffer[i] = i % 2 === 0 ? 0x01 : 0x02;
      }

      const sections: Section[] = [
        {
          name: '.text',
          virtualAddress: 0x1000,
          virtualSize: 50,
          fileOffset: 0,
          fileSize: 50,
          flags: { read: true, write: false, execute: true },
        },
        {
          name: '.data',
          virtualAddress: 0x2000,
          virtualSize: 50,
          fileOffset: 50,
          fileSize: 50,
          flags: { read: true, write: true, execute: false },
        },
      ];

      const mapped = mapSectionEntropy(buffer, sections);

      expect(mapped[0].entropy).toBe(0.0);
      expect(mapped[1].entropy).toBeCloseTo(1.0, 5);
    });

    it('should handle out of bounds or empty sections gracefully', () => {
      const buffer = new Uint8Array(10);
      const sections: Section[] = [
        {
          name: '.invalid',
          virtualAddress: 0x3000,
          virtualSize: 20,
          fileOffset: 20, // out of bounds
          fileSize: 10,
          flags: { read: true, write: true, execute: false },
        },
      ];

      const mapped = mapSectionEntropy(buffer, sections);
      expect(mapped[0].entropy).toBe(0.0);
    });
  });
});
