import { describe, it, expect } from 'vitest';
import {
  computeMD5,
  computeSHA1,
  computeSHA256,
} from '../src/analyzer/hashes.js';

describe('Hash Computation Tests', () => {
  const encoder = new TextEncoder();

  describe('MD5', () => {
    it('should compute MD5 for empty data', () => {
      const data = new Uint8Array([]);
      const hash = computeMD5(data);
      expect(hash).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });

    it('should compute MD5 for standard input "abc"', () => {
      const data = encoder.encode('abc');
      const hash = computeMD5(data);
      expect(hash).toBe('900150983cd24fb0d6963f7d28e17f72');
    });

    it('should compute MD5 for "hello world"', () => {
      const data = encoder.encode('hello world');
      const hash = computeMD5(data);
      expect(hash).toBe('5eb63bbbe01eeed093cb22bb8f5acdc3');
    });
  });

  describe('SHA-1', () => {
    it('should compute SHA-1 for empty data', () => {
      const data = new Uint8Array([]);
      const hash = computeSHA1(data);
      expect(hash).toBe('da39a3ee5e6b4b0d3255bfef95601890afd80709');
    });

    it('should compute SHA-1 for standard input "abc"', () => {
      const data = encoder.encode('abc');
      const hash = computeSHA1(data);
      expect(hash).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    });

    it('should compute SHA-1 for "hello world"', () => {
      const data = encoder.encode('hello world');
      const hash = computeSHA1(data);
      expect(hash).toBe('2aae6c35c94fcfb415dbe95f408b9ce91ee846ed');
    });
  });

  describe('SHA-256', () => {
    it('should compute SHA-256 for empty data', () => {
      const data = new Uint8Array([]);
      const hash = computeSHA256(data);
      expect(hash).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should compute SHA-256 for standard input "abc"', () => {
      const data = encoder.encode('abc');
      const hash = computeSHA256(data);
      expect(hash).toBe(
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
      );
    });

    it('should compute SHA-256 for "hello world"', () => {
      const data = encoder.encode('hello world');
      const hash = computeSHA256(data);
      expect(hash).toBe(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should compute SHA-256 for a single byte of zero', () => {
      const data = new Uint8Array([0]);
      const hash = computeSHA256(data);
      expect(hash).toBe(
        '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d'
      );
    });

    it('should compute SHA-256 for a single byte of 0xff', () => {
      const data = new Uint8Array([0xff]);
      const hash = computeSHA256(data);
      expect(hash).toBe(
        'a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89'
      );
    });
  });

  describe('Repetitive and Boundary Input Tests', () => {
    it('should compute correct MD5 for a long sequence of characters', () => {
      const data = encoder.encode('a'.repeat(1000));
      expect(computeMD5(data)).toBe('cabe45dcc9ae5b66ba86600cca6b8ba8');
    });

    it('should compute correct SHA-1 for a long sequence of characters', () => {
      const data = encoder.encode('a'.repeat(1000));
      expect(computeSHA1(data)).toBe(
        '291e9a6c66994949b57ba5e650361e98fc36b1ba'
      );
    });

    it('should compute correct SHA-256 for a long sequence of characters', () => {
      const data = encoder.encode('a'.repeat(1000));
      expect(computeSHA256(data)).toBe(
        '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3'
      );
    });
  });
});
