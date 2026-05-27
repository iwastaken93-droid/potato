import { describe, it, expect } from 'vitest';
import { SignatureScanner, SignatureRule } from '../src/analyzer/signatures.js';

describe('Binary Signature Scanner Unit Tests', () => {
  describe('Custom Signature Registration & Clearing', () => {
    it('should initialize with default rules when registerDefaults is true', () => {
      const scanner = new SignatureScanner(true);
      const rules = scanner.getRules();
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.some(r => r.name === 'GCC')).toBe(true);
      expect(rules.some(r => r.name === 'UPX')).toBe(true);
      expect(rules.some(r => r.name === 'AES S-box')).toBe(true);
    });

    it('should initialize empty when registerDefaults is false', () => {
      const scanner = new SignatureScanner(false);
      expect(scanner.getRules()).toEqual([]);
    });

    it('should allow registering a custom rule', () => {
      const scanner = new SignatureScanner(false);
      const rule: SignatureRule = {
        name: 'MyCustomRule',
        category: 'other',
        patterns: [{ type: 'text', value: 'Hello' }],
      };
      scanner.register(rule);
      expect(scanner.getRules()).toHaveLength(1);
      expect(scanner.getRules()[0].name).toBe('MyCustomRule');
    });

    it('should clear registered rules', () => {
      const scanner = new SignatureScanner(true);
      expect(scanner.getRules().length).toBeGreaterThan(0);
      scanner.clear();
      expect(scanner.getRules()).toEqual([]);
    });
  });

  describe('Pattern Scanning Functionality', () => {
    it('should return empty results for an empty buffer', () => {
      const scanner = new SignatureScanner(false);
      scanner.register({
        name: 'Test',
        category: 'other',
        patterns: [{ type: 'text', value: 'hello' }],
      });
      const buffer = new Uint8Array(0);
      expect(scanner.scan(buffer)).toEqual([]);
    });

    describe('Text Pattern Matching', () => {
      it('should match exact case-sensitive text', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'TextRule',
          category: 'other',
          patterns: [{ type: 'text', value: 'Target' }],
        });
        const encoder = new TextEncoder();
        const buffer = encoder.encode('Some prefix Target and suffix Target');

        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].ruleName).toBe('TextRule');
        expect(results[0].matches).toHaveLength(2);
        expect(results[0].matches[0]).toEqual({
          patternType: 'text',
          matchedValue: 'Target',
          offset: 12,
        });
        expect(results[0].matches[1]).toEqual({
          patternType: 'text',
          matchedValue: 'Target',
          offset: 30,
        });
      });

      it('should match case-insensitive text when configured', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'TextRuleIC',
          category: 'other',
          patterns: [{ type: 'text', value: 'tArGeT', caseInsensitive: true }],
        });
        const encoder = new TextEncoder();
        const buffer = encoder.encode('target TARGET Target');

        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].matches).toHaveLength(3);
        expect(results[0].matches[0].matchedValue).toBe('target');
        expect(results[0].matches[1].matchedValue).toBe('TARGET');
        expect(results[0].matches[2].matchedValue).toBe('Target');
      });
    });

    describe('Hex Pattern Matching', () => {
      it('should match exact hex patterns without wildcards', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'HexRule',
          category: 'other',
          patterns: [{ type: 'hex', value: '48 8d 05' }],
        });
        const buffer = new Uint8Array([0x90, 0x48, 0x8d, 0x05, 0x90]);
        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].matches).toHaveLength(1);
        expect(results[0].matches[0]).toEqual({
          patternType: 'hex',
          matchedValue: '48 8d 05',
          offset: 1,
        });
      });

      it('should match hex patterns with wildcards', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'HexWildcard',
          category: 'other',
          patterns: [{ type: 'hex', value: '55 89 ?? 90' }],
        });
        const buffer = new Uint8Array([0x55, 0x89, 0xe5, 0x90, 0x00, 0x55, 0x89, 0xff, 0x90]);
        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].matches).toHaveLength(2);
        expect(results[0].matches[0]).toEqual({
          patternType: 'hex',
          matchedValue: '55 89 e5 90',
          offset: 0,
        });
        expect(results[0].matches[1]).toEqual({
          patternType: 'hex',
          matchedValue: '55 89 ff 90',
          offset: 5,
        });
      });
    });

    describe('Regex Pattern Matching', () => {
      it('should match RegExp patterns against the binary', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'RegexRule',
          category: 'other',
          patterns: [{ type: 'regex', value: /version \d+\.\d+/ }],
        });
        const encoder = new TextEncoder();
        const buffer = encoder.encode('App version 1.2 is running version 3.4');
        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].matches).toHaveLength(2);
        expect(results[0].matches[0]).toEqual({
          patternType: 'regex',
          matchedValue: 'version 1.2',
          offset: 4,
        });
        expect(results[0].matches[1]).toEqual({
          patternType: 'regex',
          matchedValue: 'version 3.4',
          offset: 27,
        });
      });

      it('should match RegExp patterns containing non-ASCII bytes mapped via latin1', () => {
        const scanner = new SignatureScanner(false);
        scanner.register({
          name: 'BinaryRegex',
          category: 'other',
          patterns: [{ type: 'regex', value: /\x80\xff\x00/ }],
        });
        const buffer = new Uint8Array([0x01, 0x80, 0xff, 0x00, 0x02]);
        const results = scanner.scan(buffer);
        expect(results).toHaveLength(1);
        expect(results[0].matches).toHaveLength(1);
        expect(results[0].matches[0].offset).toBe(1);
      });
    });
  });

  describe('Default Signatures Verification', () => {
    const scanner = new SignatureScanner(true);

    it('should detect GCC signature', () => {
      const buffer = new TextEncoder().encode('Some binary containing GCC: (GNU) 11.2.0 string.');
      const results = scanner.scan(buffer);
      const gccResult = results.find(r => r.ruleName === 'GCC');
      expect(gccResult).toBeDefined();
      expect(gccResult?.category).toBe('compiler');
      expect(gccResult?.matches.some(m => m.matchedValue === 'GCC: (GNU) 11.2.0')).toBe(true);
    });

    it('should detect MSVC signature', () => {
      // 52 69 63 68 is "Rich"
      const buffer = new Uint8Array([0x90, 0x52, 0x69, 0x63, 0x68, 0x90]);
      const results = scanner.scan(buffer);
      const msvcResult = results.find(r => r.ruleName === 'MSVC');
      expect(msvcResult).toBeDefined();
      expect(msvcResult?.category).toBe('compiler');
    });

    it('should detect Clang signature', () => {
      const buffer = new TextEncoder().encode('Built with clang version 14.0.0 (https://github.com...)');
      const results = scanner.scan(buffer);
      const clangResult = results.find(r => r.ruleName === 'Clang');
      expect(clangResult).toBeDefined();
      expect(clangResult?.category).toBe('compiler');
    });

    it('should detect Go compiler signatures', () => {
      // fb ff ff ff is Go PCCLN magic in PE/ELF
      const buffer = new Uint8Array([0x00, 0xfb, 0xff, 0xff, 0xff, 0x00]);
      const results = scanner.scan(buffer);
      const goResult = results.find(r => r.ruleName === 'Go');
      expect(goResult).toBeDefined();
      expect(goResult?.category).toBe('compiler');
    });

    it('should detect Rust signature', () => {
      const buffer = new TextEncoder().encode('rustc-f3751c6767b140884b2e81138a26b07db3f05c48');
      const results = scanner.scan(buffer);
      const rustResult = results.find(r => r.ruleName === 'Rust');
      expect(rustResult).toBeDefined();
      expect(rustResult?.category).toBe('compiler');
    });

    it('should detect UPX packer signature', () => {
      const buffer = new Uint8Array([0x55, 0x50, 0x58, 0x21]); // UPX!
      const results = scanner.scan(buffer);
      const upxResult = results.find(r => r.ruleName === 'UPX');
      expect(upxResult).toBeDefined();
      expect(upxResult?.category).toBe('packer');
    });

    it('should detect MD5 constants', () => {
      const buffer = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
      ]);
      const results = scanner.scan(buffer);
      const md5Result = results.find(r => r.ruleName === 'MD5 Constants');
      expect(md5Result).toBeDefined();
      expect(md5Result?.category).toBe('crypto');
    });

    it('should detect AES S-box constants', () => {
      const buffer = new Uint8Array([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      ]);
      const results = scanner.scan(buffer);
      const aesResult = results.find(r => r.ruleName === 'AES S-box');
      expect(aesResult).toBeDefined();
      expect(aesResult?.category).toBe('crypto');
    });
  });
});
