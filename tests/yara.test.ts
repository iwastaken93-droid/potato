import { describe, it, expect } from 'vitest';
import {
  unescapeString,
  parseYaraRules,
  matchPattern,
  evaluateCondition,
  YaraEngine
} from '../src/analyzer/yara.js';

describe('YARA-like Signature Engine Unit Tests', () => {
  describe('unescapeString', () => {
    it('should unescape basic character escapes', () => {
      expect(unescapeString('hello\\nworld')).toBe('hello\nworld');
      expect(unescapeString('tab\\\\separated')).toBe('tab\\separated');
      expect(unescapeString('double\\"quote')).toBe('double"quote');
    });

    it('should unescape hex character escapes', () => {
      expect(unescapeString('val \\x41\\x42\\x43')).toBe('val ABC');
    });
  });

  describe('parseYaraRules', () => {
    it('should parse a basic rule with meta, strings and conditions', () => {
      const source = `
        rule TestRule {
          meta:
            author = "Antigravity"
            version = 1.2
            is_active = true
          strings:
            $text_str = "hello" ascii nocase
            $wide_str = "world" wide
            $hex_str = { 48 8d ?? 55 }
          condition:
            $text_str and ($wide_str or not $hex_str)
        }
      `;

      const rules = parseYaraRules(source);
      expect(rules).toHaveLength(1);
      
      const rule = rules[0];
      expect(rule.name).toBe('TestRule');
      expect(rule.meta).toEqual({
        author: 'Antigravity',
        version: 1.2,
        is_active: true
      });

      expect(rule.strings).toHaveLength(3);
      expect(rule.strings[0]).toEqual({
        id: '$text_str',
        type: 'text',
        value: 'hello',
        modifiers: { ascii: true, wide: false, nocase: true }
      });
      expect(rule.strings[1]).toEqual({
        id: '$wide_str',
        type: 'text',
        value: 'world',
        modifiers: { ascii: false, wide: true, nocase: false }
      });
      expect(rule.strings[2]).toEqual({
        id: '$hex_str',
        type: 'hex',
        value: '48 8d ?? 55',
        modifiers: { ascii: true, wide: false, nocase: false }
      });

      expect(rule.condition).toBe('$text_str and ($wide_str or not $hex_str)');
    });
  });

  describe('matchPattern', () => {
    it('should match hex pattern with wildcards', () => {
      const buffer = new Uint8Array([0x55, 0x89, 0xe5, 0x90, 0x48, 0x8d, 0x05, 0x55]);
      const pattern = {
        id: '$hex',
        type: 'hex' as const,
        value: '48 8d ?? 55'
      };

      const matches = matchPattern(buffer, pattern);
      expect(matches).toHaveLength(1);
      expect(matches[0]).toEqual({
        stringId: '$hex',
        offset: 4,
        matchedValue: '48 8d 05 55'
      });
    });

    it('should match ascii case-insensitive text pattern', () => {
      const buffer = new TextEncoder().encode('ABC def abc GHI');
      const pattern = {
        id: '$abc',
        type: 'text' as const,
        value: 'abc',
        modifiers: { nocase: true, ascii: true }
      };

      const matches = matchPattern(buffer, pattern);
      expect(matches).toHaveLength(2);
      expect(matches[0].offset).toBe(0);
      expect(matches[0].matchedValue).toBe('ABC');
      expect(matches[1].offset).toBe(8);
      expect(matches[1].matchedValue).toBe('abc');
    });

    it('should match wide text pattern', () => {
      // "hello" encoded in wide (UTF-16LE)
      const buffer = new Uint8Array([
        0x68, 0x00, 0x65, 0x00, 0x6c, 0x00, 0x6c, 0x00, 0x6f, 0x00
      ]);

      const pattern = {
        id: '$hello',
        type: 'text' as const,
        value: 'hello',
        modifiers: { wide: true }
      };

      const matches = matchPattern(buffer, pattern);
      expect(matches).toHaveLength(1);
      expect(matches[0].offset).toBe(0);
      expect(matches[0].matchedValue).toBe('hello');
    });
  });

  describe('evaluateCondition', () => {
    it('should evaluate and/or/not boolean expressions correctly', () => {
      const values = {
        $a: true,
        $b: false,
        $c: true
      };

      expect(evaluateCondition('$a and $b', values)).toBe(false);
      expect(evaluateCondition('$a or $b', values)).toBe(true);
      expect(evaluateCondition('not $b', values)).toBe(true);
      expect(evaluateCondition('$a and not $b', values)).toBe(true);
      expect(evaluateCondition('$a and ($b or $c)', values)).toBe(true);
    });

    it('should support any of them and all of them', () => {
      const values = {
        'any of them': true,
        'all of them': false
      };

      expect(evaluateCondition('any of them', values)).toBe(true);
      expect(evaluateCondition('all of them', values)).toBe(false);
    });
  });

  describe('YaraEngine', () => {
    it('should compile and scan binary buffers correctly', () => {
      const source = `
        rule PE_Magic {
          meta:
            description = "Detects PE files"
          strings:
            $mz = "MZ" ascii
            $pe = "PE" ascii
          condition:
            $mz and $pe
        }

        rule ELF_Magic {
          meta:
            description = "Detects ELF files"
          strings:
            $elf = { 7f 45 4c 46 }
          condition:
            $elf
        }
      `;

      const engine = new YaraEngine();
      engine.compile(source);

      // Create a dummy PE buffer
      const peBuffer = new Uint8Array([
        0x4d, 0x5a, // MZ
        0x00, 0x00,
        0x50, 0x45, // PE
        0x00, 0x00
      ]);

      const results = engine.scan(peBuffer);
      expect(results).toHaveLength(2);

      const peResult = results.find(r => r.ruleName === 'PE_Magic');
      const elfResult = results.find(r => r.ruleName === 'ELF_Magic');

      expect(peResult?.matched).toBe(true);
      expect(peResult?.matches).toHaveLength(2);
      expect(peResult?.matches[0].stringId).toBe('$mz');
      expect(peResult?.matches[0].offset).toBe(0);
      expect(peResult?.matches[1].stringId).toBe('$pe');
      expect(peResult?.matches[1].offset).toBe(4);

      expect(elfResult?.matched).toBe(false);
      expect(elfResult?.matches).toHaveLength(0);
    });
  });
});
