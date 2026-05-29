import { describe, it, expect } from 'vitest';
import { ReportGenerator } from '../src/analyzer/reportGenerator.js';
import type { ReportData } from '../src/analyzer/reportGenerator.js';

describe('ReportGenerator Unit Tests', () => {
  const mockBaseData: ReportData = {
    fileName: 'test_binary.exe',
    fileSize: 1024 * 1024 + 512, // 1,049,088 bytes (1.00 MB)
    architecture: 'x86_64',
    entryPoint: 0x140001000,
    sections: [
      {
        name: '.text',
        virtualAddress: 0x140001000,
        virtualSize: 4096,
        fileOffset: 0x400,
        fileSize: 4096,
        entropy: 5.8421,
        flags: { read: true, write: false, execute: true },
      },
      {
        name: '.data',
        virtualAddress: 0x140002000,
        virtualSize: 2048,
        fileOffset: 0x1400,
        fileSize: 1024,
        entropy: 1.2345,
        flags: { read: true, write: true, execute: false },
      },
      {
        name: '.rsrc',
        virtualAddress: 0x140003000,
        virtualSize: 512,
        fileOffset: 0x1800,
        fileSize: 512,
        flags: { read: true, write: false, execute: false },
      },
    ],
    symbols: [
      {
        name: 'main',
        address: 0x140001000,
        size: 128,
        binding: 'global',
        type: 'function',
      },
      {
        name: 'g_value',
        address: 0x140002010,
        size: 4,
        binding: 'global',
        type: 'object',
      },
      {
        name: 'no_size_symbol',
        address: 0x140002020,
        binding: 'local',
        type: 'object',
      },
    ],
    signatures: [
      {
        ruleName: 'GCC Compiler',
        category: 'compiler',
        matches: [{ offset: 0x100, patternType: 'text' }],
      },
    ],
    entropy: {
      overall: 4.5678,
      highEntropyBlocks: [
        {
          start: 0x500,
          end: 0x700,
          length: 512,
          entropy: 7.8543,
          isHighEntropy: true,
        },
      ],
    },
    strings: [
      {
        offset: 0x1500,
        virtualAddress: 0x140002100,
        encoding: 'ascii',
        tags: ['interesting', 'path'],
        value: 'C:\\Windows\\System32\\cmd.exe',
      },
      {
        offset: 0x1600,
        virtualAddress: 0x140002200,
        encoding: 'utf8',
        tags: [],
        value: 'Hello | World\nNew Line\rReturn',
      },
    ],
  };

  describe('generateJSON', () => {
    it('should generate valid JSON string representation of the report data', () => {
      const jsonStr = ReportGenerator.generateJSON(mockBaseData);
      expect(typeof jsonStr).toBe('string');

      const parsed = JSON.parse(jsonStr);
      expect(parsed.fileName).toBe(mockBaseData.fileName);
      expect(parsed.fileSize).toBe(mockBaseData.fileSize);
      expect(parsed.architecture).toBe(mockBaseData.architecture);
      expect(parsed.entryPoint).toBe(mockBaseData.entryPoint);
      expect(parsed.sections).toHaveLength(mockBaseData.sections.length);
      expect(parsed.symbols).toHaveLength(mockBaseData.symbols.length);
      expect(parsed.signatures).toHaveLength(mockBaseData.signatures.length);
      expect(parsed.entropy.overall).toBe(mockBaseData.entropy.overall);
      expect(parsed.entropy.highEntropyBlocks).toHaveLength(
        mockBaseData.entropy.highEntropyBlocks.length
      );
      expect(parsed.strings).toHaveLength(mockBaseData.strings.length);
    });
  });

  describe('generateMarkdown', () => {
    it('should format size correctly for different thresholds (0, bytes, KB, MB)', () => {
      const testCases = [
        { size: 0, expectedStr: '0 B' },
        { size: 512, expectedStr: '512 B' },
        { size: 1536, expectedStr: '1.5 KB' },
        { size: 1048576, expectedStr: '1 MB' },
        { size: 1073741824, expectedStr: '1 GB' },
      ];

      for (const tc of testCases) {
        const data: ReportData = {
          ...mockBaseData,
          fileSize: tc.size,
          sections: [],
          symbols: [],
          signatures: [],
          entropy: { overall: 0, highEntropyBlocks: [] },
          strings: [],
        };
        const md = ReportGenerator.generateMarkdown(data);
        expect(md).toContain(tc.expectedStr);
      }
    });

    it('should format metadata, entry points and overall entropy correctly', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('# Binary Analysis Report: test_binary.exe');
      expect(md).toContain('**File Name** | test_binary.exe');
      expect(md).toContain('**Architecture** | X86_64');
      expect(md).toContain('**Entry Point** | 0x140001000');
      expect(md).toContain('**Overall Entropy** | 4.5678');
    });

    it('should render section table with formatted columns and flags', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('## 📦 Sections');
      expect(md).toContain(
        '`.text` | 0x140001000 | 4 KB | 0x400 | 4 KB | 5.8421 | `R-X`'
      );
      expect(md).toContain(
        '`.data` | 0x140002000 | 2 KB | 0x1400 | 1 KB | 1.2345 | `RW-`'
      );
      expect(md).toContain(
        '`.rsrc` | 0x140003000 | 512 B | 0x1800 | 512 B | N/A | `R--`'
      );
    });

    it('should print fallback when there are no sections', () => {
      const data = { ...mockBaseData, sections: [] };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain('No sections found.');
    });

    it('should render symbols and highlight function vs other counts', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('## 🏷️ Symbols');
      expect(md).toContain('Total Symbols: 3 (Functions: 1, Other: 2)');
      expect(md).toContain(
        '`main` | 0x140001000 | `function` | `global` | 128'
      );
      expect(md).toContain('`g_value` | 0x140002010 | `object` | `global` | 4');
      expect(md).toContain(
        '`no_size_symbol` | 0x140002020 | `object` | `local` | N/A'
      );
    });

    it('should truncate symbol rendering at 50 but include mention of JSON', () => {
      const manySymbols: ReportData['symbols'] = [];
      for (let i = 0; i < 60; i++) {
        manySymbols.push({
          name: `sym_${i}`,
          address: 0x1000 + i * 4,
          binding: 'local',
          type: 'function',
          size: 4,
        });
      }
      const data = { ...mockBaseData, symbols: manySymbols };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain(
        'Showing top 50 symbols. Check JSON report for full list.'
      );
      expect(md).toContain('`sym_0`');
      expect(md).toContain('`sym_49`');
      expect(md).not.toContain('`sym_50`');
    });

    it('should print fallback when there are no symbols', () => {
      const data = { ...mockBaseData, symbols: [] };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain('No symbols found.');
    });

    it('should render signatures scan matches with virtual address/offset patterns', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('## 🛡️ Signature Scan Results');
      expect(md).toContain('**GCC Compiler** | `compiler` | 0x100 (text)');
    });

    it('should print fallback when there are no signatures matched', () => {
      const data = { ...mockBaseData, signatures: [] };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain('No signatures matched.');
    });

    it('should render high entropy blocks correctly', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('## 📈 High Entropy Blocks');
      expect(md).toContain('0x500 | 0x700 | 512 B | 7.8543');
    });

    it('should print fallback when there are no high entropy blocks', () => {
      const data = {
        ...mockBaseData,
        entropy: { overall: 2.0, highEntropyBlocks: [] },
      };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain('No high entropy blocks detected (entropy >= 7.2).');
    });

    it('should render extracted strings and escape pipeline/newlines correctly', () => {
      const md = ReportGenerator.generateMarkdown(mockBaseData);
      expect(md).toContain('## 💬 Extracted Strings (Top 100)');
      expect(md).toContain(
        '0x1500 | 0x140002100 | `ascii` | `interesting`, `path` | `C:\\Windows\\System32\\cmd.exe`'
      );
      // Verify escaping of '|', '\n', '\r'
      expect(md).toContain('Hello \\| World\\nNew Line\\rReturn');
    });

    it('should truncate strings rendering at 100 but include mention of JSON', () => {
      const manyStrings: ReportData['strings'] = [];
      for (let i = 0; i < 110; i++) {
        manyStrings.push({
          offset: i,
          virtualAddress: 0x2000 + i,
          encoding: 'ascii',
          tags: [],
          value: `str_${i}`,
        });
      }
      const data = { ...mockBaseData, strings: manyStrings };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain(
        'Showing top 100 strings. Check JSON report for full list.'
      );
      expect(md).toContain('`str_0`');
      expect(md).toContain('`str_99`');
      expect(md).not.toContain('`str_100`');
    });

    it('should print fallback when there are no strings', () => {
      const data = { ...mockBaseData, strings: [] };
      const md = ReportGenerator.generateMarkdown(data);
      expect(md).toContain('No strings extracted.');
    });
  });
});
