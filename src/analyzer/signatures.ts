/**
 * Binary signature scanner.
 * Supports registering custom signatures/rules (byte sequences, wildcards, regular expressions)
 * and scanning binary buffers to detect compilers, packers, and cryptographic constants.
 */

import { parseHexPattern } from './search.js';

export type RuleCategory = 'compiler' | 'packer' | 'crypto' | 'other';

export type SignaturePattern =
  | { type: 'hex'; value: string }
  | { type: 'text'; value: string; caseInsensitive?: boolean }
  | { type: 'regex'; value: RegExp };

export interface SignatureRule {
  name: string;
  category: RuleCategory;
  patterns: SignaturePattern[];
}

export interface MatchInfo {
  patternType: 'hex' | 'text' | 'regex';
  matchedValue: string; // Hex representation or text representation of matched bytes
  offset: number;
}

export interface ScanResult {
  ruleName: string;
  category: RuleCategory;
  matches: MatchInfo[];
}

export class SignatureScanner {
  private rules: SignatureRule[] = [];

  constructor(registerDefaults = true) {
    if (registerDefaults) {
      this.registerDefaultRules();
    }
  }

  /**
   * Registers a custom signature rule.
   */
  public register(rule: SignatureRule): void {
    this.rules.push(rule);
  }

  /**
   * Clears all registered rules.
   */
  public clear(): void {
    this.rules = [];
  }

  /**
   * Returns the list of registered rules.
   */
  public getRules(): SignatureRule[] {
    return this.rules;
  }

  /**
   * Scans a binary buffer against all registered rules.
   *
   * @param buffer Binary buffer to scan.
   * @returns Array of scan results containing rule matches.
   */
  public scan(buffer: Uint8Array): ScanResult[] {
    const results: ScanResult[] = [];
    if (buffer.length === 0) {
      return results;
    }

    // Decode buffer using ISO-8859-1 (latin1) to guarantee 1-to-1 byte to character code mapping.
    // This allows us to perform substring search and regular expression match.
    const latin1Decoder = new TextDecoder('iso-8859-1');
    const latin1String = latin1Decoder.decode(buffer);

    for (const rule of this.rules) {
      const matches: MatchInfo[] = [];

      for (const pattern of rule.patterns) {
        if (pattern.type === 'hex') {
          const parsed = parseHexPattern(pattern.value);
          if (parsed.length === 0 || parsed.length > buffer.length) {
            continue;
          }

          const limit = buffer.length - parsed.length;
          for (let i = 0; i <= limit; i++) {
            let matched = true;
            for (let j = 0; j < parsed.length; j++) {
              const pByte = parsed[j];
              if (pByte !== null && buffer[i + j] !== pByte) {
                matched = false;
                break;
              }
            }
            if (matched) {
              const matchedBytes = buffer.subarray(i, i + parsed.length);
              const hexVal = Array.from(matchedBytes)
                .map((b) => b.toString(16).padStart(2, '0'))
                .join(' ');
              matches.push({
                patternType: 'hex',
                matchedValue: hexVal,
                offset: i,
              });
            }
          }
        } else if (pattern.type === 'text') {
          const needle = pattern.value;
          if (needle.length === 0 || needle.length > latin1String.length) {
            continue;
          }

          const searchStr = pattern.caseInsensitive
            ? latin1String.toLowerCase()
            : latin1String;
          const findStr = pattern.caseInsensitive
            ? needle.toLowerCase()
            : needle;

          let index = searchStr.indexOf(findStr);
          while (index !== -1) {
            matches.push({
              patternType: 'text',
              matchedValue: latin1String.substring(
                index,
                index + needle.length
              ),
              offset: index,
            });
            index = searchStr.indexOf(findStr, index + 1);
          }
        } else if (pattern.type === 'regex') {
          // Ensure global flag is set to find all occurrences
          const flags = pattern.value.flags;
          const globalRegex = new RegExp(
            pattern.value.source,
            flags.includes('g') ? flags : flags + 'g'
          );

          let match: RegExpExecArray | null;
          // Reset lastIndex to ensure fresh scan
          globalRegex.lastIndex = 0;

          while ((match = globalRegex.exec(latin1String)) !== null) {
            // Avoid infinite loops for zero-width matches
            const matchLen = match[0].length;
            matches.push({
              patternType: 'regex',
              matchedValue: match[0],
              offset: match.index,
            });

            if (matchLen === 0) {
              globalRegex.lastIndex++;
            }
          }
        }
      }

      if (matches.length > 0) {
        results.push({
          ruleName: rule.name,
          category: rule.category,
          matches,
        });
      }
    }

    return results;
  }

  /**
   * Registers pre-defined signature rules for compilers, packers, and cryptography.
   */
  private registerDefaultRules(): void {
    // --- COMPILERS ---
    this.register({
      name: 'GCC',
      category: 'compiler',
      patterns: [
        { type: 'text', value: 'GCC: (GNU)' },
        { type: 'regex', value: /GCC: \(GNU\) \d+\.\d+\.\d+/ },
      ],
    });

    this.register({
      name: 'Clang',
      category: 'compiler',
      patterns: [
        { type: 'text', value: 'clang version', caseInsensitive: true },
        { type: 'regex', value: /clang version \d+\.\d+\.\d+/i },
      ],
    });

    this.register({
      name: 'MSVC',
      category: 'compiler',
      patterns: [
        { type: 'text', value: 'Microsoft Visual C++' },
        { type: 'hex', value: '52 69 63 68' }, // "Rich" header signature
      ],
    });

    this.register({
      name: 'Go',
      category: 'compiler',
      patterns: [
        { type: 'text', value: 'Go build ID:' },
        // Go PCCLN table magic: 0xfffffffb or 0xfffffffa (BE/LE variations)
        { type: 'hex', value: 'fb ff ff ff' },
        { type: 'hex', value: 'fa ff ff ff' },
        { type: 'hex', value: 'ff ff ff fb' },
        { type: 'hex', value: 'ff ff ff fa' },
      ],
    });

    this.register({
      name: 'Rust',
      category: 'compiler',
      patterns: [
        { type: 'text', value: '/rustc/' },
        { type: 'text', value: 'rustc-' },
        { type: 'regex', value: /rustc-[0-9a-f]{40}/ },
      ],
    });

    // --- PACKERS ---
    this.register({
      name: 'UPX',
      category: 'packer',
      patterns: [
        { type: 'text', value: 'UPX!' },
        { type: 'hex', value: '55 50 58 21' }, // "UPX!" magic bytes
        { type: 'text', value: 'UPX0' },
        { type: 'text', value: 'UPX1' },
      ],
    });

    this.register({
      name: 'ASPack',
      category: 'packer',
      patterns: [
        { type: 'text', value: 'aspack', caseInsensitive: true },
        { type: 'text', value: '.aspack' },
      ],
    });

    // --- CRYPTO CONSTANTS ---
    this.register({
      name: 'MD5 Constants',
      category: 'crypto',
      patterns: [
        // MD5 state initializers: 01 23 45 67 (LE)
        {
          type: 'hex',
          value: '01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10',
        },
      ],
    });

    this.register({
      name: 'SHA-256 Constants',
      category: 'crypto',
      patterns: [
        // SHA-256 H0-H3 first initial values in LE or BE
        // 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
        {
          type: 'hex',
          value: '67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5',
        }, // LE
        {
          type: 'hex',
          value: '6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a',
        }, // BE
      ],
    });

    this.register({
      name: 'AES S-box',
      category: 'crypto',
      patterns: [
        // S-box starting sequence: 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
        {
          type: 'hex',
          value: '63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76',
        },
      ],
    });
  }
}
