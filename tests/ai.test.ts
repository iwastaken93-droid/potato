import { describe, it, expect } from 'vitest';
import { AIExplanationEngine } from '../src/analyzer/ai.js';

describe('AI Code Explanation Engine Tests', () => {
  it('should detect RC4 symmetric stream cipher signatures', () => {
    const rc4Code = `
      void decrypt(uint8_t *buffer, int size) {
        uint8_t s[256];
        int i, j = 0;
        for (i = 0; i < 256; i++) s[i] = i;
        // Swap bytes logic
        swap(&s[i], &s[j]);
      }
    `;
    const result = AIExplanationEngine.analyze(rc4Code, {
      functionName: 'rc4_decrypt',
    });
    expect(result.summary).toContain('RC4');
    expect(result.patterns.map((p) => p.name)).toContain(
      'RC4 Cryptographic Cipher'
    );
    expect(result.complexity.time).toContain('O(N)');
    expect(result.pseudocode).toContain('rc4_crypt');
    expect(result.suggestions.length).toBeGreaterThan(0);
  });

  it('should detect TEA/XTEA cipher delta constant and round offsets', () => {
    const teaCode = `
      // Tiny Encryption algorithm loop
      uint32_t delta = 0x9e3779b9;
      sum += delta;
      v0 += ((v1 << 4) ^ (v1 >> 5)) + v1;
    `;
    const result = AIExplanationEngine.analyze(teaCode);
    expect(result.summary).toContain('Tiny Encryption Algorithm');
    expect(result.patterns.map((p) => p.name)).toContain(
      'TEA/XTEA Block Cipher'
    );
    expect(result.complexity.time).toContain('O(R)');
  });

  it('should detect Base64 alphabet and conversion loops', () => {
    const b64Code = `
      const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      encoded[j++] = alphabet[(triple >> 18) & 0x3F];
    `;
    const result = AIExplanationEngine.analyze(b64Code, {
      functionName: 'base64_decode',
    });
    expect(result.summary).toContain('Base64');
    expect(result.patterns.map((p) => p.name)).toContain(
      'Base64 Text Conversion'
    );
  });

  it('should detect PEB lookup anti-debugging signatures', () => {
    const pebCode = `
      mov eax, fs:[30h]
      movzx ebx, byte ptr [eax + 2] // BeingDebugged
      cmp ebx, 0
      jne debug_detected
    `;
    const result = AIExplanationEngine.analyze(pebCode, {
      functionName: 'anti_debug_check',
    });
    expect(result.summary).toContain('debugger');
    expect(result.patterns.map((p) => p.name)).toContain(
      'Anti-Debugging & Evasion'
    );
  });

  it('should fallback gracefully to standard control flow analysis if no patterns match', () => {
    const regularCode = `
      int sum = 0;
      for (int i = 0; i < 10; i++) {
        sum += i;
      }
      return sum;
    `;
    const result = AIExplanationEngine.analyze(regularCode, {
      functionName: 'process_data',
    });
    expect(result.summary).toContain('process_data');
    expect(result.patterns.map((p) => p.name)).toContain(
      'Looping Iterative Routine'
    );
  });
});
