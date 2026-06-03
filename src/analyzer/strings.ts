/**
 * String Extraction Module.
 * Scans binary buffers for ASCII and Unicode (UTF-16 LE/BE) strings,
 * maps them to virtual memory addresses, and categorizes potential file paths, URLs, or API names.
 */

export interface ExtractedString {
  /** The extracted string content */
  value: string;
  /** Offset in the binary buffer where the string starts */
  offset: number;
  /** Translated virtual memory address */
  virtualAddress: number;
  /** Type of encoding detected: 'ascii' | 'utf16le' | 'utf16be' */
  encoding: 'ascii' | 'utf16le' | 'utf16be';
  /** Detected categories (if any) */
  tags: ('filepath' | 'url' | 'api' | string)[];
}

export interface StringExtractOptions {
  /** Minimum string length (default: 4) */
  minLength?: number;
  /** Base virtual address (default: 0) */
  baseAddress?: number;
  /** Section mappings to translate buffer offsets to virtual addresses */
  sections?: {
    fileOffset: number;
    fileSize: number;
    virtualAddress: number;
    name?: string;
  }[];
  /** Whether to scan for ASCII/UTF-8 (default: true) */
  ascii?: boolean;
  /** Whether to scan for UTF-16LE (default: true) */
  utf16le?: boolean;
  /** Whether to scan for UTF-16BE (default: true) */
  utf16be?: boolean;
}

/**
 * Detects if a string resembles a file path.
 */
export function isFilePath(str: string): boolean {
  // Windows absolute or relative paths
  if (/^[a-zA-Z]:\\[\\\w\s.-]+/i.test(str)) return true;
  // Unix paths starting with standard systems or structure
  if (
    /^\/(?:bin|usr|lib|etc|var|opt|tmp|home|sbin|dev|sys|proc|run)\b/i.test(str)
  )
    return true;
  if (/^\/(?:[\w\s.-]+\/)+[\w\s.-]*$/i.test(str)) return true;
  // Common filenames with extensions
  if (
    /^[a-zA-Z0-9_-]+\.(exe|dll|sys|so|dylib|ini|conf|bat|sh|json|xml|bin|cfg)$/i.test(
      str
    )
  )
    return true;
  return false;
}

/**
 * Detects if a string is a valid API name/identifier.
 */
export function isApiName(str: string): boolean {
  // Must be a valid C identifier (excluding extremely short or long ones)
  if (!/^[a-zA-Z_][a-zA-Z0-9_]{2,63}$/.test(str)) return false;
  // Common prefixes or suffixes for API functions
  if (
    /^(Get|Set|Create|Write|Read|Open|Close|Initialize|Query|Reg|Nt|Zw|Rtl|Is|Virtual|Local|Global)[A-Z]/i.test(
      str
    )
  )
    return true;
  // Common suffix A or W (Windows ANSI/Unicode) for API functions
  if (/^[a-zA-Z_][a-zA-Z0-9_]+[AW]$/.test(str)) return true;
  // Libc common functions
  const commonLibc = new Set([
    'malloc',
    'calloc',
    'realloc',
    'free',
    'memcpy',
    'memset',
    'memmove',
    'memcmp',
    'strlen',
    'strcpy',
    'strncpy',
    'strcat',
    'strncat',
    'strcmp',
    'strncmp',
    'printf',
    'sprintf',
    'fprintf',
    'scanf',
    'sscanf',
    'fopen',
    'fclose',
    'fread',
    'fwrite',
    'exit',
    'abort',
    'getenv',
    'system',
    'fork',
    'execve',
    'waitpid',
    'pthread_create',
  ]);
  if (commonLibc.has(str)) return true;
  // JNI / Java style or camelCase with non-trivial length
  if (/^[a-z]+[A-Z][a-zA-Z0-9]*$/.test(str)) return true;
  return false;
}

/**
 * Detects if a string is a URL.
 */
export function isUrl(str: string): boolean {
  return /^(https?|ftp|file):\/\/[a-zA-Z0-9-+&@#/%?=~_|!:,.;]*[a-zA-Z0-9-+&@#/%=~_|]$/i.test(
    str
  );
}

/**
 * Scans a binary buffer and extracts readable strings.
 */
export function extractStrings(
  buffer: ArrayBuffer | Uint8Array,
  options: StringExtractOptions = {}
): ExtractedString[] {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const minLength = options.minLength ?? 4;
  const baseAddress = options.baseAddress ?? 0;
  const sections = options.sections ?? [];
  const runAscii = options.ascii ?? true;
  const runUtf16Le = options.utf16le ?? true;
  const runUtf16Be = options.utf16be ?? true;

  const results: ExtractedString[] = [];

  const getVirtualAddress = (offset: number): number => {
    for (const sec of sections) {
      if (offset >= sec.fileOffset && offset < sec.fileOffset + sec.fileSize) {
        return sec.virtualAddress + (offset - sec.fileOffset);
      }
    }
    return baseAddress + offset;
  };

  const tagString = (val: string): ('filepath' | 'url' | 'api' | string)[] => {
    const tags: string[] = [];
    if (isUrl(val)) {
      tags.push('url');
    } else if (isFilePath(val)) {
      tags.push('filepath');
    } else if (isApiName(val)) {
      tags.push('api');
    }
    if (isPgpKey(val)) {
      tags.push('pgp-key');
    }
    if (isOAuthToken(val)) {
      tags.push('oauth-token');
    }
    if (isJwt(val)) {
      tags.push('jwt');
    }
    if (isApiKey(val)) {
      tags.push('api-key');
    }
    return tags;
  };

  const isPrintableAscii = (b: number): boolean => {
    return (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
  };

  const maxStrings = 10000;

  // Scan ASCII/UTF-8
  if (runAscii) {
    let start = -1;
    for (let i = 0; i < bytes.length; i++) {
      if (results.length >= maxStrings) break;
      if (isPrintableAscii(bytes[i])) {
        if (start === -1) {
          start = i;
        }
      } else {
        if (start !== -1) {
          const len = i - start;
          if (len >= minLength) {
            const raw = bytes.subarray(start, i);
            const value = new TextDecoder('utf-8').decode(raw);
            results.push({
              value,
              offset: start,
              virtualAddress: getVirtualAddress(start),
              encoding: 'ascii',
              tags: tagString(value),
            });
          }
          start = -1;
        }
      }
    }
    if (start !== -1 && results.length < maxStrings) {
      const len = bytes.length - start;
      if (len >= minLength) {
        const raw = bytes.subarray(start);
        const value = new TextDecoder('utf-8').decode(raw);
        results.push({
          value,
          offset: start,
          virtualAddress: getVirtualAddress(start),
          encoding: 'ascii',
          tags: tagString(value),
        });
      }
    }
  }

  // Scan UTF-16LE
  if (runUtf16Le && results.length < maxStrings) {
    let start = -1;
    for (let i = 0; i < bytes.length - 1; i += 2) {
      if (results.length >= maxStrings) break;
      const b1 = bytes[i];
      const b2 = bytes[i + 1];
      const isPrint = isPrintableAscii(b1) && b2 === 0x00;
      if (isPrint) {
        if (start === -1) {
          start = i;
        }
      } else {
        if (start !== -1) {
          const len = (i - start) / 2;
          if (len >= minLength) {
            const raw = bytes.subarray(start, i);
            const value = new TextDecoder('utf-16le').decode(raw);
            results.push({
              value,
              offset: start,
              virtualAddress: getVirtualAddress(start),
              encoding: 'utf16le',
              tags: tagString(value),
            });
          }
          start = -1;
        }
      }
    }
    if (start !== -1 && results.length < maxStrings) {
      const len = (bytes.length - start) / 2;
      const end = start + Math.floor(len) * 2;
      if (Math.floor(len) >= minLength) {
        const raw = bytes.subarray(start, end);
        const value = new TextDecoder('utf-16le').decode(raw);
        results.push({
          value,
          offset: start,
          virtualAddress: getVirtualAddress(start),
          encoding: 'utf16le',
          tags: tagString(value),
        });
      }
    }
  }

  // Scan UTF-16BE
  if (runUtf16Be && results.length < maxStrings) {
    let start = -1;
    for (let i = 0; i < bytes.length - 1; i += 2) {
      if (results.length >= maxStrings) break;
      const b1 = bytes[i];
      const b2 = bytes[i + 1];
      const isPrint = isPrintableAscii(b2) && b1 === 0x00;
      if (isPrint) {
        if (start === -1) {
          start = i;
        }
      } else {
        if (start !== -1) {
          const len = (i - start) / 2;
          if (len >= minLength) {
            const raw = bytes.subarray(start, i);
            const value = new TextDecoder('utf-16be').decode(raw);
            results.push({
              value,
              offset: start,
              virtualAddress: getVirtualAddress(start),
              encoding: 'utf16be',
              tags: tagString(value),
            });
          }
          start = -1;
        }
      }
    }
    if (start !== -1 && results.length < maxStrings) {
      const len = (bytes.length - start) / 2;
      const end = start + Math.floor(len) * 2;
      if (Math.floor(len) >= minLength) {
        const raw = bytes.subarray(start, end);
        const value = new TextDecoder('utf-16be').decode(raw);
        results.push({
          value,
          offset: start,
          virtualAddress: getVirtualAddress(start),
          encoding: 'utf16be',
          tags: tagString(value),
        });
      }
    }
  }

  return results;
}

/**
 * Calculates Shannon entropy of a string.
 */
export function getStringEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const counts = new Map<string, number>();
  for (let i = 0; i < len; i++) {
    const char = str[i];
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Detects if a string is base64 or has high entropy.
 */
export function isBase64OrHighEntropy(str: string): boolean {
  if (str.length < 12) return false;
  
  const entropy = getStringEntropy(str);
  
  // Base64 check
  const isBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(str);
  if (isBase64 && str.length >= 16) {
    let categories = 0;
    if (/[a-z]/.test(str)) categories++;
    if (/[A-Z]/.test(str)) categories++;
    if (/[0-9]/.test(str)) categories++;
    if (/[+/=]/.test(str)) categories++;
    if (categories >= 3 && entropy >= 3.5) {
      return true;
    }
  }
  
  // Hex key check
  const isHex = /^[0-9a-fA-F]+$/.test(str);
  if (isHex && str.length >= 16 && entropy >= 3.0) {
    return true;
  }
  
  // General high entropy
  if (str.length >= 16 && entropy >= 4.5) {
    return true;
  }
  
  return false;
}

/**
 * Detects if a string is a registry key starting with HKEY_... (or HK...)
 */
export function isRegistryKey(str: string): boolean {
  return /^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(\\[a-zA-Z0-9_\-\s.]+)*$/i.test(str) || /^HKEY_/i.test(str);
}

/**
 * Detects if a string is a format string containing %s, %d, or other format specifiers.
 */
export function isFormatString(str: string): boolean {
  return /%[0-9.-]*[sdfxXupgGcs]/i.test(str);
}

/**
 * Detects if a string is a PGP Private or Public Key.
 */
export function isPgpKey(str: string): boolean {
  return /-----BEGIN PGP (PRIVATE|PUBLIC) KEY BLOCK-----/i.test(str);
}

/**
 * Detects if a string resembles an OAuth Token.
 */
export function isOAuthToken(str: string): boolean {
  // Google OAuth Access Token
  if (/^ya29\.[a-zA-Z0-9_\-]{20,}$/.test(str)) {
    return getStringEntropy(str) >= 3.5;
  }
  // Slack Access Token
  if (/^xox[baprs]-[a-zA-Z0-9\-]{10,60}$/.test(str)) {
    return getStringEntropy(str) >= 3.0;
  }
  // GitHub Access Token / OAuth
  if (/^gh[o-rs]_[a-zA-Z0-9]{36,40}$/.test(str)) {
    return getStringEntropy(str) >= 3.0;
  }
  // Generic OAuth / Bearer Token pattern (20-128 chars, alphanumeric with high entropy)
  if (/^[a-zA-Z0-9_\-\.\~]{20,128}$/.test(str)) {
    const entropy = getStringEntropy(str);
    if (entropy >= 4.5 && !isFilePath(str) && !isApiName(str) && !isUrl(str)) {
      let categories = 0;
      if (/[a-z]/.test(str)) categories++;
      if (/[A-Z]/.test(str)) categories++;
      if (/[0-9]/.test(str)) categories++;
      if (categories >= 2) return true;
    }
  }
  return false;
}

/**
 * Detects if a string is a JSON Web Token (JWT).
 */
export function isJwt(str: string): boolean {
  if (!/^eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}$/.test(str)) {
    return false;
  }
  return getStringEntropy(str) >= 4.0;
}

/**
 * Detects if a string resembles an API Key (Google, AWS, Slack, etc.).
 */
export function isApiKey(str: string): boolean {
  // Google API Key
  if (/^AIzaSy[a-zA-Z0-9_\-]{33}$/.test(str)) return true;

  // AWS Access Key ID
  if (/^(AKIA|ASIA)[A-Z0-9]{16}$/.test(str)) return true;

  // AWS Secret Access Key: 40 base64 chars with high entropy
  if (/^[a-zA-Z0-9/+=]{40}$/.test(str)) {
    const entropy = getStringEntropy(str);
    if (entropy >= 4.5) return true;
  }

  // Slack App token
  if (/^xapp-[0-9a-zA-Z-]{10,60}$/.test(str)) return true;

  // Slack Webhook URL
  if (/^https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}$/.test(str)) return true;

  // Generic API keys (e.g. hex/base64 keys of typical lengths: 32, 64 characters)
  if (/^[a-zA-Z0-9_\-]{32,64}$/.test(str)) {
    const entropy = getStringEntropy(str);
    if (entropy >= 4.5 && !isFilePath(str) && !isApiName(str) && !isUrl(str)) {
      let categories = 0;
      if (/[a-zA-Z]/.test(str)) categories++;
      if (/[0-9]/.test(str)) categories++;
      if (categories >= 2) return true;
    }
  }

  return false;
}

