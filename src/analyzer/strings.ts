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
    return tags;
  };

  const isPrintableAscii = (b: number): boolean => {
    return (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
  };

  // Scan ASCII/UTF-8
  if (runAscii) {
    let start = -1;
    for (let i = 0; i < bytes.length; i++) {
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
    if (start !== -1) {
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
  if (runUtf16Le) {
    let start = -1;
    for (let i = 0; i < bytes.length - 1; i += 2) {
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
    if (start !== -1) {
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
  if (runUtf16Be) {
    let start = -1;
    for (let i = 0; i < bytes.length - 1; i += 2) {
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
    if (start !== -1) {
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
