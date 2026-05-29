/**
 * Binary search and pattern matching engine.
 * Supports searching for text strings, hex patterns (with wildcards),
 * and instructions/mnemonics.
 */

import { Instruction } from '../disassembler/types.js';

/**
 * Options for text searching.
 */
export interface TextSearchOptions {
  /**
   * Encoding of the text in the binary.
   * @default 'utf8'
   */
  encoding?: 'utf8' | 'ascii' | 'utf16le';

  /**
   * Whether the search should be case-insensitive.
   * @default false
   */
  caseInsensitive?: boolean;
}

/**
 * Result of a text search match.
 */
export interface TextSearchResult {
  /** The byte offset of the match in the buffer */
  offset: number;
  /** The matched string */
  match: string;
}

/**
 * Result of a hex pattern search match.
 */
export interface HexSearchResult {
  /** The byte offset of the match in the buffer */
  offset: number;
  /** The matched byte sequence */
  bytes: Uint8Array;
}

/**
 * Criteria for querying instructions.
 */
export interface InstructionQuery {
  /** Mnemonic to search for (e.g. 'mov', 'push') - can be exact string or RegExp */
  mnemonic?: string | RegExp;

  /** Operands string to search for (e.g. 'rax, rbx') - can be exact string or RegExp */
  opStr?: string | RegExp;

  /** Address range to filter instructions */
  addressRange?: {
    min?: number;
    max?: number;
  };

  /** Custom filter function for advanced queries */
  filter?: (inst: Instruction) => boolean;
}

/**
 * Result of an instruction search.
 */
export interface InstructionSearchResult {
  /** The index of the instruction in the input array */
  index: number;
  /** The matched instruction */
  instruction: Instruction;
}

/**
 * Result of an instruction sequence search.
 */
export interface InstructionSequenceResult {
  /** The start index of the sequence in the input array */
  startIndex: number;
  /** The instructions that form the matched sequence */
  instructions: Instruction[];
}

/**
 * Encodes a string to UTF-16LE bytes.
 */
function encodeUTF16LE(str: string): Uint8Array {
  const bytes = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    bytes[i * 2] = code & 0xff;
    bytes[i * 2 + 1] = (code >> 8) & 0xff;
  }
  return bytes;
}

/**
 * Encodes a string to ASCII/UTF-8 bytes.
 */
function encodeUTF8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Searches a binary buffer for occurrences of a text string.
 *
 * @param buffer The binary buffer to search in.
 * @param text The text string to search for.
 * @param options Configuration options for the search.
 * @returns Array of matches with offset and match content.
 */
export function searchText(
  buffer: Uint8Array,
  text: string,
  options: TextSearchOptions = {}
): TextSearchResult[] {
  if (text.length === 0) {
    return [];
  }

  const encoding = options.encoding || 'utf8';
  const caseInsensitive = !!options.caseInsensitive;

  let needle: Uint8Array;
  if (encoding === 'utf16le') {
    needle = encodeUTF16LE(text);
  } else {
    needle = encodeUTF8(text);
  }

  const results: TextSearchResult[] = [];
  const needleLen = needle.length;
  const limit = buffer.length - needleLen;

  for (let i = 0; i <= limit; i++) {
    let match = true;
    for (let j = 0; j < needleLen; j++) {
      const b = buffer[i + j];
      const n = needle[j];

      if (caseInsensitive) {
        // Convert both to lowercase ASCII if applicable
        const bLower = b >= 65 && b <= 90 ? b + 32 : b;
        const nLower = n >= 65 && n <= 90 ? n + 32 : n;
        if (bLower !== nLower) {
          match = false;
          break;
        }
      } else {
        if (b !== n) {
          match = false;
          break;
        }
      }
    }

    if (match) {
      // Decode the matched section to return the actual match text
      const matchedBytes = buffer.subarray(i, i + needleLen);
      let matchStr = text;
      if (encoding === 'utf16le') {
        matchStr = new TextDecoder('utf-16le').decode(matchedBytes);
      } else {
        matchStr = new TextDecoder('utf-8').decode(matchedBytes);
      }

      results.push({
        offset: i,
        match: matchStr,
      });
    }
  }

  return results;
}

/**
 * Parses a hex pattern string with wildcards (e.g. '48 8d ?? 55')
 * into an array of bytes and null values representing wildcards.
 *
 * @param pattern Hex pattern string.
 * @returns Array of numbers (byte values) or null (wildcards).
 */
export function parseHexPattern(pattern: string): (number | null)[] {
  if (/[^0-9a-fA-F?\s]/.test(pattern)) {
    throw new Error(`Invalid characters in hex pattern: "${pattern}"`);
  }

  const tokens = pattern.match(/\?\?|\?|[0-9a-fA-F]{1,2}/g);
  if (!tokens) {
    return [];
  }

  return tokens.map((token) => {
    if (token.includes('?')) {
      return null;
    }
    return parseInt(token, 16);
  });
}

/**
 * Searches a binary buffer for occurrences of a hex pattern (which may contain wildcards).
 *
 * @param buffer The binary buffer to search in.
 * @param pattern The hex pattern string (e.g., '48 8d ?? 55').
 * @returns Array of matches with offset and the matched byte sequence.
 */
export function searchHex(
  buffer: Uint8Array,
  pattern: string
): HexSearchResult[] {
  const parsedPattern = parseHexPattern(pattern);
  if (parsedPattern.length === 0) {
    return [];
  }

  const results: HexSearchResult[] = [];
  const patternLen = parsedPattern.length;
  const limit = buffer.length - patternLen;

  for (let i = 0; i <= limit; i++) {
    let match = true;
    for (let j = 0; j < patternLen; j++) {
      const pVal = parsedPattern[j];
      if (pVal !== null && buffer[i + j] !== pVal) {
        match = false;
        break;
      }
    }

    if (match) {
      results.push({
        offset: i,
        bytes: buffer.slice(i, i + patternLen),
      });
    }
  }

  return results;
}

/**
 * Helper to check if a single instruction matches a query.
 */
function matchesQuery(inst: Instruction, query: InstructionQuery): boolean {
  if (query.mnemonic !== undefined) {
    if (query.mnemonic instanceof RegExp) {
      if (!query.mnemonic.test(inst.mnemonic)) {
        return false;
      }
    } else {
      if (inst.mnemonic.toLowerCase() !== query.mnemonic.toLowerCase()) {
        return false;
      }
    }
  }

  if (query.opStr !== undefined) {
    if (query.opStr instanceof RegExp) {
      if (!query.opStr.test(inst.opStr)) {
        return false;
      }
    } else {
      if (!inst.opStr.toLowerCase().includes(query.opStr.toLowerCase())) {
        return false;
      }
    }
  }

  if (query.addressRange !== undefined) {
    const { min, max } = query.addressRange;
    if (min !== undefined && inst.address < min) {
      return false;
    }
    if (max !== undefined && inst.address > max) {
      return false;
    }
  }

  if (query.filter !== undefined) {
    if (!query.filter(inst)) {
      return false;
    }
  }

  return true;
}

/**
 * Searches a list of parsed instructions for ones matching specific criteria.
 *
 * @param instructions Array of instructions to search.
 * @param query Query filters.
 * @returns Array of matched instruction results.
 */
export function searchInstructions(
  instructions: Instruction[],
  query: InstructionQuery
): InstructionSearchResult[] {
  const results: InstructionSearchResult[] = [];

  for (let i = 0; i < instructions.length; i++) {
    if (matchesQuery(instructions[i], query)) {
      results.push({
        index: i,
        instruction: instructions[i],
      });
    }
  }

  return results;
}

/**
 * Searches a list of parsed instructions for a sequence of queries.
 * Useful for finding specific instruction patterns (e.g. function prologue/epilogue).
 *
 * @param instructions Array of instructions to search.
 * @param sequence Array of queries to match consecutively.
 * @returns Array of matched sequence results.
 */
export function searchInstructionSequence(
  instructions: Instruction[],
  sequence: InstructionQuery[]
): InstructionSequenceResult[] {
  if (sequence.length === 0 || instructions.length < sequence.length) {
    return [];
  }

  const results: InstructionSequenceResult[] = [];
  const limit = instructions.length - sequence.length;

  for (let i = 0; i <= limit; i++) {
    let match = true;
    for (let j = 0; j < sequence.length; j++) {
      if (!matchesQuery(instructions[i + j], sequence[j])) {
        match = false;
        break;
      }
    }

    if (match) {
      results.push({
        startIndex: i,
        instructions: instructions.slice(i, i + sequence.length),
      });
    }
  }

  return results;
}
