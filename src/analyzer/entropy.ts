import { Section } from '../disassembler/types.js';

/**
 * Interface representing a block of analyzed binary data and its entropy value.
 */
export interface EntropyBlock {
  /** The starting byte offset of the block in the buffer */
  start: number;
  /** The ending byte offset of the block in the buffer (exclusive) */
  end: number;
  /** The length of the block in bytes */
  length: number;
  /** The calculated Shannon entropy value (0.0 to 8.0) */
  entropy: number;
  /** Flag indicating if the block's entropy meets or exceeds the threshold */
  isHighEntropy: boolean;
}

/**
 * Options for scanning and finding high-entropy blocks.
 */
export interface ScanOptions {
  /** The size of each scanning block in bytes (default: 256) */
  blockSize?: number;
  /** The step size (stride) to advance the scanning window (default: 128) */
  stride?: number;
  /** The entropy threshold above which a block is marked as high-entropy (default: 7.2) */
  threshold?: number;
}

/**
 * Calculates the Shannon entropy of a given byte buffer.
 * Shannon entropy represents the average information content per byte.
 * For a byte array, the maximum entropy is 8.0 (completely random or uniform distribution),
 * and the minimum is 0.0 (all bytes have the same value).
 *
 * @param buffer - The Uint8Array binary buffer to analyze.
 * @returns The Shannon entropy value as a number between 0.0 and 8.0.
 */
export function calculateEntropy(buffer: Uint8Array): number {
  const len = buffer.length;
  if (len === 0) {
    return 0.0;
  }

  // Count occurrences of each byte value (0-255)
  const counts = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    counts[buffer[i]]++;
  }

  // Calculate Shannon entropy: H(X) = -sum(P(x) * log2(P(x)))
  let entropy = 0.0;
  for (let i = 0; i < 256; i++) {
    const count = counts[i];
    if (count > 0) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Scans a binary buffer using a sliding window to find blocks with high entropy.
 * High entropy blocks (typically >= 7.2 out of 8.0) are strong signals of
 * encrypted data, compressed payloads, or obfuscated code.
 *
 * @param buffer - The binary buffer to analyze.
 * @param options - Configuration options for the scan.
 * @returns An array of EntropyBlock structures.
 */
export function findHighEntropyBlocks(
  buffer: Uint8Array,
  options: ScanOptions = {}
): EntropyBlock[] {
  const blockSize = options.blockSize ?? 256;
  const stride = options.stride ?? 128;
  const threshold = options.threshold ?? 7.2;

  if (buffer.length === 0 || blockSize <= 0 || stride <= 0) {
    return [];
  }

  const blocks: EntropyBlock[] = [];

  for (let start = 0; start < buffer.length; start += stride) {
    const end = Math.min(start + blockSize, buffer.length);
    const length = end - start;
    if (length < Math.min(blockSize, 16)) {
      // Avoid analyzing extremely small blocks at the very end of the buffer
      break;
    }

    const slice = buffer.subarray(start, end);
    const entropy = calculateEntropy(slice);

    blocks.push({
      start,
      end,
      length,
      entropy,
      isHighEntropy: entropy >= threshold,
    });
  }

  return blocks;
}

/**
 * Maps entropy levels across defined sections of a binary file.
 * Evaluates each section based on its fileOffset and fileSize, slicing the buffer
 * and writing back the computed entropy score (0.0 to 8.0).
 *
 * @param buffer - The raw binary buffer of the file.
 * @param sections - The array of binary sections to analyze.
 * @returns A new array of sections with the computed entropy field populated.
 */
export function mapSectionEntropy(
  buffer: Uint8Array,
  sections: Section[]
): Section[] {
  return sections.map((section) => {
    const start = section.fileOffset;
    const end = Math.min(start + section.fileSize, buffer.length);

    let entropy = 0.0;
    if (start < buffer.length && start >= 0 && end > start) {
      const slice = buffer.subarray(start, end);
      entropy = calculateEntropy(slice);
    }

    return {
      ...section,
      entropy,
    };
  });
}
