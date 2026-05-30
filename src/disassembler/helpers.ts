/**
 * Standalone binary decoding helper functions.
 */

export function signExtend8(val: number): number {
  return (val << 24) >> 24;
}

export function signExtend7(val: number): number {
  return val & 0x40 ? val | ~0x7f : val;
}

export function signExtend19(val: number): number {
  return val & 0x40000 ? val | ~0x7ffff : val;
}

export function signExtend26(val: number): number {
  return val & 0x2000000 ? val | ~0x3ffffff : val;
}

export function readInt32LE(data: Uint8Array, offset: number): number {
  return (
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24)
  );
}
