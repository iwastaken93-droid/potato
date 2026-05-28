import { describe, it, expect } from 'vitest';
import { deflateRawSync } from 'zlib';
import { ArchiveUnpacker } from '../src/parser/archive.js';

interface MockFile {
  path: string;
  content: Uint8Array | string;
  compress?: boolean;
}

/**
 * Utility to construct a valid ZIP archive in-memory.
 */
function createMockZip(files: MockFile[]): Uint8Array {
  const buffers: Uint8Array[] = [];
  const localHeaders: {
    path: string;
    offset: number;
    compSize: number;
    uncompSize: number;
    method: number;
  }[] = [];

  let currentOffset = 0;

  for (const file of files) {
    const rawContent =
      typeof file.content === 'string'
        ? new TextEncoder().encode(file.content)
        : file.content;
    const method = file.compress ? 8 : 0;
    const finalContent =
      method === 8 ? new Uint8Array(deflateRawSync(rawContent)) : rawContent;

    const pathBytes = new TextEncoder().encode(file.path);

    const localHeader = new Uint8Array(30 + pathBytes.length);
    const view = new DataView(localHeader.buffer);

    // Signature: "PK\x03\x04"
    localHeader[0] = 0x50;
    localHeader[1] = 0x4b;
    localHeader[2] = 0x03;
    localHeader[3] = 0x04;

    view.setUint16(4, 10, true);
    view.setUint16(6, 0, true);
    view.setUint16(8, method, true);
    view.setUint32(18, finalContent.length, true);
    view.setUint32(22, rawContent.length, true);
    view.setUint16(26, pathBytes.length, true);
    view.setUint16(28, 0, true);

    localHeader.set(pathBytes, 30);

    buffers.push(localHeader);
    buffers.push(finalContent);

    localHeaders.push({
      path: file.path,
      offset: currentOffset,
      compSize: finalContent.length,
      uncompSize: rawContent.length,
      method,
    });

    currentOffset += localHeader.length + finalContent.length;
  }

  const cdOffset = currentOffset;
  let cdSize = 0;

  for (const lh of localHeaders) {
    const pathBytes = new TextEncoder().encode(lh.path);
    const cdHeader = new Uint8Array(46 + pathBytes.length);
    const view = new DataView(cdHeader.buffer);

    // Signature: "PK\x01\x02"
    cdHeader[0] = 0x50;
    cdHeader[1] = 0x4b;
    cdHeader[2] = 0x01;
    cdHeader[3] = 0x02;

    view.setUint16(4, 10, true);
    view.setUint16(6, 10, true);
    view.setUint16(8, 0, true);
    view.setUint16(10, lh.method, true);
    view.setUint32(20, lh.compSize, true);
    view.setUint32(24, lh.uncompSize, true);
    view.setUint16(28, pathBytes.length, true);
    view.setUint16(30, 0, true);
    view.setUint16(32, 0, true);
    view.setUint32(42, lh.offset, true);

    cdHeader.set(pathBytes, 46);
    buffers.push(cdHeader);
    cdSize += cdHeader.length;
    currentOffset += cdHeader.length;
  }

  // End of Central Directory (EOCD)
  const eocd = new Uint8Array(22);
  const view = new DataView(eocd.buffer);
  eocd[0] = 0x50;
  eocd[1] = 0x4b;
  eocd[2] = 0x05;
  eocd[3] = 0x06;

  view.setUint16(8, localHeaders.length, true);
  view.setUint16(10, localHeaders.length, true);
  view.setUint32(12, cdSize, true);
  view.setUint32(16, cdOffset, true);

  buffers.push(eocd);

  // Concatenate all parts
  const totalLength = buffers.reduce((acc, b) => acc + b.length, 0);
  const finalZip = new Uint8Array(totalLength);
  let pos = 0;
  for (const b of buffers) {
    finalZip.set(b, pos);
    pos += b.length;
  }
  return finalZip;
}

describe('ArchiveUnpacker Unit Tests', () => {
  it('should list and extract a simple stored (uncompressed) file', () => {
    const fileContent = 'Hello, uncompressed world!';
    const zipBytes = createMockZip([
      { path: 'hello.txt', content: fileContent, compress: false },
    ]);

    const unpacker = new ArchiveUnpacker(zipBytes);
    const entries = unpacker.listAllEntries();

    expect(entries.length).toBe(1);
    expect(entries[0].path).toBe('hello.txt');
    expect(entries[0].size).toBe(fileContent.length);
    expect(entries[0].compressedSize).toBe(fileContent.length);
    expect(entries[0].compressionMethod).toBe(0);
    expect(entries[0].isDirectory).toBe(false);

    const extracted = unpacker.extractEntry('hello.txt');
    expect(new TextDecoder().decode(extracted)).toBe(fileContent);
  });

  it('should list and extract a deflated (compressed) file', () => {
    const fileContent = 'Deflated compression works beautifully and reduces byte count!';
    const zipBytes = createMockZip([
      { path: 'compressed.txt', content: fileContent, compress: true },
    ]);

    const unpacker = new ArchiveUnpacker(zipBytes);
    const entries = unpacker.listAllEntries();

    expect(entries.length).toBe(1);
    expect(entries[0].path).toBe('compressed.txt');
    expect(entries[0].compressionMethod).toBe(8);

    const extracted = unpacker.extractEntry('compressed.txt');
    expect(new TextDecoder().decode(extracted)).toBe(fileContent);
  });

  it('should detect executable types (ELF, DEX, Java Class, Mach-O)', () => {
    const elfMagic = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 0x01, 0x02]);
    const dexMagic = new Uint8Array([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]);
    const classMagic = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]);
    const machoMagic = new Uint8Array([0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00]);

    const zipBytes = createMockZip([
      { path: 'bin/libnative.so', content: elfMagic, compress: false },
      { path: 'classes.dex', content: dexMagic, compress: true },
      { path: 'com/example/Test.class', content: classMagic, compress: false },
      { path: 'Payload/App.app/App', content: machoMagic, compress: true },
    ]);

    const unpacker = new ArchiveUnpacker(zipBytes);
    const entries = unpacker.listAllEntries();

    const elfEntry = entries.find((e) => e.path === 'bin/libnative.so');
    const dexEntry = entries.find((e) => e.path === 'classes.dex');
    const classEntry = entries.find((e) => e.path === 'com/example/Test.class');
    const machoEntry = entries.find((e) => e.path === 'Payload/App.app/App');

    expect(elfEntry?.executableType).toBe('ELF');
    expect(dexEntry?.executableType).toBe('DEX');
    expect(classEntry?.executableType).toBe('Class');
    expect(machoEntry?.executableType).toBe('Mach-O');
  });

  it('should parse and extract from nested archives (ZIP in ZIP)', () => {
    // 1. Create inner zip
    const innerContent = 'Nested file payload here';
    const innerZipBytes = createMockZip([
      { path: 'inner.txt', content: innerContent, compress: false },
    ]);

    // 2. Create outer zip containing the inner zip
    const outerZipBytes = createMockZip([
      { path: 'nested.zip', content: innerZipBytes, compress: true },
      { path: 'outer.txt', content: 'Outer file content', compress: false },
    ]);

    const unpacker = new ArchiveUnpacker(outerZipBytes);
    const entries = unpacker.listAllEntries();

    // Must find outer.txt, nested.zip, AND nested.zip/inner.txt
    expect(entries.some((e) => e.path === 'outer.txt')).toBe(true);
    expect(entries.some((e) => e.path === 'nested.zip')).toBe(true);
    expect(entries.some((e) => e.path === 'nested.zip/inner.txt')).toBe(true);

    const innerTxtEntry = entries.find((e) => e.path === 'nested.zip/inner.txt');
    expect(innerTxtEntry?.size).toBe(innerContent.length);

    // Extract nested file
    const extractedInner = unpacker.extractEntry('nested.zip/inner.txt');
    expect(new TextDecoder().decode(extractedInner)).toBe(innerContent);
  });
});
