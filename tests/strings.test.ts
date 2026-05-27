import { describe, it, expect } from 'vitest';
import { extractStrings, isFilePath, isApiName, isUrl } from '../src/analyzer/strings.js';

describe('String Analyzer Helper Tests', () => {
  it('should identify file paths correctly', () => {
    expect(isFilePath('C:\\Windows\\System32\\kernel32.dll')).toBe(true);
    expect(isFilePath('/usr/bin/sudo')).toBe(true);
    expect(isFilePath('/etc/passwd')).toBe(true);
    expect(isFilePath('libnative.so')).toBe(true);
    expect(isFilePath('config.ini')).toBe(true);
    expect(isFilePath('not_a_path')).toBe(false);
  });

  it('should identify API names correctly', () => {
    expect(isApiName('GetProcAddress')).toBe(true);
    expect(isApiName('VirtualAlloc')).toBe(true);
    expect(isApiName('malloc')).toBe(true);
    expect(isApiName('CreateFileW')).toBe(true);
    expect(isApiName('memcpy')).toBe(true);
    expect(isApiName('not-an-api')).toBe(false);
    expect(isApiName('123api')).toBe(false);
  });

  it('should identify URLs correctly', () => {
    expect(isUrl('http://example.com')).toBe(true);
    expect(isUrl('https://google.com/search?q=test')).toBe(true);
    expect(isUrl('ftp://ftp.test.org/file.zip')).toBe(true);
    expect(isUrl('not_a_url.com')).toBe(false);
  });
});

describe('String Extraction Core Tests', () => {
  it('should successfully extract ASCII strings from buffer', () => {
    // Construct buffer with: [garbage, 'Hello', 0, 'World', 0]
    const encoder = new TextEncoder();
    const hello = encoder.encode('Hello');
    const world = encoder.encode('World');
    
    const buffer = new Uint8Array(hello.length + 1 + world.length + 1 + 2);
    // Garbage
    buffer[0] = 0x01;
    buffer[1] = 0x02;
    // Hello
    buffer.set(hello, 2);
    buffer[hello.length + 2] = 0x00; // Null terminator
    // World
    buffer.set(world, hello.length + 3);
    buffer[hello.length + 3 + world.length] = 0x00; // Null terminator

    const extracted = extractStrings(buffer, { minLength: 4 });
    
    expect(extracted).toHaveLength(2);
    expect(extracted[0]).toMatchObject({
      value: 'Hello',
      offset: 2,
      encoding: 'ascii',
    });
    expect(extracted[1]).toMatchObject({
      value: 'World',
      offset: 8,
      encoding: 'ascii',
    });
  });

  it('should respect minLength option', () => {
    const encoder = new TextEncoder();
    const test1 = encoder.encode('abc'); // Length 3
    const test2 = encoder.encode('abcde'); // Length 5
    
    const buffer = new Uint8Array(10);
    buffer.set(test1, 0);
    buffer.set(test2, 4);

    const extracted3 = extractStrings(buffer, { minLength: 3, utf16le: false, utf16be: false });
    expect(extracted3.map(e => e.value)).toContain('abc');
    expect(extracted3.map(e => e.value)).toContain('abcde');

    const extracted4 = extractStrings(buffer, { minLength: 4, utf16le: false, utf16be: false });
    expect(extracted4.map(e => e.value)).not.toContain('abc');
    expect(extracted4.map(e => e.value)).toContain('abcde');
  });

  it('should extract UTF-16LE and UTF-16BE strings', () => {
    // Construct a UTF-16LE string "Hello"
    const utf16leBytes = new Uint8Array([
      0x48, 0x00, // H
      0x65, 0x00, // e
      0x6c, 0x00, // l
      0x6c, 0x00, // l
      0x6f, 0x00, // o
      0x00, 0x00  // null
    ]);

    // Construct a UTF-16BE string "World"
    const utf16beBytes = new Uint8Array([
      0x00, 0x57, // W
      0x00, 0x6f, // o
      0x00, 0x72, // r
      0x00, 0x6c, // l
      0x00, 0x64, // d
      0x00, 0x00  // null
    ]);

    const buffer = new Uint8Array(utf16leBytes.length + utf16beBytes.length);
    buffer.set(utf16leBytes, 0);
    buffer.set(utf16beBytes, utf16leBytes.length);

    const extracted = extractStrings(buffer, { minLength: 4, ascii: false });
    
    const leString = extracted.find(e => e.encoding === 'utf16le');
    const beString = extracted.find(e => e.encoding === 'utf16be');

    expect(leString).toBeDefined();
    expect(leString?.value).toBe('Hello');
    expect(leString?.offset).toBe(0);

    expect(beString).toBeDefined();
    expect(beString?.value).toBe('World');
    expect(beString?.offset).toBe(utf16leBytes.length);
  });

  it('should map virtual addresses using baseAddress and sections', () => {
    const encoder = new TextEncoder();
    const str = encoder.encode('MySecretString');
    const buffer = new Uint8Array(100);
    buffer.set(str, 40);

    // Test with baseAddress default/custom
    const extBase = extractStrings(buffer, { baseAddress: 0x1000, utf16le: false, utf16be: false });
    expect(extBase[0].virtualAddress).toBe(0x1000 + 40);

    // Test with section mapping
    const sections = [
      {
        name: '.rodata',
        fileOffset: 30,
        fileSize: 30,
        virtualAddress: 0x400000,
      }
    ];

    const extSec = extractStrings(buffer, {
      baseAddress: 0x1000,
      sections,
      utf16le: false,
      utf16be: false,
    });
    
    // Offset 40 falls inside [30, 60), so it should be mapped to 0x400000 + (40 - 30) = 0x40000a
    expect(extSec[0].virtualAddress).toBe(0x400000 + 10);
  });

  it('should tag special strings appropriately', () => {
    const encoder = new TextEncoder();
    const url = encoder.encode('https://github.com');
    const api = encoder.encode('GetProcAddress');
    const path = encoder.encode('/usr/bin/env');
    const plain = encoder.encode('JustAPlainString');

    const buffer = new Uint8Array(200);
    buffer.set(url, 0);
    buffer.set(api, 50);
    buffer.set(path, 100);
    buffer.set(plain, 150);

    const extracted = extractStrings(buffer, { utf16le: false, utf16be: false });

    const urlItem = extracted.find(e => e.value.startsWith('https'));
    const apiItem = extracted.find(e => e.value === 'GetProcAddress');
    const pathItem = extracted.find(e => e.value === '/usr/bin/env');
    const plainItem = extracted.find(e => e.value === 'JustAPlainString');

    expect(urlItem?.tags).toContain('url');
    expect(apiItem?.tags).toContain('api');
    expect(pathItem?.tags).toContain('filepath');
    expect(plainItem?.tags).toEqual([]);
  });
});
