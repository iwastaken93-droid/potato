// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  computeMD5,
  computeSHA1,
  computeSHA256,
} from '../src/analyzer/hashes.js';
import { MetadataPanel } from '../src/ui/metadataPanel.js';

describe('Cryptographic Hashes Unit Tests', () => {
  it('should compute MD5 correctly', () => {
    // Test empty input
    expect(computeMD5(new Uint8Array(0))).toBe(
      'd41d8cd98f00b204e9800998ecf8427e'
    );
    // Test 'abc'
    const abc = new Uint8Array([97, 98, 99]);
    expect(computeMD5(abc)).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('should compute SHA-1 correctly', () => {
    // Test empty input
    expect(computeSHA1(new Uint8Array(0))).toBe(
      'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    );
    // Test 'abc'
    const abc = new Uint8Array([97, 98, 99]);
    expect(computeSHA1(abc)).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
  });

  it('should compute SHA-256 correctly', () => {
    // Test empty input
    expect(computeSHA256(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    // Test 'abc'
    const abc = new Uint8Array([97, 98, 99]);
    expect(computeSHA256(abc)).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });
});

describe('MetadataPanel Unit Tests', () => {
  let container: HTMLElement;
  let panel: MetadataPanel;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new MetadataPanel(container);

    // Mock clipboard API
    if (!navigator.clipboard) {
      (navigator as any).clipboard = {
        writeText: vi.fn().mockImplementation(() => Promise.resolve()),
      };
    } else {
      vi.spyOn(navigator.clipboard, 'writeText').mockImplementation(() =>
        Promise.resolve()
      );
    }
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.clearAllMocks();
  });

  it('should render placeholders when no data is loaded', () => {
    const text = container.textContent;
    expect(text).toContain('No binary file loaded');
  });

  it('should render file details and metadata cards when data is updated', async () => {
    const testData = {
      fileName: 'test_binary.bin',
      fileSize: 1024,
      binaryData: new Uint8Array([0x4d, 0x5a, 0x90, 0x00]), // Dummy MZ header data
      architecture: 'x86_64',
      entryPoint: 0x1000,
      sectionsCount: 4,
      symbolsCount: 15,
      lastModified: 1716825600000, // Fixed date
    };

    panel.updateData(testData);

    // Verify stats exist
    expect(container.innerHTML).toContain('test_binary.bin');
    expect(container.innerHTML).toContain('1,024 B');
    expect(container.innerHTML).toContain('X86_64');
    expect(container.innerHTML).toContain('0x1000');

    // Wait for the async setTimeout hash calculations to execute
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Verify hashes are calculated and populated
    const md5Val = container
      .querySelector('[data-hash="md5"]')
      ?.parentElement?.querySelector('.meta-hash-value')
      ?.textContent?.trim();
    const sha1Val = container
      .querySelector('[data-hash="sha1"]')
      ?.parentElement?.querySelector('.meta-hash-value')
      ?.textContent?.trim();
    const sha256Val = container
      .querySelector('[data-hash="sha256"]')
      ?.parentElement?.querySelector('.meta-hash-value')
      ?.textContent?.trim();

    expect(md5Val).toBe(computeMD5(testData.binaryData));
    expect(sha1Val).toBe(computeSHA1(testData.binaryData));
    expect(sha256Val).toBe(computeSHA256(testData.binaryData));
  });

  it('should copy hash values to clipboard when copy button is clicked', async () => {
    const testData = {
      fileName: 'test.bin',
      fileSize: 3,
      binaryData: new Uint8Array([97, 98, 99]), // 'abc'
      architecture: 'elf',
      entryPoint: 0,
      sectionsCount: 1,
      symbolsCount: 0,
    };

    panel.updateData(testData);

    // Wait for hashes
    await new Promise((resolve) => setTimeout(resolve, 100));

    const copyBtn = container.querySelector(
      '[data-hash="md5"]'
    ) as HTMLButtonElement;
    expect(copyBtn).not.toBeNull();

    copyBtn.click();
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
      '900150983cd24fb0d6963f7d28e17f72'
    );
  });
});
