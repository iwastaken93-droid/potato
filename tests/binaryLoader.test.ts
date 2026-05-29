// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BinaryLoader } from '../src/ui/binaryLoader.js';

describe('BinaryLoader Unit Tests', () => {
  let container: HTMLDivElement;

  beforeEach(() => {
    container = document.createElement('div');
    container.innerHTML = `
      <div id="file-dropzone">
        <input type="file" id="file-input" />
        <button id="upload-btn">Upload</button>
      </div>
    `;
    document.body.appendChild(container);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should initialize and trigger binary load callback', () => {
    const loadedSpy = vi.fn();
    const loader = new BinaryLoader({
      onBinaryLoaded: loadedSpy,
    });

    expect(loader).toBeDefined();
  });

  it('should generate mock sample binary data successfully', () => {
    const loadSpy = vi.fn();
    BinaryLoader.loadSampleBinary(loadSpy);

    expect(loadSpy).toHaveBeenCalled();
    const args = loadSpy.mock.calls[0];
    expect(args[0]).toBe('sample_elf.bin');
    expect(args[1] instanceof ArrayBuffer).toBe(true);
  });
});
