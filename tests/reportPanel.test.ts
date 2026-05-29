// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ReportPanel } from '../src/ui/reportPanel.js';
import type { Section, Symbol } from '../src/disassembler/types.js';
import type { ExtractedString } from '../src/analyzer/strings.js';

describe('ReportPanel Unit Tests', () => {
  let container: HTMLElement;
  let panel: ReportPanel;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new ReportPanel(container);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should render the initial structure', () => {
    const root = container.querySelector('.report-panel-root');
    expect(root).not.toBeNull();
    expect(container.textContent).toContain('Please load a binary');
  });

  it('should update data and render interactive preview by default', () => {
    const binaryData = new Uint8Array([0x90, 0x90]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 1024,
        fileOffset: 0,
        fileSize: 1024,
        flags: { read: true, write: false, execute: true },
        entropy: 4.5,
      },
    ];
    const symbols: Symbol[] = [
      {
        name: 'main',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 16,
      },
    ];
    const strings: ExtractedString[] = [
      {
        offset: 0,
        virtualAddress: 0x1000,
        encoding: 'ascii',
        tags: ['path'],
        value: '/bin/sh',
      },
    ];

    panel.updateData(
      'test.bin',
      2,
      binaryData,
      'x86_64',
      0x1000,
      sections,
      symbols,
      strings
    );

    // Should display file metadata
    expect(container.textContent).toContain('test.bin');
    expect(container.textContent).toContain('X86_64');
    expect(container.textContent).toContain('.text');
    expect(container.textContent).toContain('main');
    expect(container.textContent).toContain('/bin/sh');
  });

  it('should switch preview modes via preview method', () => {
    const binaryData = new Uint8Array([0x90, 0x90]);
    panel.updateData('test.bin', 2, binaryData, 'x86_64', 0x1000, [], [], []);

    // Switch to markdown view
    panel.preview('markdown');
    expect(
      container.querySelector('.markdown-preview-container')
    ).not.toBeNull();

    // Switch to json view
    panel.preview('json');
    expect(container.querySelector('.json-preview-container')).not.toBeNull();
  });

  it('should trigger download when downloadJSON and downloadMarkdown are called', () => {
    const binaryData = new Uint8Array([0x90, 0x90]);
    panel.updateData('test.bin', 2, binaryData, 'x86_64', 0x1000, [], [], []);

    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {});

    panel.downloadJSON();
    expect(clickSpy).toHaveBeenCalled();

    clickSpy.mockClear();

    panel.downloadMarkdown();
    expect(clickSpy).toHaveBeenCalled();
  });

  it('should copy to clipboard when copyToClipboard is called', async () => {
    const binaryData = new Uint8Array([0x90, 0x90]);
    panel.updateData('test.bin', 2, binaryData, 'x86_64', 0x1000, [], [], []);

    const writeTextSpy = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextSpy,
      },
    });

    panel.copyToClipboard();
    expect(writeTextSpy).toHaveBeenCalled();
  });
});
