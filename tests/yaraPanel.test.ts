// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { YaraPanel } from '../src/ui/yaraPanel.js';
import type { Section } from '../src/disassembler/types.js';

describe('YaraPanel Unit Tests', () => {
  let container: HTMLElement;
  let panel: YaraPanel;
  const mockNavigate = vi.fn();

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new YaraPanel(container, { onNavigate: mockNavigate });
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.clearAllMocks();
  });

  it('should render the initial structure and default rules', () => {
    const root = container.querySelector('.yara-panel-root');
    expect(root).not.toBeNull();

    const editor = container.querySelector(
      '.yara-textarea'
    ) as HTMLTextAreaElement;
    expect(editor).not.toBeNull();
    expect(editor.value).toContain('rule Detect_MZ_Header');
    expect(editor.value).toContain('rule Common_Strings');
  });

  it('should import rules programmatically and update the UI', () => {
    const customRule = `rule TestImport {
      condition:
          true
    }`;
    panel.importRules(customRule);

    expect(panel.exportRules()).toBe(customRule);

    const editor = container.querySelector(
      '.yara-textarea'
    ) as HTMLTextAreaElement;
    expect(editor.value).toBe(customRule);
  });

  it('should export the current rules source correctly', () => {
    const editor = container.querySelector(
      '.yara-textarea'
    ) as HTMLTextAreaElement;
    const testRule = 'rule TestExport { condition: false }';
    editor.value = testRule;
    // Simulate typing trigger (input event)
    editor.dispatchEvent(new Event('input'));

    expect(panel.exportRules()).toBe(testRule);
  });

  it('should export compiled rules as serialized YARA rules string correctly', () => {
    const editor = container.querySelector(
      '.yara-textarea'
    ) as HTMLTextAreaElement;
    const testRule = `rule TestCompiledExport {
      meta:
          description = "Test meta"
      strings:
          $a = "test" ascii
      condition:
          $a
    }`;
    editor.value = testRule;
    editor.dispatchEvent(new Event('input'));
    
    // Trigger compilation by calling updateData or scan
    panel.updateData(new Uint8Array([0x74, 0x65, 0x73, 0x74]), []);

    const compiledStr = panel.exportCompiledRules();
    expect(compiledStr).toContain('rule TestCompiledExport {');
    expect(compiledStr).toContain('description = "Test meta"');
    expect(compiledStr).toContain('$a = "test" ascii');
    expect(compiledStr).toContain('condition:');
  });

  it('should trigger file input selection when import button is clicked', () => {
    const fileInput = container.querySelector(
      '#yara-file-input'
    ) as HTMLInputElement;
    const importBtn = container.querySelector(
      '#yara-import-btn'
    ) as HTMLButtonElement;

    expect(fileInput).not.toBeNull();
    expect(importBtn).not.toBeNull();

    const clickSpy = vi.spyOn(fileInput, 'click');
    importBtn.click();
    expect(clickSpy).toHaveBeenCalled();
  });

  it('should trigger browser download when export button is clicked', () => {
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {});
    const exportBtn = container.querySelector(
      '#yara-export-btn'
    ) as HTMLButtonElement;

    expect(exportBtn).not.toBeNull();
    exportBtn.click();
    expect(clickSpy).toHaveBeenCalled();
  });

  it('should compile and scan when binary data is updated', () => {
    const binaryData = new Uint8Array([0x4d, 0x5a, 0x00, 0x00]);
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

    panel.updateData(binaryData, sections);

    // Check compilation success message
    const compileStatus = container.querySelector('.yara-compile-status');
    expect(compileStatus?.textContent).toContain('Success');

    // Check that we have scan results containing rule name
    const results = container.querySelector('.yara-results-list');
    expect(results?.innerHTML).toContain('Detect_MZ_Header');
    expect(results?.innerHTML).toContain('MATCHED');
  });
});
