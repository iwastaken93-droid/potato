// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BinaryPatcher } from '../src/analyzer/patcher.js';
import { PatcherPanel } from '../src/ui/patcherPanel.js';
import type { Section } from '../src/disassembler/types.js';

describe('BinaryPatcher Unit Tests', () => {
  let originalBinary: Uint8Array;
  let patcher: BinaryPatcher;

  beforeEach(() => {
    originalBinary = new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50]);
    patcher = new BinaryPatcher(originalBinary);
  });

  it('should initialize with correct binary data and empty history', () => {
    expect(patcher.getOriginalBinary()).toEqual(originalBinary);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);
    expect(patcher.getHistory()).toEqual([]);
  });

  it('should apply patch within bounds', () => {
    const record = patcher.applyPatch(
      1,
      new Uint8Array([0x99, 0x98]),
      0x1001,
      'test patch'
    );
    expect(record.offset).toBe(1);
    expect(record.address).toBe(0x1001);
    expect(record.description).toBe('test patch');
    expect(record.active).toBe(true);
    expect(record.originalBytes).toEqual(new Uint8Array([0x20, 0x30]));
    expect(record.patchedBytes).toEqual(new Uint8Array([0x99, 0x98]));

    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x99, 0x98, 0x40, 0x50])
    );
    expect(patcher.getHistory().length).toBe(1);
  });

  it('should throw error when patch is out of bounds', () => {
    expect(() => {
      patcher.applyPatch(
        4,
        new Uint8Array([0x99, 0x98]),
        0x1004,
        'out of bounds'
      );
    }).toThrow(/out of bounds/i);

    expect(() => {
      patcher.applyPatch(-1, new Uint8Array([0x99]), 0x0fff, 'out of bounds');
    }).toThrow();
  });

  it('should toggle patch active status', () => {
    const record = patcher.applyPatch(
      1,
      new Uint8Array([0x99]),
      0x1001,
      'toggle test'
    );
    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x99, 0x30, 0x40, 0x50])
    );

    const toggled = patcher.togglePatch(record.id);
    expect(toggled).toBe(true);
    expect(record.active).toBe(false);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);

    patcher.togglePatch(record.id);
    expect(record.active).toBe(true);
    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x99, 0x30, 0x40, 0x50])
    );
  });

  it('should return false when toggling or removing non-existent patch', () => {
    expect(patcher.togglePatch('non_existent')).toBe(false);
    expect(patcher.removePatch('non_existent')).toBe(false);
  });

  it('should remove patch from history', () => {
    const record1 = patcher.applyPatch(1, new Uint8Array([0x99]), 0x1001, 'p1');
    const record2 = patcher.applyPatch(3, new Uint8Array([0x88]), 0x1003, 'p2');
    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x99, 0x30, 0x88, 0x50])
    );

    const removed = patcher.removePatch(record1.id);
    expect(removed).toBe(true);
    expect(patcher.getHistory().length).toBe(1);
    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x20, 0x30, 0x88, 0x50])
    );
  });

  it('should clear all patches', () => {
    patcher.applyPatch(1, new Uint8Array([0x99]), 0x1001, 'p1');
    patcher.applyPatch(3, new Uint8Array([0x88]), 0x1003, 'p2');
    patcher.clearAll();
    expect(patcher.getHistory().length).toBe(0);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);
  });

  it('should support subscribe and unsubscribe listeners', () => {
    const listener = vi.fn();
    const unsubscribe = patcher.subscribe(listener);

    patcher.applyPatch(0, new Uint8Array([0xaa]), 0x1000, 'notify test');
    expect(listener).toHaveBeenCalledTimes(1);
    expect(listener).toHaveBeenCalledWith(
      patcher.getPatchedBinary(),
      patcher.getHistory()
    );

    unsubscribe();
    patcher.clearAll();
    expect(listener).toHaveBeenCalledTimes(1); // No new invocation
  });

  it('should parse hex and assembly input correctly via parseInput', () => {
    // Hex parsing
    expect(BinaryPatcher.parseInput('90 90')).toEqual(
      new Uint8Array([0x90, 0x90])
    );
    expect(BinaryPatcher.parseInput('9090')).toEqual(
      new Uint8Array([0x90, 0x90])
    );
    expect(BinaryPatcher.parseInput('\\x90\\x90')).toEqual(
      new Uint8Array([0x90, 0x90])
    );
    expect(BinaryPatcher.parseInput('0x90, 0x90')).toEqual(
      new Uint8Array([0x90, 0x90])
    );

    // Assembly translation for x86_64
    expect(BinaryPatcher.parseInput('nop', 'x86_64')).toEqual(
      new Uint8Array([0x90])
    );
    expect(BinaryPatcher.parseInput('ret', 'x86_64')).toEqual(
      new Uint8Array([0xc3])
    );
    expect(BinaryPatcher.parseInput('int3', 'x86_64')).toEqual(
      new Uint8Array([0xcc])
    );
    expect(BinaryPatcher.parseInput('xor eax, eax', 'x86_64')).toEqual(
      new Uint8Array([0x31, 0xc0])
    );
    expect(BinaryPatcher.parseInput('jmp 0x1000', 'x86_64')).toEqual(
      new Uint8Array([0xeb, 0xfe])
    );

    // Edge cases and errors
    expect(() => BinaryPatcher.parseInput('')).toThrow(/empty/i);
    expect(() => BinaryPatcher.parseInput('909')).toThrow(/length/i);
    expect(() =>
      BinaryPatcher.parseInput('invalid_instruction', 'x86_64')
    ).toThrow(/character/i);
  });

  it('should mock exportBinary click and URL calls', () => {
    const createObjectURLMock = vi.fn().mockReturnValue('blob:foo');
    const revokeObjectURLMock = vi.fn();
    global.URL.createObjectURL = createObjectURLMock;
    global.URL.revokeObjectURL = revokeObjectURLMock;

    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => {});

    patcher.exportBinary('test.bin');

    expect(createObjectURLMock).toHaveBeenCalled();
    expect(clickSpy).toHaveBeenCalled();
    expect(revokeObjectURLMock).toHaveBeenCalled();
  });

  it('should support undo and redo operations and transaction log tracking', () => {
    expect(patcher.canUndo()).toBe(false);
    expect(patcher.canRedo()).toBe(false);
    expect(patcher.getTransactionLog()).toEqual([]);

    const record1 = patcher.applyPatch(1, new Uint8Array([0x99]), 0x1001, 'p1');
    expect(patcher.canUndo()).toBe(true);
    expect(patcher.canRedo()).toBe(false);
    expect(patcher.getTransactionLog().length).toBe(1);
    expect(patcher.getTransactionLog()[0].type).toBe('apply');
    expect(patcher.getTransactionLog()[0].patchId).toBe(record1.id);
    expect(patcher.getPatchedBinary()).toEqual(new Uint8Array([0x10, 0x99, 0x30, 0x40, 0x50]));

    patcher.togglePatch(record1.id);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);
    expect(patcher.getTransactionLog().length).toBe(2);
    expect(patcher.getTransactionLog()[1].type).toBe('toggle');

    expect(patcher.undo()).toBe(true);
    expect(patcher.getPatchedBinary()).toEqual(new Uint8Array([0x10, 0x99, 0x30, 0x40, 0x50]));
    expect(patcher.canRedo()).toBe(true);

    expect(patcher.redo()).toBe(true);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);

    expect(patcher.undo()).toBe(true);
    expect(patcher.undo()).toBe(true);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);
    expect(patcher.canUndo()).toBe(false);

    expect(patcher.redo()).toBe(true);
    expect(patcher.redo()).toBe(true);
    expect(patcher.getPatchedBinary()).toEqual(originalBinary);

    expect(patcher.undo()).toBe(true);
    expect(patcher.canRedo()).toBe(true);
    patcher.applyPatch(3, new Uint8Array([0x88]), 0x1003, 'p2');
    expect(patcher.canRedo()).toBe(false);
  });
});

describe('PatcherPanel Unit Tests', () => {
  let container: HTMLElement;
  let patcher: BinaryPatcher;
  let panel: PatcherPanel;
  let onPatchAppliedMock: any;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);

    patcher = new BinaryPatcher(
      new Uint8Array([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
    );
    onPatchAppliedMock = vi.fn();

    panel = new PatcherPanel(container, patcher, {
      onPatchApplied: onPatchAppliedMock,
      architecture: 'x86_64',
      filename: 'test.bin',
    });
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should initialize panel layout and status text', () => {
    const statusText = container.querySelector('#patcher-status-text');
    expect(statusText?.textContent).toContain('Ready to patch');

    const applyBtn = container.querySelector('#patcher-apply-btn');
    expect(applyBtn).not.toBeNull();
  });

  it('should support updating state via updateData', () => {
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 8,
        fileOffset: 0,
        fileSize: 8,
        flags: { read: true, write: false, execute: true },
        entropy: 1.0,
      },
    ];
    panel.updateData(sections, 'updated.bin', 'arm');
    const statusText = container.querySelector('#patcher-status-text');
    expect(statusText?.textContent).toContain('updated.bin');
    expect(statusText?.textContent).toContain('arm');
  });

  it('should populate address field via setTargetAddress', () => {
    panel.setTargetAddress(0x1004);
    const addrInput = container.querySelector(
      '#patch-addr-input'
    ) as HTMLInputElement;
    expect(addrInput.value).toBe('0x1004');
  });

  it('should apply patch through UI interactions', () => {
    const addrInput = container.querySelector(
      '#patch-addr-input'
    ) as HTMLInputElement;
    const bytesInput = container.querySelector(
      '#patch-bytes-input'
    ) as HTMLInputElement;
    const descInput = container.querySelector(
      '#patch-desc-input'
    ) as HTMLInputElement;
    const applyBtn = container.querySelector(
      '#patcher-apply-btn'
    ) as HTMLButtonElement;

    addrInput.value = '0x2';
    bytesInput.value = '90 90';
    descInput.value = 'ui patch';

    applyBtn.click();

    expect(onPatchAppliedMock).toHaveBeenCalledTimes(1);
    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x20, 0x90, 0x90, 0x50, 0x60, 0x70, 0x80])
    );

    // Check that patch history is rendered
    const historyList = container.querySelector('#patch-history-list');
    expect(historyList?.textContent).toContain('Address: 0x2');
    expect(historyList?.textContent).toContain('ui patch');
  });

  it('should apply patch with virtual address to file offset translation', () => {
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 8,
        fileOffset: 2,
        fileSize: 4,
        flags: { read: true, write: false, execute: true },
        entropy: 1.0,
      },
    ];
    panel.updateData(sections, 'test.bin', 'x86_64');

    const addrInput = container.querySelector(
      '#patch-addr-input'
    ) as HTMLInputElement;
    const bytesInput = container.querySelector(
      '#patch-bytes-input'
    ) as HTMLInputElement;
    const applyBtn = container.querySelector(
      '#patcher-apply-btn'
    ) as HTMLButtonElement;

    addrInput.value = '0x1001'; // Should map to fileOffset 2 - 0x1000 + 0x1001 = fileOffset 3
    bytesInput.value = 'AA';

    applyBtn.click();

    expect(patcher.getPatchedBinary()).toEqual(
      new Uint8Array([0x10, 0x20, 0x30, 0xaa, 0x50, 0x60, 0x70, 0x80])
    );
  });

  it('should alert on validation failures during apply', () => {
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
    const applyBtn = container.querySelector(
      '#patcher-apply-btn'
    ) as HTMLButtonElement;

    // Empty address
    applyBtn.click();
    expect(alertSpy).toHaveBeenCalledWith(
      expect.stringContaining('Please specify a target address')
    );

    // Empty bytes
    const addrInput = container.querySelector(
      '#patch-addr-input'
    ) as HTMLInputElement;
    addrInput.value = '0x0';
    applyBtn.click();
    expect(alertSpy).toHaveBeenCalledWith(
      expect.stringContaining('Please specify instruction or hex bytes')
    );

    // Invalid input parsing
    const bytesInput = container.querySelector(
      '#patch-bytes-input'
    ) as HTMLInputElement;
    bytesInput.value = 'invalid';
    applyBtn.click();
    expect(alertSpy).toHaveBeenCalledWith(
      expect.stringContaining('Failed to apply patch')
    );

    alertSpy.mockRestore();
  });

  it('should support interactive history toggle and remove buttons', () => {
    patcher.applyPatch(0, new Uint8Array([0xaa]), 0x0, 'desc');
    panel = new PatcherPanel(container, patcher, {
      onPatchApplied: onPatchAppliedMock,
      architecture: 'x86_64',
      filename: 'test.bin',
    });

    const historyList = container.querySelector(
      '#patch-history-list'
    ) as HTMLDivElement;

    // Test toggle click
    const toggleBtn = historyList.querySelector(
      '.toggle-btn'
    ) as HTMLButtonElement;
    toggleBtn.click();
    expect(onPatchAppliedMock).toHaveBeenCalled();
    expect(patcher.getHistory()[0].active).toBe(false);

    // Test remove click
    const removeBtn = historyList.querySelector(
      '.patch-btn-danger'
    ) as HTMLButtonElement;
    removeBtn.click();
    expect(patcher.getHistory().length).toBe(0);
  });

  it('should clear all patches on clear button click', () => {
    patcher.applyPatch(0, new Uint8Array([0xaa]), 0x0, 'desc');
    panel = new PatcherPanel(container, patcher, {
      onPatchApplied: onPatchAppliedMock,
      architecture: 'x86_64',
      filename: 'test.bin',
    });

    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
    const clearBtn = container.querySelector(
      '#patcher-clear-btn'
    ) as HTMLButtonElement;
    clearBtn.click();

    expect(confirmSpy).toHaveBeenCalled();
    expect(patcher.getHistory().length).toBe(0);
    expect(onPatchAppliedMock).toHaveBeenCalled();
    confirmSpy.mockRestore();
  });
});
