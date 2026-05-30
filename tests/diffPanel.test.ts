// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { DiffPanel } from '../src/ui/diffPanel.js';

describe('DiffPanel UI Tests', () => {
  let container: HTMLElement;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should construct and initialize buttons', () => {
    const panel = new DiffPanel(container);
    const buttons = container.querySelectorAll('.btn-mode-toggle');
    // byte, instruction, trace
    expect(buttons.length).toBe(3);
    expect(buttons[0].textContent).toBe('Byte Diff');
    expect(buttons[1].textContent).toBe('Instruction Diff');
    expect(buttons[2].textContent).toBe('Trace Diff');
  });

  it('should support switching modes', () => {
    const panel = new DiffPanel(container);
    const buttons = container.querySelectorAll('.btn-mode-toggle');

    // Switch to instruction mode
    (buttons[1] as HTMLButtonElement).click();
    expect(buttons[0].classList.contains('active')).toBe(false);
    expect(buttons[1].classList.contains('active')).toBe(true);

    // Switch to trace mode
    (buttons[2] as HTMLButtonElement).click();
    expect(buttons[1].classList.contains('active')).toBe(false);
    expect(buttons[2].classList.contains('active')).toBe(true);
  });

  it('should render trace diff execution step pairs side-by-side', () => {
    const panel = new DiffPanel(container);
    const primaryData = new Uint8Array([0x90, 0x90]);
    const secondaryData = new Uint8Array([0x90, 0x90]);

    const insts1 = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        size: 1,
      },
    ];

    const insts2 = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        size: 1,
      },
    ];

    // Load data
    panel.updateData(primaryData, [], insts1, 'Primary', 0x1000);

    // Mock drop/file load internally
    (panel as any).binaryData2 = secondaryData;
    (panel as any).sections2 = [];
    (panel as any).instructions2 = insts2;
    (panel as any).entryPoint2 = 0x1000;
    (panel as any).fileName2 = 'Secondary';

    // Switch to trace diff
    (panel as any).switchMode('trace');

    // Verify side-by-side panels are rendered
    const paneLeft = container.querySelector('#diff-pane-left');
    const paneRight = container.querySelector('#diff-pane-right');
    expect(paneLeft).not.toBeNull();
    expect(paneRight).not.toBeNull();

    // Verify trace steps
    const rowL = paneLeft?.querySelector('.diff-row');
    const rowR = paneRight?.querySelector('.diff-row');
    expect(rowL?.textContent).toContain('Step 0');
    expect(rowR?.textContent).toContain('Step 0');
  });
});
