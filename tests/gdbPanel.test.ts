// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { GDBPanel } from '../src/ui/gdbPanel.js';
import type { Instruction, Section } from '../src/disassembler/types.js';

// Define globally required mocks for JSDOM
if (typeof global.ResizeObserver === 'undefined') {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

describe('GDBPanel Unit Tests', () => {
  let container: HTMLElement;
  let onNavigateMock: any;
  let onStepMock: any;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    onNavigateMock = vi.fn();
    onStepMock = vi.fn();
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.restoreAllMocks();
  });

  it('should initialize and render layout correctly', () => {
    const panel = new GDBPanel(container, {
      onNavigate: onNavigateMock,
      onStep: onStepMock,
    });

    // Verify basic DOM elements are rendered
    expect(container.querySelector('.gdb-panel-root')).not.toBeNull();
    expect(container.querySelector('#gdb-step-btn')).not.toBeNull();
    expect(container.querySelector('#gdb-continue-btn')).not.toBeNull();
    expect(container.querySelector('#gdb-reset-btn')).not.toBeNull();
    expect(container.querySelector('#gdb-console-log')).not.toBeNull();
    expect(container.querySelector('#gdb-command-input')).not.toBeNull();
    expect(container.querySelector('#gdb-send-btn')).not.toBeNull();
    expect(container.querySelector('#gdb-reg-grid')).not.toBeNull();
    expect(container.querySelector('#gdb-mem-addr')).not.toBeNull();
    expect(container.querySelector('#gdb-mem-len')).not.toBeNull();
    expect(container.querySelector('#gdb-mem-dump')).not.toBeNull();

    // Verify displays connection status
    const rootText = container.querySelector('.gdb-controls')?.textContent;
    expect(rootText).toContain('GDB Status:');
    expect(rootText).toContain('RSP SIMULATOR ACTIVE');
  });

  it('should initialize emulator state and render registers and memory on updateData', () => {
    const panel = new GDBPanel(container, {
      onNavigate: onNavigateMock,
      onStep: onStepMock,
    });

    const binaryData = new Uint8Array([0x48, 0x89, 0xc0]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 3,
        fileOffset: 0,
        fileSize: 3,
        flags: { read: true, write: false, execute: true },
      },
    ];
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x48, 0x89, 0xc0]),
        mnemonic: 'mov',
        opStr: 'rax, rax',
        operands: [
          { type: 'reg', reg: 'rax', access: 'w' },
          { type: 'reg', reg: 'rax', access: 'r' },
        ],
        size: 3,
      },
    ];

    panel.updateData(binaryData, sections, 0x1000, instructions);

    // After updating data, standard handshake is sent, registers and memory should render
    const regGrid = container.querySelector('#gdb-reg-grid') as HTMLDivElement;
    expect(regGrid.children.length).toBeGreaterThan(0);

    // Verify rip register shows the correct initial entry point
    const ripBox = Array.from(regGrid.children).find(
      (child) => child.querySelector('.gdb-reg-name')?.textContent === 'rip'
    );
    expect(ripBox).not.toBeUndefined();
    expect(ripBox?.querySelector('.gdb-reg-value')?.textContent).toBe('0x1000');

    // Verify memory display reads address 0x1000
    const memDump = container.querySelector('#gdb-mem-dump') as HTMLDivElement;
    expect(memDump.textContent).toContain('0x00001000:');
    // First byte at 0x1000 is 0x48
    expect(memDump.textContent).toContain('48');
  });

  it('should allow inputting and sending commands/packets via console log UI', () => {
    const panel = new GDBPanel(container, {
      onNavigate: onNavigateMock,
      onStep: onStepMock,
    });

    const input = container.querySelector(
      '#gdb-command-input'
    ) as HTMLInputElement;
    const sendBtn = container.querySelector(
      '#gdb-send-btn'
    ) as HTMLButtonElement;
    const consoleLog = container.querySelector(
      '#gdb-console-log'
    ) as HTMLDivElement;

    // Send simple raw command without '$'
    input.value = 'qSupported';
    sendBtn.click();

    // Verify that the packet transaction is rendered in log
    const consoleContent = consoleLog.innerHTML;
    expect(consoleContent).toContain('qSupported');
    expect(consoleContent).toContain('PacketSize');

    // Send packet format with '$'
    input.value = '$?#3f';
    sendBtn.click();

    // The protocol parser should receive this and trigger response stop reason S05
    expect(consoleLog.textContent).toContain('RSP Stream Parser output');
    expect(consoleLog.textContent).toContain('S05');
  });

  it('should handle toolbar button interactions (Step, Continue, Reset)', () => {
    const panel = new GDBPanel(container, {
      onNavigate: onNavigateMock,
      onStep: onStepMock,
    });

    // Provide target reset setup
    const binaryData = new Uint8Array([0x48, 0x89, 0xc0, 0x48, 0x89, 0xc0]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 6,
        fileOffset: 0,
        fileSize: 6,
        flags: { read: true, write: false, execute: true },
      },
    ];
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x48, 0x89, 0xc0]),
        mnemonic: 'mov',
        opStr: 'rax, rax',
        operands: [
          { type: 'reg', reg: 'rax', access: 'w' },
          { type: 'reg', reg: 'rax', access: 'r' },
        ],
        size: 3,
      },
      {
        address: 0x1003,
        bytes: new Uint8Array([0x48, 0x89, 0xc0]),
        mnemonic: 'mov',
        opStr: 'rax, rax',
        operands: [
          { type: 'reg', reg: 'rax', access: 'w' },
          { type: 'reg', reg: 'rax', access: 'r' },
        ],
        size: 3,
      },
    ];

    panel.updateData(binaryData, sections, 0x1000, instructions);

    const stepBtn = container.querySelector(
      '#gdb-step-btn'
    ) as HTMLButtonElement;
    const contBtn = container.querySelector(
      '#gdb-continue-btn'
    ) as HTMLButtonElement;
    const resetBtn = container.querySelector(
      '#gdb-reset-btn'
    ) as HTMLButtonElement;

    // Click Step
    stepBtn.click();
    expect(onStepMock).toHaveBeenCalled();
    // rip should advance from 0x1000 to 0x1003 (size of mov is 3)
    const ripBoxStep = Array.from(
      container.querySelector('#gdb-reg-grid')!.children
    ).find(
      (child) => child.querySelector('.gdb-reg-name')?.textContent === 'rip'
    );
    expect(ripBoxStep?.querySelector('.gdb-reg-value')?.textContent).toBe(
      '0x1003'
    );

    // Click Reset
    resetBtn.click();
    // Verify reset message is logged
    const consoleLog = container.querySelector(
      '#gdb-console-log'
    ) as HTMLDivElement;
    expect(consoleLog.textContent).toContain('Target Reset');

    // Click Continue
    contBtn.click();
    expect(consoleLog.textContent).toContain('-> $c#63');
  });

  it('should support modifying register values via prompt click', () => {
    const panel = new GDBPanel(container, {
      onNavigate: onNavigateMock,
      onStep: onStepMock,
    });

    const binaryData = new Uint8Array([0x48, 0x89, 0xc0]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 3,
        fileOffset: 0,
        fileSize: 3,
        flags: { read: true, write: false, execute: true },
      },
    ];
    panel.updateData(binaryData, sections, 0x1000, []);

    const regGrid = container.querySelector('#gdb-reg-grid') as HTMLDivElement;
    const raxBox = Array.from(regGrid.children).find(
      (child) => child.querySelector('.gdb-reg-name')?.textContent === 'rax'
    ) as HTMLDivElement;
    expect(raxBox).not.toBeUndefined();

    // Mock prompt
    const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('0x1234');
    raxBox.click();

    expect(promptSpy).toHaveBeenCalled();
    // rax value should now be set to 0x1234 - find it in the re-rendered DOM
    const updatedRaxBox = Array.from(
      container.querySelector('#gdb-reg-grid')!.children
    ).find(
      (child) => child.querySelector('.gdb-reg-name')?.textContent === 'rax'
    ) as HTMLDivElement;
    expect(updatedRaxBox.querySelector('.gdb-reg-value')?.textContent).toBe(
      '0x1234'
    );
  });
});
