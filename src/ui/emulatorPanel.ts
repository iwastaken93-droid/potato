/**
 * Premium Emulator Panel UI Component
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides step controls, register display, stack view, and memory inspector.
 */

import { Emulator } from '../emulator/emulator.js';
import { Instruction, Section } from '../disassembler/types.js';

export interface EmulatorPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
  onStep?: (rip: number) => void;
}

export class EmulatorPanel {
  private container: HTMLElement;
  private options: EmulatorPanelOptions;
  private emulator: Emulator;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private regListEl!: HTMLDivElement;
  private stackListEl!: HTMLDivElement;
  private memInspectInput!: HTMLInputElement;
  private memContentEl!: HTMLDivElement;

  private stepBtn!: HTMLButtonElement;
  private runBtn!: HTMLButtonElement;
  private resetBtn!: HTMLButtonElement;
  private statusTextEl!: HTMLDivElement;

  private isRunningInterval: number | null = null;
  private lastInspectedMemoryAddr: bigint = 0x1000n;

  constructor(container: HTMLElement, options: EmulatorPanelOptions) {
    this.container = container;
    this.options = options;
    this.emulator = new Emulator();

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates emulator panel data, maps sections, and resets emulator state.
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    entryPoint: number,
    instructions: Instruction[]
  ) {
    this.stopRunning();
    this.emulator.reset(entryPoint);
    this.emulator.memory.loadSections(binaryData, sections);
    this.emulator.loadInstructions(instructions);

    this.updateUI();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'emulator-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject Styles if not already present
    if (!document.getElementById('emulator-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'emulator-panel-styles';
      style.textContent = `
        .emulator-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
          color: var(--text-primary);
          overflow-y: auto;
        }
        .emulator-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 1.5rem;
          height: calc(100% - 4.5rem);
          min-height: 0;
        }
        .emulator-column {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          min-height: 0;
        }
        .emulator-card {
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-height: 0;
        }
        .emulator-card-title {
          font-size: 0.875rem;
          font-weight: 600;
          color: var(--accent-start);
          text-transform: uppercase;
          letter-spacing: 0.05em;
          border-bottom: 1px solid rgba(255, 255, 255, 0.05);
          padding-bottom: 0.5rem;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .emulator-controls {
          display: flex;
          gap: 0.75rem;
          align-items: center;
          padding: 0.5rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: var(--radius-md);
        }
        .emu-btn {
          padding: 0.5rem 1rem;
          background: var(--btn-bg, rgba(255, 255, 255, 0.05));
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          color: var(--text-primary);
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .emu-btn:hover {
          background: rgba(255, 255, 255, 0.1);
          transform: translateY(-1px);
        }
        .emu-btn-primary {
          background: linear-gradient(135deg, var(--accent-start), var(--accent-end));
          border: none;
          color: white;
        }
        .emu-btn-primary:hover {
          filter: brightness(1.1);
        }
        .reg-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
          gap: 0.5rem;
          overflow-y: auto;
          flex-grow: 1;
        }
        .reg-box {
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: var(--radius-sm);
          padding: 0.35rem 0.5rem;
          display: flex;
          flex-direction: column;
          gap: 0.1rem;
          cursor: pointer;
          transition: border-color 0.2s;
        }
        .reg-box:hover {
          border-color: var(--accent-start);
          background: rgba(255, 255, 255, 0.04);
        }
        .reg-name {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        .reg-value {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          color: #e5c07b;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .stack-list {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
          overflow-y: auto;
          flex-grow: 1;
          font-family: var(--font-mono);
          font-size: 0.8rem;
        }
        .stack-item {
          display: grid;
          grid-template-columns: 80px 140px 1fr;
          padding: 0.25rem 0.5rem;
          background: rgba(255, 255, 255, 0.01);
          border-radius: 2px;
          border-left: 2px solid transparent;
        }
        .stack-item.rsp-pointed {
          border-left-color: var(--accent-start);
          background: rgba(var(--accent-start-rgb, 99, 102, 241), 0.1);
        }
        .stack-addr {
          color: var(--text-secondary);
        }
        .stack-val {
          color: #98c379;
        }
        .stack-desc {
          color: var(--text-muted);
          font-style: italic;
        }
        .mem-inspect-header {
          display: flex;
          gap: 0.5rem;
        }
        .mem-inspect-input {
          flex-grow: 1;
          background: rgba(0, 0, 0, 0.2);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          padding: 0.35rem 0.5rem;
          color: var(--text-primary);
          font-family: var(--font-mono);
          font-size: 0.85rem;
        }
        .mem-inspect-results {
          flex-grow: 1;
          overflow-y: auto;
          font-family: var(--font-mono);
          font-size: 0.8rem;
          background: rgba(0, 0, 0, 0.1);
          padding: 0.5rem;
          border-radius: var(--radius-sm);
          min-height: 100px;
        }
        .mem-inspect-line {
          display: flex;
          gap: 1rem;
          padding: 0.1rem 0;
        }
        .mem-inspect-addr {
          color: var(--accent-start);
          width: 80px;
        }
        .mem-inspect-bytes {
          color: var(--text-primary);
        }
        .mem-inspect-ascii {
          color: var(--text-secondary);
        }
      `;
      document.head.appendChild(style);
    }

    // Top control bar
    const controlsBar = document.createElement('div');
    controlsBar.className = 'emulator-controls';
    controlsBar.innerHTML = `
      <button class="emu-btn emu-btn-primary" id="emu-step-btn">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13 5l7 7-7 7M5 5l7 7-7 7"/>
        </svg> Step (F7)
      </button>
      <button class="emu-btn" id="emu-run-btn">
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
          <path d="M8 5v14l11-7z"/>
        </svg> Run
      </button>
      <button class="emu-btn" id="emu-reset-btn">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 7.89"/>
        </svg> Reset
      </button>
      <div id="emu-status-text" style="margin-left: auto; font-size: 0.8rem; color: var(--text-secondary);">
        Ready to emulate
      </div>
    `;
    this.rootEl.appendChild(controlsBar);

    // Main grid
    const mainGrid = document.createElement('div');
    mainGrid.className = 'emulator-grid';

    // Left Column: CPU Registers
    const leftCol = document.createElement('div');
    leftCol.className = 'emulator-column';
    leftCol.innerHTML = `
      <div class="emulator-card" style="flex-grow: 1;">
        <div class="emulator-card-title">
          <span>Registers (Double click to edit)</span>
        </div>
        <div class="reg-grid" id="emu-reg-grid"></div>
      </div>
    `;
    mainGrid.appendChild(leftCol);

    // Right Column: Stack & Memory
    const rightCol = document.createElement('div');
    rightCol.className = 'emulator-column';
    rightCol.innerHTML = `
      <div class="emulator-card" style="height: 50%;">
        <div class="emulator-card-title">
          <span>Stack View</span>
        </div>
        <div class="stack-list" id="emu-stack-list"></div>
      </div>
      <div class="emulator-card" style="height: 50%;">
        <div class="emulator-card-title">
          <span>Memory Inspector</span>
        </div>
        <div class="mem-inspect-header">
          <input type="text" class="mem-inspect-input" id="emu-mem-input" value="0x7fffffffd000" />
          <button class="emu-btn" id="emu-mem-inspect-btn">Inspect</button>
        </div>
        <div class="mem-inspect-results" id="emu-mem-content"></div>
      </div>
    `;
    mainGrid.appendChild(rightCol);

    this.rootEl.appendChild(mainGrid);
    this.container.appendChild(this.rootEl);

    // Cache elements
    this.regListEl = this.rootEl.querySelector(
      '#emu-reg-grid'
    ) as HTMLDivElement;
    this.stackListEl = this.rootEl.querySelector(
      '#emu-stack-list'
    ) as HTMLDivElement;
    this.memInspectInput = this.rootEl.querySelector(
      '#emu-mem-input'
    ) as HTMLInputElement;
    this.memContentEl = this.rootEl.querySelector(
      '#emu-mem-content'
    ) as HTMLDivElement;
    this.stepBtn = this.rootEl.querySelector(
      '#emu-step-btn'
    ) as HTMLButtonElement;
    this.runBtn = this.rootEl.querySelector(
      '#emu-run-btn'
    ) as HTMLButtonElement;
    this.resetBtn = this.rootEl.querySelector(
      '#emu-reset-btn'
    ) as HTMLButtonElement;
    this.statusTextEl = this.rootEl.querySelector(
      '#emu-status-text'
    ) as HTMLDivElement;
  }

  private setupEvents() {
    this.stepBtn.addEventListener('click', () => this.step());
    this.runBtn.addEventListener('click', () => this.toggleRun());
    this.resetBtn.addEventListener('click', () => {
      this.stopRunning();
      // Just step triggers RIP updates or resets
      const rip = this.emulator.cpu.read('rip');
      this.emulator.cpu.reset();
      this.emulator.cpu.write('rip', rip);
      this.updateUI();
    });

    const inspectBtn = this.rootEl.querySelector(
      '#emu-mem-inspect-btn'
    ) as HTMLButtonElement;
    inspectBtn.addEventListener('click', () => {
      try {
        const val = this.memInspectInput.value.trim();
        this.lastInspectedMemoryAddr = BigInt(
          val.startsWith('0x') ? val : '0x' + val
        );
        this.updateMemoryView();
      } catch {
        alert('Invalid memory address format');
      }
    });

    // Register double click to edit
    this.regListEl.addEventListener('dblclick', (e) => {
      const box = (e.target as HTMLElement).closest('.reg-box');
      if (!box) return;
      const reg = box.getAttribute('data-reg');
      if (!reg) return;

      const currentVal = this.emulator.cpu.read(reg);
      const newValStr = prompt(
        `Enter new value for ${reg.toUpperCase()} (hex or decimal):`,
        '0x' + currentVal.toString(16)
      );
      if (newValStr !== null) {
        try {
          const val = BigInt(
            newValStr.trim().startsWith('0x')
              ? newValStr.trim()
              : '0x' + newValStr.trim()
          );
          this.emulator.cpu.write(reg, val);
          this.updateUI();
        } catch {
          alert('Invalid value format');
        }
      }
    });
  }

  public step() {
    const rip = this.emulator.cpu.read('rip');
    const success = this.emulator.step();
    if (success) {
      const newRip = this.emulator.cpu.read('rip');
      this.statusTextEl.textContent = `Stepped to 0x${newRip.toString(16)}`;
      this.updateUI();
      if (this.options.onStep) {
        this.options.onStep(Number(newRip));
      }
    } else {
      this.stopRunning();
      this.statusTextEl.textContent = `Unable to execute instruction at 0x${rip.toString(16)}`;
    }
  }

  private toggleRun() {
    if (this.isRunningInterval) {
      this.stopRunning();
    } else {
      this.runBtn.innerHTML = `
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M10 9v6m4-6v6"/>
        </svg> Pause
      `;
      this.runBtn.classList.add('emu-btn-primary');
      this.statusTextEl.textContent = 'Running...';
      this.isRunningInterval = window.setInterval(() => {
        const rip = this.emulator.cpu.read('rip');
        const success = this.emulator.step();
        if (!success) {
          this.stopRunning();
          this.statusTextEl.textContent = `Stopped execution at 0x${rip.toString(16)}`;
          return;
        }
        // Check breakpoint
        const newRip = this.emulator.cpu.read('rip');
        if (this.emulator.breakpoints.has(Number(newRip))) {
          this.stopRunning();
          this.statusTextEl.textContent = `Breakpoint hit at 0x${newRip.toString(16)}`;
        }
        this.updateUI();
        if (this.options.onStep) {
          this.options.onStep(Number(newRip));
        }
      }, 100);
    }
  }

  private stopRunning() {
    if (this.isRunningInterval) {
      window.clearInterval(this.isRunningInterval);
      this.isRunningInterval = null;
    }
    this.runBtn.innerHTML = `
      <svg width="14" height="14" fill="currentColor" viewBox="0 0 24 24">
        <path d="M8 5v14l11-7z"/>
      </svg> Run
    `;
    this.runBtn.classList.remove('emu-btn-primary');
  }

  public updateUI() {
    this.updateRegisters();
    this.updateStack();
    this.updateMemoryView();
  }

  private updateRegisters() {
    this.regListEl.innerHTML = '';
    const state = this.emulator.cpu.getState();
    for (const [reg, val] of Object.entries(state)) {
      const box = document.createElement('div');
      box.className = 'reg-box';
      box.setAttribute('data-reg', reg);
      box.innerHTML = `
        <span class="reg-name">${reg.toUpperCase()}</span>
        <span class="reg-value" title="0x${val.toString(16)}">0x${val.toString(16)}</span>
      `;
      this.regListEl.appendChild(box);
    }
  }

  private updateStack() {
    this.stackListEl.innerHTML = '';
    const rsp = this.emulator.cpu.read('rsp');
    // Read 8 stack slots around RSP
    for (let i = -2; i < 10; i++) {
      const addr = rsp + BigInt(i * 8);
      const val = this.emulator.memory.read64(addr);

      const item = document.createElement('div');
      item.className = 'stack-item';
      if (addr === rsp) {
        item.className += ' rsp-pointed';
      }

      let desc = '';
      if (addr === rsp) desc = 'RSP';
      else if (addr === rsp + 8n) desc = 'RSP+8';
      else if (addr === rsp - 8n) desc = 'RSP-8';

      item.innerHTML = `
        <span class="stack-addr">0x${addr.toString(16)}</span>
        <span class="stack-val">0x${val.toString(16)}</span>
        <span class="stack-desc">${desc}</span>
      `;
      this.stackListEl.appendChild(item);
    }
  }

  private updateMemoryView() {
    this.memContentEl.innerHTML = '';
    const baseAddr = this.lastInspectedMemoryAddr;

    // Renders 8 lines of hex view
    for (let line = 0; line < 8; line++) {
      const addr = baseAddr + BigInt(line * 16);
      const lineBytes = this.emulator.memory.readBuffer(addr, 16);

      let hexStr = '';
      let asciiStr = '';

      for (let i = 0; i < 16; i++) {
        const b = lineBytes[i];
        hexStr += b.toString(16).padStart(2, '0') + ' ';
        asciiStr += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
      }

      const lineEl = document.createElement('div');
      lineEl.className = 'mem-inspect-line';
      lineEl.innerHTML = `
        <span class="mem-inspect-addr">0x${addr.toString(16)}</span>
        <span class="mem-inspect-bytes">${hexStr}</span>
        <span class="mem-inspect-ascii">${asciiStr}</span>
      `;
      this.memContentEl.appendChild(lineEl);
    }
  }
}
