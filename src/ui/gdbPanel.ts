/**
 * GDB Debugger Panel UI Component
 * Part of the Universal Reverse Engineering Tool
 * Simulates a GDB RSP (Remote Serial Protocol) session against the emulator,
 * using GDBProtocolParser, handleGDBCommand, and RSP command formats.
 */

import { Emulator } from '../emulator/emulator.js';
import { Instruction, Section } from '../disassembler/types.js';
import {
  GDBProtocolParser,
  handleGDBCommand,
  formatPacket,
  X86_64_REGISTERS,
  fromLittleEndianHex,
  toLittleEndianHex,
} from '../emulator/gdbProtocol.js';

export interface GDBPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
  onStep?: (rip: number) => void;
}

export class GDBPanel {
  private container: HTMLElement;
  private options: GDBPanelOptions;
  private emulator: Emulator;
  private parser: GDBProtocolParser;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private regGridEl!: HTMLDivElement;
  private logConsoleEl!: HTMLDivElement;
  private commandInputEl!: HTMLInputElement;
  private sendBtnEl!: HTMLButtonElement;
  private memAddrInputEl!: HTMLInputElement;
  private memLenInputEl!: HTMLInputElement;
  private memDumpEl!: HTMLDivElement;

  private stepBtnEl!: HTMLButtonElement;
  private contBtnEl!: HTMLButtonElement;
  private resetBtnEl!: HTMLButtonElement;

  private lastInspectedMemoryAddr: bigint = 0x1000n;
  private lastInspectedMemoryLen: number = 64;

  constructor(container: HTMLElement, options: GDBPanelOptions) {
    this.container = container;
    this.options = options;
    this.emulator = new Emulator();

    // Stream parser instantiation
    this.parser = new GDBProtocolParser((packet) => {
      this.logSystem(`RSP Stream Parser output: type=${packet.type}`);
      if (packet.type === 'packet') {
        if (packet.data !== undefined) {
          this.logPacket('in', formatPacket(packet.data));
          const responsePayload = handleGDBCommand(packet.data, this.emulator);
          const responsePacket = formatPacket(responsePayload);
          this.logPacket('out', responsePacket);
          this.refreshUIFromRSP();
        } else {
          this.logSystem(`Received corrupted packet (checksum failed)`);
        }
      } else if (packet.type === 'ack') {
        this.logSystem(`RSP Stream ACK (+)`);
      } else if (packet.type === 'nak') {
        this.logSystem(`RSP Stream NAK (-)`);
      }
    });

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates data, loads binary/sections/instructions and resets GDB state.
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    entryPoint: number,
    instructions: Instruction[]
  ) {
    this.emulator.reset(entryPoint);
    this.emulator.memory.loadSections(binaryData, sections);
    this.emulator.loadInstructions(instructions);

    this.logSystem(
      `System target reset. Entry Point: 0x${entryPoint.toString(16)}`
    );
    // Seed GDB protocol state with standard handshake
    this.sendRawRSPCommand('qSupported');
    this.refreshUIFromRSP();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'gdb-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject Styles if not already present
    if (!document.getElementById('gdb-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'gdb-panel-styles';
      style.textContent = `
        .gdb-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
          color: var(--text-primary);
          overflow-y: auto;
        }
        .gdb-grid {
          display: grid;
          grid-template-columns: 1.2fr 1fr;
          gap: 1.5rem;
          height: calc(100% - 4.5rem);
          min-height: 0;
        }
        .gdb-column {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          min-height: 0;
        }
        .gdb-card {
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-height: 0;
        }
        .gdb-card-title {
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
        .gdb-controls {
          display: flex;
          gap: 0.75rem;
          align-items: center;
          padding: 0.5rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: var(--radius-md);
        }
        .gdb-btn {
          padding: 0.5rem 1rem;
          background: rgba(255, 255, 255, 0.05);
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
        .gdb-btn:hover:not(:disabled) {
          background: rgba(255, 255, 255, 0.1);
          transform: translateY(-1px);
        }
        .gdb-btn-primary {
          background: linear-gradient(135deg, var(--accent-start), var(--accent-end));
          border: none;
          color: white;
        }
        .gdb-btn-primary:hover:not(:disabled) {
          filter: brightness(1.1);
        }
        .gdb-btn:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
        .console-log {
          flex-grow: 1;
          background: rgba(0, 0, 0, 0.3);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          padding: 0.75rem;
          font-family: var(--font-mono);
          font-size: 0.8rem;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .console-line {
          line-height: 1.4;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .console-line.in { color: #56b6c2; } /* Packet from client (in) */
        .console-line.out { color: #98c379; } /* Packet to client (out) */
        .console-line.sys { color: #abb2bf; opacity: 0.7; } /* Internal message */
        
        .gdb-input-row {
          display: flex;
          gap: 0.5rem;
        }
        .gdb-input {
          flex-grow: 1;
          background: rgba(0, 0, 0, 0.2);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          padding: 0.5rem;
          color: var(--text-primary);
          font-family: var(--font-mono);
          font-size: 0.85rem;
        }
        .gdb-reg-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
          gap: 0.5rem;
          overflow-y: auto;
          flex-grow: 1;
        }
        .gdb-reg-box {
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
        .gdb-reg-box:hover {
          border-color: var(--accent-start);
          background: rgba(255, 255, 255, 0.04);
        }
        .gdb-reg-name {
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
        .gdb-reg-value {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          color: #e5c07b;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .gdb-mem-dump {
          flex-grow: 1;
          font-family: var(--font-mono);
          font-size: 0.8rem;
          background: rgba(0, 0, 0, 0.2);
          padding: 0.5rem;
          border-radius: var(--radius-sm);
          overflow-y: auto;
          white-space: pre;
          min-height: 120px;
        }
      `;
      document.head.appendChild(style);
    }

    // Build components structure
    this.rootEl.innerHTML = `
      <!-- Toolbar controls -->
      <div class="gdb-controls">
        <button class="gdb-btn gdb-btn-primary" id="gdb-step-btn">
          ✨ Step (s)
        </button>
        <button class="gdb-btn" id="gdb-continue-btn">
          ▶ Continue (c)
        </button>
        <button class="gdb-btn" id="gdb-reset-btn">
          🔄 Reset Target
        </button>
        <div style="flex-grow: 1;"></div>
        <div style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">
          GDB Status: <span style="color: #98c379; font-weight: bold;">RSP SIMULATOR ACTIVE</span>
        </div>
      </div>

      <!-- Main Columns Grid -->
      <div class="gdb-grid">
        <!-- Left: Console Log and Packet Terminal -->
        <div class="gdb-column">
          <div class="gdb-card" style="flex: 1;">
            <div class="gdb-card-title">GDB RSP Transaction Log & Console</div>
            <div class="console-log" id="gdb-console-log"></div>
            <div class="gdb-input-row">
              <input type="text" class="gdb-input" id="gdb-command-input" placeholder="Type raw GDB packet payload (e.g. 'g', 'm1000,10', 's') or raw packet (e.g. '$?#3f')..." />
              <button class="gdb-btn gdb-btn-primary" id="gdb-send-btn">Send</button>
            </div>
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: -0.25rem;">
              Tip: Raw packet formats start with '$' and end with '#' + 2-digit checksum. If no format is matched, we auto-package it.
            </div>
          </div>
        </div>

        <!-- Right: Registers and Memory Map -->
        <div class="gdb-column">
          <!-- Registers -->
          <div class="gdb-card" style="flex: 1;">
            <div class="gdb-card-title">
              <span>Registers (via '$g')</span>
              <button class="gdb-btn" id="gdb-refresh-regs" style="padding: 0.15rem 0.5rem; font-size: 0.75rem;">Refresh</button>
            </div>
            <div class="gdb-reg-grid" id="gdb-reg-grid"></div>
          </div>

          <!-- Memory Dump -->
          <div class="gdb-card" style="flex: 1;">
            <div class="gdb-card-title">Memory Inspector (via '$m')</div>
            <div style="display: flex; gap: 0.5rem; align-items: center;">
              <span style="font-size: 0.8rem; color: var(--text-secondary);">Addr:</span>
              <input type="text" class="gdb-input" id="gdb-mem-addr" value="0x1000" style="max-width: 120px;" />
              <span style="font-size: 0.8rem; color: var(--text-secondary);">Size:</span>
              <input type="number" class="gdb-input" id="gdb-mem-len" value="64" style="max-width: 80px;" />
              <button class="gdb-btn" id="gdb-mem-refresh">Inspect</button>
            </div>
            <div class="gdb-mem-dump" id="gdb-mem-dump"></div>
          </div>
        </div>
      </div>
    `;

    this.container.appendChild(this.rootEl);

    // Cache elements
    this.regGridEl = this.rootEl.querySelector('#gdb-reg-grid')!;
    this.logConsoleEl = this.rootEl.querySelector('#gdb-console-log')!;
    this.commandInputEl = this.rootEl.querySelector('#gdb-command-input')!;
    this.sendBtnEl = this.rootEl.querySelector('#gdb-send-btn')!;
    this.memAddrInputEl = this.rootEl.querySelector('#gdb-mem-addr')!;
    this.memLenInputEl = this.rootEl.querySelector('#gdb-mem-len')!;
    this.memDumpEl = this.rootEl.querySelector('#gdb-mem-dump')!;

    this.stepBtnEl = this.rootEl.querySelector('#gdb-step-btn')!;
    this.contBtnEl = this.rootEl.querySelector('#gdb-continue-btn')!;
    this.resetBtnEl = this.rootEl.querySelector('#gdb-reset-btn')!;
  }

  private setupEvents() {
    this.stepBtnEl.addEventListener('click', () => {
      this.sendRawRSPCommand('s');
    });

    this.contBtnEl.addEventListener('click', () => {
      this.sendRawRSPCommand('c');
    });

    this.resetBtnEl.addEventListener('click', () => {
      this.emulator.reset(Number(this.emulator.cpu.read('rip')));
      this.logSystem(
        `Target Reset. RIP reset to: 0x${this.emulator.cpu.read('rip').toString(16)}`
      );
      this.refreshUIFromRSP();
    });

    this.rootEl
      .querySelector('#gdb-refresh-regs')
      ?.addEventListener('click', () => {
        this.refreshUIFromRSP();
      });

    this.rootEl
      .querySelector('#gdb-mem-refresh')
      ?.addEventListener('click', () => {
        this.refreshMemoryFromInputs();
      });

    this.sendBtnEl.addEventListener('click', () => this.handleConsoleSend());
    this.commandInputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.handleConsoleSend();
      }
    });
  }

  private logPacket(direction: 'in' | 'out', packet: string) {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `console-line ${direction}`;
    line.textContent = `[${time}] ${direction === 'in' ? '<-' : '->'} ${packet}`;
    this.logConsoleEl.appendChild(line);
    this.logConsoleEl.scrollTop = this.logConsoleEl.scrollHeight;
  }

  private logSystem(message: string) {
    const time = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `console-line sys`;
    line.textContent = `[${time}] [*] ${message}`;
    this.logConsoleEl.appendChild(line);
    this.logConsoleEl.scrollTop = this.logConsoleEl.scrollHeight;
  }

  private handleConsoleSend() {
    const input = this.commandInputEl.value.trim();
    if (!input) return;
    this.commandInputEl.value = '';

    // Check if it's formatted as a full packet or needs packetization
    if (input.startsWith('$')) {
      this.logSystem(
        `Feeding raw data stream to GDB Protocol Parser: ${input}`
      );
      this.parser.feed(input);
    } else {
      this.sendRawRSPCommand(input);
    }
  }

  /**
   * Formats, logs, executes, and records the GDB RSP command.
   */
  private sendRawRSPCommand(cmdPayload: string): string {
    const requestPacket = formatPacket(cmdPayload);
    this.logPacket('out', requestPacket);

    // Handle command using standard gdbProtocol handler
    const responsePayload = handleGDBCommand(cmdPayload, this.emulator);
    const responsePacket = formatPacket(responsePayload);
    this.logPacket('in', responsePacket);

    this.refreshUIFromRSP();

    return responsePayload;
  }

  private refreshUIFromRSP() {
    // 1. Refresh Registers via RSP 'g'
    const hexRegs = handleGDBCommand('g', this.emulator);
    this.renderRegistersFromHex(hexRegs);

    // 2. Refresh Memory display
    this.refreshMemoryFromInputs();

    // 3. Highlight instruction inside the main app if navigating
    const ripVal = this.emulator.cpu.read('rip');
    if (this.options.onStep) {
      this.options.onStep(Number(ripVal));
    }
  }

  private renderRegistersFromHex(hexData: string) {
    this.regGridEl.innerHTML = '';
    let offset = 0;

    X86_64_REGISTERS.forEach((reg, index) => {
      const charsNeeded = reg.size * 2;
      let val = 0n;
      if (offset + charsNeeded <= hexData.length) {
        const hexSlice = hexData.slice(offset, offset + charsNeeded);
        val = fromLittleEndianHex(hexSlice);
      }
      offset += charsNeeded;

      const regBox = document.createElement('div');
      regBox.className = 'gdb-reg-box';
      regBox.innerHTML = `
        <span class="gdb-reg-name">${reg.name}</span>
        <span class="gdb-reg-value">0x${val.toString(16)}</span>
      `;

      regBox.addEventListener('click', () => {
        const inputVal = prompt(
          `Enter hex value for register ${reg.name}:`,
          `0x${val.toString(16)}`
        );
        if (inputVal !== null) {
          try {
            const cleanVal = inputVal.replace('0x', '').trim();
            const parsedVal = BigInt(`0x${cleanVal}`);
            const regIdxHex = index.toString(16);
            const valHex = toLittleEndianHex(parsedVal, reg.size);
            this.sendRawRSPCommand(`P${regIdxHex}=${valHex}`);
          } catch {
            alert('Invalid hexadecimal number format');
          }
        }
      });

      this.regGridEl.appendChild(regBox);
    });
  }

  private refreshMemoryFromInputs() {
    try {
      const addrStr = this.memAddrInputEl.value.trim();
      const lenStr = this.memLenInputEl.value.trim();

      const addr = BigInt(addrStr.startsWith('0x') ? addrStr : `0x${addrStr}`);
      const len = parseInt(lenStr, 10);

      if (isNaN(len) || len <= 0) return;

      this.lastInspectedMemoryAddr = addr;
      this.lastInspectedMemoryLen = len;

      // Construct RSP read memory command: m<addr>,<length>
      const cmd = `m${addr.toString(16)},${len.toString(16)}`;
      const responseHex = handleGDBCommand(cmd, this.emulator);

      // Render Hex Dump style format
      if (responseHex && !responseHex.startsWith('E')) {
        let dumpText = '';
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          const byteStr = responseHex.slice(i * 2, i * 2 + 2);
          bytes[i] = parseInt(byteStr, 16);
        }

        // Format dump
        const bytesPerLine = 16;
        for (let i = 0; i < len; i += bytesPerLine) {
          const lineAddr = addr + BigInt(i);
          let hexPart = '';
          let asciiPart = '';

          for (let j = 0; j < bytesPerLine; j++) {
            if (i + j < len) {
              const byte = bytes[i + j];
              hexPart += byte.toString(16).padStart(2, '0') + ' ';
              asciiPart +=
                byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
            } else {
              hexPart += '   ';
            }
          }
          dumpText += `0x${lineAddr.toString(16).padStart(8, '0')}:  ${hexPart} |${asciiPart}|\n`;
        }
        this.memDumpEl.textContent = dumpText;
      } else {
        this.memDumpEl.textContent = `Memory Read Failed: RSP error response (${responseHex})`;
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this.memDumpEl.textContent = `Error parsing inspect address: ${msg}`;
    }
  }
}
