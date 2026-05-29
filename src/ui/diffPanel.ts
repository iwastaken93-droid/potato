/**
 * Premium Binary Diff Panel
 * Part of the Universal Reverse Engineering Tool (URET)
 *
 * Provides a side-by-side comparative layout for comparing two binary files at the byte or disassembler level.
 */

import { Instruction, Section } from '../disassembler/types.js';
import {
  diffBytes,
  diffInstructions,
  ByteDiffResult,
  InstructionDiffResult,
} from '../analyzer/diff.js';
import { parseElf } from '../parser/elf.js';
import { PEParser } from '../parser/pe.js';
import { parseWasm } from '../parser/wasm.js';
import { parseMacho } from '../parser/macho.js';
import { parseDex } from '../parser/dex.js';
import { DisassemblerRouter } from '../disassembler/router.js';

export class DiffPanel {
  private container: HTMLElement;

  // Binary 1 Data (Loaded in primary workbench)
  private binaryData1: Uint8Array = new Uint8Array(0);
  private sections1: Section[] = [];
  private instructions1: Instruction[] = [];
  private fileName1: string = 'Primary Binary';

  // Binary 2 Data (Loaded in diff panel)
  private binaryData2: Uint8Array | null = null;
  private sections2: Section[] = [];
  private instructions2: Instruction[] = [];
  private fileName2: string = '';

  // Mode state
  private mode: 'byte' | 'instruction' = 'byte';

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private dropzoneEl!: HTMLDivElement;
  private fileInputEl!: HTMLInputElement;
  private modeSelectorContainer!: HTMLDivElement;
  private diffViewportContainer!: HTMLDivElement;
  private statsFooterEl!: HTMLDivElement;

  // Sync scroll lock
  private activeScrollSource: HTMLElement | null = null;

  constructor(container: HTMLElement) {
    this.container = container;
    this.injectStyles();
    this.initLayout();
  }

  /**
   * Update the primary binary data (from the workbench).
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    instructions: Instruction[],
    fileName: string = 'Primary Binary'
  ) {
    this.binaryData1 = binaryData;
    this.sections1 = sections;
    this.instructions1 = instructions;
    this.fileName1 = fileName;
    this.render();
  }

  private injectStyles() {
    if (document.getElementById('diff-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'diff-panel-styles';
    style.textContent = `
      .diff-panel-root {
        display: flex;
        flex-direction: column;
        height: 100%;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        gap: 1.25rem;
      }

      .diff-header-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 1rem;
        background: rgba(255, 255, 255, 0.01);
        border: 1px solid var(--border-color);
        padding: 1rem 1.25rem;
        border-radius: var(--radius-md);
      }

      .diff-title-section h3 {
        margin: 0;
        font-size: 1.2rem;
        font-weight: 700;
        background: var(--gradient-accent);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }

      .diff-title-section p {
        margin: 0;
        font-size: 0.8rem;
        color: var(--text-muted);
      }

      .diff-actions {
        display: flex;
        align-items: center;
        gap: 1rem;
      }

      .btn-mode-toggle {
        background: var(--bg-tertiary);
        border: 1px solid var(--border-color);
        padding: 0.5rem 1rem;
        border-radius: var(--radius-sm);
        color: var(--text-muted);
        cursor: pointer;
        font-weight: 500;
        transition: all var(--transition-fast);
      }

      .btn-mode-toggle.active {
        background: var(--gradient-accent);
        color: var(--text-primary);
        border-color: transparent;
      }

      .diff-dropzone {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        border: 2px dashed var(--border-color);
        border-radius: var(--radius-md);
        padding: 2.5rem;
        background: var(--bg-glass);
        cursor: pointer;
        transition: all var(--transition-fast);
        gap: 0.75rem;
        text-align: center;
      }

      .diff-dropzone:hover {
        border-color: var(--accent-start);
        background: var(--bg-glass-hover);
      }

      .diff-dropzone p {
        margin: 0;
        font-size: 0.9rem;
        color: var(--text-secondary);
      }

      .diff-dropzone span {
        font-size: 0.8rem;
        color: var(--text-muted);
      }

      .diff-files-info {
        display: flex;
        justify-content: space-between;
        gap: 1.5rem;
        font-size: 0.85rem;
        background: rgba(255, 255, 255, 0.02);
        padding: 0.75rem 1.25rem;
        border-radius: var(--radius-sm);
        border: 1px solid var(--border-color);
      }

      .diff-viewport {
        display: flex;
        flex: 1;
        gap: 1px;
        background: var(--border-color);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        overflow: hidden;
        min-height: 0;
      }

      .diff-pane {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-width: 0;
        background: var(--bg-secondary);
      }

      .diff-pane-header {
        background: rgba(255, 255, 255, 0.02);
        padding: 0.6rem 1rem;
        font-size: 0.8rem;
        font-weight: 600;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-secondary);
        display: flex;
        justify-content: space-between;
      }

      .diff-pane-content {
        flex: 1;
        overflow-y: auto;
        font-family: var(--font-mono);
        font-size: 0.825rem;
        line-height: 1.4rem;
        padding: 0.5rem 0;
        box-sizing: border-box;
      }

      /* Custom scrollbars */
      .diff-pane-content::-webkit-scrollbar {
        width: 6px;
        height: 6px;
      }
      .diff-pane-content::-webkit-scrollbar-thumb {
        background: var(--border-hover);
        border-radius: 3px;
      }

      /* Row Stylings */
      .diff-row {
        display: flex;
        width: 100%;
        padding: 0 1rem;
        box-sizing: border-box;
        transition: background-color var(--transition-fast);
      }

      .diff-row:hover {
        background: rgba(255, 255, 255, 0.02);
      }

      .diff-row.type-delete {
        background: rgba(239, 68, 68, 0.08);
        border-left: 3px solid var(--error);
      }

      .diff-row.type-insert {
        background: rgba(16, 185, 129, 0.08);
        border-left: 3px solid var(--success);
      }

      .diff-row.type-replace {
        background: rgba(245, 158, 11, 0.08);
        border-left: 3px solid var(--warning);
      }

      .diff-offset {
        color: var(--text-muted);
        width: 70px;
        flex-shrink: 0;
        user-select: none;
      }

      .diff-bytes-col {
        display: flex;
        gap: 0.4rem;
        flex: 1;
        min-width: 0;
      }

      .diff-byte {
        width: 22px;
        text-align: center;
        display: inline-block;
      }

      .diff-byte.diff-changed {
        color: var(--warning);
        font-weight: 600;
        background: rgba(245, 158, 11, 0.15);
        border-radius: 2px;
      }

      .diff-byte.diff-empty {
        color: transparent;
        user-select: none;
      }

      .diff-byte.diff-empty::after {
        content: "--";
        color: rgba(255, 255, 255, 0.15);
      }

      .diff-ascii-col {
        width: 140px;
        flex-shrink: 0;
        color: var(--text-muted);
        border-left: 1px solid var(--border-color);
        padding-left: 0.8rem;
        margin-left: 0.8rem;
        white-space: pre;
      }

      .diff-inst-col {
        display: flex;
        gap: 1rem;
        flex: 1;
        min-width: 0;
      }

      .diff-inst-mnemonic {
        color: var(--accent-start);
        width: 60px;
        flex-shrink: 0;
        font-weight: 500;
      }

      .diff-inst-ops {
        color: var(--text-secondary);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        flex: 1;
      }

      .diff-inst-bytes {
        color: var(--text-disabled);
        width: 120px;
        flex-shrink: 0;
      }

      .diff-footer {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: var(--bg-secondary);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        padding: 0.75rem 1.25rem;
        font-size: 0.8rem;
      }

      .diff-stats-list {
        display: flex;
        gap: 1.5rem;
      }

      .diff-stat-item {
        display: flex;
        align-items: center;
        gap: 0.35rem;
      }

      .diff-stat-indicator {
        width: 8px;
        height: 8px;
        border-radius: 50%;
      }

      .indicator-equal { background: var(--text-muted); }
      .indicator-insert { background: var(--success); }
      .indicator-delete { background: var(--error); }
      .indicator-replace { background: var(--warning); }
    `;
    document.head.appendChild(style);
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'diff-panel-root';

    // Header Bar
    const headerBar = document.createElement('div');
    headerBar.className = 'diff-header-bar';
    headerBar.innerHTML = `
      <div class="diff-title-section">
        <h3>Binary Diff Viewer</h3>
        <p>Compare primary and secondary binary side-by-side</p>
      </div>
    `;

    const actions = document.createElement('div');
    actions.className = 'diff-actions';

    // Mode toggles
    const toggleGroup = document.createElement('div');
    toggleGroup.style.display = 'flex';
    toggleGroup.style.gap = '0.5rem';

    const btnByte = document.createElement('button');
    btnByte.className = 'btn-mode-toggle active';
    btnByte.innerText = 'Byte Diff';
    btnByte.onclick = () => this.switchMode('byte');

    const btnInst = document.createElement('button');
    btnInst.className = 'btn-mode-toggle';
    btnInst.innerText = 'Instruction Diff';
    btnInst.onclick = () => this.switchMode('instruction');

    toggleGroup.appendChild(btnByte);
    toggleGroup.appendChild(btnInst);
    actions.appendChild(toggleGroup);
    headerBar.appendChild(actions);

    this.modeSelectorContainer = toggleGroup;
    this.rootEl.appendChild(headerBar);

    // Dropzone / File Select
    this.dropzoneEl = document.createElement('div');
    this.dropzoneEl.className = 'diff-dropzone';
    this.dropzoneEl.innerHTML = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--accent-start)">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
        <polyline points="17 8 12 3 7 8"></polyline>
        <line x1="12" y1="3" x2="12" y2="15"></line>
      </svg>
      <p>Drag & drop the secondary binary file here, or click to browse</p>
      <span>Supports ELF, PE, Mach-O, WASM, DEX formats</span>
    `;

    this.fileInputEl = document.createElement('input');
    this.fileInputEl.type = 'file';
    this.fileInputEl.style.display = 'none';
    this.fileInputEl.onchange = (e) => this.handleFileSelect(e);

    this.dropzoneEl.onclick = () => this.fileInputEl.click();
    this.dropzoneEl.ondragover = (e) => {
      e.preventDefault();
      this.dropzoneEl.style.borderColor = 'var(--success)';
    };
    this.dropzoneEl.ondragleave = () => {
      this.dropzoneEl.style.borderColor = 'var(--border-color)';
    };
    this.dropzoneEl.ondrop = (e) => {
      e.preventDefault();
      this.dropzoneEl.style.borderColor = 'var(--border-color)';
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        this.loadSecondaryFile(e.dataTransfer.files[0]);
      }
    };

    this.rootEl.appendChild(this.dropzoneEl);
    this.rootEl.appendChild(this.fileInputEl);

    // Viewport (rendered initially empty)
    this.diffViewportContainer = document.createElement('div');
    this.diffViewportContainer.className = 'diff-viewport';
    this.diffViewportContainer.style.display = 'none';
    this.rootEl.appendChild(this.diffViewportContainer);

    // Footer stats
    this.statsFooterEl = document.createElement('div');
    this.statsFooterEl.className = 'diff-footer';
    this.statsFooterEl.style.display = 'none';
    this.rootEl.appendChild(this.statsFooterEl);

    this.container.appendChild(this.rootEl);
  }

  private switchMode(mode: 'byte' | 'instruction') {
    this.mode = mode;
    const buttons =
      this.modeSelectorContainer.querySelectorAll('.btn-mode-toggle');
    buttons.forEach((btn, idx) => {
      if (
        (mode === 'byte' && idx === 0) ||
        (mode === 'instruction' && idx === 1)
      ) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    this.renderDiffViewport();
  }

  private handleFileSelect(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.loadSecondaryFile(input.files[0]);
    }
  }

  private loadSecondaryFile(file: File) {
    this.fileName2 = file.name;
    const reader = new FileReader();
    reader.onload = (event) => {
      if (event.target && event.target.result instanceof ArrayBuffer) {
        this.processSecondaryBinary(event.target.result);
      }
    };
    reader.readAsArrayBuffer(file);
  }

  private processSecondaryBinary(arrayBuffer: ArrayBuffer) {
    const data = new Uint8Array(arrayBuffer);
    this.binaryData2 = data;

    // Detect format and architecture
    const arch = DisassemblerRouter.detectArchitecture(data);

    let entryPoint = 0;
    let sections: Section[] = [];

    try {
      if (arch === 'wasm') {
        const wasm = parseWasm(arrayBuffer);
        entryPoint = wasm.version;
        sections = wasm.customSections.map((s: any) => ({
          name: s.name,
          virtualAddress: 0,
          virtualSize: s.size,
          fileOffset: 0,
          fileSize: s.size,
          flags: { read: true, write: false, execute: false },
        }));
      } else if (
        data[0] === 0x7f &&
        data[1] === 0x45 &&
        data[2] === 0x4c &&
        data[3] === 0x46
      ) {
        const elf = parseElf(arrayBuffer);
        entryPoint = Number(elf.header.entryPoint);
        sections = elf.sectionHeaders.map((sh: any) => ({
          name: sh.name || sh.typeName,
          virtualAddress: Number(sh.addr),
          virtualSize: Number(sh.size),
          fileOffset: Number(sh.offset),
          fileSize: Number(sh.size),
          flags: {
            read: (Number(sh.flags) & 4) !== 0,
            write: (Number(sh.flags) & 2) !== 0,
            execute: (Number(sh.flags) & 1) !== 0,
          },
        }));
      } else if (data[0] === 0x4d && data[1] === 0x5a) {
        const peParser = new PEParser(arrayBuffer);
        const pe = peParser.parse();
        entryPoint =
          Number(pe.optionalHeader.addressOfEntryPoint) +
          Number(pe.optionalHeader.imageBase);
        sections = pe.sections.map((s: any) => ({
          name: s.name,
          virtualAddress:
            s.virtualAddress + Number(pe.optionalHeader.imageBase),
          virtualSize: s.virtualSize,
          fileOffset: s.pointerToRawData,
          fileSize: s.sizeOfRawData,
          flags: {
            read: (s.characteristics & 0x40000000) !== 0,
            write: (s.characteristics & 0x80000000) !== 0,
            execute: (s.characteristics & 0x20000000) !== 0,
          },
        }));
      } else if (
        (data[0] === 0xfe &&
          data[1] === 0xed &&
          data[2] === 0xfa &&
          data[3] === 0xce) ||
        (data[0] === 0xce &&
          data[1] === 0xfa &&
          data[2] === 0xed &&
          data[3] === 0xfe) ||
        (data[0] === 0xfe &&
          data[1] === 0xed &&
          data[2] === 0xfa &&
          data[3] === 0xcf) ||
        (data[0] === 0xcf &&
          data[1] === 0xfa &&
          data[2] === 0xed &&
          data[3] === 0xfe)
      ) {
        const macho = parseMacho(arrayBuffer);
        sections = macho.sections.map((s: any) => ({
          name: s.sectname,
          virtualAddress: Number(s.addr),
          virtualSize: Number(s.size),
          fileOffset: s.offset,
          fileSize: Number(s.size),
          flags: {
            read: true,
            write: (s.flags & 0x2) !== 0,
            execute: s.sectname === '__text',
          },
        }));
        const textSection = sections.find((s) => s.name === '__text');
        if (textSection) {
          entryPoint = textSection.virtualAddress;
        } else if (macho.symbols.length > 0) {
          entryPoint = Number(macho.symbols[0].value);
        }
      } else if (
        data[0] === 0x64 &&
        data[1] === 0x65 &&
        data[2] === 0x78 &&
        data[3] === 0x0a
      ) {
        const dex = parseDex(data);
        entryPoint = dex.entryPoint || 0x1000;
        sections = [
          {
            name: '.header',
            virtualAddress: 0,
            virtualSize: dex.header.headerSize,
            fileOffset: 0,
            fileSize: dex.header.headerSize,
            flags: { read: true, write: false, execute: false },
          },
          {
            name: '.code',
            virtualAddress: dex.header.dataOff || 0x1000,
            virtualSize: dex.header.dataSize || data.length,
            fileOffset: dex.header.dataOff || 0,
            fileSize: dex.header.dataSize || data.length,
            flags: { read: true, write: false, execute: true },
          },
        ];
      }
    } catch (e) {
      console.warn(
        'Failed to parse file structure, falling back to raw data',
        e
      );
    }

    this.sections2 = sections;

    // Disassemble
    const router = new DisassemblerRouter();
    this.instructions2 = router.disassemble(data, {
      arch,
      baseAddress:
        sections.find((s: any) => s.flags.execute)?.virtualAddress || 0x1000,
      entryPoint,
    });

    this.render();
  }

  private render() {
    if (!this.binaryData2) {
      this.dropzoneEl.style.display = 'flex';
      this.diffViewportContainer.style.display = 'none';
      this.statsFooterEl.style.display = 'none';
      return;
    }

    this.dropzoneEl.style.display = 'none';
    this.diffViewportContainer.style.display = 'flex';
    this.statsFooterEl.style.display = 'flex';

    this.renderDiffViewport();
  }

  private renderDiffViewport() {
    this.diffViewportContainer.innerHTML = '';

    const paneLeft = document.createElement('div');
    paneLeft.className = 'diff-pane';
    paneLeft.innerHTML = `
      <div class="diff-pane-header">
        <span>${this.fileName1}</span>
        <span>Original</span>
      </div>
      <div class="diff-pane-content" id="diff-pane-left"></div>
    `;

    const paneRight = document.createElement('div');
    paneRight.className = 'diff-pane';
    paneRight.innerHTML = `
      <div class="diff-pane-header">
        <span>${this.fileName2}</span>
        <span>Revised</span>
      </div>
      <div class="diff-pane-content" id="diff-pane-right"></div>
    `;

    this.diffViewportContainer.appendChild(paneLeft);
    this.diffViewportContainer.appendChild(paneRight);

    const contentLeft = paneLeft.querySelector(
      '#diff-pane-left'
    ) as HTMLDivElement;
    const contentRight = paneRight.querySelector(
      '#diff-pane-right'
    ) as HTMLDivElement;

    // Setup sync scroll
    const syncScroll = (src: HTMLDivElement, dest: HTMLDivElement) => {
      src.addEventListener('scroll', () => {
        if (this.activeScrollSource && this.activeScrollSource !== src) return;
        this.activeScrollSource = src;
        dest.scrollTop = src.scrollTop;
        dest.scrollLeft = src.scrollLeft;
        this.activeScrollSource = null;
      });
    };

    syncScroll(contentLeft, contentRight);
    syncScroll(contentRight, contentLeft);

    const stats = { equal: 0, insert: 0, delete: 0, replace: 0 };

    if (this.mode === 'byte') {
      const diffs = diffBytes(this.binaryData1, this.binaryData2!);

      // Gather stats
      diffs.forEach((d) => {
        stats[d.type]++;
      });

      // Render side-by-side grouped by 16 items
      const chunkSize = 16;
      for (let i = 0; i < diffs.length; i += chunkSize) {
        const chunk = diffs.slice(i, i + chunkSize);

        // Rows
        const rowL = document.createElement('div');
        rowL.className = 'diff-row';
        const rowR = document.createElement('div');
        rowR.className = 'diff-row';

        // Check if any element in chunk is modified
        const isDelete = chunk.every((c) => c.type === 'delete');
        const isInsert = chunk.every((c) => c.type === 'insert');
        const isReplace = chunk.some(
          (c) =>
            c.type === 'replace' || c.type === 'delete' || c.type === 'insert'
        );

        let rowClass = '';
        if (isDelete) rowClass = 'type-delete';
        else if (isInsert) rowClass = 'type-insert';
        else if (isReplace) rowClass = 'type-replace';

        if (rowClass) {
          rowL.classList.add(rowClass);
          rowR.classList.add(rowClass);
        }

        // Offsets
        const firstWithOffset1 = chunk.find((c) => c.offset1 !== null);
        const offset1Str =
          firstWithOffset1 !== undefined
            ? firstWithOffset1.offset1!.toString(16).padStart(8, '0')
            : '';
        const firstWithOffset2 = chunk.find((c) => c.offset2 !== null);
        const offset2Str =
          firstWithOffset2 !== undefined
            ? firstWithOffset2.offset2!.toString(16).padStart(8, '0')
            : '';

        // Left HTML content
        let bytesHtmlL = `<div class="diff-offset">${offset1Str}</div><div class="diff-bytes-col">`;
        let asciiL = '';
        chunk.forEach((item) => {
          if (item.byte1 !== null) {
            const hex = item.byte1.toString(16).padStart(2, '0');
            const cls = item.type !== 'equal' ? 'diff-changed' : '';
            bytesHtmlL += `<span class="diff-byte ${cls}">${hex}</span>`;
            asciiL +=
              item.byte1 >= 32 && item.byte1 <= 126
                ? String.fromCharCode(item.byte1)
                : '.';
          } else {
            bytesHtmlL += `<span class="diff-byte diff-empty"></span>`;
            asciiL += ' ';
          }
        });
        bytesHtmlL += `</div><div class="diff-ascii-col">${asciiL}</div>`;
        rowL.innerHTML = bytesHtmlL;

        // Right HTML content
        let bytesHtmlR = `<div class="diff-offset">${offset2Str}</div><div class="diff-bytes-col">`;
        let asciiR = '';
        chunk.forEach((item) => {
          if (item.byte2 !== null) {
            const hex = item.byte2.toString(16).padStart(2, '0');
            const cls = item.type !== 'equal' ? 'diff-changed' : '';
            bytesHtmlR += `<span class="diff-byte ${cls}">${hex}</span>`;
            asciiR +=
              item.byte2 >= 32 && item.byte2 <= 126
                ? String.fromCharCode(item.byte2)
                : '.';
          } else {
            bytesHtmlR += `<span class="diff-byte diff-empty"></span>`;
            asciiR += ' ';
          }
        });
        bytesHtmlR += `</div><div class="diff-ascii-col">${asciiR}</div>`;
        rowR.innerHTML = bytesHtmlR;

        contentLeft.appendChild(rowL);
        contentRight.appendChild(rowR);
      }
    } else {
      // Instruction Diff Mode
      const diffs = diffInstructions(this.instructions1, this.instructions2);

      diffs.forEach((d) => {
        stats[d.type]++;
      });

      diffs.forEach((item) => {
        const rowL = document.createElement('div');
        rowL.className = 'diff-row';
        const rowR = document.createElement('div');
        rowR.className = 'diff-row';

        let rowClass = '';
        if (item.type === 'delete') rowClass = 'type-delete';
        else if (item.type === 'insert') rowClass = 'type-insert';
        else if (item.type === 'replace') rowClass = 'type-replace';

        if (rowClass) {
          rowL.classList.add(rowClass);
          rowR.classList.add(rowClass);
        }

        // Left Pane Instruction
        if (item.inst1) {
          const addr = item.inst1.address.toString(16).toUpperCase();
          const bytes = Array.from(item.inst1.bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ');
          rowL.innerHTML = `
            <div class="diff-offset" style="width: 80px;">${addr}</div>
            <div class="diff-inst-col">
              <span class="diff-inst-bytes">${bytes}</span>
              <span class="diff-inst-mnemonic">${item.inst1.mnemonic}</span>
              <span class="diff-inst-ops">${item.inst1.opStr}</span>
            </div>
          `;
        } else {
          rowL.innerHTML = `<div class="diff-offset" style="width: 80px; color: transparent;">-</div><div class="diff-inst-col"><span style="color: rgba(255,255,255,0.15)">--</span></div>`;
        }

        // Right Pane Instruction
        if (item.inst2) {
          const addr = item.inst2.address.toString(16).toUpperCase();
          const bytes = Array.from(item.inst2.bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ');
          rowR.innerHTML = `
            <div class="diff-offset" style="width: 80px;">${addr}</div>
            <div class="diff-inst-col">
              <span class="diff-inst-bytes">${bytes}</span>
              <span class="diff-inst-mnemonic">${item.inst2.mnemonic}</span>
              <span class="diff-inst-ops">${item.inst2.opStr}</span>
            </div>
          `;
        } else {
          rowR.innerHTML = `<div class="diff-offset" style="width: 80px; color: transparent;">-</div><div class="diff-inst-col"><span style="color: rgba(255,255,255,0.15)">--</span></div>`;
        }

        contentLeft.appendChild(rowL);
        contentRight.appendChild(rowR);
      });
    }

    // Render stats footer
    this.statsFooterEl.innerHTML = `
      <span>Binary diffing complete.</span>
      <div class="diff-stats-list">
        <div class="diff-stat-item">
          <span class="diff-stat-indicator indicator-equal"></span>
          <span>${stats.equal} unchanged</span>
        </div>
        <div class="diff-stat-item">
          <span class="diff-stat-indicator indicator-insert"></span>
          <span>${stats.insert} insertions</span>
        </div>
        <div class="diff-stat-item">
          <span class="diff-stat-indicator indicator-delete"></span>
          <span>${stats.delete} deletions</span>
        </div>
        <div class="diff-stat-item">
          <span class="diff-stat-indicator indicator-replace"></span>
          <span>${stats.replace} modifications</span>
        </div>
      </div>
    `;
  }
}
