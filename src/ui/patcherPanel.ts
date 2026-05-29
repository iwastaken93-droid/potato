/**
 * Premium Binary Patching Panel UI Component
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout, allows patching, tracks history, and exports.
 */

import { BinaryPatcher, PatchRecord } from '../analyzer/patcher.js';
import { Section } from '../disassembler/types.js';

export interface PatcherPanelOptions {
  onPatchApplied: (patchedBinary: Uint8Array, patches: PatchRecord[]) => void;
  architecture?: string;
  filename?: string;
}

export class PatcherPanel {
  private container: HTMLElement;
  private patcher: BinaryPatcher;
  private options: PatcherPanelOptions;
  private sections: Section[] = [];
  private currentArchitecture: string = 'x86_64';
  private currentFilename: string = 'binary.bin';

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private historyListEl!: HTMLDivElement;
  private patchAddressInput!: HTMLInputElement;
  private patchBytesInput!: HTMLInputElement;
  private patchDescInput!: HTMLInputElement;
  private applyBtn!: HTMLButtonElement;
  private exportBtn!: HTMLButtonElement;
  private clearBtn!: HTMLButtonElement;
  private statusTextEl!: HTMLDivElement;

  constructor(
    container: HTMLElement,
    patcher: BinaryPatcher,
    options: PatcherPanelOptions
  ) {
    this.container = container;
    this.patcher = patcher;
    this.options = options;

    if (options.architecture) {
      this.currentArchitecture = options.architecture;
    }
    if (options.filename) {
      this.currentFilename = options.filename;
    }

    this.initLayout();
    this.setupEvents();
    this.renderHistory();
  }

  /**
   * Updates state data (sections, filename, architecture)
   */
  public updateData(
    sections: Section[],
    filename: string,
    architecture: string
  ) {
    this.sections = sections;
    this.currentFilename = filename;
    this.currentArchitecture = architecture;
    this.statusTextEl.textContent = `Patcher ready for ${filename} (${architecture})`;
  }

  /**
   * Set target input address from outer interactions (like selecting an offset or instruction)
   */
  public setTargetAddress(address: number) {
    this.patchAddressInput.value = '0x' + address.toString(16);
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'patcher-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
      overflow-y: auto;
    `;

    // Inject Styles if not already present
    if (!document.getElementById('patcher-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'patcher-panel-styles';
      style.textContent = `
        .patcher-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
          color: var(--text-primary);
        }
        .patcher-grid {
          display: grid;
          grid-template-columns: 1fr 1.5fr;
          gap: 1.5rem;
          flex-grow: 1;
          min-height: 0;
        }
        .patcher-column {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          min-height: 0;
        }
        .patcher-card {
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: var(--radius-md);
          padding: 1.25rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }
        .patcher-card-title {
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
        .patch-form-group {
          display: flex;
          flex-direction: column;
          gap: 0.35rem;
        }
        .patch-label {
          font-size: 0.75rem;
          color: var(--text-secondary);
          font-weight: 500;
        }
        .patch-input {
          background: rgba(0, 0, 0, 0.2);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          padding: 0.5rem;
          color: var(--text-primary);
          font-family: var(--font-mono);
          font-size: 0.85rem;
          transition: border-color 0.2s;
        }
        .patch-input:focus {
          border-color: var(--accent-start);
          outline: none;
        }
        .patch-btn {
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
          justify-content: center;
          gap: 0.5rem;
        }
        .patch-btn:hover {
          background: rgba(255, 255, 255, 0.1);
          transform: translateY(-1px);
        }
        .patch-btn-primary {
          background: linear-gradient(135deg, var(--accent-start), var(--accent-end));
          border: none;
          color: white;
        }
        .patch-btn-primary:hover {
          filter: brightness(1.1);
        }
        .patch-btn-danger {
          background: rgba(239, 68, 68, 0.15);
          border-color: rgba(239, 68, 68, 0.3);
          color: #f87171;
        }
        .patch-btn-danger:hover {
          background: rgba(239, 68, 68, 0.25);
        }
        .patch-history-list {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
          overflow-y: auto;
          flex-grow: 1;
        }
        .patch-history-item {
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: var(--radius-sm);
          padding: 0.75rem;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 1rem;
          transition: border-color 0.2s;
        }
        .patch-history-item:hover {
          border-color: rgba(255, 255, 255, 0.08);
        }
        .patch-info {
          display: flex;
          flex-direction: column;
          gap: 0.2rem;
          font-family: var(--font-mono);
          font-size: 0.8rem;
        }
        .patch-addr-offset {
          color: var(--accent-start);
          font-weight: 600;
        }
        .patch-byte-diff {
          display: flex;
          gap: 0.5rem;
          align-items: center;
          font-size: 0.75rem;
        }
        .bytes-red {
          color: #f87171;
          text-decoration: line-through;
        }
        .bytes-green {
          color: #4ade80;
        }
        .patch-desc-text {
          color: var(--text-muted);
          font-size: 0.75rem;
          font-style: italic;
        }
        .patch-actions {
          display: flex;
          gap: 0.5rem;
          align-items: center;
        }
        .toggle-btn {
          cursor: pointer;
          background: none;
          border: none;
          padding: 0.25rem;
          color: var(--text-secondary);
          transition: color 0.2s;
        }
        .toggle-btn.active {
          color: #4ade80;
        }
      `;
      document.head.appendChild(style);
    }

    // Top control bar
    const controlsBar = document.createElement('div');
    controlsBar.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.04);
      padding: 0.75rem 1.25rem;
      border-radius: var(--radius-md);
    `;
    controlsBar.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.15rem;">
        <span style="font-size: 0.9rem; font-weight: 600; color: var(--text-primary);">Binary Patching Engine</span>
        <div id="patcher-status-text" style="font-size: 0.75rem; color: var(--text-muted);">
          Ready to patch
        </div>
      </div>
      <div style="display: flex; gap: 0.75rem;">
        <button class="patch-btn" id="patcher-clear-btn">
          🗑️ Clear All
        </button>
        <button class="patch-btn patch-btn-primary" id="patcher-export-btn">
          📥 Export Patched Binary
        </button>
      </div>
    `;
    this.rootEl.appendChild(controlsBar);

    // Grid layout
    const grid = document.createElement('div');
    grid.className = 'patcher-grid';

    // Left Column: Apply Patch Form
    const leftCol = document.createElement('div');
    leftCol.className = 'patcher-column';
    leftCol.innerHTML = `
      <div class="patcher-card" style="height: 100%; justify-content: flex-start; gap: 1.25rem;">
        <div class="patcher-card-title">Apply Custom Patch</div>
        
        <div class="patch-form-group">
          <label class="patch-label">Target Address (Hex, e.g. 0x1000 or Offset)</label>
          <input type="text" class="patch-input" id="patch-addr-input" placeholder="0x1000" />
        </div>
        
        <div class="patch-form-group">
          <label class="patch-label">Instruction / Hex Bytes (e.g. "nop" or "90 90")</label>
          <input type="text" class="patch-input" id="patch-bytes-input" placeholder="e.g. nop, 90 90, 31 C0" />
        </div>
        
        <div class="patch-form-group">
          <label class="patch-label">Patch Description / Note</label>
          <input type="text" class="patch-input" id="patch-desc-input" placeholder="e.g. bypass check, nop function" />
        </div>
        
        <button class="patch-btn patch-btn-primary" id="patcher-apply-btn" style="margin-top: 1rem; width: 100%;">
          🛠️ Apply Patch
        </button>
      </div>
    `;
    grid.appendChild(leftCol);

    // Right Column: Patch History
    const rightCol = document.createElement('div');
    rightCol.className = 'patcher-column';
    rightCol.innerHTML = `
      <div class="patcher-card" style="height: 100%; min-height: 0;">
        <div class="patcher-card-title">Patch History</div>
        <div class="patch-history-list" id="patch-history-list"></div>
      </div>
    `;
    grid.appendChild(rightCol);

    this.rootEl.appendChild(grid);
    this.container.appendChild(this.rootEl);

    // Cache elements
    this.historyListEl = this.rootEl.querySelector(
      '#patch-history-list'
    ) as HTMLDivElement;
    this.patchAddressInput = this.rootEl.querySelector(
      '#patch-addr-input'
    ) as HTMLInputElement;
    this.patchBytesInput = this.rootEl.querySelector(
      '#patch-bytes-input'
    ) as HTMLInputElement;
    this.patchDescInput = this.rootEl.querySelector(
      '#patch-desc-input'
    ) as HTMLInputElement;
    this.applyBtn = this.rootEl.querySelector(
      '#patcher-apply-btn'
    ) as HTMLButtonElement;
    this.exportBtn = this.rootEl.querySelector(
      '#patcher-export-btn'
    ) as HTMLButtonElement;
    this.clearBtn = this.rootEl.querySelector(
      '#patcher-clear-btn'
    ) as HTMLButtonElement;
    this.statusTextEl = this.rootEl.querySelector(
      '#patcher-status-text'
    ) as HTMLDivElement;
  }

  private setupEvents() {
    this.applyBtn.addEventListener('click', () => this.handleApplyPatch());
    this.exportBtn.addEventListener('click', () => {
      this.patcher.exportBinary(this.currentFilename);
    });
    this.clearBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to clear all patches?')) {
        this.patcher.clearAll();
        this.renderHistory();
        this.options.onPatchApplied(
          this.patcher.getPatchedBinary(),
          this.patcher.getHistory()
        );
      }
    });

    // History event delegation
    this.historyListEl.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const item = target.closest('.patch-history-item');
      if (!item) return;
      const patchId = item.getAttribute('data-id');
      if (!patchId) return;

      if (
        target.classList.contains('toggle-btn') ||
        target.closest('.toggle-btn')
      ) {
        this.patcher.togglePatch(patchId);
        this.renderHistory();
        this.options.onPatchApplied(
          this.patcher.getPatchedBinary(),
          this.patcher.getHistory()
        );
      } else if (
        target.classList.contains('patch-btn-danger') ||
        target.closest('.patch-btn-danger')
      ) {
        this.patcher.removePatch(patchId);
        this.renderHistory();
        this.options.onPatchApplied(
          this.patcher.getPatchedBinary(),
          this.patcher.getHistory()
        );
      }
    });
  }

  private handleApplyPatch() {
    const addrStr = this.patchAddressInput.value.trim();
    const bytesStr = this.patchBytesInput.value.trim();
    const descStr = this.patchDescInput.value.trim() || 'Custom manual patch';

    if (!addrStr) {
      alert('Please specify a target address/offset.');
      return;
    }
    if (!bytesStr) {
      alert('Please specify instruction or hex bytes.');
      return;
    }

    try {
      // Parse address/offset
      let address = parseInt(
        addrStr.startsWith('0x') ? addrStr : '0x' + addrStr,
        16
      );
      if (isNaN(address)) {
        address = parseInt(addrStr, 10);
      }
      if (isNaN(address)) {
        throw new Error('Invalid address format');
      }

      // Convert virtual address to file offset
      let offset = address;
      let foundSection = false;

      // If we have sections, we need to translate Virtual Address -> Offset
      if (this.sections.length > 0) {
        for (const s of this.sections) {
          if (
            address >= s.virtualAddress &&
            address < s.virtualAddress + s.fileSize
          ) {
            offset = address - s.virtualAddress + s.fileOffset;
            foundSection = true;
            break;
          }
        }
      }

      // Fallback or validation
      if (offset < 0 || offset >= this.patcher.getOriginalBinary().length) {
        if (address >= 0 && address < this.patcher.getOriginalBinary().length) {
          offset = address; // treat address directly as file offset
        } else {
          throw new Error('Target address/offset is out of binary bounds.');
        }
      }

      const parsedBytes = BinaryPatcher.parseInput(
        bytesStr,
        this.currentArchitecture
      );

      const record = this.patcher.applyPatch(
        offset,
        parsedBytes,
        address,
        descStr
      );

      this.statusTextEl.textContent = `Applied patch ${record.id} at 0x${address.toString(16)}`;
      this.renderHistory();

      // Reset input fields but keep address
      this.patchBytesInput.value = '';
      this.patchDescInput.value = '';

      this.options.onPatchApplied(
        this.patcher.getPatchedBinary(),
        this.patcher.getHistory()
      );
    } catch (err: any) {
      alert('Failed to apply patch: ' + err.message);
    }
  }

  private renderHistory() {
    this.historyListEl.innerHTML = '';
    const history = this.patcher.getHistory();

    if (history.length === 0) {
      this.historyListEl.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); font-size: 0.85rem; padding: 2rem; border: 1px dashed rgba(255,255,255,0.05); border-radius: var(--radius-sm);">
          <span>No patch history. Applied patches will appear here.</span>
        </div>
      `;
      return;
    }

    // Render each record
    for (const record of history) {
      const item = document.createElement('div');
      item.className = 'patch-history-item';
      item.setAttribute('data-id', record.id);

      const origHex = Array.from(record.originalBytes)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');
      const patHex = Array.from(record.patchedBytes)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');

      item.innerHTML = `
        <div class="patch-info">
          <span class="patch-addr-offset">Address: 0x${record.address.toString(16)} (Offset: 0x${record.offset.toString(16)})</span>
          <div class="patch-byte-diff">
            <span class="bytes-red">${origHex}</span>
            <span style="color: var(--text-muted);">➔</span>
            <span class="bytes-green">${patHex}</span>
          </div>
          <span class="patch-desc-text">${record.description}</span>
        </div>
        <div class="patch-actions">
          <button class="toggle-btn ${record.active ? 'active' : ''}" title="${record.active ? 'Deactivate' : 'Activate'}">
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </button>
          <button class="patch-btn patch-btn-danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" title="Remove Patch">
            Remove
          </button>
        </div>
      `;
      this.historyListEl.appendChild(item);
    }
  }
}
