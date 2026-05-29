import { Section, SectionFlags } from '../disassembler/types.js';

export interface MemoryMapOptions {
  onNavigate?: (offset: number, address: number) => void;
  onClose?: () => void;
}

export class MemoryMapOverlay {
  private container: HTMLElement | null = null;
  private overlayEl!: HTMLDivElement;
  private binaryData: Uint8Array;
  private sections: Section[];
  private options: MemoryMapOptions;

  // View state
  private colorMode: 'section' | 'entropy' | 'permission' = 'section';
  private hoveredCellIndex: number | null = null;
  private cellsCount = 512;
  private cellBytesSize = 0;

  constructor(
    binaryData: Uint8Array,
    sections: Section[],
    options: MemoryMapOptions = {}
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    this.options = options;
    this.cellBytesSize = Math.max(
      1,
      Math.ceil(this.binaryData.length / this.cellsCount)
    );

    this.injectStyles();
    this.createOverlayDOM();
    this.setupEvents();
    this.render();
  }

  private injectStyles() {
    if (document.getElementById('memory-map-styles')) return;

    const style = document.createElement('style');
    style.id = 'memory-map-styles';
    style.textContent = `
      .mem-map-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(10, 12, 16, 0.7);
        backdrop-filter: blur(12px) saturate(160%);
        -webkit-backdrop-filter: blur(12px) saturate(160%);
        z-index: 9999;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        pointer-events: none;
        transition: opacity var(--transition-normal, 0.25s) ease;
        padding: 2rem;
        box-sizing: border-box;
      }
      .mem-map-overlay.active {
        opacity: 1;
        pointer-events: auto;
      }
      .mem-map-card {
        background: rgba(22, 26, 33, 0.9);
        border: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        border-radius: var(--radius-lg, 18px);
        width: 1000px;
        max-width: 95vw;
        height: 700px;
        max-height: 90vh;
        display: grid;
        grid-template-columns: 1fr 280px;
        grid-template-rows: auto 1fr;
        grid-template-areas: 
          "header header"
          "grid sidebar";
        overflow: hidden;
        animation: scaleIn 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
      }
      @keyframes scaleIn {
        from { transform: scale(0.95); opacity: 0; }
        to { transform: scale(1); opacity: 1; }
      }
      .mem-map-header {
        grid-area: header;
        padding: 1.25rem 1.75rem;
        border-bottom: 1px solid var(--border-color, rgba(255, 255, 255, 0.08));
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: rgba(15, 17, 21, 0.4);
      }
      .mem-map-title {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      .mem-map-title h3 {
        margin: 0;
        font-family: var(--font-sans);
        font-size: 1.2rem;
        background: linear-gradient(135deg, #a5b4fc, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }
      .mem-map-controls {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }
      .control-btn {
        background: rgba(255, 255, 255, 0.04);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: var(--text-muted, #94a3b8);
        padding: 0.35rem 0.85rem;
        border-radius: var(--radius-sm, 6px);
        font-size: 0.8rem;
        font-weight: 600;
        cursor: pointer;
        transition: all var(--transition-fast, 0.15s) ease;
      }
      .control-btn:hover {
        background: rgba(255, 255, 255, 0.08);
        color: var(--text-primary, #f8fafc);
        border-color: rgba(255, 255, 255, 0.16);
      }
      .control-btn.active {
        background: rgba(99, 102, 241, 0.15);
        color: #a5b4fc;
        border-color: #6366f1;
      }
      .close-btn {
        background: transparent;
        border: none;
        color: var(--text-muted, #94a3b8);
        font-size: 1.5rem;
        cursor: pointer;
        transition: color var(--transition-fast, 0.15s) ease;
        line-height: 1;
        padding: 0.25rem;
      }
      .close-btn:hover {
        color: var(--error, #ef4444);
      }
      .mem-map-grid-container {
        grid-area: grid;
        padding: 1.75rem;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
      }
      .mem-map-bar-wrapper {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
      }
      .bar-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-disabled, #475569);
        letter-spacing: 0.05em;
        font-weight: 700;
      }
      .mem-map-bar {
        display: flex;
        height: 24px;
        border-radius: var(--radius-sm, 6px);
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
        background: rgba(0, 0, 0, 0.2);
      }
      .mem-map-bar-segment {
        height: 100%;
        cursor: pointer;
        transition: opacity var(--transition-fast, 0.15s);
        position: relative;
      }
      .mem-map-bar-segment:hover {
        opacity: 0.85;
      }
      .grid-layout {
        display: grid;
        grid-template-columns: repeat(32, 1fr);
        gap: 4px;
        background: rgba(0, 0, 0, 0.25);
        padding: 1rem;
        border-radius: var(--radius-md, 12px);
        border: 1px solid rgba(255, 255, 255, 0.04);
      }
      .grid-cell {
        aspect-ratio: 1;
        border-radius: 2px;
        cursor: pointer;
        transition: transform 0.1s ease, box-shadow 0.1s ease;
        position: relative;
      }
      .grid-cell:hover {
        transform: scale(1.2);
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.5);
        z-index: 10;
        outline: 1px solid rgba(255, 255, 255, 0.6);
      }
      .mem-map-sidebar {
        grid-area: sidebar;
        border-left: 1px solid var(--border-color, rgba(255, 255, 255, 0.08));
        background: rgba(15, 17, 21, 0.25);
        padding: 1.5rem;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
        overflow-y: auto;
      }
      .sidebar-title {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-disabled, #475569);
        letter-spacing: 0.05em;
        font-weight: 700;
        border-bottom: 1px solid rgba(255, 255, 255, 0.06);
        padding-bottom: 0.5rem;
      }
      .info-field {
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
      }
      .info-label {
        font-size: 0.7rem;
        color: var(--text-muted, #94a3b8);
      }
      .info-value {
        font-size: 0.85rem;
        font-weight: 600;
        font-family: var(--font-mono, monospace);
        color: var(--text-primary, #f8fafc);
        word-break: break-all;
      }
      .bytes-preview-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 4px;
        font-family: var(--font-mono, monospace);
        font-size: 0.75rem;
        text-align: center;
        background: rgba(0, 0, 0, 0.3);
        padding: 0.5rem;
        border-radius: var(--radius-sm, 6px);
        border: 1px solid rgba(255, 255, 255, 0.04);
      }
      .bytes-preview-cell {
        color: #a5b4fc;
        padding: 2px 0;
      }
      .legend-container {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        margin-top: auto;
        padding-top: 1rem;
        border-top: 1px solid rgba(255, 255, 255, 0.06);
      }
      .legend-item {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.75rem;
        color: var(--text-muted, #94a3b8);
      }
      .legend-color {
        width: 12px;
        height: 12px;
        border-radius: 2px;
      }
    `;
    document.head.appendChild(style);
  }

  private createOverlayDOM() {
    this.overlayEl = document.createElement('div');
    this.overlayEl.className = 'mem-map-overlay';

    this.overlayEl.innerHTML = `
      <div class="mem-map-card">
        <header class="mem-map-header">
          <div class="mem-map-title">
            <span>🗺️</span>
            <h3>Binary Memory Map & Entropy Visualizer</h3>
          </div>
          <div class="mem-map-controls">
            <button class="control-btn active" data-mode="section">Sections</button>
            <button class="control-btn" data-mode="entropy">Entropy Heatmap</button>
            <button class="control-btn" data-mode="permission">Permissions</button>
            <button class="close-btn" style="margin-left: 0.5rem;">&times;</button>
          </div>
        </header>

        <div class="mem-map-grid-container">
          <!-- Proportional Section Bar -->
          <div class="mem-map-bar-wrapper">
            <div class="bar-label">Binary Section Proportions</div>
            <div class="mem-map-bar" id="mem-map-section-bar"></div>
          </div>

          <!-- The main detailed address space grid -->
          <div class="mem-map-bar-wrapper">
            <div class="bar-label">Interactive Address Space Grid (Each Block = <span id="cell-size-label">0</span> bytes)</div>
            <div class="grid-layout" id="mem-map-grid"></div>
          </div>
        </div>

        <aside class="mem-map-sidebar">
          <div class="sidebar-title">Segment Inspector</div>
          
          <div class="info-field">
            <span class="info-label">Section</span>
            <span class="info-value" id="inspect-section">-</span>
          </div>

          <div class="info-field">
            <span class="info-label">Offset Range</span>
            <span class="info-value" id="inspect-offsets">-</span>
          </div>

          <div class="info-field">
            <span class="info-label">Virtual Addresses</span>
            <span class="info-value" id="inspect-addresses">-</span>
          </div>

          <div class="info-field">
            <span class="info-label">Permissions</span>
            <span class="info-value" id="inspect-perms">-</span>
          </div>

          <div class="info-field">
            <span class="info-label">Local Entropy</span>
            <span class="info-value" id="inspect-entropy">-</span>
          </div>

          <div class="info-field">
            <span class="info-label">Data Preview (Hex)</span>
            <div class="bytes-preview-grid" id="inspect-preview">
              <span style="grid-column: span 4; color: var(--text-disabled, #475569);">Hover a block</span>
            </div>
          </div>

          <div class="legend-container" id="legend-box"></div>
        </aside>
      </div>
    `;

    document.body.appendChild(this.overlayEl);
  }

  private setupEvents() {
    // Mode toggling buttons
    const modeBtns = this.overlayEl.querySelectorAll('.control-btn');
    modeBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget as HTMLButtonElement;
        const mode = target.dataset.mode as any;
        if (mode) {
          modeBtns.forEach((b) => b.classList.remove('active'));
          target.classList.add('active');
          this.colorMode = mode;
          this.render();
        }
      });
    });

    // Close button
    const closeBtn = this.overlayEl.querySelector('.close-btn');
    closeBtn?.addEventListener('click', () => {
      this.hide();
    });

    // Close on overlay clicking outside card
    this.overlayEl.addEventListener('click', (e) => {
      if (e.target === this.overlayEl) {
        this.hide();
      }
    });
  }

  public show(container: HTMLElement | null = null) {
    this.container = container;
    this.overlayEl.classList.add('active');
    // Calculate sizing dynamically in case state changed
    this.cellBytesSize = Math.max(
      1,
      Math.ceil(this.binaryData.length / this.cellsCount)
    );
    const sizeLabel = this.overlayEl.querySelector('#cell-size-label');
    if (sizeLabel) sizeLabel.textContent = this.cellBytesSize.toLocaleString();
    this.render();
  }

  public hide() {
    this.overlayEl.classList.remove('active');
    if (this.options.onClose) {
      this.options.onClose();
    }
  }

  // Get color configuration based on current view modes
  private getSectionColor(sectionName: string): string {
    const s = sectionName.toLowerCase();
    if (s.includes('text') || s.includes('code')) return '#6366f1'; // Indigo
    if (s.includes('data')) {
      if (s.includes('rodata')) return '#14b8a6'; // Teal
      return '#f59e0b'; // Amber
    }
    if (s.includes('bss')) return '#3b82f6'; // Blue
    if (s.includes('idata') || s.includes('edata')) return '#ec4899'; // Pink
    if (s.includes('rsrc')) return '#06b6d4'; // Cyan
    if (s.includes('reloc')) return '#8b5cf6'; // Violet
    return '#6b7280'; // Gray
  }

  private getPermissionColor(flags: SectionFlags): string {
    if (flags.execute) return '#818cf8'; // Executable - purple-ish blue
    if (flags.write) return '#f87171'; // Writeable - red/orange-ish
    if (flags.read) return '#34d399'; // Read only - green-ish
    return '#475569'; // No access/other - gray
  }

  private getEntropyColor(entropy: number): string {
    // scale entropy from 0.0 - 8.0 into a blue->red gradient
    const ratio = Math.min(1, Math.max(0, entropy / 8.0));
    // HSL representation: 220 (cool blue) down to 0 (vibrant red/orange)
    const hue = 220 - ratio * 220;
    return `hsl(${hue}, 85%, 50%)`;
  }

  // Calculate local Shannon entropy for a block of binaryData
  private calculateLocalEntropy(
    offsetStart: number,
    offsetEnd: number
  ): number {
    const slice = this.binaryData.slice(offsetStart, offsetEnd);
    if (slice.length === 0) return 0;
    const counts = new Uint32Array(256);
    for (let i = 0; i < slice.length; i++) {
      counts[slice[i]]++;
    }
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (counts[i] > 0) {
        const p = counts[i] / slice.length;
        entropy -= p * Math.log2(p);
      }
    }
    return entropy;
  }

  private getSectionForOffset(offset: number): Section | null {
    // Find section containing the offset
    for (const section of this.sections) {
      if (
        offset >= section.fileOffset &&
        offset < section.fileOffset + section.fileSize
      ) {
        return section;
      }
    }
    return null;
  }

  private render() {
    this.renderSectionBar();
    this.renderGrid();
    this.renderLegend();
    this.updateInspector();
  }

  private renderSectionBar() {
    const bar = this.overlayEl.querySelector('#mem-map-section-bar')!;
    bar.innerHTML = '';

    if (this.sections.length === 0) {
      bar.innerHTML = `<div style="padding: 4px; color: var(--text-muted); font-size: 0.75rem;">No sections defined</div>`;
      return;
    }

    const totalSize = Math.max(1, this.binaryData.length);
    const sorted = [...this.sections].sort(
      (a, b) => a.fileOffset - b.fileOffset
    );

    // Render bar segments representing each section
    sorted.forEach((section) => {
      const pct = (section.fileSize / totalSize) * 100;
      if (pct < 0.1) return; // Skip tiny sections to look clean

      const segment = document.createElement('div');
      segment.className = 'mem-map-bar-segment';
      segment.style.width = `${pct}%`;
      segment.style.backgroundColor = this.getSectionColor(section.name);
      segment.title = `${section.name} (0x${section.fileOffset.toString(16)} - Size: ${section.fileSize})`;

      segment.addEventListener('click', () => {
        this.navigateToOffset(section.fileOffset);
      });

      bar.appendChild(segment);
    });
  }

  private renderGrid() {
    const grid = this.overlayEl.querySelector('#mem-map-grid')!;
    grid.innerHTML = '';

    const cellsFrag = document.createDocumentFragment();

    for (let i = 0; i < this.cellsCount; i++) {
      const cellStart = i * this.cellBytesSize;
      const cellEnd = Math.min(
        this.binaryData.length,
        cellStart + this.cellBytesSize
      );
      if (cellStart >= this.binaryData.length) break;

      const cell = document.createElement('div');
      cell.className = 'grid-cell';
      cell.dataset.cellIndex = i.toString();

      // Find section & calculate properties
      const midOffset = Math.floor((cellStart + cellEnd) / 2);
      const section = this.getSectionForOffset(midOffset);
      const entropy = this.calculateLocalEntropy(cellStart, cellEnd);

      // Color mapping
      let color = '#334155'; // Background gray
      if (this.colorMode === 'section') {
        color = section ? this.getSectionColor(section.name) : '#334155';
      } else if (this.colorMode === 'entropy') {
        color = this.getEntropyColor(entropy);
      } else if (this.colorMode === 'permission') {
        color = section ? this.getPermissionColor(section.flags) : '#475569';
      }

      cell.style.backgroundColor = color;

      // Click to navigate
      cell.addEventListener('click', () => {
        this.navigateToOffset(cellStart);
      });

      // Hover updates inspector
      cell.addEventListener('mouseenter', () => {
        this.hoveredCellIndex = i;
        this.updateInspector();
      });

      cellsFrag.appendChild(cell);
    }

    grid.appendChild(cellsFrag);
  }

  private renderLegend() {
    const legend = this.overlayEl.querySelector('#legend-box')!;
    legend.innerHTML = '';

    const title = document.createElement('div');
    title.className = 'sidebar-title';
    title.textContent = 'Map Legend';
    legend.appendChild(title);

    if (this.colorMode === 'section') {
      // Find all unique section names we colorized
      const uniqueNames = Array.from(new Set(this.sections.map((s) => s.name)));
      if (uniqueNames.length === 0) uniqueNames.push('Default');
      uniqueNames.forEach((name) => {
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `
          <div class="legend-color" style="background-color: ${this.getSectionColor(name)}"></div>
          <span>${name}</span>
        `;
        legend.appendChild(item);
      });
    } else if (this.colorMode === 'entropy') {
      const states = [
        { label: 'Low (0.0 - 2.0)', color: this.getEntropyColor(1.0) },
        { label: 'Medium (2.0 - 5.0)', color: this.getEntropyColor(3.5) },
        { label: 'High (5.0 - 7.0)', color: this.getEntropyColor(6.0) },
        {
          label: 'Packed/Encrypted (7.0 - 8.0)',
          color: this.getEntropyColor(7.8),
        },
      ];
      states.forEach((state) => {
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `
          <div class="legend-color" style="background-color: ${state.color}"></div>
          <span>${state.label}</span>
        `;
        legend.appendChild(item);
      });
    } else if (this.colorMode === 'permission') {
      const perms = [
        { label: 'R-X (Code / Executable)', color: '#818cf8' },
        { label: 'RW- (Data / Read-Write)', color: '#f87171' },
        { label: 'R-- (Read-Only Data)', color: '#34d399' },
        { label: '--- (No permissions/Other)', color: '#475569' },
      ];
      perms.forEach((perm) => {
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `
          <div class="legend-color" style="background-color: ${perm.color}"></div>
          <span>${perm.label}</span>
        `;
        legend.appendChild(item);
      });
    }
  }

  private updateInspector() {
    const secEl = this.overlayEl.querySelector('#inspect-section')!;
    const offsetsEl = this.overlayEl.querySelector('#inspect-offsets')!;
    const addrsEl = this.overlayEl.querySelector('#inspect-addresses')!;
    const permsEl = this.overlayEl.querySelector('#inspect-perms')!;
    const entrEl = this.overlayEl.querySelector('#inspect-entropy')!;
    const previewEl = this.overlayEl.querySelector('#inspect-preview')!;

    if (this.hoveredCellIndex === null) {
      secEl.textContent = '-';
      offsetsEl.textContent = '-';
      addrsEl.textContent = '-';
      permsEl.textContent = '-';
      entrEl.textContent = '-';
      previewEl.innerHTML = `<span style="grid-column: span 4; color: var(--text-disabled);">Hover a block</span>`;
      return;
    }

    const cellStart = this.hoveredCellIndex * this.cellBytesSize;
    const cellEnd = Math.min(
      this.binaryData.length,
      cellStart + this.cellBytesSize
    );

    const midOffset = Math.floor((cellStart + cellEnd) / 2);
    const section = this.getSectionForOffset(midOffset);
    const entropy = this.calculateLocalEntropy(cellStart, cellEnd);

    secEl.textContent = section ? section.name : 'Raw binary (No Section)';
    offsetsEl.textContent = `0x${cellStart.toString(16).toUpperCase()} - 0x${Math.max(
      0,
      cellEnd - 1
    )
      .toString(16)
      .toUpperCase()}`;

    // Map file offsets to virtual addresses if sections align
    if (section) {
      const vStart = section.virtualAddress + (cellStart - section.fileOffset);
      const vEnd = section.virtualAddress + (cellEnd - section.fileOffset);
      addrsEl.textContent = `0x${vStart.toString(16).toUpperCase()} - 0x${Math.max(
        0,
        vEnd - 1
      )
        .toString(16)
        .toUpperCase()}`;
      permsEl.textContent = `${section.flags.read ? 'R' : '-'}${section.flags.write ? 'W' : '-'}${section.flags.execute ? 'X' : '-'}`;
    } else {
      addrsEl.textContent = 'N/A';
      permsEl.textContent = 'R--';
    }

    entrEl.textContent = `${entropy.toFixed(4)} / 8.0000`;

    // Hex preview of the first 16 bytes in this cell
    const previewSlice = this.binaryData.slice(cellStart, cellStart + 16);
    previewEl.innerHTML = '';

    if (previewSlice.length === 0) {
      previewEl.innerHTML = `<span style="grid-column: span 4; color: var(--text-disabled);">No data</span>`;
      return;
    }

    previewSlice.forEach((byte) => {
      const cell = document.createElement('span');
      cell.className = 'bytes-preview-cell';
      cell.textContent = byte.toString(16).toUpperCase().padStart(2, '0');
      previewEl.appendChild(cell);
    });
  }

  private navigateToOffset(offset: number) {
    let address = 0x1000;
    // Resolve virtual address if in a section
    const section = this.getSectionForOffset(offset);
    if (section) {
      address = section.virtualAddress + (offset - section.fileOffset);
    } else {
      // fallback calculation
      const execSec = this.sections.find((s) => s.flags.execute);
      if (execSec) {
        address = execSec.virtualAddress + offset;
      } else {
        address = 0x1000 + offset;
      }
    }

    if (this.options.onNavigate) {
      this.options.onNavigate(offset, address);
    }
    this.hide();
  }
}
