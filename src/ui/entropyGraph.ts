/**
 * Premium, interactive Entropy Graph Visualizer component.
 * Displays Shannon entropy across binary offsets in an interactive HTML5 Canvas.
 * Supports window size/threshold controls, hover inspect, and jumping to Hex/Assembly.
 */

import { Section } from '../disassembler/types.js';
import {
  calculateEntropy,
  findHighEntropyBlocks,
  EntropyBlock,
} from '../analyzer/entropy.js';

export interface EntropyGraphOptions {
  onNavigate?: (offset: number, targetView: 'hex' | 'assembly') => void;
}

export class EntropyGraph {
  private container: HTMLElement;
  private data: Uint8Array;
  private sections: Section[];
  private options: EntropyGraphOptions;

  // Configuration state
  private windowSize = 256;
  private stride = 128;
  private threshold = 7.2;

  // Component State
  private entropyBlocks: EntropyBlock[] = [];
  private hoveredBlock: EntropyBlock | null = null;
  private selectedBlock: EntropyBlock | null = null;

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private canvas!: HTMLCanvasElement;
  private blocksListContainer!: HTMLDivElement;
  private sectionsListContainer!: HTMLDivElement;
  private windowSelect!: HTMLSelectElement;
  private thresholdInput!: HTMLInputElement;

  constructor(
    container: HTMLElement,
    data: Uint8Array,
    sections: Section[],
    options: EntropyGraphOptions = {}
  ) {
    this.container = container;
    this.data = data;
    this.sections = sections;
    this.options = options;

    this.initLayout();
    this.recalculate();
    this.setupEventListeners();
    this.draw();
  }

  /**
   * Re-analyzes binary data and finds blocks/sections
   */
  private recalculate() {
    this.stride = Math.max(32, Math.floor(this.windowSize / 2));

    // Scan the binary for sliding-window entropy blocks
    this.entropyBlocks = findHighEntropyBlocks(this.data, {
      blockSize: this.windowSize,
      stride: this.stride,
      threshold: this.threshold,
    });

    this.renderSidebar();
  }

  /**
   * Sets new binary data and sections
   */
  public updateData(data: Uint8Array, sections: Section[]) {
    this.data = data;
    this.sections = sections;
    this.hoveredBlock = null;
    this.selectedBlock = null;
    this.recalculate();
    this.resizeCanvas();
    this.draw();
  }

  private initLayout() {
    this.container.innerHTML = '';

    // Inject Styles if needed
    if (!document.getElementById('entropy-graph-styles')) {
      const style = document.createElement('style');
      style.id = 'entropy-graph-styles';
      style.textContent = `
        .entropy-graph-root {
          display: flex;
          width: 100%;
          height: 100%;
          background: var(--bg-primary, #090d16);
          border: 1px solid var(--border-color, #1e293b);
          border-radius: var(--radius-md, 8px);
          overflow: hidden;
          font-family: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif);
          color: var(--text-primary, #f8fafc);
        }
        .entropy-graph-main {
          flex: 1;
          display: flex;
          flex-direction: column;
          padding: 1.5rem;
          min-width: 0;
          height: 100%;
          box-sizing: border-box;
        }
        .entropy-graph-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1.25rem;
          gap: 1rem;
        }
        .entropy-title-area h3 {
          margin: 0;
          font-size: 1.2rem;
          font-weight: 700;
          background: linear-gradient(135deg, #a78bfa 0%, #6366f1 100%);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
        }
        .entropy-subtitle {
          font-size: 0.75rem;
          color: var(--text-muted, #94a3b8);
          margin-top: 0.25rem;
          display: block;
        }
        .entropy-controls {
          display: flex;
          align-items: center;
          gap: 1.25rem;
          background: rgba(15, 23, 42, 0.4);
          padding: 0.5rem 1rem;
          border-radius: var(--radius-sm, 6px);
          border: 1px solid var(--border-color, #1e293b);
        }
        .entropy-controls label {
          font-size: 0.75rem;
          color: var(--text-secondary, #cbd5e1);
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-weight: 600;
        }
        .entropy-controls select, .entropy-controls input {
          background: rgba(30, 41, 59, 0.7);
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: var(--text-primary, #f8fafc);
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
          font-size: 0.75rem;
          outline: none;
          transition: border-color 0.15s ease;
        }
        .entropy-controls select:focus, .entropy-controls input:focus {
          border-color: #6366f1;
        }
        .canvas-container {
          flex: 1;
          position: relative;
          background: rgba(15, 23, 42, 0.3);
          border-radius: 6px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          overflow: hidden;
          min-height: 250px;
        }
        .canvas-container canvas {
          display: block;
          width: 100%;
          height: 100%;
          cursor: crosshair;
        }
        .entropy-sidebar {
          width: 320px;
          border-left: 1px solid var(--border-color, #1e293b);
          background: rgba(15, 23, 42, 0.25);
          display: flex;
          flex-direction: column;
          height: 100%;
          box-sizing: border-box;
        }
        .entropy-sidebar-title, .entropy-sections-title {
          font-size: 0.8rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: var(--text-disabled, #64748b);
          padding: 1rem 1.25rem 0.5rem 1.25rem;
          border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }
        .entropy-sections-title {
          border-top: 1px solid var(--border-color, #1e293b);
          margin-top: auto;
        }
        .entropy-blocks-list, .entropy-sections-list {
          flex: 1;
          overflow-y: auto;
          padding: 0.75rem 1.25rem;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }
        .entropy-sections-list {
          flex: 0 0 160px;
          max-height: 160px;
        }
        .entropy-block-card, .entropy-section-card {
          background: rgba(30, 41, 59, 0.3);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: 6px;
          padding: 0.65rem 0.85rem;
          transition: all 0.2s ease;
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .entropy-block-card:hover, .entropy-section-card:hover {
          background: rgba(30, 41, 59, 0.6);
          border-color: rgba(99, 102, 241, 0.3);
          transform: translateY(-1px);
        }
        .entropy-block-card.high-entropy {
          border-left: 3px solid #ef4444;
        }
        .card-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .card-title {
          font-size: 0.8rem;
          font-weight: 600;
          font-family: var(--font-mono, monospace);
          color: #f1f5f9;
        }
        .card-val {
          font-size: 0.75rem;
          font-weight: 700;
          font-family: var(--font-mono, monospace);
        }
        .card-val.high {
          color: #ef4444;
        }
        .card-val.normal {
          color: #10b981;
        }
        .card-subtext {
          font-size: 0.7rem;
          color: var(--text-muted, #94a3b8);
          font-family: var(--font-mono, monospace);
        }
        .card-actions {
          display: flex;
          gap: 0.5rem;
          margin-top: 0.4rem;
        }
        .card-btn {
          background: rgba(99, 102, 241, 0.15);
          border: 1px solid rgba(99, 102, 241, 0.3);
          color: #c7d2fe;
          font-size: 0.65rem;
          padding: 0.2rem 0.5rem;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 600;
          transition: all 0.15s ease;
        }
        .card-btn:hover {
          background: #6366f1;
          color: white;
        }
        .entropy-blocks-list::-webkit-scrollbar, .entropy-sections-list::-webkit-scrollbar {
          width: 6px;
        }
        .entropy-blocks-list::-webkit-scrollbar-thumb, .entropy-sections-list::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.1);
          border-radius: 3px;
        }
        .entropy-blocks-list::-webkit-scrollbar-thumb:hover, .entropy-sections-list::-webkit-scrollbar-thumb:hover {
          background: rgba(255, 255, 255, 0.25);
        }
      `;
      document.head.appendChild(style);
    }

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'entropy-graph-root';

    // Left side panel
    const mainEl = document.createElement('div');
    mainEl.className = 'entropy-graph-main';
    mainEl.innerHTML = `
      <div class="entropy-graph-header">
        <div class="entropy-title-area">
          <h3>📊 Shannon Entropy Analysis</h3>
          <span class="entropy-subtitle">Visualizes byte-level information density. Red peaks highlight encrypted or compressed structures.</span>
        </div>
        <div class="entropy-controls">
          <label>Window:
            <select id="entropy-window-select">
              <option value="128">128 Bytes</option>
              <option value="256" selected>256 Bytes</option>
              <option value="512">512 Bytes</option>
              <option value="1024">1024 Bytes</option>
            </select>
          </label>
          <label>Threshold:
            <input type="number" id="entropy-threshold-input" min="5.0" max="8.0" step="0.1" value="7.2" style="width: 50px;" />
          </label>
        </div>
      </div>
      <div class="canvas-container">
        <canvas id="entropy-canvas"></canvas>
      </div>
    `;

    // Right side sidebar
    const sidebarEl = document.createElement('div');
    sidebarEl.className = 'entropy-sidebar';
    sidebarEl.innerHTML = `
      <div class="entropy-sidebar-title">🛡️ High Entropy Zones</div>
      <div class="entropy-blocks-list" id="entropy-blocks-list"></div>
      <div class="entropy-sections-title">📁 Section Entropy</div>
      <div class="entropy-sections-list" id="entropy-sections-list"></div>
    `;

    this.rootEl.appendChild(mainEl);
    this.rootEl.appendChild(sidebarEl);
    this.container.appendChild(this.rootEl);

    // Cache elements
    this.canvas = mainEl.querySelector('#entropy-canvas') as HTMLCanvasElement;
    this.windowSelect = mainEl.querySelector(
      '#entropy-window-select'
    ) as HTMLSelectElement;
    this.thresholdInput = mainEl.querySelector(
      '#entropy-threshold-input'
    ) as HTMLInputElement;
    this.blocksListContainer = sidebarEl.querySelector(
      '#entropy-blocks-list'
    ) as HTMLDivElement;
    this.sectionsListContainer = sidebarEl.querySelector(
      '#entropy-sections-list'
    ) as HTMLDivElement;
  }

  private renderSidebar() {
    // 1. Render High Entropy Blocks list
    this.blocksListContainer.innerHTML = '';
    const highBlocks = this.entropyBlocks.filter((b) => b.isHighEntropy);

    if (highBlocks.length === 0) {
      this.blocksListContainer.innerHTML = `
        <div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; margin-top: 2rem;">
          No blocks above threshold (${this.threshold.toFixed(1)}) found.
        </div>
      `;
    } else {
      highBlocks.forEach((b) => {
        const card = document.createElement('div');
        card.className = 'entropy-block-card high-entropy';

        card.innerHTML = `
          <div class="card-row">
            <span class="card-title">0x${b.start.toString(16).toUpperCase()} - 0x${b.end.toString(16).toUpperCase()}</span>
            <span class="card-val high">${b.entropy.toFixed(3)}</span>
          </div>
          <span class="card-subtext">Offset: ${b.start} | Len: ${b.length} B</span>
          <div class="card-actions">
            <button class="card-btn" data-action="hex" data-offset="${b.start}">Jump to Hex</button>
            <button class="card-btn" data-action="assembly" data-offset="${b.start}">Jump to ASM</button>
          </div>
        `;
        this.blocksListContainer.appendChild(card);
      });
    }

    // 2. Render Section Entropy list
    this.sectionsListContainer.innerHTML = '';
    if (this.sections.length === 0) {
      this.sectionsListContainer.innerHTML = `
        <div style="font-size: 0.75rem; color: var(--text-muted); text-align: center; margin-top: 1rem;">
          No section details available.
        </div>
      `;
    } else {
      this.sections.forEach((s) => {
        const start = s.fileOffset;
        const end = Math.min(start + s.fileSize, this.data.length);
        let secEntropy = 0;
        if (start < this.data.length && start >= 0 && end > start) {
          secEntropy = calculateEntropy(this.data.subarray(start, end));
        }

        const isHigh = secEntropy >= this.threshold;
        const card = document.createElement('div');
        card.className = `entropy-section-card ${isHigh ? 'high-entropy' : ''}`;

        card.innerHTML = `
          <div class="card-row">
            <span class="card-title" style="color: #60a5fa;">${s.name}</span>
            <span class="card-val ${isHigh ? 'high' : 'normal'}">${secEntropy.toFixed(3)}</span>
          </div>
          <span class="card-subtext">Offset: 0x${s.fileOffset.toString(16).toUpperCase()} | Size: ${s.fileSize} B</span>
          <div class="card-actions">
            <button class="card-btn" data-action="hex" data-offset="${s.fileOffset}">Jump to Section</button>
          </div>
        `;
        this.sectionsListContainer.appendChild(card);
      });
    }
  }

  private setupEventListeners() {
    // Window select listener
    this.windowSelect.addEventListener('change', () => {
      this.windowSize = parseInt(this.windowSelect.value);
      this.recalculate();
      this.draw();
    });

    // Threshold input listener
    this.thresholdInput.addEventListener('input', () => {
      const val = parseFloat(this.thresholdInput.value);
      if (!isNaN(val) && val >= 0 && val <= 8) {
        this.threshold = val;
        this.recalculate();
        this.draw();
      }
    });

    // Resize observer to auto-resize canvas
    const resizeObserver = new ResizeObserver(() => {
      this.resizeCanvas();
      this.draw();
    });
    resizeObserver.observe(this.canvas.parentElement!);

    // Mouse interactive events on canvas
    this.canvas.addEventListener('mousemove', (e) => this.handleMouseMove(e));
    this.canvas.addEventListener('mouseleave', () => this.handleMouseLeave());
    this.canvas.addEventListener('click', (e) => this.handleMouseClick(e));

    // Jump buttons listeners in sidebar
    this.blocksListContainer.addEventListener('click', (e) =>
      this.handleSidebarClick(e)
    );
    this.sectionsListContainer.addEventListener('click', (e) =>
      this.handleSidebarClick(e)
    );
  }

  private handleSidebarClick(e: MouseEvent) {
    const btn = (e.target as HTMLElement).closest(
      '.card-btn'
    ) as HTMLButtonElement;
    if (!btn) return;
    const action = btn.dataset.action as 'hex' | 'assembly';
    const offset = parseInt(btn.dataset.offset || '0');
    if (this.options.onNavigate) {
      this.options.onNavigate(offset, action);
    }
  }

  private resizeCanvas() {
    const parent = this.canvas.parentElement!;
    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = parent.clientWidth * dpr;
    this.canvas.height = parent.clientHeight * dpr;
  }

  private handleMouseMove(e: MouseEvent) {
    if (this.entropyBlocks.length === 0) return;

    const rect = this.canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const dpr = window.devicePixelRatio || 1;
    const canvasWidth = this.canvas.width / dpr;
    const padding = { left: 50, right: 20, top: 20, bottom: 40 };
    const chartWidth = canvasWidth - padding.left - padding.right;

    // Check if within chart area
    if (x >= padding.left && x <= padding.left + chartWidth) {
      const pct = (x - padding.left) / chartWidth;
      const index = Math.round(pct * (this.entropyBlocks.length - 1));
      const block = this.entropyBlocks[index];
      if (block) {
        this.hoveredBlock = block;
        this.draw();
      }
    } else {
      this.hoveredBlock = null;
      this.draw();
    }
  }

  private handleMouseLeave() {
    this.hoveredBlock = null;
    this.draw();
  }

  private handleMouseClick(e: MouseEvent) {
    if (this.hoveredBlock && this.options.onNavigate) {
      // By default jump to assembly if execution section, otherwise hex
      const isExec = this.sections.some(
        (s) =>
          this.hoveredBlock!.start >= s.fileOffset &&
          this.hoveredBlock!.start < s.fileOffset + s.fileSize &&
          s.flags.execute
      );
      this.options.onNavigate(
        this.hoveredBlock.start,
        isExec ? 'assembly' : 'hex'
      );
    }
  }

  private draw() {
    const ctx = this.canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    ctx.resetTransform();
    ctx.scale(dpr, dpr);

    const width = this.canvas.width / dpr;
    const height = this.canvas.height / dpr;

    // Clear Canvas
    ctx.clearRect(0, 0, width, height);

    // Padding settings
    const padding = { left: 50, right: 20, top: 20, bottom: 40 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    if (chartWidth <= 0 || chartHeight <= 0) return;

    // 1. Draw Grid lines and Y axis scale
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    ctx.font = '10px monospace';
    ctx.fillStyle = '#64748b';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';

    const yLevels = [0, 2, 4, 6, 8];
    yLevels.forEach((val) => {
      const y = padding.top + chartHeight - (val / 8) * chartHeight;
      // Grid line
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      // Y Axis Label
      ctx.fillText(val.toFixed(1), padding.left - 10, y);
    });

    if (this.entropyBlocks.length === 0) return;

    // 2. Map coordinates for each block
    const coords: { x: number; y: number; block: EntropyBlock }[] = [];
    this.entropyBlocks.forEach((block, idx) => {
      const x =
        padding.left + (idx / (this.entropyBlocks.length - 1)) * chartWidth;
      const y = padding.top + chartHeight - (block.entropy / 8) * chartHeight;
      coords.push({ x, y, block });
    });

    // 3. Draw Threshold horizontal line
    const threshY =
      padding.top + chartHeight - (this.threshold / 8) * chartHeight;
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
    ctx.setLineDash([5, 5]);
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(padding.left, threshY);
    ctx.lineTo(width - padding.right, threshY);
    ctx.stroke();
    ctx.setLineDash([]); // Reset line dash

    // Draw Threshold text label
    ctx.fillStyle = 'rgba(239, 68, 68, 0.8)';
    ctx.font = '9px sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(
      `THRESHOLD (${this.threshold.toFixed(1)})`,
      padding.left + 5,
      threshY - 6
    );

    // 4. Draw Glow shadow & line path
    ctx.beginPath();
    ctx.moveTo(coords[0].x, coords[0].y);
    for (let i = 1; i < coords.length; i++) {
      ctx.lineTo(coords[i].x, coords[i].y);
    }
    ctx.lineTo(coords[coords.length - 1].x, padding.top + chartHeight);
    ctx.lineTo(coords[0].x, padding.top + chartHeight);
    ctx.closePath();

    // Fill gradient
    const fillGrad = ctx.createLinearGradient(
      0,
      padding.top,
      0,
      padding.top + chartHeight
    );
    fillGrad.addColorStop(0, 'rgba(139, 92, 246, 0.25)'); // Indigo/Purple
    fillGrad.addColorStop(1, 'rgba(99, 102, 241, 0.0)');
    ctx.fillStyle = fillGrad;
    ctx.fill();

    // Stroke the line
    ctx.beginPath();
    ctx.moveTo(coords[0].x, coords[0].y);
    for (let i = 1; i < coords.length; i++) {
      ctx.lineTo(coords[i].x, coords[i].y);
    }
    ctx.lineWidth = 2.5;

    // Line gradient style: glow orange/red for high entropy, blue/violet for normal
    const lineGrad = ctx.createLinearGradient(
      padding.left,
      0,
      padding.left + chartWidth,
      0
    );
    coords.forEach((pt) => {
      const progress = (pt.x - padding.left) / chartWidth;
      const color = pt.block.isHighEntropy ? '#ef4444' : '#6366f1';
      lineGrad.addColorStop(Math.min(1, Math.max(0, progress)), color);
    });
    ctx.strokeStyle = lineGrad;
    ctx.stroke();

    // 5. Draw Section backgrounds at the bottom of the chart
    ctx.fillStyle = 'rgba(255, 255, 255, 0.02)';
    ctx.font = '8px monospace';
    ctx.textAlign = 'center';
    this.sections.forEach((s) => {
      const sStartPct = s.fileOffset / this.data.length;
      const sEndPct =
        Math.min(s.fileOffset + s.fileSize, this.data.length) /
        this.data.length;
      const x1 = padding.left + sStartPct * chartWidth;
      const x2 = padding.left + sEndPct * chartWidth;

      if (x2 > x1) {
        ctx.fillStyle = 'rgba(255, 255, 255, 0.02)';
        ctx.fillRect(x1, padding.top, x2 - x1, chartHeight);
        ctx.fillStyle = 'rgba(96, 165, 250, 0.3)';
        ctx.fillText(
          s.name,
          x1 + (x2 - x1) / 2,
          padding.top + chartHeight + 12
        );
      }
    });

    // 6. Draw X axis offset ticks
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    const numTicks = 5;
    for (let i = 0; i < numTicks; i++) {
      const pct = i / (numTicks - 1);
      const offset = Math.round(pct * this.data.length);
      const x = padding.left + pct * chartWidth;
      ctx.fillText(
        `0x${offset.toString(16).toUpperCase()}`,
        x,
        padding.top + chartHeight + 20
      );
    }

    // 7. Interactive Crosshair and Tooltip
    if (this.hoveredBlock) {
      const hoverIdx = this.entropyBlocks.indexOf(this.hoveredBlock);
      const pt = coords[hoverIdx];

      if (pt) {
        // Vertical guide line
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.2)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(pt.x, padding.top);
        ctx.lineTo(pt.x, padding.top + chartHeight);
        ctx.stroke();

        // Highlight dot
        ctx.fillStyle = pt.block.isHighEntropy ? '#ef4444' : '#6366f1';
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 6, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();

        // Find enclosing section if any
        const sec = this.sections.find(
          (s) =>
            pt.block.start >= s.fileOffset &&
            pt.block.start < s.fileOffset + s.fileSize
        );
        const sectionName = sec ? sec.name : 'N/A';

        // Draw Tooltip Box
        const tooltipWidth = 180;
        const tooltipHeight = 90;
        let tooltipX = pt.x + 15;
        let tooltipY = pt.y - tooltipHeight / 2;

        // Keep tooltip inside chart boundaries
        if (tooltipX + tooltipWidth > width) {
          tooltipX = pt.x - tooltipWidth - 15;
        }
        if (tooltipY < padding.top) {
          tooltipY = padding.top;
        }
        if (tooltipY + tooltipHeight > padding.top + chartHeight) {
          tooltipY = padding.top + chartHeight - tooltipHeight;
        }

        ctx.fillStyle = 'rgba(15, 23, 42, 0.9)';
        ctx.strokeStyle = pt.block.isHighEntropy ? '#ef4444' : '#6366f1';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.roundRect(tooltipX, tooltipY, tooltipWidth, tooltipHeight, 6);
        ctx.fill();
        ctx.stroke();

        // Tooltip text
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 11px sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillText(
          `Offset: 0x${pt.block.start.toString(16).toUpperCase()}`,
          tooltipX + 12,
          tooltipY + 10
        );

        ctx.fillStyle = '#94a3b8';
        ctx.font = '10px monospace';
        ctx.fillText(`Dec: ${pt.block.start}`, tooltipX + 12, tooltipY + 28);
        ctx.fillText(`Section: ${sectionName}`, tooltipX + 12, tooltipY + 42);

        const statusText = pt.block.isHighEntropy
          ? '⚠️ High Entropy'
          : '✓ Normal';
        ctx.fillStyle = pt.block.isHighEntropy ? '#f87171' : '#34d399';
        ctx.font = 'bold 10px sans-serif';
        ctx.fillText(statusText, tooltipX + 12, tooltipY + 56);

        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 12px monospace';
        ctx.textAlign = 'right';
        ctx.fillText(
          pt.block.entropy.toFixed(3),
          tooltipX + tooltipWidth - 12,
          tooltipY + 10
        );

        ctx.fillStyle = '#64748b';
        ctx.font = '8px sans-serif';
        ctx.fillText(
          'Click to Jump',
          tooltipX + tooltipWidth - 12,
          tooltipY + tooltipHeight - 16
        );
      }
    }
  }
}
