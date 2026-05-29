/**
 * Premium Vulnerability Scanner UI Panel
 * Matches URET dark, glassmorphic layout.
 */

import { Section, Symbol, Instruction } from '../disassembler/types.js';
import {
  VulnScanner,
  VulnMatch,
  VulnScannerConfig,
} from '../analyzer/vulnScanner.js';

export interface VulnPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export class VulnPanel {
  private container: HTMLElement;
  private options: VulnPanelOptions;
  private scanner: VulnScanner;

  // Binary data cache
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private symbols: Symbol[] = [];
  private instructions: Instruction[] = [];

  // Config state
  private config: VulnScannerConfig = {
    unsafeApi: true,
    bufferOverflow: true,
    integerOverflow: true,
  };

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private scanResultsEl!: HTMLDivElement;
  private summaryStatsEl!: HTMLDivElement;

  constructor(container: HTMLElement, options: VulnPanelOptions) {
    this.container = container;
    this.options = options;
    this.scanner = new VulnScanner();

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates panel datasets and triggers scanner auto-run.
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    symbols: Symbol[],
    instructions: Instruction[]
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    this.symbols = symbols;
    this.instructions = instructions;

    this.runScan();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'vuln-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
      overflow: hidden;
    `;

    // Premium styling
    if (!document.getElementById('vuln-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'vuln-panel-styles';
      style.textContent = `
        .vuln-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }
        .vuln-header-controls {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 1rem;
          background: rgba(255, 255, 255, 0.01);
          border: 1px solid rgba(255, 255, 255, 0.04);
          padding: 1.25rem;
          border-radius: var(--radius-md);
          flex-wrap: wrap;
        }
        .vuln-title-area {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .vuln-title {
          font-size: 1.15rem;
          font-weight: 700;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .vuln-subtitle {
          font-size: 0.8rem;
          color: var(--text-muted);
        }
        .vuln-config-area {
          display: flex;
          gap: 1rem;
          align-items: center;
        }
        .vuln-config-checkbox {
          display: flex;
          align-items: center;
          gap: 0.35rem;
          font-size: 0.85rem;
          color: var(--text-secondary);
          cursor: pointer;
        }
        .vuln-config-checkbox input {
          accent-color: var(--accent-start);
        }
        .vuln-stats-bar {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 1rem;
        }
        .vuln-stat-card {
          background: rgba(255, 255, 255, 0.01);
          border: 1px solid var(--border-color);
          padding: 0.75rem;
          border-radius: var(--radius-sm);
          text-align: center;
        }
        .vuln-stat-val {
          font-size: 1.25rem;
          font-weight: 700;
        }
        .vuln-stat-lbl {
          font-size: 0.75rem;
          color: var(--text-muted);
          margin-top: 0.2rem;
        }
        .vuln-results-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          padding-right: 4px;
        }
        .vuln-card {
          background: rgba(255, 255, 255, 0.015);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
          transition: all var(--transition-fast);
        }
        .vuln-card:hover {
          background: rgba(255, 255, 255, 0.035);
          border-color: rgba(239, 68, 68, 0.3);
        }
        .vuln-card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .vuln-card-title {
          font-weight: 700;
          font-size: 0.95rem;
          color: var(--text-primary);
        }
        .vuln-card-badge {
          font-size: 0.7rem;
          text-transform: uppercase;
          font-weight: 700;
          padding: 2px 8px;
          border-radius: 4px;
        }
        .vuln-card-badge.high {
          background: rgba(239, 68, 68, 0.15);
          color: #f87171;
          border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .vuln-card-badge.medium {
          background: rgba(245, 158, 11, 0.15);
          color: #fbbf24;
          border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .vuln-card-badge.low {
          background: rgba(59, 130, 246, 0.15);
          color: #60a5fa;
          border: 1px solid rgba(59, 130, 246, 0.3);
        }
        .vuln-card-desc {
          font-size: 0.85rem;
          color: var(--text-secondary);
          line-height: 1.45;
        }
        .vuln-card-meta {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          color: var(--text-muted);
          margin-top: 0.25rem;
        }
        .vuln-card-btn {
          background: transparent;
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 0.25rem 0.5rem;
          border-radius: var(--radius-sm);
          cursor: pointer;
          font-size: 0.75rem;
          transition: all var(--transition-fast);
        }
        .vuln-card-btn:hover {
          background: rgba(255, 255, 255, 0.05);
          color: var(--text-primary);
          border-color: var(--text-muted);
        }
        .vuln-empty-state {
          flex: 1;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          color: var(--text-muted);
          gap: 0.5rem;
        }
      `;
      document.head.appendChild(style);
    }

    // Structure layout
    this.rootEl.innerHTML = `
      <div class="vuln-header-controls">
        <div class="vuln-title-area">
          <div class="vuln-title">🛡️ Vulnerability Scanner</div>
          <div class="vuln-subtitle">Static pattern detection for memory and arithmetic flaws</div>
        </div>
        <div class="vuln-config-area">
          <label class="vuln-config-checkbox">
            <input type="checkbox" id="vuln-chk-unsafe" checked />
            Unsafe APIs
          </label>
          <label class="vuln-config-checkbox">
            <input type="checkbox" id="vuln-chk-buf" checked />
            Buffer Overflows
          </label>
          <label class="vuln-config-checkbox">
            <input type="checkbox" id="vuln-chk-int" checked />
            Integer Overflows
          </label>
        </div>
      </div>

      <div class="vuln-stats-bar" id="vuln-stats-bar">
        <div class="vuln-stat-card">
          <div class="vuln-stat-val" id="vuln-stat-total" style="color: var(--text-primary);">0</div>
          <div class="vuln-stat-lbl">Total Issues</div>
        </div>
        <div class="vuln-stat-card">
          <div class="vuln-stat-val" id="vuln-stat-high" style="color: #f87171;">0</div>
          <div class="vuln-stat-lbl">High Severity</div>
        </div>
        <div class="vuln-stat-card">
          <div class="vuln-stat-val" id="vuln-stat-medium" style="color: #fbbf24;">0</div>
          <div class="vuln-stat-lbl">Medium Severity</div>
        </div>
        <div class="vuln-stat-card">
          <div class="vuln-stat-val" id="vuln-stat-low" style="color: #60a5fa;">0</div>
          <div class="vuln-stat-lbl">Low Severity</div>
        </div>
      </div>

      <div class="vuln-results-list" id="vuln-results-list"></div>
    `;

    this.container.appendChild(this.rootEl);
    this.scanResultsEl = document.getElementById(
      'vuln-results-list'
    ) as HTMLDivElement;
    this.summaryStatsEl = document.getElementById(
      'vuln-stats-bar'
    ) as HTMLDivElement;
  }

  private setupEvents() {
    const chkUnsafe = document.getElementById(
      'vuln-chk-unsafe'
    ) as HTMLInputElement;
    const chkBuf = document.getElementById('vuln-chk-buf') as HTMLInputElement;
    const chkInt = document.getElementById('vuln-chk-int') as HTMLInputElement;

    const updateConfig = () => {
      this.config.unsafeApi = chkUnsafe.checked;
      this.config.bufferOverflow = chkBuf.checked;
      this.config.integerOverflow = chkInt.checked;
      this.runScan();
    };

    chkUnsafe?.addEventListener('change', updateConfig);
    chkBuf?.addEventListener('change', updateConfig);
    chkInt?.addEventListener('change', updateConfig);
  }

  private runScan() {
    if (!this.scanResultsEl) return;

    this.scanResultsEl.innerHTML = '';
    const matches = this.scanner.scan(
      this.binaryData,
      this.sections,
      this.symbols,
      this.instructions,
      this.config
    );

    // Update statistics
    let high = 0,
      medium = 0,
      low = 0;
    matches.forEach((m) => {
      if (m.severity === 'high') high++;
      else if (m.severity === 'medium') medium++;
      else if (m.severity === 'low') low++;
    });

    document.getElementById('vuln-stat-total')!.textContent =
      matches.length.toString();
    document.getElementById('vuln-stat-high')!.textContent = high.toString();
    document.getElementById('vuln-stat-medium')!.textContent =
      medium.toString();
    document.getElementById('vuln-stat-low')!.textContent = low.toString();

    if (matches.length === 0) {
      this.scanResultsEl.innerHTML = `
        <div class="vuln-empty-state">
          <span>✨ No potential vulnerabilities detected.</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">Ensure valid assembly instructions and symbols are loaded.</span>
        </div>
      `;
      return;
    }

    matches.forEach((m) => {
      const card = document.createElement('div');
      card.className = 'vuln-card';

      let addrString = 'N/A';
      if (typeof m.address === 'number') {
        addrString = `0x${m.address.toString(16).toUpperCase()}`;
      }

      card.innerHTML = `
        <div class="vuln-card-header">
          <span class="vuln-card-title">${this.getCategoryName(m.category)}</span>
          <span class="vuln-card-badge ${m.severity}">${m.severity}</span>
        </div>
        <div class="vuln-card-desc">${m.description}</div>
        <div class="vuln-card-meta">
          <span>Address: <code style="font-family: var(--font-mono); color: #e2e8f0;">${addrString}</code></span>
          <span>Evidence: <code style="font-family: var(--font-mono); color: #e2e8f0;">${m.evidence}</code></span>
          ${typeof m.address === 'number' ? `<button class="vuln-card-btn" data-addr="${m.address}">Go to Address</button>` : ''}
        </div>
      `;

      if (typeof m.address === 'number') {
        card.querySelector('.vuln-card-btn')?.addEventListener('click', () => {
          this.options.onNavigate('assembly', m.address!);
        });
      }

      this.scanResultsEl.appendChild(card);
    });
  }

  private getCategoryName(category: string): string {
    switch (category) {
      case 'unsafe_api':
        return 'Unsafe API Usage';
      case 'buffer_overflow':
        return 'Potential Buffer Overflow';
      case 'integer_overflow':
        return 'Potential Integer Overflow';
      case 'format_string':
        return 'Format String Vulnerability';
      default:
        return 'Security Flaw';
    }
  }
}
