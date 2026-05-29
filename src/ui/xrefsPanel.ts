/**
 * Premium XRefs (Cross-References) Panel UI Component
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and displays references to/from addresses.
 */

import { Instruction, Section, Symbol } from '../disassembler/types.js';
import { ExtractedString } from '../analyzer/strings.js';
import { XRefEngine, XRef } from '../analyzer/xrefs.js';

export interface XRefsPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export class XRefsPanel {
  private container: HTMLElement;
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private symbols: Symbol[] = [];
  private instructions: Instruction[] = [];
  private strings: ExtractedString[] = [];
  private options: XRefsPanelOptions;

  // XRef Engine
  private engine: XRefEngine;
  private allXRefs: XRef[] = [];

  // Selected state
  private selectedAddress: number | null = null;
  private activeTab: 'all' | 'to' | 'from' = 'all';
  private searchQuery: string = '';

  // DOM elements
  private rootEl!: HTMLDivElement;
  private statsCardsEl!: HTMLDivElement;
  private selectedAddrHeaderEl!: HTMLDivElement;
  private resultsContainerEl!: HTMLDivElement;
  private searchInputEl!: HTMLInputElement;
  private tabButtons: Map<string, HTMLButtonElement> = new Map();

  constructor(container: HTMLElement, options: XRefsPanelOptions) {
    this.container = container;
    this.options = options;
    this.engine = new XRefEngine();
    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates panel data and performs cross-reference analysis
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    symbols: Symbol[],
    instructions: Instruction[],
    strings: ExtractedString[]
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    this.symbols = symbols;
    this.instructions = instructions;
    this.strings = strings;

    this.engine.clear();
    this.engine.analyze(instructions, sections, symbols, binaryData);
    this.allXRefs = this.engine.getAllXRefs();

    this.renderStats();
    this.renderResults();
  }

  /**
   * Sets focus on a specific address to display its incoming and outgoing references
   */
  public selectAddress(address: number | null) {
    this.selectedAddress = address;
    if (address !== null) {
      this.activeTab = 'to'; // Default to showing references TO this address when selected
    } else {
      this.activeTab = 'all';
    }
    this.updateTabActiveState();
    this.renderSelectedHeader();
    this.renderResults();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'xrefs-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject styles
    if (!document.getElementById('xrefs-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'xrefs-panel-styles';
      style.textContent = `
        .xrefs-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }

        .xrefs-header-controls {
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

        .xrefs-title-area {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }

        .xrefs-title {
          font-size: 1.15rem;
          font-weight: 700;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .xrefs-subtitle {
          font-size: 0.8rem;
          color: var(--text-muted);
        }

        .xrefs-controls-row {
          display: flex;
          gap: 1rem;
          align-items: center;
          flex-wrap: wrap;
        }

        .xrefs-search-box {
          position: relative;
          display: flex;
          align-items: center;
        }

        .xrefs-search-input {
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          color: var(--text-primary);
          padding: 0.4rem 0.75rem 0.4rem 2rem;
          outline: none;
          font-size: 0.85rem;
          width: 240px;
          transition: all var(--transition-fast);
        }

        .xrefs-search-input:focus {
          border-color: var(--accent-start);
          box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2);
        }

        .xrefs-search-icon {
          position: absolute;
          left: 0.75rem;
          color: var(--text-muted);
          font-size: 0.85rem;
          pointer-events: none;
        }

        .xrefs-tab-selector {
          display: flex;
          background: rgba(15, 17, 21, 0.5);
          border: 1px solid var(--border-color);
          padding: 0.25rem;
          border-radius: var(--radius-md);
          gap: 0.25rem;
        }

        .xrefs-tab-btn {
          background: transparent;
          border: none;
          color: var(--text-muted);
          padding: 0.35rem 0.85rem;
          border-radius: var(--radius-sm);
          font-size: 0.8rem;
          font-weight: 500;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .xrefs-tab-btn:hover {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.03);
        }

        .xrefs-tab-btn.active {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.08);
          box-shadow: var(--shadow-sm);
        }

        /* Stats Cards styling */
        .xrefs-stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 1rem;
        }

        .xrefs-stat-card {
          background: rgba(15, 17, 21, 0.3);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }

        .xrefs-stat-value {
          font-size: 1.5rem;
          font-weight: 700;
          color: var(--text-primary);
        }

        .xrefs-stat-label {
          font-size: 0.75rem;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }

        /* Address header */
        .xrefs-address-header {
          background: rgba(139, 92, 246, 0.05);
          border: 1px solid rgba(139, 92, 246, 0.15);
          padding: 0.75rem 1.25rem;
          border-radius: var(--radius-md);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .xrefs-address-info {
          font-family: var(--font-mono);
          font-size: 0.9rem;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .xrefs-clear-addr-btn {
          background: transparent;
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: var(--text-muted);
          padding: 0.25rem 0.5rem;
          font-size: 0.75rem;
          border-radius: var(--radius-sm);
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .xrefs-clear-addr-btn:hover {
          color: var(--text-primary);
          border-color: var(--text-muted);
        }

        /* Results table styling */
        .xrefs-table-container {
          flex: 1;
          overflow: auto;
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          background: rgba(15, 17, 21, 0.4);
        }

        .xrefs-table {
          width: 100%;
          border-collapse: collapse;
          text-align: left;
          font-size: 0.85rem;
        }

        .xrefs-table th {
          background: rgba(20, 24, 30, 0.8);
          color: var(--text-muted);
          font-weight: 600;
          padding: 0.75rem 1rem;
          border-bottom: 1px solid var(--border-color);
          position: sticky;
          top: 0;
          z-index: 10;
        }

        .xrefs-table td {
          padding: 0.75rem 1rem;
          border-bottom: 1px solid rgba(255, 255, 255, 0.03);
          color: var(--text-secondary);
        }

        .xrefs-table tr:hover td {
          background: rgba(255, 255, 255, 0.02);
          color: var(--text-primary);
        }

        .xrefs-clickable-addr {
          font-family: var(--font-mono);
          color: var(--accent-start);
          cursor: pointer;
          text-decoration: underline;
        }

        .xrefs-clickable-addr:hover {
          color: var(--accent-end);
        }

        .xrefs-badge {
          display: inline-block;
          padding: 0.15rem 0.4rem;
          font-size: 0.7rem;
          font-weight: 600;
          border-radius: 4px;
          text-transform: uppercase;
        }

        .xrefs-badge-call {
          background: rgba(16, 185, 129, 0.1);
          color: #10b981;
          border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .xrefs-badge-jump {
          background: rgba(245, 158, 11, 0.1);
          color: #f59e0b;
          border: 1px solid rgba(245, 158, 11, 0.2);
        }

        .xrefs-badge-data_read {
          background: rgba(59, 130, 246, 0.1);
          color: #3b82f6;
          border: 1px solid rgba(59, 130, 246, 0.2);
        }

        .xrefs-badge-data_write {
          background: rgba(239, 68, 68, 0.1);
          color: #ef4444;
          border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .xrefs-badge-data {
          background: rgba(139, 92, 246, 0.1);
          color: #8b5cf6;
          border: 1px solid rgba(139, 92, 246, 0.2);
        }

        .xrefs-badge-unknown {
          background: rgba(107, 114, 128, 0.1);
          color: #6b7280;
          border: 1px solid rgba(107, 114, 128, 0.2);
        }

        .xrefs-no-results {
          padding: 3rem;
          text-align: center;
          color: var(--text-muted);
          font-size: 0.9rem;
        }
      `;
      document.head.appendChild(style);
    }

    // Header Controls
    const headerControls = document.createElement('div');
    headerControls.className = 'xrefs-header-controls';

    const titleArea = document.createElement('div');
    titleArea.className = 'xrefs-title-area';
    titleArea.innerHTML = `
      <div class="xrefs-title">🔍 Cross References (XRefs)</div>
      <div class="xrefs-subtitle">Analyze incoming and outgoing references inside binary instructions</div>
    `;
    headerControls.appendChild(titleArea);

    const controlsRow = document.createElement('div');
    controlsRow.className = 'xrefs-controls-row';

    // Search bar
    const searchBox = document.createElement('div');
    searchBox.className = 'xrefs-search-box';
    searchBox.innerHTML = `
      <span class="xrefs-search-icon">🔍</span>
      <input type="text" class="xrefs-search-input" placeholder="Search references..." />
    `;
    this.searchInputEl = searchBox.querySelector(
      '.xrefs-search-input'
    ) as HTMLInputElement;
    controlsRow.appendChild(searchBox);

    // Tab buttons
    const tabSelector = document.createElement('div');
    tabSelector.className = 'xrefs-tab-selector';

    const tabsConfig = [
      { id: 'all', label: 'All References' },
      { id: 'to', label: 'Incoming To' },
      { id: 'from', label: 'Outgoing From' },
    ];

    tabsConfig.forEach((tab) => {
      const btn = document.createElement('button');
      btn.className = 'xrefs-tab-btn';
      btn.textContent = tab.label;
      btn.dataset.tab = tab.id;
      tabSelector.appendChild(btn);
      this.tabButtons.set(tab.id, btn);
    });

    controlsRow.appendChild(tabSelector);
    headerControls.appendChild(controlsRow);
    this.rootEl.appendChild(headerControls);

    // Stats Grid
    this.statsCardsEl = document.createElement('div');
    this.statsCardsEl.className = 'xrefs-stats-grid';
    this.rootEl.appendChild(this.statsCardsEl);

    // Selected Address Header (hidden by default)
    this.selectedAddrHeaderEl = document.createElement('div');
    this.selectedAddrHeaderEl.className = 'xrefs-address-header';
    this.selectedAddrHeaderEl.style.display = 'none';
    this.rootEl.appendChild(this.selectedAddrHeaderEl);

    // Table Container / Results list
    this.resultsContainerEl = document.createElement('div');
    this.resultsContainerEl.className = 'xrefs-table-container';
    this.rootEl.appendChild(this.resultsContainerEl);

    this.container.appendChild(this.rootEl);
    this.updateTabActiveState();
  }

  private setupEvents() {
    // Search input
    this.searchInputEl.addEventListener('input', () => {
      this.searchQuery = this.searchInputEl.value.toLowerCase().trim();
      this.renderResults();
    });

    // Tab buttons
    this.tabButtons.forEach((btn, tabId) => {
      btn.addEventListener('click', () => {
        this.activeTab = tabId as any;
        this.updateTabActiveState();
        this.renderResults();
      });
    });

    // Clicks on table addresses/rows
    this.resultsContainerEl.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.classList.contains('xrefs-clickable-addr')) {
        const address = parseInt(target.dataset.addr || '0', 10);
        if (address) {
          const viewType = target.dataset.view || 'assembly';
          this.options.onNavigate(viewType as any, address);
        }
      }
    });
  }

  private updateTabActiveState() {
    this.tabButtons.forEach((btn, id) => {
      if (id === this.activeTab) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
  }

  private renderSelectedHeader() {
    if (this.selectedAddress === null) {
      this.selectedAddrHeaderEl.style.display = 'none';
      return;
    }

    const hexAddr = `0x${this.selectedAddress.toString(16).toUpperCase()}`;
    const sym = this.symbols.find((s) => s.address === this.selectedAddress);
    const symName = sym ? ` (${sym.name})` : '';

    this.selectedAddrHeaderEl.style.display = 'flex';
    this.selectedAddrHeaderEl.innerHTML = `
      <div class="xrefs-address-info">
        <span>📍 Focus Address:</span>
        <strong class="xrefs-clickable-addr" data-addr="${this.selectedAddress}" data-view="assembly">${hexAddr}</strong>
        <span style="color: var(--text-muted);">${symName}</span>
      </div>
      <button class="xrefs-clear-addr-btn">Clear Filter</button>
    `;

    const clearBtn = this.selectedAddrHeaderEl.querySelector(
      '.xrefs-clear-addr-btn'
    );
    clearBtn?.addEventListener('click', () => this.selectAddress(null));
  }

  private renderStats() {
    this.statsCardsEl.innerHTML = '';

    const total = this.allXRefs.length;
    const calls = this.allXRefs.filter((x) => x.type === 'CALL').length;
    const jumps = this.allXRefs.filter((x) => x.type === 'JUMP').length;
    const dataRefs = this.allXRefs.filter((x) =>
      x.type.startsWith('DATA')
    ).length;

    const stats = [
      { label: 'Total References', value: total },
      { label: 'Function Calls', value: calls },
      { label: 'Branch Jumps', value: jumps },
      { label: 'Data references', value: dataRefs },
    ];

    stats.forEach((stat) => {
      const card = document.createElement('div');
      card.className = 'xrefs-stat-card';
      card.innerHTML = `
        <div class="xrefs-stat-value">${stat.value}</div>
        <div class="xrefs-stat-label">${stat.label}</div>
      `;
      this.statsCardsEl.appendChild(card);
    });
  }

  private getSymbolAt(addr: number): string {
    const sym = this.symbols.find((s) => s.address === addr);
    return sym ? sym.name : '';
  }

  private getStringAt(addr: number): string {
    const str = this.strings.find((s) => s.virtualAddress === addr);
    return str ? str.value : '';
  }

  private renderResults() {
    this.resultsContainerEl.innerHTML = '';

    let listToRender: XRef[] = [];

    if (this.selectedAddress !== null) {
      if (this.activeTab === 'to') {
        listToRender = this.engine.getXRefsTo(this.selectedAddress);
      } else if (this.activeTab === 'from') {
        listToRender = this.engine.getXRefsFrom(this.selectedAddress);
      } else {
        const incoming = this.engine.getXRefsTo(this.selectedAddress);
        const outgoing = this.engine.getXRefsFrom(this.selectedAddress);
        listToRender = [...incoming, ...outgoing];
      }
    } else {
      if (this.activeTab === 'to') {
        listToRender = this.allXRefs;
      } else if (this.activeTab === 'from') {
        listToRender = this.allXRefs;
      } else {
        listToRender = this.allXRefs;
      }
    }

    // Filter by search query
    if (this.searchQuery) {
      listToRender = listToRender.filter((xref) => {
        const srcHex = `0x${xref.from.toString(16)}`;
        const destHex = `0x${xref.to.toString(16)}`;
        const srcSym = this.getSymbolAt(xref.from).toLowerCase();
        const targetSym = this.getSymbolAt(xref.to).toLowerCase();
        const targetStr = this.getStringAt(xref.to).toLowerCase();
        const context = xref.context?.toLowerCase() || '';

        return (
          srcHex.includes(this.searchQuery) ||
          destHex.includes(this.searchQuery) ||
          srcSym.includes(this.searchQuery) ||
          targetSym.includes(this.searchQuery) ||
          targetStr.includes(this.searchQuery) ||
          context.includes(this.searchQuery)
        );
      });
    }

    if (listToRender.length === 0) {
      this.resultsContainerEl.innerHTML = `
        <div class="xrefs-no-results">
          No references found. Try searching or adjusting filters.
        </div>
      `;
      return;
    }

    const table = document.createElement('table');
    table.className = 'xrefs-table';
    table.innerHTML = `
      <thead>
        <tr>
          <th style="width: 15%">Source Address</th>
          <th style="width: 15%">Source Symbol</th>
          <th style="width: 10%">Type</th>
          <th style="width: 15%">Target Address</th>
          <th style="width: 15%">Target Symbol</th>
          <th style="width: 30%">Details / Context</th>
        </tr>
      </thead>
      <tbody></tbody>
    `;

    const tbody = table.querySelector('tbody')!;

    listToRender.forEach((xref) => {
      const tr = document.createElement('tr');

      const srcHex = `0x${xref.from.toString(16).toUpperCase()}`;
      const destHex = `0x${xref.to.toString(16).toUpperCase()}`;
      const srcSym = this.getSymbolAt(xref.from) || '-';
      const targetSym = this.getSymbolAt(xref.to) || '-';
      const badgeClass = `xrefs-badge xrefs-badge-${xref.type.toLowerCase()}`;

      let detailsText = xref.context || '';
      const targetStr = this.getStringAt(xref.to);
      if (targetStr) {
        detailsText += ` ("${targetStr}")`;
      }

      tr.innerHTML = `
        <td>
          <span class="xrefs-clickable-addr" data-addr="${xref.from}" data-view="assembly">${srcHex}</span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${srcSym}</td>
        <td>
          <span class="${badgeClass}">${xref.type}</span>
        </td>
        <td>
          <span class="xrefs-clickable-addr" data-addr="${xref.to}" data-view="${targetStr ? 'hex' : 'assembly'}">${destHex}</span>
        </td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem;">${targetSym}</td>
        <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${detailsText}</td>
      `;

      tbody.appendChild(tr);
    });

    this.resultsContainerEl.appendChild(table);
  }
}
