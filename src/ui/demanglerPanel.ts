/**
 * Premium Symbol Demangler Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides interactive C++ name demangling.
 */

import { demangle, DemangledSymbol } from '../analyzer/demangler.js';
import { Symbol as BinarySymbol } from '../disassembler/types.js';

export interface DemanglerPanelOptions {
  onNavigate?: (targetView: 'assembly' | 'hex', address: number) => void;
}

export class DemanglerPanel {
  private container: HTMLElement;
  private symbols: BinarySymbol[] = [];
  private options: DemanglerPanelOptions;

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private inputEl!: HTMLInputElement;
  private demangleBtn!: HTMLButtonElement;
  private playgroundResultEl!: HTMLDivElement;
  private symbolsTableBody!: HTMLTableSectionElement;
  private symbolsSearchInput!: HTMLInputElement;
  private statsMangledCountEl!: HTMLSpanElement;
  private statsDemangledCountEl!: HTMLSpanElement;

  private sampleSymbols = [
    { name: '_ZN3foo3bar3bazEib', desc: 'GCC Nested Name with Args' },
    {
      name: '_ZNK3std6vectorIiSaIiEE9push_backERKi',
      desc: 'GCC std::vector Template',
    },
    { name: '?add@Math@@YAHHH@Z', desc: 'MSVC Method returning Int' },
    { name: '?func@Class@Namespace@@YAXXZ', desc: 'MSVC Namespace + Class' },
    { name: '_ZN3foo6helperEPiRKc', desc: 'GCC Pointer & Const Ref Args' },
  ];

  constructor(
    container: HTMLElement,
    symbols: BinarySymbol[],
    options: DemanglerPanelOptions = {}
  ) {
    this.container = container;
    this.symbols = symbols;
    this.options = options;

    this.injectStyles();
    this.initLayout();
    this.setupEvents();
    this.updateStats();
    this.renderSymbolsList();
  }

  /**
   * Updates the symbols list
   */
  public updateData(symbols: BinarySymbol[]) {
    this.symbols = symbols;
    this.updateStats();
    this.renderSymbolsList();
  }

  private injectStyles() {
    if (document.getElementById('demangler-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'demangler-panel-styles';
    style.textContent = `
      .demangler-root {
        display: grid;
        grid-template-columns: 380px 1fr;
        gap: 1.5rem;
        height: 100%;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        overflow: hidden;
      }

      .demangler-left-pane {
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
        overflow-y: auto;
        padding-right: 4px;
      }

      .demangler-right-pane {
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
        min-width: 0;
        height: 100%;
        overflow: hidden;
      }

      /* Cards & Glassmorphism */
      .demangler-card {
        background: rgba(22, 26, 33, 0.45);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-lg);
        padding: 1.25rem;
        display: flex;
        flex-direction: column;
        gap: 1rem;
        box-shadow: var(--shadow-md);
      }

      .card-title {
        font-size: 1rem;
        font-weight: 700;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin: 0;
      }

      /* Playground Form */
      .playground-input-group {
        display: flex;
        gap: 0.5rem;
      }

      .playground-input {
        flex: 1;
        background: rgba(10, 12, 16, 0.6);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 0.75rem 1rem;
        color: var(--text-primary);
        font-family: var(--font-mono);
        font-size: 0.85rem;
        transition: all var(--transition-fast);
      }

      .playground-input:focus {
        outline: none;
        border-color: var(--accent-start);
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      }

      /* Demangled detail visual elements */
      .detail-badge-group {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
      }

      .detail-badge {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        padding: 0.25rem 0.5rem;
        border-radius: var(--radius-sm);
        background: rgba(99, 102, 241, 0.15);
        border: 1px solid rgba(99, 102, 241, 0.3);
        color: #818cf8;
      }

      .detail-badge.lang-cpp {
        background: rgba(16, 185, 129, 0.15);
        border-color: rgba(16, 185, 129, 0.3);
        color: #34d399;
      }

      .detail-badge.kind-fn {
        background: rgba(245, 158, 11, 0.15);
        border-color: rgba(245, 158, 11, 0.3);
        color: #fbbf24;
      }

      .detail-grid {
        display: grid;
        grid-template-columns: 90px 1fr;
        gap: 0.75rem;
        font-size: 0.85rem;
      }

      .detail-label {
        color: var(--text-muted);
        font-weight: 600;
      }

      .detail-value {
        color: var(--text-secondary);
        font-family: var(--font-mono);
        word-break: break-all;
      }

      /* Sample Playground Cards */
      .samples-list {
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
      }

      .sample-item {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 0.6rem 0.85rem;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        gap: 0.2rem;
        transition: all var(--transition-fast);
      }

      .sample-item:hover {
        background: rgba(255, 255, 255, 0.05);
        border-color: var(--border-hover);
        transform: translateX(2px);
      }

      .sample-sym {
        font-family: var(--font-mono);
        font-size: 0.8rem;
        color: var(--text-primary);
        word-break: break-all;
      }

      .sample-desc {
        font-size: 0.7rem;
        color: var(--text-muted);
      }

      /* Stats display */
      .demangler-stats {
        display: flex;
        gap: 1rem;
      }

      .stat-mini-card {
        flex: 1;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 0.75rem;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 0.25rem;
      }

      .stat-mini-val {
        font-size: 1.25rem;
        font-weight: 700;
        color: var(--accent-start);
      }

      .stat-mini-lbl {
        font-size: 0.65rem;
        text-transform: uppercase;
        color: var(--text-muted);
        letter-spacing: 0.05em;
      }

      /* Symbols Table Pane */
      .table-card {
        flex: 1;
        display: flex;
        flex-direction: column;
        min-height: 0;
        overflow: hidden;
      }

      .table-container {
        flex: 1;
        overflow-y: auto;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        background: rgba(10, 12, 16, 0.2);
      }

      .symbols-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
        font-size: 0.85rem;
      }

      .symbols-table th {
        background: rgba(15, 17, 21, 0.8);
        padding: 0.75rem 1rem;
        font-weight: 600;
        color: var(--text-primary);
        border-bottom: 1px solid var(--border-color);
        position: sticky;
        top: 0;
        z-index: 10;
      }

      .symbols-table td {
        padding: 0.75rem 1rem;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-secondary);
        max-width: 300px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .symbols-table tr {
        transition: background var(--transition-fast);
      }

      .symbols-table tr:hover {
        background: rgba(255, 255, 255, 0.03);
      }

      .table-action-btn {
        background: rgba(99, 102, 241, 0.15);
        border: 1px solid rgba(99, 102, 241, 0.3);
        color: #818cf8;
        padding: 0.25rem 0.5rem;
        border-radius: var(--radius-sm);
        cursor: pointer;
        font-size: 0.75rem;
        transition: all var(--transition-fast);
      }

      .table-action-btn:hover {
        background: var(--accent-start);
        color: #ffffff;
      }

      .search-controls {
        display: flex;
        gap: 0.75rem;
        margin-bottom: 0.5rem;
      }
    `;
    document.head.appendChild(style);
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'demangler-root';

    // Left column: Playground, Stats, Samples
    const leftPane = document.createElement('div');
    leftPane.className = 'demangler-left-pane';

    // Stat cards
    const statsCard = document.createElement('div');
    statsCard.className = 'demangler-stats';
    statsCard.innerHTML = `
      <div class="stat-mini-card">
        <span class="stat-mini-val" id="demangler-stats-mangled">-</span>
        <span class="stat-mini-lbl">Mangled Symbols</span>
      </div>
      <div class="stat-mini-card">
        <span class="stat-mini-val" id="demangler-stats-demangled">-</span>
        <span class="stat-mini-lbl">C++ Demangled</span>
      </div>
    `;

    // Playground card
    const playgroundCard = document.createElement('div');
    playgroundCard.className = 'demangler-card';
    playgroundCard.innerHTML = `
      <h3 class="card-title">🔬 Demangler Playground</h3>
      <div class="playground-input-group">
        <input type="text" class="playground-input" id="playground-sym-input" placeholder="Enter mangled symbol..." />
        <button class="btn btn-primary" id="playground-demangle-btn" style="padding: 0.5rem 1rem;">Demangle</button>
      </div>
      <div id="playground-result-container"></div>
    `;

    // Samples card
    const samplesCard = document.createElement('div');
    samplesCard.className = 'demangler-card';
    const samplesHeader = document.createElement('h3');
    samplesHeader.className = 'card-title';
    samplesHeader.textContent = '💡 Quick Sample Presets';
    samplesCard.appendChild(samplesHeader);

    const samplesList = document.createElement('div');
    samplesList.className = 'samples-list';
    this.sampleSymbols.forEach((s) => {
      const item = document.createElement('div');
      item.className = 'sample-item';
      item.dataset.sym = s.name;
      item.innerHTML = `
        <span class="sample-sym">${s.name}</span>
        <span class="sample-desc">${s.desc}</span>
      `;
      samplesList.appendChild(item);
    });
    samplesCard.appendChild(samplesList);

    leftPane.appendChild(statsCard);
    leftPane.appendChild(playgroundCard);
    leftPane.appendChild(samplesCard);

    // Right column: Table of all binary symbols
    const rightPane = document.createElement('div');
    rightPane.className = 'demangler-right-pane';

    const tableCard = document.createElement('div');
    tableCard.className = 'demangler-card table-card';
    tableCard.innerHTML = `
      <h3 class="card-title">📁 Binary Symbol Directory</h3>
      <div class="search-controls">
        <input type="text" class="playground-input" id="symbols-search-input" placeholder="Filter symbols..." />
      </div>
      <div class="table-container">
        <table class="symbols-table">
          <thead>
            <tr>
              <th style="width: 80px;">Address</th>
              <th>Mangled Symbol</th>
              <th>Demangled Result</th>
              <th style="width: 100px;">Actions</th>
            </tr>
          </thead>
          <tbody id="symbols-table-body"></tbody>
        </table>
      </div>
    `;

    rightPane.appendChild(tableCard);

    this.rootEl.appendChild(leftPane);
    this.rootEl.appendChild(rightPane);
    this.container.appendChild(this.rootEl);

    // Cache elements
    this.inputEl = this.rootEl.querySelector(
      '#playground-sym-input'
    ) as HTMLInputElement;
    this.demangleBtn = this.rootEl.querySelector(
      '#playground-demangle-btn'
    ) as HTMLButtonElement;
    this.playgroundResultEl = this.rootEl.querySelector(
      '#playground-result-container'
    ) as HTMLDivElement;
    this.symbolsTableBody = this.rootEl.querySelector(
      '#symbols-table-body'
    ) as HTMLTableSectionElement;
    this.symbolsSearchInput = this.rootEl.querySelector(
      '#symbols-search-input'
    ) as HTMLInputElement;
    this.statsMangledCountEl = this.rootEl.querySelector(
      '#demangler-stats-mangled'
    ) as HTMLSpanElement;
    this.statsDemangledCountEl = this.rootEl.querySelector(
      '#demangler-stats-demangled'
    ) as HTMLSpanElement;
  }

  private setupEvents() {
    // Demangle Button
    this.demangleBtn.addEventListener('click', () => {
      this.handleDemanglePlayground();
    });

    // Enter Key
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.handleDemanglePlayground();
      }
    });

    // Preset Sample clicks
    this.rootEl.querySelectorAll('.sample-item').forEach((item) => {
      item.addEventListener('click', (e) => {
        const target = e.currentTarget as HTMLDivElement;
        const sym = target.dataset.sym || '';
        this.inputEl.value = sym;
        this.handleDemanglePlayground();
      });
    });

    // Live filtering
    this.symbolsSearchInput.addEventListener('input', () => {
      this.renderSymbolsList();
    });
  }

  private updateStats() {
    if (!this.statsMangledCountEl || !this.statsDemangledCountEl) return;

    let mangledCount = 0;
    let demangledCount = 0;

    this.symbols.forEach((s) => {
      const isM = s.name.startsWith('_Z') || s.name.startsWith('?');
      if (isM) {
        mangledCount++;
        const r = demangle(s.name);
        if (r.isMangled) {
          demangledCount++;
        }
      }
    });

    this.statsMangledCountEl.textContent = mangledCount.toString();
    this.statsDemangledCountEl.textContent = demangledCount.toString();
  }

  private handleDemanglePlayground() {
    const val = this.inputEl.value.trim();
    if (!val) {
      this.playgroundResultEl.innerHTML = '';
      return;
    }

    const res = demangle(val);
    this.renderResult(res);
  }

  private renderResult(res: DemangledSymbol) {
    this.playgroundResultEl.innerHTML = '';

    const resCard = document.createElement('div');
    resCard.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 1rem;
      margin-top: 0.5rem;
    `;

    const titleRow = document.createElement('div');
    titleRow.style.cssText =
      'display: flex; justify-content: space-between; align-items: center;';

    const titleVal = document.createElement('div');
    titleVal.style.cssText =
      'font-weight: 700; font-size: 0.9rem; color: #818cf8; font-family: var(--font-mono); word-break: break-all;';
    titleVal.textContent = res.demangled;
    titleRow.appendChild(titleVal);

    resCard.appendChild(titleRow);

    // Badges
    const badgeRow = document.createElement('div');
    badgeRow.className = 'detail-badge-group';
    if (res.isMangled) {
      const langBadge = document.createElement('span');
      langBadge.className = 'detail-badge lang-cpp';
      langBadge.textContent = 'C++';
      badgeRow.appendChild(langBadge);

      if (res.kind === 'function') {
        const kindBadge = document.createElement('span');
        kindBadge.className = 'detail-badge kind-fn';
        kindBadge.textContent = 'Function';
        badgeRow.appendChild(kindBadge);
      }
    } else {
      const plainBadge = document.createElement('span');
      plainBadge.className = 'detail-badge';
      plainBadge.style.cssText =
        'background: rgba(255,255,255,0.05); border-color: rgba(255,255,255,0.1); color: var(--text-muted);';
      plainBadge.textContent = 'Unmangled';
      badgeRow.appendChild(plainBadge);
    }
    resCard.appendChild(badgeRow);

    // Detailed Grid
    if (res.isMangled) {
      const grid = document.createElement('div');
      grid.className = 'detail-grid';

      let html = '';
      if (res.name) {
        html += `<span class="detail-label">Base Name:</span><span class="detail-value">${res.name}</span>`;
      }
      if (res.className) {
        html += `<span class="detail-label">Class:</span><span class="detail-value">${res.className}</span>`;
      }
      if (res.namespaces && res.namespaces.length > 0) {
        html += `<span class="detail-label">Namespaces:</span><span class="detail-value">${res.namespaces.join(' :: ')}</span>`;
      }
      if (res.parameters && res.parameters.length > 0) {
        html += `<span class="detail-label">Parameters:</span><span class="detail-value">${res.parameters.join(', ')}</span>`;
      }
      if (res.returnType) {
        html += `<span class="detail-label">Return Type:</span><span class="detail-value">${res.returnType}</span>`;
      }
      if (res.modifiers && res.modifiers.length > 0) {
        html += `<span class="detail-label">Modifiers:</span><span class="detail-value">${res.modifiers.join(' ')}</span>`;
      }

      grid.innerHTML = html;
      resCard.appendChild(grid);
    }

    this.playgroundResultEl.appendChild(resCard);
  }

  private renderSymbolsList() {
    if (!this.symbolsTableBody) return;

    this.symbolsTableBody.innerHTML = '';
    const query = this.symbolsSearchInput.value.toLowerCase().trim();

    const filtered = this.symbols.filter((s) => {
      if (!query) return true;
      const demangledName = demangle(s.name).demangled;
      return (
        s.name.toLowerCase().includes(query) ||
        demangledName.toLowerCase().includes(query)
      );
    });

    if (filtered.length === 0) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `<td colspan="4" style="text-align: center; color: var(--text-disabled); padding: 2rem;">No symbols found</td>`;
      this.symbolsTableBody.appendChild(emptyRow);
      return;
    }

    filtered.forEach((s) => {
      const demangled = demangle(s.name);
      const row = document.createElement('tr');

      const addrCell = document.createElement('td');
      addrCell.style.fontFamily = 'var(--font-mono)';
      addrCell.style.color = 'var(--accent-start)';
      addrCell.textContent = '0x' + s.address.toString(16).toUpperCase();

      const mangledCell = document.createElement('td');
      mangledCell.style.fontFamily = 'var(--font-mono)';
      mangledCell.textContent = s.name;

      const demangledCell = document.createElement('td');
      demangledCell.style.fontFamily = 'var(--font-mono)';
      if (demangled.isMangled) {
        demangledCell.style.color = '#34d399';
        demangledCell.textContent = demangled.demangled;
      } else {
        demangledCell.style.color = 'var(--text-muted)';
        demangledCell.textContent = s.name;
      }

      const actionsCell = document.createElement('td');

      const loadBtn = document.createElement('button');
      loadBtn.className = 'table-action-btn';
      loadBtn.textContent = 'Inspect';
      loadBtn.addEventListener('click', () => {
        this.inputEl.value = s.name;
        this.handleDemanglePlayground();
      });

      actionsCell.appendChild(loadBtn);

      // If address navigation exists
      if (s.address && this.options.onNavigate) {
        const navBtn = document.createElement('button');
        navBtn.className = 'table-action-btn';
        navBtn.style.marginLeft = '0.5rem';
        navBtn.textContent = 'Go to Code';
        navBtn.addEventListener('click', () => {
          this.options.onNavigate!('assembly', s.address);
        });
        actionsCell.appendChild(navBtn);
      }

      row.appendChild(addrCell);
      row.appendChild(mangledCell);
      row.appendChild(demangledCell);
      row.appendChild(actionsCell);

      this.symbolsTableBody.appendChild(row);
    });
  }
}
