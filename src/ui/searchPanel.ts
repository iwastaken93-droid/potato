/**
 * Premium Search Panel UI Component
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides advanced searching (Text, Hex with wildcards, Instruction)
 */

import { Instruction, Section, Symbol } from '../disassembler/types.js';
import { ExtractedString } from '../analyzer/strings.js';

export interface SearchPanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export interface SearchResult {
  address: number;
  offset: number;
  section: string;
  type: 'Text' | 'Hex' | 'Instruction' | 'Symbol';
  preview: string;
  matchedText: string;
}

export class SearchPanel {
  private container: HTMLElement;
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private symbols: Symbol[] = [];
  private instructions: Instruction[] = [];
  private strings: ExtractedString[] = [];
  private comments: Map<number, string> = new Map();
  private options: SearchPanelOptions;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private queryInput!: HTMLInputElement;
  private modeButtons: Map<string, HTMLButtonElement> = new Map();
  private activeMode: 'text' | 'hex' | 'instruction' = 'text';
  private resultsListEl!: HTMLDivElement;

  // Filters
  private caseSensitiveCheckbox!: HTMLInputElement;
  private sectionSelect!: HTMLSelectElement;
  private minAddrInput!: HTMLInputElement;
  private maxAddrInput!: HTMLInputElement;
  private statusTextEl!: HTMLDivElement;

  constructor(container: HTMLElement, options: SearchPanelOptions) {
    this.container = container;
    this.options = options;

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates the search data with the current binary's state
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    symbols: Symbol[],
    instructions: Instruction[],
    strings: ExtractedString[],
    comments: Map<number, string> = new Map()
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    this.symbols = symbols;
    this.instructions = instructions;
    this.strings = strings;
    this.comments = comments;

    this.populateSectionsFilter();
    this.performSearch();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'search-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject styles
    if (!document.getElementById('search-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'search-panel-styles';
      style.textContent = `
        .search-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }

        .search-header-controls {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          background: rgba(255, 255, 255, 0.01);
          border: 1px solid rgba(255, 255, 255, 0.04);
          padding: 1.25rem;
          border-radius: var(--radius-md);
        }

        .search-input-wrapper {
          display: flex;
          gap: 0.75rem;
          align-items: center;
        }

        .search-input-container {
          position: relative;
          flex: 1;
        }

        .search-input-icon {
          position: absolute;
          left: 1rem;
          top: 50%;
          transform: translateY(-50%);
          color: var(--text-muted);
          pointer-events: none;
          font-size: 1.1rem;
        }

        .search-field {
          width: 100%;
          padding: 0.75rem 1rem 0.75rem 2.5rem;
          background: rgba(15, 17, 21, 0.7);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          color: var(--text-primary);
          font-family: var(--font-sans);
          font-size: 0.95rem;
          outline: none;
          transition: all var(--transition-fast);
        }

        .search-field:focus {
          border-color: var(--accent-start);
          box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15);
        }

        .search-mode-selector {
          display: flex;
          background: rgba(15, 17, 21, 0.5);
          border: 1px solid var(--border-color);
          padding: 0.25rem;
          border-radius: var(--radius-md);
          gap: 0.25rem;
        }

        .search-mode-btn {
          flex: 1;
          background: transparent;
          border: none;
          color: var(--text-muted);
          padding: 0.6rem 1.2rem;
          font-size: 0.85rem;
          font-weight: 600;
          border-radius: var(--radius-sm);
          cursor: pointer;
          transition: all var(--transition-fast);
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
        }

        .search-mode-btn:hover {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.02);
        }

        .search-mode-btn.active {
          background: var(--gradient-accent);
          color: var(--text-primary);
          box-shadow: var(--shadow-sm);
        }

        /* Filters list styling */
        .search-filters-row {
          display: flex;
          flex-wrap: wrap;
          gap: 1rem;
          align-items: center;
          font-size: 0.85rem;
        }

        .filter-group {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .filter-label {
          color: var(--text-muted);
          font-weight: 500;
        }

        .search-select-box, .search-numeric-input {
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          color: var(--text-primary);
          padding: 0.4rem 0.75rem;
          outline: none;
          font-size: 0.85rem;
          transition: all var(--transition-fast);
        }

        .search-select-box:focus, .search-numeric-input:focus {
          border-color: var(--accent-start);
        }

        .search-numeric-input {
          width: 100px;
          font-family: var(--font-mono);
        }

        .checkbox-container {
          display: flex;
          align-items: center;
          gap: 0.4rem;
          cursor: pointer;
          color: var(--text-secondary);
          user-select: none;
        }

        .checkbox-container input {
          cursor: pointer;
          accent-color: var(--accent-start);
        }

        /* Results Area styling */
        .search-results-container {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-height: 0;
        }

        .search-status-bar {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          color: var(--text-muted);
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 0.5rem;
        }

        .search-results-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          padding-right: 6px;
        }

        .search-result-card {
          background: rgba(255, 255, 255, 0.015);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          transition: all var(--transition-fast);
          position: relative;
          overflow: hidden;
        }

        .search-result-card:hover {
          background: rgba(255, 255, 255, 0.035);
          border-color: rgba(99, 102, 241, 0.3);
          transform: translateY(-1px);
        }

        .result-meta-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 0.5rem;
        }

        .result-address-badge {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          font-weight: 700;
          color: #38bdf8;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .result-offset {
          color: var(--text-muted);
          font-size: 0.75rem;
          font-weight: 400;
        }

        .result-badges {
          display: flex;
          gap: 0.5rem;
          align-items: center;
        }

        .badge {
          font-size: 0.7rem;
          text-transform: uppercase;
          font-weight: 700;
          padding: 2px 6px;
          border-radius: 4px;
          border: 1px solid var(--border-color);
        }

        .badge-mode {
          background: rgba(99, 102, 241, 0.1);
          color: #a5b4fc;
          border-color: rgba(99, 102, 241, 0.2);
        }

        .badge-section {
          background: rgba(255, 255, 255, 0.05);
          color: var(--text-secondary);
        }

        .result-preview-box {
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.03);
          border-radius: var(--radius-sm);
          padding: 0.6rem 0.8rem;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          line-height: 1.4;
          color: var(--text-secondary);
          word-break: break-all;
        }

        .highlight-match {
          background: rgba(239, 68, 68, 0.18);
          color: #f87171;
          border-bottom: 1px dashed #f87171;
          padding: 0 1px;
          font-weight: 600;
        }

        .highlight-hex-match {
          background: rgba(16, 185, 129, 0.18);
          color: #34d399;
          border-bottom: 1px dashed #34d399;
          padding: 0 1px;
          font-weight: 600;
        }

        .result-actions {
          display: flex;
          justify-content: flex-end;
          gap: 0.5rem;
        }

        .action-nav-btn {
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 0.35rem 0.75rem;
          border-radius: var(--radius-sm);
          font-size: 0.75rem;
          font-weight: 600;
          cursor: pointer;
          transition: all var(--transition-fast);
          display: flex;
          align-items: center;
          gap: 0.35rem;
        }

        .action-nav-btn:hover {
          background: rgba(99, 102, 241, 0.12);
          border-color: var(--accent-start);
          color: var(--text-primary);
        }

        .action-nav-btn.asm-btn:hover {
          box-shadow: 0 0 8px rgba(56, 189, 248, 0.2);
        }
        .action-nav-btn.hex-btn:hover {
          box-shadow: 0 0 8px rgba(52, 211, 153, 0.2);
        }
        .action-nav-btn.dec-btn:hover {
          box-shadow: 0 0 8px rgba(139, 92, 246, 0.2);
        }
      `;
      document.head.appendChild(style);
    }

    // Header structure
    const headerControls = document.createElement('div');
    headerControls.className = 'search-header-controls';

    // Mode Selector Row
    const modeSelector = document.createElement('div');
    modeSelector.className = 'search-mode-selector';

    const modes = [
      {
        id: 'text',
        label: '🔍 Text',
        placeholder: 'Search strings, symbols, or comments...',
      },
      {
        id: 'hex',
        label: '🔢 Hex / Wildcard',
        placeholder: 'e.g. 55 ?? 48 8d or 89 05 ?? ?? ?? 00',
      },
      {
        id: 'instruction',
        label: '⚙️ Instruction',
        placeholder: 'e.g. mov rax or jmp or add',
      },
    ];

    modes.forEach((mode) => {
      const btn = document.createElement('button');
      btn.className = `search-mode-btn ${this.activeMode === mode.id ? 'active' : ''}`;
      btn.innerHTML = mode.label;
      btn.addEventListener('click', () =>
        this.switchMode(mode.id as any, mode.placeholder)
      );
      this.modeButtons.set(mode.id, btn);
      modeSelector.appendChild(btn);
    });
    headerControls.appendChild(modeSelector);

    // Input row
    const inputWrapper = document.createElement('div');
    inputWrapper.className = 'search-input-wrapper';

    const inputContainer = document.createElement('div');
    inputContainer.className = 'search-input-container';

    const iconSpan = document.createElement('span');
    iconSpan.className = 'search-input-icon';
    iconSpan.textContent = '🔎';

    this.queryInput = document.createElement('input');
    this.queryInput.type = 'text';
    this.queryInput.className = 'search-field';
    this.queryInput.placeholder = modes[0].placeholder;

    inputContainer.appendChild(iconSpan);
    inputContainer.appendChild(this.queryInput);
    inputWrapper.appendChild(inputContainer);
    headerControls.appendChild(inputWrapper);

    // Filters row
    const filtersRow = document.createElement('div');
    filtersRow.className = 'search-filters-row';

    // Case sensitivity
    const caseLabel = document.createElement('label');
    caseLabel.className = 'checkbox-container';
    this.caseSensitiveCheckbox = document.createElement('input');
    this.caseSensitiveCheckbox.type = 'checkbox';
    caseLabel.appendChild(this.caseSensitiveCheckbox);
    caseLabel.appendChild(document.createTextNode(' Case Sensitive'));
    filtersRow.appendChild(caseLabel);

    // Section Filter
    const sectionGroup = document.createElement('div');
    sectionGroup.className = 'filter-group';
    const sectionLabel = document.createElement('span');
    sectionLabel.className = 'filter-label';
    sectionLabel.textContent = 'Section:';
    this.sectionSelect = document.createElement('select');
    this.sectionSelect.className = 'search-select-box';
    const optAll = document.createElement('option');
    optAll.value = 'all';
    optAll.textContent = 'All Sections';
    this.sectionSelect.appendChild(optAll);
    sectionGroup.appendChild(sectionLabel);
    sectionGroup.appendChild(this.sectionSelect);
    filtersRow.appendChild(sectionGroup);

    // Address Range filters
    const rangeGroup = document.createElement('div');
    rangeGroup.className = 'filter-group';
    const rangeLabel = document.createElement('span');
    rangeLabel.className = 'filter-label';
    rangeLabel.textContent = 'Addr Range:';

    this.minAddrInput = document.createElement('input');
    this.minAddrInput.type = 'text';
    this.minAddrInput.className = 'search-numeric-input';
    this.minAddrInput.placeholder = 'Min (hex)';

    const rangeSep = document.createElement('span');
    rangeSep.className = 'filter-label';
    rangeSep.textContent = '-';

    this.maxAddrInput = document.createElement('input');
    this.maxAddrInput.type = 'text';
    this.maxAddrInput.className = 'search-numeric-input';
    this.maxAddrInput.placeholder = 'Max (hex)';

    rangeGroup.appendChild(rangeLabel);
    rangeGroup.appendChild(this.minAddrInput);
    rangeGroup.appendChild(rangeSep);
    rangeGroup.appendChild(this.maxAddrInput);
    filtersRow.appendChild(rangeGroup);

    headerControls.appendChild(filtersRow);
    this.rootEl.appendChild(headerControls);

    // Results container
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'search-results-container';

    // Status bar
    const statusBar = document.createElement('div');
    statusBar.className = 'search-status-bar';
    this.statusTextEl = document.createElement('div');
    this.statusTextEl.textContent = 'Ready to search';
    statusBar.appendChild(this.statusTextEl);
    resultsContainer.appendChild(statusBar);

    // List
    this.resultsListEl = document.createElement('div');
    this.resultsListEl.className = 'search-results-list';
    resultsContainer.appendChild(this.resultsListEl);

    this.rootEl.appendChild(resultsContainer);
    this.container.appendChild(this.rootEl);

    // Initial message
    this.resultsListEl.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
        🔒 Enter a search query above to inspect the loaded binary.
      </div>
    `;
  }

  private switchMode(
    mode: 'text' | 'hex' | 'instruction',
    placeholder: string
  ) {
    this.activeMode = mode;
    this.modeButtons.forEach((btn, id) => {
      if (id === mode) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });
    this.queryInput.placeholder = placeholder;

    // Toggle case sensitive checkbox relevance
    if (mode === 'hex') {
      this.caseSensitiveCheckbox.disabled = true;
      this.caseSensitiveCheckbox.parentElement!.style.opacity = '0.5';
    } else {
      this.caseSensitiveCheckbox.disabled = false;
      this.caseSensitiveCheckbox.parentElement!.style.opacity = '1';
    }

    this.performSearch();
  }

  private setupEvents() {
    const triggerSearch = () => this.performSearch();

    this.queryInput.addEventListener('input', triggerSearch);
    this.caseSensitiveCheckbox.addEventListener('change', triggerSearch);
    this.sectionSelect.addEventListener('change', triggerSearch);
    this.minAddrInput.addEventListener('input', triggerSearch);
    this.maxAddrInput.addEventListener('input', triggerSearch);
  }

  private populateSectionsFilter() {
    // Keep first option
    this.sectionSelect.innerHTML = '<option value="all">All Sections</option>';
    this.sections.forEach((sec) => {
      const opt = document.createElement('option');
      opt.value = sec.name;
      opt.textContent = `${sec.name} (0x${sec.virtualAddress.toString(16)})`;
      this.sectionSelect.appendChild(opt);
    });
  }

  private performSearch() {
    const query = this.queryInput.value.trim();
    if (!query) {
      this.statusTextEl.textContent = 'Ready to search';
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          🔒 Enter a search query above to inspect the loaded binary.
        </div>
      `;
      return;
    }

    // Get filter states
    const caseSensitive = this.caseSensitiveCheckbox.checked;
    const sectionName = this.sectionSelect.value;
    const minAddrStr = this.minAddrInput.value.trim();
    const maxAddrStr = this.maxAddrInput.value.trim();

    let minAddr = minAddrStr ? parseInt(minAddrStr, 16) : 0;
    let maxAddr = maxAddrStr ? parseInt(maxAddrStr, 16) : Infinity;

    if (isNaN(minAddr)) minAddr = 0;
    if (isNaN(maxAddr)) maxAddr = Infinity;

    let results: SearchResult[] = [];

    // Retrieve active executable section base for offset mapping
    const executeSection = this.sections.find((s) => s.flags.execute);
    const textBaseAddress = executeSection
      ? executeSection.virtualAddress
      : 0x1000;

    if (this.activeMode === 'text') {
      const lQuery = caseSensitive ? query : query.toLowerCase();

      // 1. Search symbols
      this.symbols.forEach((sym) => {
        const name = caseSensitive ? sym.name : sym.name.toLowerCase();
        if (
          name.includes(lQuery) &&
          sym.address >= minAddr &&
          sym.address <= maxAddr
        ) {
          if (
            sectionName === 'all' ||
            this.isAddressInSection(sym.address, sectionName)
          ) {
            results.push({
              address: sym.address,
              offset: sym.address - textBaseAddress,
              section: this.getSectionNameForAddress(sym.address),
              type: 'Symbol',
              preview: `Symbol: ${sym.name} [Type: ${sym.type}, Binding: ${sym.binding}]`,
              matchedText: query,
            });
          }
        }
      });

      // 2. Search extracted strings
      this.strings.forEach((str) => {
        const val = caseSensitive ? str.value : str.value.toLowerCase();
        if (
          val.includes(lQuery) &&
          str.virtualAddress >= minAddr &&
          str.virtualAddress <= maxAddr
        ) {
          if (
            sectionName === 'all' ||
            this.isAddressInSection(str.virtualAddress, sectionName)
          ) {
            results.push({
              address: str.virtualAddress,
              offset: str.offset,
              section: this.getSectionNameForAddress(str.virtualAddress),
              type: 'Text',
              preview: `"${str.value}" (${str.encoding})`,
              matchedText: query,
            });
          }
        }
      });

      // 3. Search comments
      this.comments.forEach((comment, addr) => {
        const text = caseSensitive ? comment : comment.toLowerCase();
        if (text.includes(lQuery) && addr >= minAddr && addr <= maxAddr) {
          if (
            sectionName === 'all' ||
            this.isAddressInSection(addr, sectionName)
          ) {
            results.push({
              address: addr,
              offset: addr - textBaseAddress,
              section: this.getSectionNameForAddress(addr),
              type: 'Text',
              preview: `// ${comment}`,
              matchedText: query,
            });
          }
        }
      });
    } else if (this.activeMode === 'hex') {
      // Hex wildcard search on binaryData
      // Parse query tokens: e.g. "55 ?? 48 8d"
      const tokens = query.split(/\s+/);
      const pattern: { value: number; isWildcard: boolean }[] = [];
      let parseOk = true;

      for (const tok of tokens) {
        if (tok === '??' || tok === '?') {
          pattern.push({ value: 0, isWildcard: true });
        } else {
          const val = parseInt(tok, 16);
          if (isNaN(val) || val < 0 || val > 255) {
            parseOk = false;
            break;
          }
          pattern.push({ value: val, isWildcard: false });
        }
      }

      if (parseOk && pattern.length > 0) {
        // Search across the raw binary data
        for (let i = 0; i <= this.binaryData.length - pattern.length; i++) {
          let match = true;
          for (let j = 0; j < pattern.length; j++) {
            if (pattern[j].isWildcard) continue;
            if (this.binaryData[i + j] !== pattern[j].value) {
              match = false;
              break;
            }
          }

          if (match) {
            // Check filters
            const addr = textBaseAddress + i;
            if (addr >= minAddr && addr <= maxAddr) {
              const secName = this.getSectionNameForAddress(addr);
              if (sectionName === 'all' || secName === sectionName) {
                // Build a nice hex preview snippet
                const matchBytes = Array.from(
                  this.binaryData.slice(i, i + Math.max(pattern.length, 8))
                );
                const hexStr = matchBytes
                  .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
                  .join(' ');
                results.push({
                  address: addr,
                  offset: i,
                  section: secName,
                  type: 'Hex',
                  preview: hexStr,
                  matchedText: query,
                });
              }
            }
          }
        }
      } else {
        this.statusTextEl.textContent = 'Invalid hex query pattern';
        this.resultsListEl.innerHTML = `
          <div style="text-align: center; color: var(--error); margin-top: 4rem; font-size: 0.95rem;">
            ⚠️ Invalid Hex pattern. Use tokens like '55', '??', 'A9', etc.
          </div>
        `;
        return;
      }
    } else if (this.activeMode === 'instruction') {
      const lQuery = caseSensitive ? query : query.toLowerCase();

      this.instructions.forEach((inst) => {
        const fullInstText = `${inst.mnemonic} ${inst.opStr}`;
        const searchTarget = caseSensitive
          ? fullInstText
          : fullInstText.toLowerCase();

        if (
          searchTarget.includes(lQuery) &&
          inst.address >= minAddr &&
          inst.address <= maxAddr
        ) {
          if (
            sectionName === 'all' ||
            this.isAddressInSection(inst.address, sectionName)
          ) {
            // Build hex representation of instructions
            const instHex = Array.from(inst.bytes)
              .map((b) => b.toString(16).padStart(2, '0'))
              .join(' ');
            results.push({
              address: inst.address,
              offset: inst.address - textBaseAddress,
              section: this.getSectionNameForAddress(inst.address),
              type: 'Instruction',
              preview: `${inst.mnemonic.toUpperCase()} ${inst.opStr}  ; (Hex: ${instHex})`,
              matchedText: query,
            });
          }
        }
      });
    }

    // Render results
    this.statusTextEl.textContent = `Found ${results.length} result(s)`;
    this.renderResults(results);
  }

  private renderResults(results: SearchResult[]) {
    this.resultsListEl.innerHTML = '';
    if (results.length === 0) {
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          No matching results found for this filter/query combo.
        </div>
      `;
      return;
    }

    const fragment = document.createDocumentFragment();
    // Cap results at 200 for extreme rendering performance
    const renderLimit = Math.min(results.length, 200);

    for (let i = 0; i < renderLimit; i++) {
      const res = results[i];
      const card = document.createElement('div');
      card.className = 'search-result-card';

      // Meta row
      const metaRow = document.createElement('div');
      metaRow.className = 'result-meta-row';

      const addrBadge = document.createElement('span');
      addrBadge.className = 'result-address-badge';
      addrBadge.innerHTML = `0x${res.address.toString(16).toUpperCase()} <span class="result-offset">Offset: 0x${res.offset.toString(16).toUpperCase()}</span>`;

      const badgesDiv = document.createElement('div');
      badgesDiv.className = 'result-badges';

      const modeBadge = document.createElement('span');
      modeBadge.className = 'badge badge-mode';
      modeBadge.textContent = res.type;

      const secBadge = document.createElement('span');
      secBadge.className = 'badge badge-section';
      secBadge.textContent = res.section || 'unknown';

      badgesDiv.appendChild(modeBadge);
      badgesDiv.appendChild(secBadge);

      metaRow.appendChild(addrBadge);
      metaRow.appendChild(badgesDiv);
      card.appendChild(metaRow);

      // Preview box with highlighting
      const previewBox = document.createElement('div');
      previewBox.className = 'result-preview-box';

      if (res.type === 'Hex') {
        previewBox.innerHTML = this.highlightHexSnippet(
          res.preview,
          res.matchedText
        );
      } else {
        previewBox.innerHTML = this.highlightTextSnippet(
          res.preview,
          res.matchedText,
          this.caseSensitiveCheckbox.checked
        );
      }
      card.appendChild(previewBox);

      // Action buttons
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'result-actions';

      const asmBtn = document.createElement('button');
      asmBtn.className = 'action-nav-btn asm-btn';
      asmBtn.innerHTML = '⚡ Assembly';
      asmBtn.addEventListener('click', () =>
        this.options.onNavigate('assembly', res.address)
      );

      const hexBtn = document.createElement('button');
      hexBtn.className = 'action-nav-btn hex-btn';
      hexBtn.innerHTML = '🔢 Hex Viewer';
      hexBtn.addEventListener('click', () =>
        this.options.onNavigate('hex', res.address)
      );

      const decBtn = document.createElement('button');
      decBtn.className = 'action-nav-btn dec-btn';
      decBtn.innerHTML = '⚙️ Decompiler';
      decBtn.addEventListener('click', () =>
        this.options.onNavigate('decompiler', res.address)
      );

      actionsDiv.appendChild(asmBtn);
      actionsDiv.appendChild(hexBtn);
      actionsDiv.appendChild(decBtn);
      card.appendChild(actionsDiv);

      fragment.appendChild(card);
    }

    if (results.length > renderLimit) {
      const footerNotice = document.createElement('div');
      footerNotice.style.cssText =
        'text-align: center; color: var(--text-muted); font-size: 0.8rem; padding: 1rem;';
      footerNotice.textContent = `Showing top 200 of ${results.length} results. Refine your query or filters for more precise matches.`;
      fragment.appendChild(footerNotice);
    }

    this.resultsListEl.appendChild(fragment);
  }

  private highlightTextSnippet(
    text: string,
    match: string,
    caseSensitive: boolean
  ): string {
    const escapedText = this.escapeHtml(text);
    if (!match) return escapedText;

    const escapedMatch = this.escapeRegExp(match);
    const regex = new RegExp(`(${escapedMatch})`, caseSensitive ? 'g' : 'gi');
    return escapedText.replace(
      regex,
      '<span class="highlight-match">$1</span>'
    );
  }

  private highlightHexSnippet(previewHex: string, pattern: string): string {
    // previewHex is like "55 48 8D 05 00 00 00 00"
    // pattern can contain wildcard, like "55 ?? 48 8d"
    // Let's tokenize pattern and see how they align.
    const previewTokens = previewHex.split(' ');
    const patternTokens = pattern.trim().split(/\s+/);

    const highlighted = previewTokens.map((tok, idx) => {
      if (idx < patternTokens.length) {
        const patTok = patternTokens[idx];
        if (patTok === '??' || patTok === '?') {
          return `<span class="highlight-hex-match">${tok}</span>`;
        }
        if (patTok.toLowerCase() === tok.toLowerCase()) {
          return `<span class="highlight-hex-match">${tok}</span>`;
        }
      }
      return tok;
    });

    return highlighted.join(' ');
  }

  private isAddressInSection(address: number, sectionName: string): boolean {
    const sec = this.sections.find((s) => s.name === sectionName);
    if (!sec) return false;
    return (
      address >= sec.virtualAddress &&
      address < sec.virtualAddress + sec.virtualSize
    );
  }

  private getSectionNameForAddress(address: number): string {
    const sec = this.sections.find(
      (s) =>
        address >= s.virtualAddress &&
        address < s.virtualAddress + s.virtualSize
    );
    return sec ? sec.name : '';
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private escapeRegExp(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
