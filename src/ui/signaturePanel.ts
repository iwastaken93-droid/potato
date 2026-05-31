/**
 * Premium Signatures Scan Result Viewer Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides signature-based file detection
 */

import { Section } from '../disassembler/types.js';
import {
  SignatureScanner,
  ScanResult,
  RuleCategory,
} from '../analyzer/signatures.js';

export interface SignaturePanelOptions {
  onNavigate: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export class SignaturePanel {
  private container: HTMLElement;
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private options: SignaturePanelOptions;
  private scanner: SignatureScanner;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private resultsListEl!: HTMLDivElement;
  private categoryFilterSelect!: HTMLSelectElement;
  private statusTextEl!: HTMLDivElement;
  private ruleCountEl!: HTMLSpanElement;

  private currentResults: ScanResult[] = [];
  private activeCategoryFilter: string = 'all';

  constructor(container: HTMLElement, options: SignaturePanelOptions) {
    this.container = container;
    this.options = options;
    this.scanner = new SignatureScanner(true);

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates the signature panel data and automatically performs a scan
   */
  public updateData(binaryData: Uint8Array, sections: Section[]) {
    this.binaryData = binaryData;
    this.sections = sections;

    this.runScan();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'signature-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject styles matching searchPanel.ts
    if (!document.getElementById('signature-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'signature-panel-styles';
      style.textContent = `
        .signature-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }

        .sig-header-controls {
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

        .sig-title-area {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }

        .sig-title {
          font-size: 1.15rem;
          font-weight: 700;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .sig-subtitle {
          font-size: 0.8rem;
          color: var(--text-muted);
        }

        .sig-filters-row {
          display: flex;
          gap: 1rem;
          align-items: center;
        }

        .sig-filter-label {
          font-size: 0.85rem;
          color: var(--text-muted);
          font-weight: 500;
        }

        .sig-select-box {
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          color: var(--text-primary);
          padding: 0.4rem 0.75rem;
          outline: none;
          font-size: 0.85rem;
          transition: all var(--transition-fast);
        }

        .sig-select-box:focus {
          border-color: var(--accent-start);
        }

        /* Results container styling */
        .sig-results-container {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-height: 0;
        }

        .sig-status-bar {
          display: flex;
          justify-content: space-between;
          font-size: 0.8rem;
          color: var(--text-muted);
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 0.5rem;
        }

        .sig-results-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 1.25rem;
          padding-right: 6px;
        }

        .sig-category-group {
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .sig-category-header {
          font-size: 0.9rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          padding-bottom: 0.35rem;
          border-bottom: 2px solid rgba(255, 255, 255, 0.05);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .sig-category-header.compiler {
          color: #a5b4fc; /* light indigo */
          border-bottom-color: rgba(99, 102, 241, 0.3);
        }

        .sig-category-header.packer {
          color: #fdba74; /* light orange */
          border-bottom-color: rgba(249, 115, 22, 0.3);
        }

        .sig-category-header.crypto {
          color: #6ee7b7; /* light emerald/green */
          border-bottom-color: rgba(16, 185, 129, 0.3);
        }

        .sig-category-header.other {
          color: #cbd5e1; /* light slate */
          border-bottom-color: rgba(148, 163, 184, 0.3);
        }

        .sig-result-card {
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

        .sig-result-card:hover {
          background: rgba(255, 255, 255, 0.035);
          border-color: rgba(99, 102, 241, 0.3);
          transform: translateY(-1px);
        }

        .sig-meta-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          flex-wrap: wrap;
          gap: 0.5rem;
        }

        .sig-rule-name {
          font-weight: 700;
          font-size: 0.95rem;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .sig-rule-badge {
          font-size: 0.7rem;
          text-transform: uppercase;
          font-weight: 700;
          padding: 2px 6px;
          border-radius: 4px;
          border: 1px solid var(--border-color);
        }

        .sig-rule-badge.compiler {
          background: rgba(99, 102, 241, 0.1);
          color: #a5b4fc;
          border-color: rgba(99, 102, 241, 0.2);
        }

        .sig-rule-badge.packer {
          background: rgba(249, 115, 22, 0.1);
          color: #fdba74;
          border-color: rgba(249, 115, 22, 0.2);
        }

        .sig-rule-badge.crypto {
          background: rgba(16, 185, 129, 0.1);
          color: #6ee7b7;
          border-color: rgba(16, 185, 129, 0.2);
        }

        .sig-rule-badge.other {
          background: rgba(148, 163, 184, 0.1);
          color: #cbd5e1;
          border-color: rgba(148, 163, 184, 0.2);
        }

        /* Matches breakdown */
        .sig-matches-container {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .sig-match-item {
          background: rgba(15, 17, 21, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.03);
          border-radius: var(--radius-sm);
          padding: 0.6rem 0.8rem;
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 1rem;
          flex-wrap: wrap;
        }

        .sig-match-details {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }

        .sig-match-addr {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          font-weight: 700;
          color: #38bdf8;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .sig-match-offset {
          color: var(--text-muted);
          font-size: 0.75rem;
          font-weight: 400;
        }

        .sig-match-preview {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          color: var(--text-secondary);
          word-break: break-all;
        }

        .sig-match-type-tag {
          font-size: 0.7rem;
          color: var(--text-muted);
          font-weight: 500;
          font-style: italic;
        }

        .sig-match-actions {
          display: flex;
          gap: 0.5rem;
        }

        .sig-action-btn {
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

        .sig-action-btn:hover {
          background: rgba(99, 102, 241, 0.12);
          border-color: var(--accent-start);
          color: var(--text-primary);
        }

        .sig-action-btn.asm-btn:hover {
          box-shadow: 0 0 8px rgba(56, 189, 248, 0.2);
        }
        .sig-action-btn.hex-btn:hover {
          box-shadow: 0 0 8px rgba(52, 211, 153, 0.2);
        }
      `;
      document.head.appendChild(style);
    }

    // Header controls
    const headerControls = document.createElement('div');
    headerControls.className = 'sig-header-controls';

    const titleArea = document.createElement('div');
    titleArea.className = 'sig-title-area';

    const title = document.createElement('div');
    title.className = 'sig-title';
    title.innerHTML = '🛡️ Premium Signatures Scan';

    const subtitle = document.createElement('div');
    subtitle.className = 'sig-subtitle';
    subtitle.innerHTML = `Loaded rules: <span id="sig-rules-count" style="font-weight: 600; color: #a5b4fc;">${this.scanner.getRules().length}</span> signatures`;

    titleArea.appendChild(title);
    titleArea.appendChild(subtitle);
    headerControls.appendChild(titleArea);

    // Filters row
    const filtersRow = document.createElement('div');
    filtersRow.className = 'sig-filters-row';

    const filterLabel = document.createElement('span');
    filterLabel.className = 'sig-filter-label';
    filterLabel.textContent = 'Category:';

    this.categoryFilterSelect = document.createElement('select');
    this.categoryFilterSelect.className = 'sig-select-box';

    const categories: { value: string; label: string }[] = [
      { value: 'all', label: 'All Categories' },
      { value: 'compiler', label: 'Compilers' },
      { value: 'packer', label: 'Packers' },
      { value: 'crypto', label: 'Cryptography' },
      { value: 'other', label: 'Other/Custom' },
    ];

    categories.forEach((cat) => {
      const opt = document.createElement('option');
      opt.value = cat.value;
      opt.textContent = cat.label;
      this.categoryFilterSelect.appendChild(opt);
    });

    filtersRow.appendChild(filterLabel);
    filtersRow.appendChild(this.categoryFilterSelect);
    headerControls.appendChild(filtersRow);

    this.rootEl.appendChild(headerControls);

    // Results area
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'sig-results-container';

    // Status bar
    const statusBar = document.createElement('div');
    statusBar.className = 'sig-status-bar';
    this.statusTextEl = document.createElement('div');
    this.statusTextEl.textContent = 'Ready to scan';
    statusBar.appendChild(this.statusTextEl);
    resultsContainer.appendChild(statusBar);

    // List
    this.resultsListEl = document.createElement('div');
    this.resultsListEl.className = 'sig-results-list';
    resultsContainer.appendChild(this.resultsListEl);

    this.rootEl.appendChild(resultsContainer);
    this.container.appendChild(this.rootEl);

    this.ruleCountEl = document.getElementById(
      'sig-rules-count'
    ) as HTMLSpanElement;

    // Initial state info
    this.resultsListEl.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
        🔍 Load a binary file to run compiler, packer, and crypto signature scanning automatically.
      </div>
    `;
  }

  private setupEvents() {
    this.categoryFilterSelect.addEventListener('change', () => {
      this.activeCategoryFilter = this.categoryFilterSelect.value;
      this.renderResults();
    });
  }

  private runScan() {
    if (this.binaryData.length === 0) {
      this.currentResults = [];
      this.statusTextEl.textContent = 'No binary data loaded';
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          🔍 Load a binary file to run compiler, packer, and crypto signature scanning automatically.
        </div>
      `;
      return;
    }

    this.statusTextEl.textContent = 'Scanning binary...';
    try {
      this.currentResults = this.scanner.scan(this.binaryData);
      this.renderResults();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this.statusTextEl.textContent = 'Scan failed';
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--error); margin-top: 4rem; font-size: 0.95rem;">
          ⚠️ Scan failed: ${msg}
        </div>
      `;
    }
  }

  private getAddressFromOffset(offset: number): number {
    const sec = this.sections.find(
      (s) => offset >= s.fileOffset && offset < s.fileOffset + s.fileSize
    );
    if (sec) {
      return sec.virtualAddress + (offset - sec.fileOffset);
    }
    // Fallback: if no section maps this offset, map from executable section or default base
    const executeSection = this.sections.find((s) => s.flags.execute);
    const textBaseAddress = executeSection
      ? executeSection.virtualAddress
      : 0x1000;
    return textBaseAddress + offset;
  }

  private renderResults() {
    this.resultsListEl.innerHTML = '';

    // Filter results according to category filter
    const filteredResults = this.currentResults.filter((res) => {
      if (this.activeCategoryFilter === 'all') return true;
      return res.category === this.activeCategoryFilter;
    });

    // Group results by category
    const categoriesMap: Record<RuleCategory, ScanResult[]> = {
      compiler: [],
      packer: [],
      crypto: [],
      other: [],
    };

    let totalMatchesCount = 0;

    filteredResults.forEach((res) => {
      if (categoriesMap[res.category]) {
        categoriesMap[res.category].push(res);
        totalMatchesCount += res.matches.length;
      }
    });

    this.statusTextEl.textContent = `Found ${filteredResults.length} rule matches (${totalMatchesCount} total matched offsets)`;

    const categoriesOrder: {
      key: RuleCategory;
      label: string;
      icon: string;
    }[] = [
      { key: 'compiler', label: 'Compilers / Toolchains', icon: '⚙️' },
      {
        key: 'packer',
        label: 'Packers / Protectors / Compressors',
        icon: '📦',
      },
      {
        key: 'crypto',
        label: 'Cryptographic Constants / Algorithms',
        icon: '🔑',
      },
      { key: 'other', label: 'Other Signatures', icon: '🏷️' },
    ];

    let hasAnyMatches = false;
    const fragment = document.createDocumentFragment();

    categoriesOrder.forEach((cat) => {
      const resultsForCat = categoriesMap[cat.key];
      if (!resultsForCat || resultsForCat.length === 0) return;

      hasAnyMatches = true;

      // Group container
      const groupDiv = document.createElement('div');
      groupDiv.className = 'sig-category-group';

      // Category Header
      const headerDiv = document.createElement('div');
      headerDiv.className = `sig-category-header ${cat.key}`;
      headerDiv.textContent = `${cat.icon} ${cat.label} (${resultsForCat.length})`;
      groupDiv.appendChild(headerDiv);

      // Category Results
      resultsForCat.forEach((res) => {
        const card = document.createElement('div');
        card.className = 'sig-result-card';

        // Meta header inside card
        const metaRow = document.createElement('div');
        metaRow.className = 'sig-meta-row';

        const ruleNameDiv = document.createElement('div');
        ruleNameDiv.className = 'sig-rule-name';
        ruleNameDiv.textContent = res.ruleName;

        const badge = document.createElement('span');
        badge.className = `sig-rule-badge ${res.category}`;
        badge.textContent = res.category;

        metaRow.appendChild(ruleNameDiv);
        metaRow.appendChild(badge);
        card.appendChild(metaRow);

        // Matches Breakdown
        const matchesContainer = document.createElement('div');
        matchesContainer.className = 'sig-matches-container';

        res.matches.forEach((match) => {
          const matchItem = document.createElement('div');
          matchItem.className = 'sig-match-item';

          const virtualAddress = this.getAddressFromOffset(match.offset);

          // Left side info
          const detailsDiv = document.createElement('div');
          detailsDiv.className = 'sig-match-details';

          const addrBadge = document.createElement('div');
          addrBadge.className = 'sig-match-addr';
          addrBadge.innerHTML = `0x${virtualAddress.toString(16).toUpperCase()} <span class="sig-match-offset">Offset: 0x${match.offset.toString(16).toUpperCase()}</span>`;
          detailsDiv.appendChild(addrBadge);

          const previewDiv = document.createElement('div');
          previewDiv.className = 'sig-match-preview';
          previewDiv.innerHTML = `Value: <span class="sig-match-type-tag">(${match.patternType})</span> <code>${this.escapeHtml(match.matchedValue)}</code>`;
          detailsDiv.appendChild(previewDiv);

          matchItem.appendChild(detailsDiv);

          // Right side actions
          const actionsDiv = document.createElement('div');
          actionsDiv.className = 'sig-match-actions';

          const asmBtn = document.createElement('button');
          asmBtn.className = 'sig-action-btn asm-btn';
          asmBtn.innerHTML = '⚡ Assembly';
          asmBtn.addEventListener('click', () =>
            this.options.onNavigate('assembly', virtualAddress)
          );

          const hexBtn = document.createElement('button');
          hexBtn.className = 'sig-action-btn hex-btn';
          hexBtn.innerHTML = '🔢 Hex Viewer';
          hexBtn.addEventListener('click', () =>
            this.options.onNavigate('hex', virtualAddress)
          );

          actionsDiv.appendChild(asmBtn);
          actionsDiv.appendChild(hexBtn);
          matchItem.appendChild(actionsDiv);

          matchesContainer.appendChild(matchItem);
        });

        card.appendChild(matchesContainer);
        groupDiv.appendChild(card);
      });

      fragment.appendChild(groupDiv);
    });

    if (!hasAnyMatches) {
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          No signatures detected matching the current category filter.
        </div>
      `;
    } else {
      this.resultsListEl.appendChild(fragment);
    }
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
