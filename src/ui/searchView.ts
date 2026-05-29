import { Instruction } from '../disassembler/types.js';
import { ExtractedString } from '../analyzer/strings.js';

export interface SearchResult {
  address: number;
  type: 'Instruction' | 'String' | 'Comment' | 'Hex';
  context: string;
  matchedText: string;
}

export class SearchView {
  private container: HTMLElement;
  private instructions: Instruction[];
  private strings: ExtractedString[];
  private comments: Map<number, string>;
  private onAddressSelect: (address: number) => void;

  private rootEl!: HTMLDivElement;
  private inputEl!: HTMLInputElement;
  private typeSelectEl!: HTMLSelectElement;
  private resultsEl!: HTMLDivElement;

  constructor(
    container: HTMLElement,
    instructions: Instruction[],
    strings: ExtractedString[],
    comments: Map<number, string>,
    onAddressSelect: (address: number) => void
  ) {
    this.container = container;
    this.instructions = instructions;
    this.strings = strings;
    this.comments = comments;
    this.onAddressSelect = onAddressSelect;

    this.initLayout();
    this.setupEvents();
  }

  public updateData(
    instructions: Instruction[],
    strings: ExtractedString[],
    comments: Map<number, string>
  ) {
    this.instructions = instructions;
    this.strings = strings;
    this.comments = comments;
    this.performSearch();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'glass-panel search-panel';
    this.rootEl.style.height = '100%';
    this.rootEl.style.display = 'flex';
    this.rootEl.style.flexDirection = 'column';
    this.rootEl.style.gap = '1rem';
    this.rootEl.style.padding = '1.5rem';

    // Inject styles
    if (!document.getElementById('search-view-styles')) {
      const style = document.createElement('style');
      style.id = 'search-view-styles';
      style.textContent = `
        .search-panel {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(12px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
        }
        .search-row {
          display: flex;
          gap: 0.75rem;
        }
        .search-bar-input {
          flex: 1;
          padding: 0.75rem 1rem;
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          color: var(--text-primary);
          font-family: var(--font-sans);
          font-size: 0.9rem;
          outline: none;
          transition: border-color 0.2s;
        }
        .search-bar-input:focus {
          border-color: var(--accent-start);
        }
        .search-select {
          padding: 0.75rem 1rem;
          background: rgba(15, 17, 21, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          color: var(--text-primary);
          font-size: 0.9rem;
          outline: none;
          cursor: pointer;
        }
        .search-results-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
          padding-right: 4px;
        }
        .search-result-item {
          display: grid;
          grid-template-columns: 100px 100px 1fr;
          gap: 1rem;
          padding: 0.75rem 1rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          cursor: pointer;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          align-items: center;
          transition: all 0.15s ease;
        }
        .search-result-item:hover {
          background: rgba(99, 102, 241, 0.08);
          border-color: var(--accent-start);
          transform: translateX(2px);
        }
        .result-address {
          color: #38bdf8;
          font-weight: 600;
        }
        .result-type {
          font-size: 0.75rem;
          text-transform: uppercase;
          font-weight: 700;
          color: var(--text-muted);
          background: rgba(255, 255, 255, 0.05);
          padding: 2px 6px;
          border-radius: 4px;
          text-align: center;
          border: 1px solid var(--border-color);
        }
        .result-context {
          color: var(--text-secondary);
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        .result-match-highlight {
          background: rgba(251, 191, 36, 0.25);
          color: #fbbf24;
          padding: 0 2px;
          border-radius: 2px;
          font-weight: 600;
        }
      `;
      document.head.appendChild(style);
    }

    const controls = document.createElement('div');
    controls.className = 'search-row';

    this.inputEl = document.createElement('input');
    this.inputEl.type = 'text';
    this.inputEl.className = 'search-bar-input';
    this.inputEl.placeholder =
      'Search opcode, hex string, comments, strings...';

    this.typeSelectEl = document.createElement('select');
    this.typeSelectEl.className = 'search-select';
    this.typeSelectEl.innerHTML = `
      <option value="all">All Types</option>
      <option value="instruction">Instructions</option>
      <option value="string">Strings</option>
      <option value="comment">Comments</option>
    `;

    controls.appendChild(this.inputEl);
    controls.appendChild(this.typeSelectEl);
    this.rootEl.appendChild(controls);

    this.resultsEl = document.createElement('div');
    this.resultsEl.className = 'search-results-list';
    this.rootEl.appendChild(this.resultsEl);

    this.container.appendChild(this.rootEl);

    // Initial empty state message
    this.resultsEl.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); margin-top: 3rem; font-size: 0.9rem;">
        Type a query to search across the entire binary.
      </div>
    `;
  }

  private setupEvents() {
    const handleInput = () => this.performSearch();
    this.inputEl.addEventListener('input', handleInput);
    this.typeSelectEl.addEventListener('change', handleInput);

    this.resultsEl.addEventListener('click', (e) => {
      const item = (e.target as HTMLElement).closest(
        '.search-result-item'
      ) as HTMLElement;
      if (item && item.dataset.address) {
        const addr = parseInt(item.dataset.address, 10);
        this.onAddressSelect(addr);
      }
    });
  }

  private performSearch() {
    const query = this.inputEl.value.trim().toLowerCase();
    const filterType = this.typeSelectEl.value;

    if (!query) {
      this.resultsEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 3rem; font-size: 0.9rem;">
          Type a query to search across the entire binary.
        </div>
      `;
      return;
    }

    const results: SearchResult[] = [];

    // 1. Search Instructions
    if (filterType === 'all' || filterType === 'instruction') {
      this.instructions.forEach((inst) => {
        const textToSearch = `${inst.mnemonic} ${inst.opStr}`.toLowerCase();
        if (textToSearch.includes(query)) {
          results.push({
            address: inst.address,
            type: 'Instruction',
            context: `${inst.mnemonic.toUpperCase()} ${inst.opStr}`,
            matchedText: query,
          });
        }
      });
    }

    // 2. Search Strings
    if (filterType === 'all' || filterType === 'string') {
      this.strings.forEach((str) => {
        if (str.value.toLowerCase().includes(query)) {
          results.push({
            address: str.virtualAddress,
            type: 'String',
            context: `"${str.value}" (${str.encoding})`,
            matchedText: query,
          });
        }
      });
    }

    // 3. Search Comments
    if (filterType === 'all' || filterType === 'comment') {
      this.comments.forEach((comment, addr) => {
        if (comment.toLowerCase().includes(query)) {
          results.push({
            address: addr,
            type: 'Comment',
            context: `// ${comment}`,
            matchedText: query,
          });
        }
      });
    }

    // Render results
    if (results.length === 0) {
      this.resultsEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 3rem; font-size: 0.9rem;">
          No matches found for "${query}".
        </div>
      `;
      return;
    }

    this.resultsEl.innerHTML = '';
    const fragment = document.createDocumentFragment();

    // Limit to top 150 results for performance
    results.slice(0, 150).forEach((res) => {
      const item = document.createElement('div');
      item.className = 'search-result-item';
      item.dataset.address = res.address.toString();

      const addrSpan = document.createElement('span');
      addrSpan.className = 'result-address';
      addrSpan.textContent = `0x${res.address.toString(16).toUpperCase()}`;

      const typeSpan = document.createElement('span');
      typeSpan.className = 'result-type';
      typeSpan.textContent = res.type;

      // Safe HTML highlight
      const contextSpan = document.createElement('span');
      contextSpan.className = 'result-context';

      const safeContext = this.escapeHtml(res.context);
      const highlighted = safeContext.replace(
        new RegExp(this.escapeRegExp(res.matchedText), 'gi'),
        (match) => `<span class="result-match-highlight">${match}</span>`
      );
      contextSpan.innerHTML = highlighted;

      item.appendChild(addrSpan);
      item.appendChild(typeSpan);
      item.appendChild(contextSpan);
      fragment.appendChild(item);
    });

    this.resultsEl.appendChild(fragment);
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
