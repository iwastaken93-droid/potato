import { ExtractedString } from '../analyzer/strings.js';

export interface StringsViewOptions {
  onNavigate?: (offset: number, address: number) => void;
}

export class StringsView {
  private container: HTMLElement;
  private allStrings: ExtractedString[] = [];
  private filteredStrings: ExtractedString[] = [];
  private options: StringsViewOptions;

  // View state
  private searchQuery = '';
  private selectedTagFilter = 'all';
  private selectedEncodingFilter = 'all';
  private sortBy: 'offset' | 'address' | 'encoding' | 'value' = 'address';
  private sortOrder: 'asc' | 'desc' = 'asc';

  // DOM elements
  private rootEl!: HTMLDivElement;
  private tableContainerEl!: HTMLDivElement;
  private searchInput!: HTMLInputElement;
  private tableBody!: HTMLTableSectionElement;
  private totalCountEl!: HTMLSpanElement;
  private tagFiltersContainer!: HTMLDivElement;
  private encodingFilterSelect!: HTMLSelectElement;

  constructor(
    container: HTMLElement,
    strings: ExtractedString[],
    options: StringsViewOptions = {}
  ) {
    this.container = container;
    this.allStrings = strings;
    this.filteredStrings = [...strings];
    this.options = options;

    this.injectStyles();
    this.initDOM();
    this.applyFiltersAndSort();
  }

  /**
   * Update the strings data (e.g., when a new binary is loaded).
   */
  public setStrings(strings: ExtractedString[]) {
    this.allStrings = strings;
    this.applyFiltersAndSort();
  }

  private injectStyles() {
    if (document.getElementById('strings-view-styles')) return;

    const style = document.createElement('style');
    style.id = 'strings-view-styles';
    style.textContent = `
      .strings-view-root {
        display: grid;
        grid-template-rows: auto auto 1fr;
        height: 100%;
        gap: 1rem;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        overflow: hidden;
      }

      /* Control panel with search and filters */
      .strings-controls {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        align-items: center;
        justify-content: space-between;
        background: rgba(22, 26, 33, 0.4);
        padding: 1rem 1.25rem;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        backdrop-filter: blur(10px);
      }

      .search-wrapper {
        position: relative;
        flex: 1;
        min-width: 280px;
      }

      .search-wrapper::before {
        content: "🔍";
        position: absolute;
        left: 0.85rem;
        top: 50%;
        transform: translateY(-50%);
        font-size: 0.9rem;
        opacity: 0.5;
        pointer-events: none;
      }

      .strings-search-input {
        width: 100%;
        padding: 0.75rem 1rem 0.75rem 2.25rem;
        background: rgba(15, 17, 21, 0.6);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        color: var(--text-primary);
        font-family: var(--font-sans);
        font-size: 0.9rem;
        transition: all var(--transition-fast);
      }

      .strings-search-input:focus {
        outline: none;
        border-color: var(--accent-start);
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      }

      .filters-group {
        display: flex;
        align-items: center;
        gap: 0.75rem;
      }

      .filter-select {
        padding: 0.75rem 1rem;
        background: rgba(15, 17, 21, 0.6);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        color: var(--text-primary);
        font-size: 0.9rem;
        cursor: pointer;
        outline: none;
        transition: all var(--transition-fast);
      }

      .filter-select:focus {
        border-color: var(--accent-start);
      }

      /* Stats and quick filter chips */
      .strings-stats-row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
        gap: 1rem;
        padding: 0 0.5rem;
      }

      .strings-count-badge {
        font-size: 0.85rem;
        color: var(--text-muted);
      }

      .strings-count-badge strong {
        color: var(--accent-end);
        font-size: 1rem;
      }

      .quick-chips {
        display: flex;
        gap: 0.5rem;
      }

      .quick-chip {
        padding: 0.35rem 0.75rem;
        border-radius: var(--radius-full);
        font-size: 0.75rem;
        font-weight: 600;
        cursor: pointer;
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid var(--border-color);
        color: var(--text-muted);
        transition: all var(--transition-fast);
      }

      .quick-chip:hover {
        background: rgba(255, 255, 255, 0.08);
        color: var(--text-primary);
      }

      .quick-chip.active {
        background: var(--gradient-accent);
        border-color: transparent;
        color: white;
        box-shadow: 0 0 10px rgba(99, 102, 241, 0.3);
      }

      /* Table Container */
      .strings-table-container {
        overflow-y: auto;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        background: rgba(22, 26, 33, 0.3);
        backdrop-filter: blur(10px);
      }

      .strings-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
        font-size: 0.85rem;
      }

      .strings-table th {
        position: sticky;
        top: 0;
        z-index: 10;
        background: var(--bg-tertiary);
        padding: 0.85rem 1rem;
        font-weight: 600;
        color: var(--text-muted);
        border-bottom: 1px solid var(--border-color);
        cursor: pointer;
        user-select: none;
        transition: color var(--transition-fast), background-color var(--transition-fast);
      }

      .strings-table th:hover {
        color: var(--text-primary);
        background: rgba(255, 255, 255, 0.03);
      }

      .strings-table th .sort-indicator {
        margin-left: 0.35rem;
        font-size: 0.75rem;
      }

      .strings-table td {
        padding: 0 1rem;
        height: 38px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        vertical-align: middle;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        box-sizing: border-box;
      }

      .strings-row {
        cursor: pointer;
        transition: all var(--transition-fast);
        position: relative;
        height: 38px;
        box-sizing: border-box;
      }

      .strings-row::before {
        content: "";
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 3px;
        background: var(--accent-start);
        opacity: 0;
        transition: opacity var(--transition-fast);
      }

      .strings-row:hover {
        background: rgba(255, 255, 255, 0.03);
        transform: translateX(2px);
      }

      .strings-row:hover::before {
        opacity: 1;
      }

      .strings-row:active {
        transform: translateX(0) scale(0.995);
      }

      /* Formatting inside columns */
      .col-address, .col-offset {
        font-family: var(--font-mono);
        color: var(--text-muted);
        font-size: 0.8rem;
        width: 110px;
      }

      .col-encoding {
        width: 100px;
      }

      .encoding-badge {
        display: inline-block;
        padding: 0.15rem 0.5rem;
        border-radius: var(--radius-sm);
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        font-family: var(--font-mono);
      }

      .encoding-badge.ascii {
        background: rgba(99, 102, 241, 0.15);
        color: #818cf8;
        border: 1px solid rgba(99, 102, 241, 0.3);
      }

      .encoding-badge.unicode {
        background: rgba(236, 72, 153, 0.15);
        color: #f472b6;
        border: 1px solid rgba(236, 72, 153, 0.3);
      }

      .col-tags {
        width: 130px;
      }

      .tag-badge {
        display: inline-block;
        padding: 0.15rem 0.5rem;
        border-radius: var(--radius-sm);
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-right: 0.25rem;
      }

      .tag-badge.url {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(29, 78, 216, 0.2));
        color: #60a5fa;
        border: 1px solid rgba(59, 130, 246, 0.4);
      }

      .tag-badge.filepath {
        background: linear-gradient(135deg, rgba(234, 179, 8, 0.2), rgba(161, 98, 7, 0.2));
        color: #facc15;
        border: 1px solid rgba(234, 179, 8, 0.4);
      }

      .tag-badge.api {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(4, 120, 87, 0.2));
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
      }

      .tag-badge.other {
        background: rgba(255, 255, 255, 0.05);
        color: var(--text-muted);
        border: 1px solid rgba(255, 255, 255, 0.1);
      }

      .col-value {
        font-family: var(--font-mono);
        color: var(--text-secondary);
        word-break: break-all;
        max-width: 450px;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      /* No results view */
      .no-results {
        text-align: center;
        padding: 3rem;
        color: var(--text-muted);
        font-style: italic;
      }
    `;
    document.head.appendChild(style);
  }

  private initDOM() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'strings-view-root';

    // 1. Controls Row
    const controls = document.createElement('div');
    controls.className = 'strings-controls';

    const searchWrapper = document.createElement('div');
    searchWrapper.className = 'search-wrapper';

    this.searchInput = document.createElement('input');
    this.searchInput.type = 'text';
    this.searchInput.className = 'strings-search-input';
    this.searchInput.placeholder = 'Search strings (value, offset, or address)...';
    searchWrapper.appendChild(this.searchInput);

    const filters = document.createElement('div');
    filters.className = 'filters-group';

    this.encodingFilterSelect = document.createElement('select');
    this.encodingFilterSelect.className = 'filter-select';
    this.encodingFilterSelect.innerHTML = `
      <option value="all">All Encodings</option>
      <option value="ascii">ASCII</option>
      <option value="unicode">Unicode (UTF-16)</option>
    `;
    filters.appendChild(this.encodingFilterSelect);

    controls.appendChild(searchWrapper);
    controls.appendChild(filters);

    // 2. Stats & Chips Row
    const statsRow = document.createElement('div');
    statsRow.className = 'strings-stats-row';

    this.totalCountEl = document.createElement('span');
    this.totalCountEl.className = 'strings-count-badge';
    this.totalCountEl.innerHTML = `Showing <strong>0</strong> of 0 strings`;

    this.tagFiltersContainer = document.createElement('div');
    this.tagFiltersContainer.className = 'quick-chips';
    this.renderTagChips();

    statsRow.appendChild(this.totalCountEl);
    statsRow.appendChild(this.tagFiltersContainer);

    // 3. Table Container
    this.tableContainerEl = document.createElement('div');
    this.tableContainerEl.className = 'strings-table-container';

    const table = document.createElement('table');
    table.className = 'strings-table';

    const thead = document.createElement('thead');
    thead.innerHTML = `
      <tr>
        <th data-sort="offset">Offset <span class="sort-indicator"></span></th>
        <th data-sort="address">Virtual Address <span class="sort-indicator"></span></th>
        <th data-sort="encoding">Encoding <span class="sort-indicator"></span></th>
        <th data-sort="tags">Tags <span class="sort-indicator"></span></th>
        <th data-sort="value">Value <span class="sort-indicator"></span></th>
      </tr>
    `;

    this.tableBody = document.createElement('tbody');
    table.appendChild(thead);
    table.appendChild(this.tableBody);
    this.tableContainerEl.appendChild(table);

    // Append all
    this.rootEl.appendChild(controls);
    this.rootEl.appendChild(statsRow);
    this.rootEl.appendChild(this.tableContainerEl);
    this.container.appendChild(this.rootEl);

    // Event listeners
    this.tableContainerEl.addEventListener('scroll', () => {
      this.renderRows();
    });

    this.searchInput.addEventListener('input', () => {
      this.searchQuery = this.searchInput.value.toLowerCase().trim();
      this.applyFiltersAndSort();
    });

    this.encodingFilterSelect.addEventListener('change', () => {
      this.selectedEncodingFilter = this.encodingFilterSelect.value;
      this.applyFiltersAndSort();
    });

    thead.querySelectorAll('th').forEach((th) => {
      th.addEventListener('click', () => {
        const sortField = th.dataset.sort as any;
        if (this.sortBy === sortField) {
          this.sortOrder = this.sortOrder === 'asc' ? 'desc' : 'asc';
        } else {
          this.sortBy = sortField;
          this.sortOrder = 'asc';
        }
        this.updateSortIndicators(thead);
        this.applyFiltersAndSort();
      });
    });

    this.updateSortIndicators(thead);
  }

  private renderTagChips() {
    this.tagFiltersContainer.innerHTML = '';
    const tags = ['all', 'api', 'filepath', 'url'];

    tags.forEach((tag) => {
      const chip = document.createElement('div');
      chip.className = `quick-chip ${this.selectedTagFilter === tag ? 'active' : ''}`;
      chip.textContent = tag.toUpperCase();
      chip.addEventListener('click', () => {
        this.selectedTagFilter = tag;
        this.renderTagChips();
        this.applyFiltersAndSort();
      });
      this.tagFiltersContainer.appendChild(chip);
    });
  }

  private updateSortIndicators(thead: HTMLTableSectionElement) {
    thead.querySelectorAll('th').forEach((th) => {
      const indicator = th.querySelector('.sort-indicator') as HTMLSpanElement;
      const sortField = th.dataset.sort;
      if (sortField === this.sortBy) {
        indicator.textContent = this.sortOrder === 'asc' ? '▲' : '▼';
      } else {
        indicator.textContent = '';
      }
    });
  }

  private applyFiltersAndSort() {
    // 1. Filtering
    this.filteredStrings = this.allStrings.filter((str) => {
      // Filter by encoding
      if (this.selectedEncodingFilter !== 'all') {
        const isUnicode = str.encoding.startsWith('utf16');
        if (this.selectedEncodingFilter === 'ascii' && isUnicode) return false;
        if (this.selectedEncodingFilter === 'unicode' && !isUnicode) return false;
      }

      // Filter by tag
      if (this.selectedTagFilter !== 'all') {
        if (!str.tags.includes(this.selectedTagFilter)) return false;
      }

      // Filter by search query
      if (this.searchQuery) {
        const valMatch = str.value.toLowerCase().includes(this.searchQuery);
        const offsetMatch = `0x${str.offset.toString(16)}`.includes(this.searchQuery) || String(str.offset).includes(this.searchQuery);
        const addrMatch = `0x${str.virtualAddress.toString(16)}`.includes(this.searchQuery);
        if (!valMatch && !offsetMatch && !addrMatch) return false;
      }

      return true;
    });

    // 2. Sorting
    this.filteredStrings.sort((a, b) => {
      let comparison = 0;
      if (this.sortBy === 'offset') {
        comparison = a.offset - b.offset;
      } else if (this.sortBy === 'address') {
        comparison = a.virtualAddress - b.virtualAddress;
      } else if (this.sortBy === 'encoding') {
        comparison = a.encoding.localeCompare(b.encoding);
      } else if (this.sortBy === 'value') {
        comparison = a.value.localeCompare(b.value);
      } else {
        // Tag sorting (sort based on first tag or empty)
        const tagA = a.tags[0] || '';
        const tagB = b.tags[0] || '';
        comparison = tagA.localeCompare(tagB);
      }
      return this.sortOrder === 'asc' ? comparison : -comparison;
    });

    // 3. Render Table rows
    this.renderRows();
  }

  private renderRows() {
    this.totalCountEl.innerHTML = `Showing <strong>${this.filteredStrings.length}</strong> of ${this.allStrings.length} strings`;

    if (this.filteredStrings.length === 0) {
      this.tableBody.innerHTML = '';
      const row = document.createElement('tr');
      row.innerHTML = `<td colspan="5" class="no-results">No strings matched the current filters.</td>`;
      this.tableBody.appendChild(row);
      return;
    }

    const rowHeight = 38; // px
    const scrollTop = this.tableContainerEl.scrollTop;
    const containerHeight = this.tableContainerEl.clientHeight || 400;

    const len = this.filteredStrings.length;
    const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - 10);
    const endIndex = Math.min(len, Math.ceil((scrollTop + containerHeight) / rowHeight) + 10);

    this.tableBody.innerHTML = '';

    // 1. Top Spacer Row
    const topSpacerHeight = startIndex * rowHeight;
    if (topSpacerHeight > 0) {
      const topSpacer = document.createElement('tr');
      topSpacer.style.height = `${topSpacerHeight}px`;
      topSpacer.innerHTML = `<td colspan="5" style="padding: 0; border: none; height: ${topSpacerHeight}px;"></td>`;
      this.tableBody.appendChild(topSpacer);
    }

    // 2. Visible Rows
    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const str = this.filteredStrings[i];
      const row = document.createElement('tr');
      row.className = 'strings-row';
      row.style.height = `${rowHeight}px`;

      const isUnicode = str.encoding.startsWith('utf16');
      const encodingClass = isUnicode ? 'unicode' : 'ascii';
      const encodingLabel = isUnicode ? 'Unicode' : 'ASCII';

      // Render tags badges
      let tagsHtml = '';
      if (str.tags.length > 0) {
        str.tags.forEach((tag) => {
          const lowerTag = tag.toLowerCase();
          const badgeClass = ['url', 'filepath', 'api'].includes(lowerTag) ? lowerTag : 'other';
          tagsHtml += `<span class="tag-badge ${badgeClass}">${tag}</span>`;
        });
      } else {
        tagsHtml = '<span style="color: var(--text-disabled)">-</span>';
      }

      row.innerHTML = `
        <td class="col-offset">0x${str.offset.toString(16).toUpperCase()}</td>
        <td class="col-address">0x${str.virtualAddress.toString(16).toUpperCase()}</td>
        <td class="col-encoding"><span class="encoding-badge ${encodingClass}">${encodingLabel}</span></td>
        <td class="col-tags">${tagsHtml}</td>
        <td class="col-value" title="${this.escapeHtml(str.value)}">${this.escapeHtml(str.value)}</td>
      `;

      row.addEventListener('click', () => {
        if (this.options.onNavigate) {
          this.options.onNavigate(str.offset, str.virtualAddress);
        }
      });

      fragment.appendChild(row);
    }
    this.tableBody.appendChild(fragment);

    // 3. Bottom Spacer Row
    const bottomSpacerHeight = (len - endIndex) * rowHeight;
    if (bottomSpacerHeight > 0) {
      const bottomSpacer = document.createElement('tr');
      bottomSpacer.style.height = `${bottomSpacerHeight}px`;
      bottomSpacer.innerHTML = `<td colspan="5" style="padding: 0; border: none; height: ${bottomSpacerHeight}px;"></td>`;
      this.tableBody.appendChild(bottomSpacer);
    }
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
