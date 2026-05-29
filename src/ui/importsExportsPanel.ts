export interface ImportsExportsPanelOptions {
  onNavigate?: (targetView: 'assembly' | 'hex', address: number) => void;
}

export class ImportsExportsPanel {
  private container: HTMLElement;
  private dependencies: any = null;
  private options: ImportsExportsPanelOptions;

  // View state
  private activeSubTab: 'imports' | 'exports' = 'imports';
  private searchQuery = '';

  // DOM elements
  private rootEl!: HTMLDivElement;
  private searchInput!: HTMLInputElement;
  private tableBody!: HTMLTableSectionElement;
  private importsTabBtn!: HTMLButtonElement;
  private exportsTabBtn!: HTMLButtonElement;
  private statsImportsCount!: HTMLSpanElement;
  private statsExportsCount!: HTMLSpanElement;
  private statsLibraryCount!: HTMLSpanElement;

  constructor(
    container: HTMLElement,
    dependencies: any,
    options: ImportsExportsPanelOptions = {}
  ) {
    this.container = container;
    this.dependencies = dependencies;
    this.options = options;

    this.injectStyles();
    this.initDOM();
    this.render();
  }

  /**
   * Update the dependencies data when a new binary is loaded.
   */
  public updateData(dependencies: any) {
    this.dependencies = dependencies;
    this.searchQuery = '';
    if (this.searchInput) {
      this.searchInput.value = '';
    }
    this.updateStats();
    this.render();
  }

  private injectStyles() {
    if (document.getElementById('imports-exports-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'imports-exports-panel-styles';
    style.textContent = `
      .imp-exp-root {
        display: flex;
        flex-direction: column;
        height: 100%;
        gap: 1rem;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        overflow: hidden;
      }

      /* Premium Glassmorphic Stats Section */
      .imp-exp-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 1rem;
        margin-bottom: 0.5rem;
      }

      .stat-card {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1rem;
        backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
        transition: transform var(--transition-fast), border-color var(--transition-fast);
      }

      .stat-card:hover {
        transform: translateY(-2px);
        border-color: var(--border-hover);
        background: rgba(255, 255, 255, 0.04);
      }

      .stat-card .stat-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-muted);
        font-weight: 700;
        letter-spacing: 0.05em;
      }

      .stat-card .stat-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: var(--text-primary);
        background: var(--gradient-accent);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }

      /* Control panel with search and tabs */
      .imp-exp-controls {
        display: flex;
        flex-wrap: wrap;
        gap: 1rem;
        align-items: center;
        justify-content: space-between;
        background: rgba(22, 26, 33, 0.4);
        padding: 0.75rem 1.25rem;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        backdrop-filter: blur(10px);
      }

      .tab-switcher {
        display: flex;
        gap: 0.5rem;
        background: rgba(10, 12, 16, 0.5);
        padding: 0.25rem;
        border-radius: var(--radius-sm);
        border: 1px solid var(--border-color);
      }

      .tab-switcher-btn {
        background: transparent;
        border: none;
        color: var(--text-muted);
        padding: 0.5rem 1rem;
        font-size: 0.85rem;
        font-weight: 600;
        border-radius: var(--radius-sm);
        cursor: pointer;
        transition: all var(--transition-fast);
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .tab-switcher-btn:hover {
        color: var(--text-primary);
      }

      .tab-switcher-btn.active {
        background: var(--bg-tertiary);
        color: var(--text-primary);
        box-shadow: var(--shadow-sm);
      }

      .tab-badge {
        font-size: 0.7rem;
        background: rgba(255, 255, 255, 0.1);
        padding: 1px 6px;
        border-radius: var(--radius-full);
        color: var(--text-secondary);
      }

      .tab-switcher-btn.active .tab-badge {
        background: var(--accent-start);
        color: #fff;
      }

      .imp-exp-search-wrapper {
        position: relative;
        flex: 1;
        min-width: 250px;
        max-width: 400px;
      }

      .imp-exp-search-wrapper::before {
        content: "🔍";
        position: absolute;
        left: 0.85rem;
        top: 50%;
        transform: translateY(-50%);
        font-size: 0.9rem;
        opacity: 0.5;
        pointer-events: none;
      }

      .imp-exp-search {
        width: 100%;
        padding: 0.6rem 1rem 0.6rem 2.2rem;
        background: rgba(15, 17, 21, 0.6);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        color: var(--text-primary);
        font-family: var(--font-sans);
        font-size: 0.85rem;
        transition: all var(--transition-fast);
      }

      .imp-exp-search:focus {
        outline: none;
        border-color: var(--accent-start);
        box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      }

      /* Premium Glassmorphic Table */
      .table-container {
        flex: 1;
        overflow-y: auto;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        background: rgba(22, 26, 33, 0.2);
        backdrop-filter: blur(12px);
        box-shadow: var(--shadow-md);
      }

      .imp-exp-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
        font-size: 0.85rem;
      }

      .imp-exp-table th {
        position: sticky;
        top: 0;
        background: rgba(26, 30, 39, 0.95);
        padding: 0.85rem 1.25rem;
        font-weight: 600;
        color: var(--text-muted);
        border-bottom: 1px solid var(--border-color);
        z-index: 10;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }

      .imp-exp-table td {
        padding: 0.85rem 1.25rem;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-secondary);
        font-family: var(--font-sans);
      }

      .imp-exp-table tr:last-child td {
        border-bottom: none;
      }

      .imp-exp-table tbody tr {
        transition: background-color var(--transition-fast);
        cursor: pointer;
      }

      .imp-exp-table tbody tr:hover {
        background-color: rgba(255, 255, 255, 0.03);
      }

      .mono-text {
        font-family: var(--font-mono) !important;
        font-size: 0.8rem;
      }

      .address-link {
        color: var(--accent-start);
        font-weight: 600;
        text-decoration: none;
      }

      .address-link:hover {
        text-decoration: underline;
      }

      .library-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: var(--radius-sm);
        font-size: 0.75rem;
        font-weight: 500;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.05);
        color: var(--text-muted);
      }

      .library-badge.dll {
        background: rgba(59, 130, 246, 0.1);
        border-color: rgba(59, 130, 246, 0.2);
        color: #93c5fd;
      }

      .library-badge.so {
        background: rgba(16, 185, 129, 0.1);
        border-color: rgba(16, 185, 129, 0.2);
        color: #6ee7b7;
      }

      .library-badge.dylib {
        background: rgba(139, 92, 246, 0.1);
        border-color: rgba(139, 92, 246, 0.2);
        color: #c084fc;
      }

      .action-btn {
        background: rgba(99, 102, 241, 0.1);
        border: 1px solid rgba(99, 102, 241, 0.2);
        color: #a5b4fc;
        padding: 2px 8px;
        border-radius: var(--radius-sm);
        cursor: pointer;
        font-size: 0.75rem;
        transition: all var(--transition-fast);
      }

      .action-btn:hover {
        background: var(--accent-start);
        color: #ffffff;
        border-color: var(--accent-start);
      }

      /* Empty State */
      .empty-state {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 4rem 2rem;
        color: var(--text-muted);
        text-align: center;
        gap: 0.5rem;
      }

      .empty-icon {
        font-size: 2.5rem;
        opacity: 0.5;
      }
    `;
    document.head.appendChild(style);
  }

  private initDOM() {
    this.rootEl = document.createElement('div');
    this.rootEl.className = 'imp-exp-root';

    this.rootEl.innerHTML = `
      <!-- Stats Summary -->
      <div class="imp-exp-stats">
        <div class="stat-card">
          <span class="stat-label">Total Imports</span>
          <span class="stat-value" id="stats-imports-count">0</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">Total Exports</span>
          <span class="stat-value" id="stats-exports-count">0</span>
        </div>
        <div class="stat-card">
          <span class="stat-label">External Libraries</span>
          <span class="stat-value" id="stats-library-count">0</span>
        </div>
      </div>

      <!-- Controls -->
      <div class="imp-exp-controls">
        <div class="tab-switcher">
          <button class="tab-switcher-btn active" id="btn-tab-imports">
            📥 Imports
            <span class="tab-badge" id="badge-imports-count">0</span>
          </button>
          <button class="tab-switcher-btn" id="btn-tab-exports">
            📤 Exports
            <span class="tab-badge" id="badge-exports-count">0</span>
          </button>
        </div>

        <div class="imp-exp-search-wrapper">
          <input type="text" class="imp-exp-search" placeholder="Search imports & exports..." id="imp-exp-search-input" />
        </div>
      </div>

      <!-- Table Container -->
      <div class="table-container">
        <table class="imp-exp-table">
          <thead id="table-head"></thead>
          <tbody id="table-body"></tbody>
        </table>
      </div>
    `;

    // Cache elements
    this.searchInput = this.rootEl.querySelector(
      '#imp-exp-search-input'
    ) as HTMLInputElement;
    this.tableBody = this.rootEl.querySelector(
      '#table-body'
    ) as HTMLTableSectionElement;
    this.importsTabBtn = this.rootEl.querySelector(
      '#btn-tab-imports'
    ) as HTMLButtonElement;
    this.exportsTabBtn = this.rootEl.querySelector(
      '#btn-tab-exports'
    ) as HTMLButtonElement;
    this.statsImportsCount = this.rootEl.querySelector(
      '#stats-imports-count'
    ) as HTMLSpanElement;
    this.statsExportsCount = this.rootEl.querySelector(
      '#stats-exports-count'
    ) as HTMLSpanElement;
    this.statsLibraryCount = this.rootEl.querySelector(
      '#stats-library-count'
    ) as HTMLSpanElement;

    // Attach listeners
    this.importsTabBtn.addEventListener('click', () =>
      this.switchSubTab('imports')
    );
    this.exportsTabBtn.addEventListener('click', () =>
      this.switchSubTab('exports')
    );
    this.searchInput.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value.toLowerCase();
      this.render();
    });

    this.container.appendChild(this.rootEl);
    this.updateStats();
  }

  private switchSubTab(tab: 'imports' | 'exports') {
    if (this.activeSubTab === tab) return;
    this.activeSubTab = tab;

    this.importsTabBtn.classList.toggle('active', tab === 'imports');
    this.exportsTabBtn.classList.toggle('active', tab === 'exports');

    this.render();
  }

  private updateStats() {
    const imports = this.dependencies?.imports || [];
    const exports = this.dependencies?.exports || [];

    // Unique library count
    const uniqueLibs = new Set(
      imports.map((imp: any) => imp.library.toLowerCase())
    );

    this.statsImportsCount.textContent = imports.length.toString();
    this.statsExportsCount.textContent = exports.length.toString();
    this.statsLibraryCount.textContent = uniqueLibs.size.toString();

    const badgeImports = this.rootEl.querySelector('#badge-imports-count');
    const badgeExports = this.rootEl.querySelector('#badge-exports-count');

    if (badgeImports) badgeImports.textContent = imports.length.toString();
    if (badgeExports) badgeExports.textContent = exports.length.toString();
  }

  private getLibraryBadgeClass(libName: string): string {
    const lower = libName.toLowerCase();
    if (lower.endsWith('.dll')) return 'library-badge dll';
    if (lower.includes('.so') || lower.endsWith('.so'))
      return 'library-badge so';
    if (lower.endsWith('.dylib') || lower.includes('libmacho'))
      return 'library-badge dylib';
    return 'library-badge';
  }

  private render() {
    const imports = this.dependencies?.imports || [];
    const exports = this.dependencies?.exports || [];
    const query = this.searchQuery;

    const tableHead = this.rootEl.querySelector('#table-head') as HTMLElement;
    this.tableBody.innerHTML = '';

    if (this.activeSubTab === 'imports') {
      tableHead.innerHTML = `
        <tr>
          <th style="width: 40%">Name</th>
          <th style="width: 30%">Library</th>
          <th style="width: 20%">Address</th>
          <th style="width: 10%">Action</th>
        </tr>
      `;

      const filteredImports = imports.filter((imp: any) => {
        return (
          imp.name.toLowerCase().includes(query) ||
          imp.library.toLowerCase().includes(query) ||
          (imp.address && `0x${imp.address.toString(16)}`.includes(query))
        );
      });

      if (filteredImports.length === 0) {
        this.renderEmptyState('No imports found matching search query');
        return;
      }

      filteredImports.forEach((imp: any) => {
        const tr = document.createElement('tr');
        const addrHex = imp.address
          ? `0x${imp.address.toString(16).toUpperCase()}`
          : 'N/A';
        const badgeClass = this.getLibraryBadgeClass(imp.library);

        tr.innerHTML = `
          <td class="mono-text" style="font-weight: 500;">${this.highlight(imp.name, query)}</td>
          <td><span class="${badgeClass}">${this.highlight(imp.library, query)}</span></td>
          <td class="mono-text">${imp.address ? `<span class="address-link">${addrHex}</span>` : addrHex}</td>
          <td>${imp.address ? `<button class="action-btn">Jump</button>` : '—'}</td>
        `;

        if (imp.address && this.options.onNavigate) {
          const navigate = () => {
            if (this.options.onNavigate) {
              this.options.onNavigate('assembly', imp.address);
            }
          };
          tr.addEventListener('dblclick', navigate);
          const btn = tr.querySelector('.action-btn');
          if (btn)
            btn.addEventListener('click', (e) => {
              e.stopPropagation();
              navigate();
            });
        }

        this.tableBody.appendChild(tr);
      });
    } else {
      tableHead.innerHTML = `
        <tr>
          <th style="width: 60%">Name</th>
          <th style="width: 30%">Address</th>
          <th style="width: 10%">Action</th>
        </tr>
      `;

      const filteredExports = exports.filter((exp: any) => {
        return (
          exp.name.toLowerCase().includes(query) ||
          (exp.address && `0x${exp.address.toString(16)}`.includes(query))
        );
      });

      if (filteredExports.length === 0) {
        this.renderEmptyState('No exports found matching search query');
        return;
      }

      filteredExports.forEach((exp: any) => {
        const tr = document.createElement('tr');
        const addrHex = exp.address
          ? `0x${exp.address.toString(16).toUpperCase()}`
          : 'N/A';

        tr.innerHTML = `
          <td class="mono-text" style="font-weight: 500;">${this.highlight(exp.name, query)}</td>
          <td class="mono-text">${exp.address ? `<span class="address-link">${addrHex}</span>` : addrHex}</td>
          <td>${exp.address ? `<button class="action-btn">Jump</button>` : '—'}</td>
        `;

        if (exp.address && this.options.onNavigate) {
          const navigate = () => {
            if (this.options.onNavigate) {
              this.options.onNavigate('assembly', exp.address);
            }
          };
          tr.addEventListener('dblclick', navigate);
          const btn = tr.querySelector('.action-btn');
          if (btn)
            btn.addEventListener('click', (e) => {
              e.stopPropagation();
              navigate();
            });
        }

        this.tableBody.appendChild(tr);
      });
    }
  }

  private renderEmptyState(message: string) {
    this.tableBody.innerHTML = `
      <tr>
        <td colspan="4">
          <div class="empty-state">
            <span class="empty-icon">🔍</span>
            <span class="empty-message">${message}</span>
          </div>
        </td>
      </tr>
    `;
  }

  private highlight(text: string, query: string): string {
    if (!query) return text;
    const regex = new RegExp(
      `(${query.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')})`,
      'gi'
    );
    return text.replace(
      regex,
      '<mark style="background: rgba(99, 102, 241, 0.4); color: inherit; border-radius: 2px; padding: 0 2px;">$1</mark>'
    );
  }
}
