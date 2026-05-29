import {
  ParsedObjcMetadata,
  ObjcClass,
  ObjcProtocol,
  ObjcMethod,
} from '../parser/machoObjc.js';

export interface MachoObjcPanelOptions {
  onNavigate?: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export class MachoObjcPanel {
  private container: HTMLElement;
  private metadata: ParsedObjcMetadata | null = null;
  private options: MachoObjcPanelOptions;

  // View state
  private activeTab: 'classes' | 'protocols' = 'classes';
  private searchQuery: string = '';
  private selectedIndex: number = 0;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private searchInput!: HTMLInputElement;
  private classesTabBtn!: HTMLButtonElement;
  private protocolsTabBtn!: HTMLButtonElement;
  private sidebarEl!: HTMLDivElement;
  private detailEl!: HTMLDivElement;
  private statsClassesEl!: HTMLSpanElement;
  private statsProtocolsEl!: HTMLSpanElement;
  private statsMethodsEl!: HTMLSpanElement;
  private statsPropsEl!: HTMLSpanElement;

  constructor(container: HTMLElement, options: MachoObjcPanelOptions = {}) {
    this.container = container;
    this.options = options;
    this.injectStyles();
    this.initDOM();
    this.updateStats();
    this.render();
  }

  /**
   * Update the binary metadata and render
   */
  public updateData(metadata: ParsedObjcMetadata | null) {
    this.metadata = metadata;
    this.searchQuery = '';
    this.selectedIndex = 0;
    if (this.searchInput) {
      this.searchInput.value = '';
    }
    this.updateStats();
    this.render();
  }

  private injectStyles() {
    if (document.getElementById('macho-objc-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'macho-objc-panel-styles';
    style.textContent = `
      .objc-panel-root {
        display: flex;
        flex-direction: column;
        height: 100%;
        gap: 1.25rem;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        overflow: hidden;
      }

      /* Premium Glassmorphic Stats Section */
      .objc-stats-row {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 1rem;
        flex-shrink: 0;
      }

      .objc-stat-card {
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

      .objc-stat-card:hover {
        transform: translateY(-2px);
        border-color: var(--border-hover);
        background: rgba(255, 255, 255, 0.04);
      }

      .objc-stat-card .stat-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-muted);
        font-weight: 700;
        letter-spacing: 0.05em;
      }

      .objc-stat-card .stat-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: var(--text-primary);
        background: var(--gradient-accent);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }

      /* Controls: Tabs & Search */
      .objc-controls {
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
        flex-shrink: 0;
      }

      .objc-tab-switcher {
        display: flex;
        gap: 0.5rem;
        background: rgba(10, 12, 16, 0.5);
        padding: 0.25rem;
        border-radius: var(--radius-sm);
        border: 1px solid var(--border-color);
      }

      .objc-tab-btn {
        background: transparent;
        border: none;
        color: var(--text-muted);
        padding: 0.5rem 1rem;
        font-size: 0.85rem;
        font-weight: 600;
        border-radius: var(--radius-sm);
        cursor: pointer;
        transition: all var(--transition-fast);
      }

      .objc-tab-btn:hover {
        color: var(--text-primary);
      }

      .objc-tab-btn.active {
        background: var(--gradient-accent);
        color: #ffffff;
      }

      .objc-search-wrapper {
        position: relative;
        flex-grow: 1;
        max-width: 400px;
      }

      .objc-search-input {
        width: 100%;
        background: rgba(10, 12, 16, 0.6);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        padding: 0.5rem 1rem;
        color: var(--text-primary);
        font-size: 0.85rem;
        box-sizing: border-box;
        transition: border-color var(--transition-fast);
      }

      .objc-search-input:focus {
        outline: none;
        border-color: var(--accent-end);
      }

      /* Main Split Grid */
      .objc-grid {
        display: grid;
        grid-template-columns: 280px 1fr;
        gap: 1.25rem;
        flex-grow: 1;
        overflow: hidden;
      }

      @media (max-width: 900px) {
        .objc-grid {
          grid-template-columns: 1fr;
          grid-template-rows: 250px 1fr;
        }
      }

      .objc-sidebar {
        background: rgba(22, 26, 33, 0.2);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 0.75rem;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
        overflow-y: auto;
      }

      .objc-list-item {
        width: 100%;
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        padding: 0.75rem 1rem;
        text-align: left;
        color: var(--text-secondary);
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: all var(--transition-fast);
        font-size: 0.85rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .objc-list-item:hover {
        background: rgba(255, 255, 255, 0.05);
        color: var(--text-primary);
        border-color: var(--border-hover);
      }

      .objc-list-item.active {
        background: var(--gradient-accent);
        color: #ffffff;
        border-color: transparent;
      }

      .objc-badge {
        font-size: 0.65rem;
        padding: 0.15rem 0.4rem;
        border-radius: 4px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.02em;
      }

      .badge-class {
        background: rgba(59, 130, 246, 0.2);
        color: #60a5fa;
        border: 1px solid rgba(59, 130, 246, 0.3);
      }

      .badge-protocol {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }

      .objc-detail-container {
        background: rgba(22, 26, 33, 0.2);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1.5rem;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
        overflow-y: auto;
      }

      .objc-detail-header h3 {
        margin: 0;
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--text-primary);
      }

      .objc-detail-header p {
        margin: 0.35rem 0 0 0;
        font-size: 0.875rem;
        color: var(--text-muted);
      }

      .objc-meta-section {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
      }

      .objc-meta-section h4 {
        margin: 0;
        font-size: 1rem;
        font-weight: 600;
        color: var(--text-primary);
        border-left: 3px solid var(--accent-end);
        padding-left: 0.5rem;
      }

      .objc-table {
        width: 100%;
        border-collapse: collapse;
        text-align: left;
      }

      .objc-table th {
        padding: 0.6rem 0.8rem;
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-muted);
        font-weight: 700;
        border-bottom: 1px solid var(--border-color);
      }

      .objc-table td {
        padding: 0.6rem 0.8rem;
        font-size: 0.85rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        font-family: var(--font-mono);
        vertical-align: middle;
      }

      .objc-addr-btn {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.2);
        color: #60a5fa;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        cursor: pointer;
        transition: all var(--transition-fast);
        font-family: var(--font-mono);
      }

      .objc-addr-btn:hover {
        background: rgba(59, 130, 246, 0.25);
        color: #93c5fd;
        border-color: #60a5fa;
      }

      .objc-no-data {
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100%;
        color: var(--text-muted);
        font-style: italic;
        font-size: 0.95rem;
      }
    `;
    document.head.appendChild(style);
  }

  private initDOM() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'objc-panel-root';

    // 1. Stats Row
    const statsRow = document.createElement('div');
    statsRow.className = 'objc-stats-row';
    statsRow.innerHTML = `
      <div class="objc-stat-card">
        <span class="stat-label">Classes</span>
        <span class="stat-value" id="objc-stats-classes">0</span>
      </div>
      <div class="objc-stat-card">
        <span class="stat-label">Protocols</span>
        <span class="stat-value" id="objc-stats-protocols">0</span>
      </div>
      <div class="objc-stat-card">
        <span class="stat-label">Recovered Methods</span>
        <span class="stat-value" id="objc-stats-methods">0</span>
      </div>
      <div class="objc-stat-card">
        <span class="stat-label">Properties</span>
        <span class="stat-value" id="objc-stats-props">0</span>
      </div>
    `;
    this.rootEl.appendChild(statsRow);

    this.statsClassesEl = statsRow.querySelector('#objc-stats-classes')!;
    this.statsProtocolsEl = statsRow.querySelector('#objc-stats-protocols')!;
    this.statsMethodsEl = statsRow.querySelector('#objc-stats-methods')!;
    this.statsPropsEl = statsRow.querySelector('#objc-stats-props')!;

    // 2. Controls Section
    const controls = document.createElement('div');
    controls.className = 'objc-controls';

    const tabSwitcher = document.createElement('div');
    tabSwitcher.className = 'objc-tab-switcher';

    this.classesTabBtn = document.createElement('button');
    this.classesTabBtn.className = 'objc-tab-btn active';
    this.classesTabBtn.textContent = 'Classes';
    this.classesTabBtn.addEventListener('click', () =>
      this.switchTab('classes')
    );

    this.protocolsTabBtn = document.createElement('button');
    this.protocolsTabBtn.className = 'objc-tab-btn';
    this.protocolsTabBtn.textContent = 'Protocols';
    this.protocolsTabBtn.addEventListener('click', () =>
      this.switchTab('protocols')
    );

    tabSwitcher.appendChild(this.classesTabBtn);
    tabSwitcher.appendChild(this.protocolsTabBtn);
    controls.appendChild(tabSwitcher);

    const searchWrapper = document.createElement('div');
    searchWrapper.className = 'objc-search-wrapper';

    this.searchInput = document.createElement('input');
    this.searchInput.type = 'text';
    this.searchInput.className = 'objc-search-input';
    this.searchInput.placeholder =
      'Search classes, protocols, methods, properties...';
    this.searchInput.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value.toLowerCase();
      this.selectedIndex = 0;
      this.render();
    });

    searchWrapper.appendChild(this.searchInput);
    controls.appendChild(searchWrapper);
    this.rootEl.appendChild(controls);

    // 3. Main Split Grid
    const grid = document.createElement('div');
    grid.className = 'objc-grid';

    this.sidebarEl = document.createElement('div');
    this.sidebarEl.className = 'objc-sidebar';

    this.detailEl = document.createElement('div');
    this.detailEl.className = 'objc-detail-container';

    grid.appendChild(this.sidebarEl);
    grid.appendChild(this.detailEl);
    this.rootEl.appendChild(grid);

    this.container.appendChild(this.rootEl);
  }

  private switchTab(tab: 'classes' | 'protocols') {
    this.activeTab = tab;
    this.selectedIndex = 0;
    if (tab === 'classes') {
      this.classesTabBtn.classList.add('active');
      this.protocolsTabBtn.classList.remove('active');
    } else {
      this.classesTabBtn.classList.remove('active');
      this.protocolsTabBtn.classList.add('active');
    }
    this.render();
  }

  private updateStats() {
    if (!this.metadata) {
      this.statsClassesEl.textContent = '0';
      this.statsProtocolsEl.textContent = '0';
      this.statsMethodsEl.textContent = '0';
      this.statsPropsEl.textContent = '0';
      return;
    }

    const classesCount = this.metadata.classes.length;
    const protocolsCount = this.metadata.protocols.length;

    let methodsCount = 0;
    let propsCount = 0;

    for (const cls of this.metadata.classes) {
      methodsCount += cls.methods?.length || 0;
      propsCount += cls.properties?.length || 0;
    }

    for (const proto of this.metadata.protocols) {
      methodsCount +=
        (proto.instanceMethods?.length || 0) +
        (proto.classMethods?.length || 0);
      propsCount += proto.properties?.length || 0;
    }

    this.statsClassesEl.textContent = classesCount.toString();
    this.statsProtocolsEl.textContent = protocolsCount.toString();
    this.statsMethodsEl.textContent = methodsCount.toString();
    this.statsPropsEl.textContent = propsCount.toString();
  }

  private getFilteredData(): (ObjcClass | ObjcProtocol)[] {
    if (!this.metadata) return [];

    if (this.activeTab === 'classes') {
      return this.metadata.classes.filter((cls) => {
        if (!this.searchQuery) return true;
        const matchesClass =
          cls.name.toLowerCase().includes(this.searchQuery) ||
          (cls.superclassName &&
            cls.superclassName.toLowerCase().includes(this.searchQuery));
        if (matchesClass) return true;

        // Check if any method matches
        const matchesMethod = cls.methods?.some((m) =>
          m.name.toLowerCase().includes(this.searchQuery)
        );
        if (matchesMethod) return true;

        // Check if any property matches
        const matchesProp = cls.properties?.some((p) =>
          p.name.toLowerCase().includes(this.searchQuery)
        );
        if (matchesProp) return true;

        return false;
      });
    } else {
      return this.metadata.protocols.filter((proto) => {
        if (!this.searchQuery) return true;
        const matchesProto = proto.name
          .toLowerCase()
          .includes(this.searchQuery);
        if (matchesProto) return true;

        // Check instance or class methods
        const matchesInstanceMeth = proto.instanceMethods?.some((m) =>
          m.name.toLowerCase().includes(this.searchQuery)
        );
        const matchesClassMeth = proto.classMethods?.some((m) =>
          m.name.toLowerCase().includes(this.searchQuery)
        );
        if (matchesInstanceMeth || matchesClassMeth) return true;

        // Check properties
        const matchesProp = proto.properties?.some((p) =>
          p.name.toLowerCase().includes(this.searchQuery)
        );
        if (matchesProp) return true;

        return false;
      });
    }
  }

  private render() {
    this.sidebarEl.innerHTML = '';
    this.detailEl.innerHTML = '';

    if (!this.metadata) {
      this.sidebarEl.innerHTML =
        '<div class="objc-no-data">No binary metadata loaded</div>';
      this.detailEl.innerHTML =
        '<div class="objc-no-data">Select a class or protocol to inspect metadata</div>';
      return;
    }

    const list = this.getFilteredData();

    if (list.length === 0) {
      this.sidebarEl.innerHTML =
        '<div class="objc-no-data">No matches found</div>';
      this.detailEl.innerHTML =
        '<div class="objc-no-data">Try a different search query</div>';
      return;
    }

    // Guard selectedIndex boundary
    if (this.selectedIndex >= list.length) {
      this.selectedIndex = 0;
    }

    // Render Sidebar Items
    list.forEach((item, index) => {
      const button = document.createElement('button');
      button.className = `objc-list-item ${index === this.selectedIndex ? 'active' : ''}`;
      button.addEventListener('click', () => {
        this.selectedIndex = index;
        this.render();
      });

      const nameSpan = document.createElement('span');
      nameSpan.textContent = item.name;
      button.appendChild(nameSpan);

      const badge = document.createElement('span');
      badge.className = `objc-badge ${this.activeTab === 'classes' ? 'badge-class' : 'badge-protocol'}`;
      badge.textContent = this.activeTab === 'classes' ? 'Class' : 'Protocol';
      button.appendChild(badge);

      this.sidebarEl.appendChild(button);
    });

    // Render Detail view of the selected item
    const selectedItem = list[this.selectedIndex];
    if (this.activeTab === 'classes') {
      this.renderClassDetail(selectedItem as ObjcClass);
    } else {
      this.renderProtocolDetail(selectedItem as ObjcProtocol);
    }
  }

  private renderClassDetail(cls: ObjcClass) {
    // 1. Header
    const header = document.createElement('div');
    header.className = 'objc-detail-header';
    header.innerHTML = `
      <h3>${cls.name}</h3>
      <p>Superclass: <span style="color: var(--accent-end); font-weight: 600;">${cls.superclassName || 'NSObject (or root)'}</span></p>
      ${cls.protocols && cls.protocols.length > 0 ? `<p style="margin-top: 0.35rem;">Adopts Protocols: ${cls.protocols.map((p) => `<span class="objc-badge badge-protocol">${p}</span>`).join(' ')}</p>` : ''}
    `;
    this.detailEl.appendChild(header);

    // 2. Methods
    const methodsSection = document.createElement('div');
    methodsSection.className = 'objc-meta-section';
    methodsSection.innerHTML = '<h4>Methods</h4>';

    if (cls.methods && cls.methods.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Selector</th>
            <th>Type Encoding</th>
            <th>IMP Address</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      cls.methods.forEach((m) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--accent-end)';
        tdName.style.fontWeight = '600';
        tdName.textContent = m.name;
        tr.appendChild(tdName);

        const tdType = document.createElement('td');
        tdType.style.color = 'var(--text-muted)';
        tdType.textContent = m.types || '';
        tr.appendChild(tdType);

        const tdImp = document.createElement('td');
        if (m.imp !== undefined && m.imp !== null) {
          const addrNum = typeof m.imp === 'bigint' ? Number(m.imp) : m.imp;
          const formattedAddr = '0x' + addrNum.toString(16).toUpperCase();

          const btn = document.createElement('button');
          btn.className = 'objc-addr-btn';
          btn.textContent = formattedAddr;
          btn.addEventListener('click', () => {
            if (this.options.onNavigate) {
              this.options.onNavigate('assembly', addrNum);
            }
          });
          tdImp.appendChild(btn);
        } else {
          tdImp.textContent = 'N/A';
          tdImp.style.color = 'var(--text-muted)';
        }
        tr.appendChild(tdImp);
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      methodsSection.appendChild(table);
    } else {
      methodsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No recovered methods found</div>';
    }
    this.detailEl.appendChild(methodsSection);

    // 3. Properties
    const propsSection = document.createElement('div');
    propsSection.className = 'objc-meta-section';
    propsSection.innerHTML = '<h4>Properties</h4>';

    if (cls.properties && cls.properties.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Property Name</th>
            <th>Attributes</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      cls.properties.forEach((p) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--text-secondary)';
        tdName.textContent = p.name;
        tr.appendChild(tdName);

        const tdAttr = document.createElement('td');
        tdAttr.style.color = 'var(--text-muted)';
        tdAttr.textContent = p.attributes || '';
        tr.appendChild(tdAttr);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      propsSection.appendChild(table);
    } else {
      propsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No recovered properties found</div>';
    }
    this.detailEl.appendChild(propsSection);

    // 4. Instance Variables (Ivars)
    const ivarsSection = document.createElement('div');
    ivarsSection.className = 'objc-meta-section';
    ivarsSection.innerHTML = '<h4>Instance Variables (Ivars)</h4>';

    if (cls.ivars && cls.ivars.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Ivar Name</th>
            <th>Type</th>
            <th>Offset</th>
            <th>Size</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      cls.ivars.forEach((iv) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--text-primary)';
        tdName.textContent = iv.name;
        tr.appendChild(tdName);

        const tdType = document.createElement('td');
        tdType.style.color = 'var(--text-muted)';
        tdType.textContent = iv.type || '';
        tr.appendChild(tdType);

        const tdOffset = document.createElement('td');
        tdOffset.style.color = 'var(--text-secondary)';
        tdOffset.textContent =
          iv.offset !== undefined ? `+${iv.offset}` : 'N/A';
        tr.appendChild(tdOffset);

        const tdSize = document.createElement('td');
        tdSize.style.color = 'var(--text-secondary)';
        tdSize.textContent = iv.size !== undefined ? `${iv.size} bytes` : 'N/A';
        tr.appendChild(tdSize);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      ivarsSection.appendChild(table);
    } else {
      ivarsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No instance variables found</div>';
    }
    this.detailEl.appendChild(ivarsSection);
  }

  private renderProtocolDetail(proto: ObjcProtocol) {
    // 1. Header
    const header = document.createElement('div');
    header.className = 'objc-detail-header';
    header.innerHTML = `
      <h3>&lt;${proto.name}&gt;</h3>
      <p>Objective-C Protocol</p>
    `;
    this.detailEl.appendChild(header);

    // 2. Instance Methods
    const instMethodsSection = document.createElement('div');
    instMethodsSection.className = 'objc-meta-section';
    instMethodsSection.innerHTML = '<h4>Instance Methods</h4>';

    if (proto.instanceMethods && proto.instanceMethods.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Selector</th>
            <th>Type Encoding</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      proto.instanceMethods.forEach((m) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--accent-end)';
        tdName.style.fontWeight = '600';
        tdName.textContent = m.name;
        tr.appendChild(tdName);

        const tdType = document.createElement('td');
        tdType.style.color = 'var(--text-muted)';
        tdType.textContent = m.types || '';
        tr.appendChild(tdType);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      instMethodsSection.appendChild(table);
    } else {
      instMethodsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No instance methods defined</div>';
    }
    this.detailEl.appendChild(instMethodsSection);

    // 3. Class Methods
    const classMethodsSection = document.createElement('div');
    classMethodsSection.className = 'objc-meta-section';
    classMethodsSection.innerHTML = '<h4>Class Methods</h4>';

    if (proto.classMethods && proto.classMethods.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Selector</th>
            <th>Type Encoding</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      proto.classMethods.forEach((m) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--accent-end)';
        tdName.style.fontWeight = '600';
        tdName.textContent = m.name;
        tr.appendChild(tdName);

        const tdType = document.createElement('td');
        tdType.style.color = 'var(--text-muted)';
        tdType.textContent = m.types || '';
        tr.appendChild(tdType);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      classMethodsSection.appendChild(table);
    } else {
      classMethodsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No class methods defined</div>';
    }
    this.detailEl.appendChild(classMethodsSection);

    // 4. Properties
    const propsSection = document.createElement('div');
    propsSection.className = 'objc-meta-section';
    propsSection.innerHTML = '<h4>Properties</h4>';

    if (proto.properties && proto.properties.length > 0) {
      const table = document.createElement('table');
      table.className = 'objc-table';
      table.innerHTML = `
        <thead>
          <tr>
            <th>Property Name</th>
            <th>Attributes</th>
          </tr>
        </thead>
      `;
      const tbody = document.createElement('tbody');
      proto.properties.forEach((p) => {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        tdName.style.color = 'var(--text-secondary)';
        tdName.textContent = p.name;
        tr.appendChild(tdName);

        const tdAttr = document.createElement('td');
        tdAttr.style.color = 'var(--text-muted)';
        tdAttr.textContent = p.attributes || '';
        tr.appendChild(tdAttr);

        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      propsSection.appendChild(table);
    } else {
      propsSection.innerHTML +=
        '<div style="color: var(--text-muted); font-style: italic; font-size: 0.85rem; padding-left: 0.5rem;">No properties defined</div>';
    }
    this.detailEl.appendChild(propsSection);
  }
}
