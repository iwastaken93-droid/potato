import { Section } from '../disassembler/types.js';

export class MemoryMapView {
  private container: HTMLElement;
  private sections: Section[];
  private onAddressSelect: (address: number) => void;

  private rootEl!: HTMLDivElement;

  constructor(
    container: HTMLElement,
    sections: Section[],
    onAddressSelect: (address: number) => void
  ) {
    this.container = container;
    this.sections = sections;
    this.onAddressSelect = onAddressSelect;

    this.initLayout();
  }

  public updateData(sections: Section[]) {
    this.sections = sections;
    this.render();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'glass-panel memory-map-panel';
    this.rootEl.style.height = '100%';
    this.rootEl.style.display = 'flex';
    this.rootEl.style.flexDirection = 'column';
    this.rootEl.style.gap = '1.5rem';
    this.rootEl.style.overflow = 'auto';

    // Inject styles
    if (!document.getElementById('memory-map-styles')) {
      const style = document.createElement('style');
      style.id = 'memory-map-styles';
      style.textContent = `
        .memory-map-grid {
          width: 100%;
          border-collapse: collapse;
          text-align: left;
          font-size: 0.85rem;
          font-family: var(--font-mono);
          color: var(--text-secondary);
        }
        .memory-map-grid th {
          background: rgba(15, 17, 21, 0.4);
          padding: 0.75rem 1rem;
          font-weight: 600;
          color: var(--text-primary);
          border-bottom: 1px solid var(--border-color);
        }
        .memory-map-grid td {
          padding: 0.75rem 1rem;
          border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }
        .memory-map-grid tr:hover {
          background: rgba(255, 255, 255, 0.02);
          cursor: pointer;
        }
        .perm-badge {
          display: inline-block;
          font-weight: 700;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 0.75rem;
          letter-spacing: 0.05em;
        }
        .perm-r { background: rgba(56, 189, 248, 0.15); color: #38bdf8; }
        .perm-w { background: rgba(245, 158, 11, 0.15); color: #f59e0b; }
        .perm-x { background: rgba(239, 68, 68, 0.15); color: #ef4444; }
        
        .entropy-container {
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .entropy-bar-bg {
          width: 80px;
          height: 6px;
          background: rgba(255, 255, 255, 0.1);
          border-radius: var(--radius-full);
          overflow: hidden;
        }
        .entropy-bar-fill {
          height: 100%;
          border-radius: var(--radius-full);
        }
        
        .memory-summary-cards {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
          gap: 1rem;
        }
        .summary-card {
          background: rgba(15, 17, 21, 0.3);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .summary-card-label {
          font-size: 0.7rem;
          text-transform: uppercase;
          color: var(--text-muted);
          font-weight: 700;
        }
        .summary-card-val {
          font-size: 1.2rem;
          font-weight: 600;
          color: var(--text-primary);
        }
      `;
      document.head.appendChild(style);
    }

    this.container.appendChild(this.rootEl);
    this.render();
  }

  private render() {
    this.rootEl.innerHTML = '';

    if (this.sections.length === 0) {
      this.rootEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 4rem;">
          No sections mapping available.
        </div>
      `;
      return;
    }

    // Compute Summary Stats
    const totalVmsize = this.sections.reduce(
      (acc, s) => acc + s.virtualSize,
      0
    );
    const totalFilesize = this.sections.reduce((acc, s) => acc + s.fileSize, 0);
    const execSections = this.sections.filter((s) => s.flags.execute);
    const maxEntropy = Math.max(...this.sections.map((s) => s.entropy ?? 0));

    // Stats Cards
    const statsContainer = document.createElement('div');
    statsContainer.className = 'memory-summary-cards';
    statsContainer.innerHTML = `
      <div class="summary-card">
        <span class="summary-card-label">Virtual Address Space</span>
        <span class="summary-card-val">${this.formatBytes(totalVmsize)}</span>
      </div>
      <div class="summary-card">
        <span class="summary-card-label">Mapped File Size</span>
        <span class="summary-card-val">${this.formatBytes(totalFilesize)}</span>
      </div>
      <div class="summary-card">
        <span class="summary-card-label">Executable Segments</span>
        <span class="summary-card-val">${execSections.length}</span>
      </div>
      <div class="summary-card">
        <span class="summary-card-label">Peak Section Entropy</span>
        <span class="summary-card-val" style="color: ${maxEntropy > 7.0 ? '#ef4444' : '#10b981'}">${maxEntropy.toFixed(3)}</span>
      </div>
    `;
    this.rootEl.appendChild(statsContainer);

    // Create table
    const table = document.createElement('table');
    table.className = 'memory-map-grid';

    let tableHtml = `
      <thead>
        <tr>
          <th>Name</th>
          <th>Virtual Start</th>
          <th>Virtual Size</th>
          <th>File Offset</th>
          <th>File Size</th>
          <th>Permissions</th>
          <th>Entropy</th>
        </tr>
      </thead>
      <tbody>
    `;

    this.sections.forEach((sec) => {
      const perms: string[] = [];
      if (sec.flags.read)
        perms.push('<span class="perm-badge perm-r">R</span>');
      if (sec.flags.write)
        perms.push('<span class="perm-badge perm-w">W</span>');
      if (sec.flags.execute)
        perms.push('<span class="perm-badge perm-x">X</span>');
      if (perms.length === 0)
        perms.push(
          '<span class="perm-badge" style="background: rgba(255,255,255,0.05); color: var(--text-disabled)">-</span>'
        );

      const ent = sec.entropy ?? 0;
      let barColor = '#10b981'; // Green
      if (ent > 7.2)
        barColor = '#ef4444'; // Red (likely encrypted/compressed)
      else if (ent > 6.0) barColor = '#f59e0b'; // Orange

      tableHtml += `
        <tr data-addr="${sec.virtualAddress}">
          <td style="font-weight: 600; color: var(--text-primary);">${sec.name}</td>
          <td style="color: #38bdf8;">0x${sec.virtualAddress.toString(16).toUpperCase()}</td>
          <td>0x${sec.virtualSize.toString(16).toUpperCase()} (${this.formatBytes(sec.virtualSize)})</td>
          <td>0x${sec.fileOffset.toString(16).toUpperCase()}</td>
          <td>0x${sec.fileSize.toString(16).toUpperCase()} (${this.formatBytes(sec.fileSize)})</td>
          <td>
            <div style="display: flex; gap: 0.25rem;">
              ${perms.join('')}
            </div>
          </td>
          <td>
            <div class="entropy-container">
              <span style="min-width: 32px;">${ent.toFixed(2)}</span>
              <div class="entropy-bar-bg">
                <div class="entropy-bar-fill" style="width: ${(ent / 8) * 100}%; background-color: ${barColor};"></div>
              </div>
            </div>
          </td>
        </tr>
      `;
    });

    tableHtml += '</tbody>';
    table.innerHTML = tableHtml;

    table.addEventListener('click', (e) => {
      const row = (e.target as HTMLElement).closest(
        'tr'
      ) as HTMLTableRowElement;
      if (row && row.dataset.addr) {
        const addr = parseInt(row.dataset.addr, 10);
        this.onAddressSelect(addr);
      }
    });

    this.rootEl.appendChild(table);
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
}
