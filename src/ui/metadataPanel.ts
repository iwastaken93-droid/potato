import { computeMD5, computeSHA1, computeSHA256 } from '../analyzer/hashes.js';

export interface MetadataPanelData {
  fileName: string;
  fileSize: number;
  binaryData: Uint8Array;
  architecture: string;
  entryPoint: number;
  sectionsCount: number;
  symbolsCount: number;
  lastModified?: number;
  objc?: {
    classes: any[];
    protocols: any[];
  } | null;
}

export class MetadataPanel {
  private container: HTMLElement;
  private data: MetadataPanelData | null = null;

  // DOM elements
  private rootEl!: HTMLDivElement;

  // Calculated hashes cache
  private md5Hash: string = '';
  private sha1Hash: string = '';
  private sha256Hash: string = '';
  private isCalculatingHashes: boolean = false;

  // ObjC selection state
  private selectedObjcType: 'class' | 'protocol' = 'class';
  private selectedObjcIndex: number = 0;

  constructor(container: HTMLElement) {
    this.container = container;
    this.injectStyles();
    this.initLayout();
  }

  /**
   * Updates the panel with new binary/file data.
   */
  public updateData(data: MetadataPanelData) {
    this.data = data;
    this.md5Hash = '';
    this.sha1Hash = '';
    this.sha256Hash = '';
    this.selectedObjcType = 'class';
    this.selectedObjcIndex = 0;

    // Async hash calculation to prevent blocking UI main thread
    this.calculateHashes(data.binaryData);
    this.render();
  }

  private injectStyles() {
    if (document.getElementById('metadata-panel-styles')) return;

    const style = document.createElement('style');
    style.id = 'metadata-panel-styles';
    style.textContent = `
      .meta-panel-root {
        display: flex;
        flex-direction: column;
        height: 100%;
        gap: 1.5rem;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(15, 17, 21, 0.2);
        overflow-y: auto;
      }

      .meta-header {
        display: flex;
        flex-direction: column;
        gap: 0.25rem;
      }

      .meta-header h2 {
        margin: 0;
        font-size: 1.5rem;
        font-weight: 700;
        background: var(--gradient-accent);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }

      .meta-header p {
        margin: 0;
        font-size: 0.875rem;
        color: var(--text-muted);
      }

      /* Grid stats layout */
      .meta-stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
      }

      .meta-stat-card {
        background: var(--bg-glass);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1.25rem;
        backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
        transition: transform var(--transition-fast), border-color var(--transition-fast), background var(--transition-fast);
      }

      .meta-stat-card:hover {
        transform: translateY(-2px);
        border-color: var(--border-hover);
        background: var(--bg-glass-hover);
      }

      .meta-stat-card .stat-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-muted);
        font-weight: 700;
        letter-spacing: 0.05em;
      }

      .meta-stat-card .stat-value {
        font-size: 1.5rem;
        font-weight: 700;
        font-family: var(--font-mono);
        color: var(--text-primary);
      }

      /* Sections container styling */
      .meta-sections-wrapper {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1.5rem;
      }

      @media (max-width: 900px) {
        .meta-sections-wrapper {
          grid-template-columns: 1fr;
        }
      }

      .meta-card {
        background: var(--bg-glass);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1.5rem;
        backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
      }

      .meta-card-title {
        margin: 0;
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--text-primary);
        display: flex;
        align-items: center;
        gap: 0.5rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 0.75rem;
      }

      /* Key-Value Details table */
      .meta-details-table {
        width: 100%;
        border-collapse: collapse;
      }

      .meta-details-table tr {
        border-bottom: 1px solid rgba(255, 255, 255, 0.03);
      }

      .meta-details-table tr:last-child {
        border-bottom: none;
      }

      .meta-details-table td {
        padding: 0.75rem 0;
        font-size: 0.9rem;
        vertical-align: top;
      }

      .meta-details-table td.detail-label {
        width: 35%;
        color: var(--text-muted);
        font-weight: 500;
      }

      .meta-details-table td.detail-value {
        color: var(--text-secondary);
        font-family: var(--font-mono);
        word-break: break-all;
      }

      /* Hashes items styling */
      .meta-hash-item {
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
        margin-bottom: 1rem;
      }

      .meta-hash-item:last-child {
        margin-bottom: 0;
      }

      .meta-hash-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .meta-hash-label {
        font-size: 0.8rem;
        font-weight: 700;
        color: var(--text-muted);
      }

      .meta-hash-row {
        display: flex;
        gap: 0.5rem;
        align-items: center;
      }

      .meta-hash-value {
        flex: 1;
        background: rgba(0, 0, 0, 0.25);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        padding: 0.6rem 0.8rem;
        font-family: var(--font-mono);
        font-size: 0.825rem;
        color: var(--text-secondary);
        word-break: break-all;
        min-height: 2.1rem;
        box-sizing: border-box;
      }

      .meta-hash-value.loading {
        color: var(--text-disabled);
        font-style: italic;
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .copy-btn {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
        cursor: pointer;
        padding: 0.5rem;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all var(--transition-fast);
        min-width: 2.2rem;
        height: 2.1rem;
      }

      .copy-btn:hover:not(:disabled) {
        background: rgba(255, 255, 255, 0.1);
        border-color: var(--border-hover);
        color: var(--text-primary);
      }

      .copy-btn:active:not(:disabled) {
        transform: scale(0.95);
      }

      .copy-btn:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      .copy-btn.copied {
        background: var(--success-glow);
        border-color: var(--success);
        color: var(--success);
      }

      /* Spinner animation */
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .spinner {
        display: inline-block;
        width: 12px;
        height: 12px;
        border: 2px solid rgba(255,255,255,0.1);
        border-top-color: var(--text-muted);
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }

      /* ObjC Section styling */
      .meta-objc-container {
        background: var(--bg-glass);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1.5rem;
        backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
      }
      
      .objc-tab-header {
        display: flex;
        gap: 1rem;
        border-bottom: 1px solid var(--border-color);
        padding-bottom: 0.5rem;
      }

      .objc-tab-btn {
        background: none;
        border: none;
        color: var(--text-muted);
        font-weight: 600;
        cursor: pointer;
        font-size: 0.95rem;
        padding: 0.25rem 0.5rem;
        border-bottom: 2px solid transparent;
        transition: all var(--transition-fast);
      }

      .objc-tab-btn:hover {
        color: var(--text-primary);
      }

      .objc-tab-btn.active {
        color: var(--accent-end);
        border-bottom-color: var(--accent-end);
      }

      .objc-grid {
        display: grid;
        grid-template-columns: 280px 1fr;
        gap: 1.5rem;
        min-height: 350px;
      }

      @media (max-width: 768px) {
        .objc-grid {
          grid-template-columns: 1fr;
        }
      }

      .objc-sidebar {
        border-right: 1px solid var(--border-color);
        padding-right: 1rem;
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
        max-height: 400px;
        overflow-y: auto;
      }

      .objc-item-btn {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
        padding: 0.5rem 0.75rem;
        text-align: left;
        cursor: pointer;
        transition: all var(--transition-fast);
        font-family: var(--font-sans);
        font-size: 0.85rem;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }

      .objc-item-btn:hover {
        background: var(--bg-glass-hover);
        color: var(--text-primary);
        border-color: var(--border-hover);
      }

      .objc-item-btn.active {
        background: var(--gradient-accent);
        color: #fff;
        border-color: transparent;
      }

      .objc-detail-view {
        padding-left: 0.5rem;
        display: flex;
        flex-direction: column;
        gap: 1.5rem;
        max-height: 400px;
        overflow-y: auto;
      }

      .objc-detail-header h4 {
        margin: 0;
        font-size: 1.25rem;
        font-weight: 700;
        color: var(--text-primary);
      }

      .objc-detail-header p {
        margin: 0.25rem 0 0 0;
        font-size: 0.85rem;
        color: var(--text-muted);
      }

      .objc-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 0.5rem;
      }

      .objc-table th {
        text-align: left;
        padding: 0.5rem;
        font-size: 0.75rem;
        text-transform: uppercase;
        color: var(--text-muted);
        border-bottom: 1px solid var(--border-color);
      }

      .objc-table td {
        padding: 0.5rem;
        font-size: 0.825rem;
        border-bottom: 1px solid rgba(255,255,255,0.03);
        font-family: var(--font-mono);
        vertical-align: top;
      }

      .objc-badge {
        font-size: 0.65rem;
        padding: 0.1rem 0.35rem;
        border-radius: 4px;
        font-weight: 700;
        text-transform: uppercase;
        display: inline-block;
      }

      .badge-class { background: rgba(59, 130, 246, 0.2); color: #60a5fa; }
      .badge-proto { background: rgba(16, 185, 129, 0.2); color: #34d399; }
      .badge-method { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
      .badge-ivar { background: rgba(139, 92, 246, 0.2); color: #a78bfa; }
      .badge-prop { background: rgba(236, 72, 153, 0.2); color: #f472b6; }
    `;
    document.head.appendChild(style);
  }

  private initLayout() {
    this.container.innerHTML = '';
    this.rootEl = document.createElement('div');
    this.rootEl.className = 'meta-panel-root';
    this.container.appendChild(this.rootEl);
    this.render();
  }

  private calculateHashes(binaryData: Uint8Array) {
    if (binaryData.length === 0) {
      this.md5Hash = 'N/A';
      this.sha1Hash = 'N/A';
      this.sha256Hash = 'N/A';
      return;
    }

    this.isCalculatingHashes = true;
    this.render();

    // Use setTimeout to allow UI to render first
    setTimeout(() => {
      try {
        this.md5Hash = computeMD5(binaryData);
        this.sha1Hash = computeSHA1(binaryData);
        this.sha256Hash = computeSHA256(binaryData);
      } catch (err) {
        console.error('Error calculating hashes:', err);
        this.md5Hash = 'Error';
        this.sha1Hash = 'Error';
        this.sha256Hash = 'Error';
      } finally {
        this.isCalculatingHashes = false;
        this.render();
      }
    }, 50);
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const val = parseFloat((bytes / Math.pow(k, i)).toFixed(2));
    return `${bytes.toLocaleString()} bytes (${val} ${sizes[i]})`;
  }

  private formatDate(timestamp?: number): string {
    const d = timestamp ? new Date(timestamp) : new Date();
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }

  private copyToClipboard(text: string, button: HTMLButtonElement) {
    if (!text || text === 'N/A' || this.isCalculatingHashes) return;

    navigator.clipboard
      .writeText(text)
      .then(() => {
        button.classList.add('copied');
        const originalHTML = button.innerHTML;
        button.innerHTML = '✓';

        setTimeout(() => {
          button.classList.remove('copied');
          button.innerHTML = originalHTML;
        }, 1500);
      })
      .catch((err) => {
        console.error('Failed to copy text: ', err);
      });
  }

  private render() {
    if (!this.data) {
      this.rootEl.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); gap: 1rem;">
          <span style="font-size: 3rem;">📁</span>
          <p>No binary file loaded. Drag and drop or browse to load a binary.</p>
        </div>
      `;
      return;
    }

    const {
      fileName,
      fileSize,
      architecture,
      entryPoint,
      sectionsCount,
      symbolsCount,
      lastModified,
      objc,
    } = this.data;

    const formattedSize = this.formatBytes(fileSize);
    const formattedEntryPoint = `0x${entryPoint.toString(16).toUpperCase()}`;
    const formattedModifiedDate = this.formatDate(lastModified);

    // Build PE Resources UI if it's a PE binary
    let peResourcesHtml = '';
    const binaryData = this.data.binaryData;
    if (
      binaryData &&
      binaryData.length > 64 &&
      binaryData[0] === 0x4d &&
      binaryData[1] === 0x5a
    ) {
      try {
        const peParser = new PEParser(binaryData.buffer);
        const pe = peParser.parse();
        if (pe.resources && pe.resources.all && pe.resources.all.length > 0) {
          const r = pe.resources;
          let manifestSection = '';
          if (r.manifests && r.manifests.length > 0) {
            manifestSection = `
              <div style="margin-top: 1rem;">
                <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--text-primary);">Manifest</h4>
                <pre class="manifest-viewer">${r.manifests.map((m) => m.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')).join('\n\n')}</pre>
              </div>
            `;
          }

          let stringsSection = '';
          const stringKeys = Object.keys(r.strings);
          if (stringKeys.length > 0) {
            stringsSection = `
              <div style="margin-top: 1rem;">
                <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--text-primary);">Parsed String Table Resources</h4>
                <div style="max-height: 200px; overflow-y: auto; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 0.5rem;">
                  <table class="resources-list-table" style="margin-top: 0;">
                    <thead>
                      <tr>
                        <th style="width: 80px;">ID</th>
                        <th>String Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${stringKeys
                        .map(
                          (k) => `
                        <tr>
                          <td style="font-family: var(--font-mono); color: var(--text-muted);">${k}</td>
                          <td style="font-family: var(--font-sans); color: var(--text-secondary);">${r.strings[Number(k)]}</td>
                        </tr>
                      `
                        )
                        .join('')}
                    </tbody>
                  </table>
                </div>
              </div>
            `;
          }

          let iconsSection = '';
          if (r.icons && r.icons.length > 0) {
            iconsSection = `
              <div style="margin-top: 1rem;">
                <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--text-primary);">Icons &amp; Group Icons</h4>
                <table class="resources-list-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Size</th>
                      <th>File Offset</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${r.icons
                      .map(
                        (i) => `
                      <tr>
                        <td style="color: var(--accent-end);">${i.type}</td>
                        <td style="font-family: var(--font-mono);">${i.size} B</td>
                        <td style="font-family: var(--font-mono);">0x${i.offset.toString(16).toUpperCase()}</td>
                      </tr>
                    `
                      )
                      .join('')}
                  </tbody>
                </table>
              </div>
            `;
          }

          peResourcesHtml = `
            <div class="meta-resources-card">
              <h3 class="meta-card-title">📦 PE Resource (.rsrc) Section</h3>
              <div style="display: flex; flex-direction: column; gap: 1rem;">
                <div>
                  <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; color: var(--text-primary);">All Resources</h4>
                  <table class="resources-list-table">
                    <thead>
                      <tr>
                        <th>Type Name</th>
                        <th>Name/ID</th>
                        <th>Lang ID</th>
                        <th>Size</th>
                        <th>Offset</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${r.all
                        .map(
                          (res) => `
                        <tr>
                          <td><span class="badge" style="background: rgba(255,255,255,0.05); padding: 0.2rem 0.4rem; border-radius: 3px;">${res.typeName}</span></td>
                          <td style="font-family: var(--font-mono);">${res.name}</td>
                          <td style="font-family: var(--font-mono);">${res.language}</td>
                          <td style="font-family: var(--font-mono);">${res.size} B</td>
                          <td style="font-family: var(--font-mono);">0x${res.offset.toString(16).toUpperCase()}</td>
                        </tr>
                      `
                        )
                        .join('')}
                    </tbody>
                  </table>
                </div>
                ${manifestSection}
                ${stringsSection}
                ${iconsSection}
              </div>
            </div>
          `;
        }
      } catch (e) {
        console.error('Error parsing PE resources for metadata panel:', e);
      }
    }

    // Build ObjC UI if metadata exists
    let objcHTML = '';
    const hasObjc =
      objc && (objc.classes.length > 0 || objc.protocols.length > 0);

    if (hasObjc) {
      const activeList =
        this.selectedObjcType === 'class' ? objc.classes : objc.protocols;
      const selectedItem = activeList[this.selectedObjcIndex];

      let sidebarItems = '';
      activeList.forEach((item, index) => {
        const isActive = index === this.selectedObjcIndex;
        sidebarItems += `
          <button class="objc-item-btn ${isActive ? 'active' : ''}" data-type="${this.selectedObjcType}" data-index="${index}">
            <span>${item.name}</span>
            <span class="objc-badge ${this.selectedObjcType === 'class' ? 'badge-class' : 'badge-proto'}">
              ${this.selectedObjcType === 'class' ? 'Class' : 'Protocol'}
            </span>
          </button>
        `;
      });

      let detailHTML = '';
      if (selectedItem) {
        if (this.selectedObjcType === 'class') {
          // Class detail view
          let methodsRows = '';
          if (selectedItem.methods && selectedItem.methods.length > 0) {
            selectedItem.methods.forEach((m: any) => {
              methodsRows += `
                <tr>
                  <td style="color: var(--accent-end); width: 45%;">${m.name}</td>
                  <td style="color: var(--text-muted); width: 30%;">${m.types}</td>
                  <td style="color: var(--success); width: 25%;">0x${BigInt(m.imp).toString(16).toUpperCase()}</td>
                </tr>
              `;
            });
          } else {
            methodsRows = `<tr><td colspan="3" style="color: var(--text-muted); font-style: italic;">No methods found</td></tr>`;
          }

          let ivarRows = '';
          if (selectedItem.ivars && selectedItem.ivars.length > 0) {
            selectedItem.ivars.forEach((iv: any) => {
              ivarRows += `
                <tr>
                  <td style="color: var(--text-primary); width: 35%;">${iv.name}</td>
                  <td style="color: var(--text-muted); width: 45%;">${iv.type}</td>
                  <td style="color: var(--text-secondary); width: 20%; text-align: right;">+${iv.offset} (size ${iv.size})</td>
                </tr>
              `;
            });
          } else {
            ivarRows = `<tr><td colspan="3" style="color: var(--text-muted); font-style: italic;">No instance variables found</td></tr>`;
          }

          let propertiesRows = '';
          if (selectedItem.properties && selectedItem.properties.length > 0) {
            selectedItem.properties.forEach((p: any) => {
              propertiesRows += `
                <tr>
                  <td style="color: var(--text-secondary); width: 35%;">${p.name}</td>
                  <td style="color: var(--text-muted); width: 65%;">${p.attributes}</td>
                </tr>
              `;
            });
          } else {
            propertiesRows = `<tr><td colspan="2" style="color: var(--text-muted); font-style: italic;">No properties found</td></tr>`;
          }

          detailHTML = `
            <div class="objc-detail-header">
              <h4>${selectedItem.name}</h4>
              <p>${selectedItem.superclassName ? `Superclass: <span style="color: var(--accent-end);">${selectedItem.superclassName}</span>` : 'Root class'}</p>
              ${selectedItem.protocols && selectedItem.protocols.length > 0 ? `<p style="margin-top: 0.25rem;">Adopts Protocols: ${selectedItem.protocols.map((p: string) => `<span class="objc-badge badge-proto">${p}</span>`).join(' ')}</p>` : ''}
            </div>

            <div>
              <h5 style="margin: 0.75rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Methods</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Selector</th>
                    <th>Type Encoding</th>
                    <th>IMP Address</th>
                  </tr>
                </thead>
                <tbody>
                  ${methodsRows}
                </tbody>
              </table>
            </div>

            <div>
              <h5 style="margin: 1.25rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Properties</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Attributes</th>
                  </tr>
                </thead>
                <tbody>
                  ${propertiesRows}
                </tbody>
              </table>
            </div>

            <div>
              <h5 style="margin: 1.25rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Instance Variables (Ivars)</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th style="text-align: right;">Offset</th>
                  </tr>
                </thead>
                <tbody>
                  ${ivarRows}
                </tbody>
              </table>
            </div>
          `;
        } else {
          // Protocol detail view
          let methodsRows = '';
          if (
            selectedItem.instanceMethods &&
            selectedItem.instanceMethods.length > 0
          ) {
            selectedItem.instanceMethods.forEach((m: any) => {
              methodsRows += `
                <tr>
                  <td style="color: var(--accent-end); width: 50%;">${m.name}</td>
                  <td style="color: var(--text-muted); width: 50%;">${m.types}</td>
                </tr>
              `;
            });
          } else {
            methodsRows = `<tr><td colspan="2" style="color: var(--text-muted); font-style: italic;">No instance methods found</td></tr>`;
          }

          let classMethodsRows = '';
          if (
            selectedItem.classMethods &&
            selectedItem.classMethods.length > 0
          ) {
            selectedItem.classMethods.forEach((m: any) => {
              classMethodsRows += `
                <tr>
                  <td style="color: var(--accent-end); width: 50%;">${m.name}</td>
                  <td style="color: var(--text-muted); width: 50%;">${m.types}</td>
                </tr>
              `;
            });
          } else {
            classMethodsRows = `<tr><td colspan="2" style="color: var(--text-muted); font-style: italic;">No class methods found</td></tr>`;
          }

          let propertiesRows = '';
          if (selectedItem.properties && selectedItem.properties.length > 0) {
            selectedItem.properties.forEach((p: any) => {
              propertiesRows += `
                <tr>
                  <td style="color: var(--text-secondary); width: 35%;">${p.name}</td>
                  <td style="color: var(--text-muted); width: 65%;">${p.attributes}</td>
                </tr>
              `;
            });
          } else {
            propertiesRows = `<tr><td colspan="2" style="color: var(--text-muted); font-style: italic;">No properties found</td></tr>`;
          }

          detailHTML = `
            <div class="objc-detail-header">
              <h4>&lt;${selectedItem.name}&gt;</h4>
              <p>Objective-C Protocol</p>
            </div>

            <div>
              <h5 style="margin: 0.75rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Instance Methods</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Selector</th>
                    <th>Type Encoding</th>
                  </tr>
                </thead>
                <tbody>
                  ${methodsRows}
                </tbody>
              </table>
            </div>

            <div>
              <h5 style="margin: 1.25rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Class Methods</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Selector</th>
                    <th>Type Encoding</th>
                  </tr>
                </thead>
                <tbody>
                  ${classMethodsRows}
                </tbody>
              </table>
            </div>

            <div>
              <h5 style="margin: 1.25rem 0 0.25rem 0; font-size: 0.9rem; color: var(--text-primary);">Properties</h5>
              <table class="objc-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Attributes</th>
                  </tr>
                </thead>
                <tbody>
                  ${propertiesRows}
                </tbody>
              </table>
            </div>
          `;
        }
      }

      objcHTML = `
        <div class="meta-objc-container">
          <h3 class="meta-card-title">🍎 Objective-C Metadata Analysis</h3>
          <div class="objc-tab-header">
            <button class="objc-tab-btn ${this.selectedObjcType === 'class' ? 'active' : ''}" id="objc-tab-classes">
              Classes (${objc.classes.length})
            </button>
            <button class="objc-tab-btn ${this.selectedObjcType === 'protocol' ? 'active' : ''}" id="objc-tab-protocols">
              Protocols (${objc.protocols.length})
            </button>
          </div>
          <div class="objc-grid">
            <div class="objc-sidebar">
              ${sidebarItems || '<div style="color: var(--text-muted); padding: 1rem; font-style: italic;">None found</div>'}
            </div>
            <div class="objc-detail-view">
              ${detailHTML || '<div style="color: var(--text-muted); padding: 1rem; font-style: italic;">Select an item from the sidebar to inspect its structure</div>'}
            </div>
          </div>
        </div>
      `;
    }

    this.rootEl.innerHTML = `
      <div class="meta-header">
        <h2>File Metadata Analysis</h2>
        <p>Comprehensive metadata, structural properties, and cryptographic hashes</p>
      </div>

      <!-- Quick Stats cards -->
      <div class="meta-stats-grid">
        <div class="meta-stat-card">
          <span class="stat-label">File Size</span>
          <span class="stat-value" title="${formattedSize}">${fileSize.toLocaleString()} B</span>
        </div>
        <div class="meta-stat-card">
          <span class="stat-label">Format / Arch</span>
          <span class="stat-value" style="color: var(--accent-end);">${architecture.toUpperCase()}</span>
        </div>
        <div class="meta-stat-card">
          <span class="stat-label">Entry Point</span>
          <span class="stat-value" style="color: var(--success);">${formattedEntryPoint}</span>
        </div>
        <div class="meta-stat-card">
          <span class="stat-label">Sections / Symbols</span>
          <span class="stat-value">${sectionsCount} / ${symbolsCount}</span>
        </div>
      </div>

      <div class="meta-sections-wrapper">
        <!-- Structural details card -->
        <div class="meta-card">
          <h3 class="meta-card-title">⚙️ Structural Details</h3>
          <table class="meta-details-table">
            <tr>
              <td class="detail-label">File Name</td>
              <td class="detail-value" style="color: var(--text-primary); font-weight: 500;">${fileName}</td>
            </tr>
            <tr>
              <td class="detail-label">Full Path / URI</td>
              <td class="detail-value" style="font-size: 0.8rem;">file:///${fileName}</td>
            </tr>
            <tr>
              <td class="detail-label">File Size</td>
              <td class="detail-value">${formattedSize}</td>
            </tr>
            <tr>
              <td class="detail-label">Architecture</td>
              <td class="detail-value">${architecture}</td>
            </tr>
            <tr>
              <td class="detail-label">Entry Point</td>
              <td class="detail-value">${formattedEntryPoint}</td>
            </tr>
            <tr>
              <td class="detail-label">Total Sections</td>
              <td class="detail-value">${sectionsCount}</td>
            </tr>
            <tr>
              <td class="detail-label">Total Symbols</td>
              <td class="detail-value">${symbolsCount}</td>
            </tr>
            <tr>
              <td class="detail-label">Last Modified</td>
              <td class="detail-value">${formattedModifiedDate}</td>
            </tr>
          </table>
        </div>

        <!-- Cryptographic Hashes card -->
        <div class="meta-card">
          <h3 class="meta-card-title">🔒 Cryptographic Hashes</h3>
          <div style="display: flex; flex-direction: column; gap: 1rem; justify-content: center; height: 100%;">
            
            <div class="meta-hash-item">
              <div class="meta-hash-header">
                <span class="meta-hash-label">MD5</span>
              </div>
              <div class="meta-hash-row">
                <div class="meta-hash-value ${this.isCalculatingHashes ? 'loading' : ''}">
                  ${this.isCalculatingHashes ? '<span class="spinner"></span> Calculating...' : this.md5Hash || 'N/A'}
                </div>
                <button class="copy-btn" data-hash="md5" ${this.isCalculatingHashes || !this.md5Hash ? 'disabled' : ''} title="Copy MD5 hash">
                  📋
                </button>
              </div>
            </div>

            <div class="meta-hash-item">
              <div class="meta-hash-header">
                <span class="meta-hash-label">SHA-1</span>
              </div>
              <div class="meta-hash-row">
                <div class="meta-hash-value ${this.isCalculatingHashes ? 'loading' : ''}">
                  ${this.isCalculatingHashes ? '<span class="spinner"></span> Calculating...' : this.sha1Hash || 'N/A'}
                </div>
                <button class="copy-btn" data-hash="sha1" ${this.isCalculatingHashes || !this.sha1Hash ? 'disabled' : ''} title="Copy SHA-1 hash">
                  📋
                </button>
              </div>
            </div>

            <div class="meta-hash-item">
              <div class="meta-hash-header">
                <span class="meta-hash-label">SHA-256</span>
              </div>
              <div class="meta-hash-row">
                <div class="meta-hash-value ${this.isCalculatingHashes ? 'loading' : ''}">
                  ${this.isCalculatingHashes ? '<span class="spinner"></span> Calculating...' : this.sha256Hash || 'N/A'}
                </div>
                <button class="copy-btn" data-hash="sha256" ${this.isCalculatingHashes || !this.sha256Hash ? 'disabled' : ''} title="Copy SHA-256 hash">
                  📋
                </button>
              </div>
            </div>

          </div>
        </div>
      </div>

      ${objcHTML}
      ${peResourcesHtml}
    `;

    // Hook up copy buttons
    this.rootEl.querySelectorAll('.copy-btn').forEach((btn) => {
      const b = btn as HTMLButtonElement;
      const type = b.dataset.hash;
      let text = '';
      if (type === 'md5') text = this.md5Hash;
      else if (type === 'sha1') text = this.sha1Hash;
      else if (type === 'sha256') text = this.sha256Hash;

      b.addEventListener('click', () => this.copyToClipboard(text, b));
    });

    // Hook up ObjC tab buttons
    if (hasObjc) {
      const tabClasses = this.rootEl.querySelector('#objc-tab-classes');
      const tabProtocols = this.rootEl.querySelector('#objc-tab-protocols');

      if (tabClasses) {
        tabClasses.addEventListener('click', () => {
          this.selectedObjcType = 'class';
          this.selectedObjcIndex = 0;
          this.render();
        });
      }

      if (tabProtocols) {
        tabProtocols.addEventListener('click', () => {
          this.selectedObjcType = 'protocol';
          this.selectedObjcIndex = 0;
          this.render();
        });
      }

      // Hook up sidebar buttons
      this.rootEl.querySelectorAll('.objc-item-btn').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          const index = parseInt(btn.getAttribute('data-index') || '0', 10);
          this.selectedObjcIndex = index;
          this.render();
        });
      });
    }
  }
}
