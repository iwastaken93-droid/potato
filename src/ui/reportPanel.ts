/**
 * Premium Report Viewer Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides export options
 */

import { Section, Symbol } from '../disassembler/types.js';
import { ExtractedString } from '../analyzer/strings.js';
import { SignatureScanner, ScanResult } from '../analyzer/signatures.js';
import {
  calculateEntropy,
  findHighEntropyBlocks,
} from '../analyzer/entropy.js';
import { ReportGenerator, ReportData } from '../analyzer/reportGenerator.js';

export class ReportPanel {
  private container: HTMLElement;
  private rootEl!: HTMLDivElement;
  private previewContentEl!: HTMLDivElement;
  private currentReportData: ReportData | null = null;
  private scanner: SignatureScanner;
  private activeTab: 'interactive' | 'markdown' | 'json' = 'interactive';

  constructor(container: HTMLElement) {
    this.container = container;
    this.scanner = new SignatureScanner(true);
    this.initLayout();
  }

  /**
   * Updates report panel data and regenerates the report
   */
  public updateData(
    fileName: string,
    fileSize: number,
    binaryData: Uint8Array,
    architecture: string,
    entryPoint: number,
    sections: Section[],
    symbols: Symbol[],
    extractedStrings: ExtractedString[]
  ) {
    // 1. Calculate overall entropy
    const overallEntropy = calculateEntropy(binaryData);

    // 2. Find high-entropy blocks
    const highEntropyBlocks = findHighEntropyBlocks(binaryData);

    // 3. Scan signatures
    const signatures = this.scanner.scan(binaryData);

    // 4. Construct report data
    this.currentReportData = {
      fileName,
      fileSize,
      architecture,
      entryPoint,
      sections,
      symbols,
      signatures,
      entropy: {
        overall: overallEntropy,
        highEntropyBlocks,
      },
      strings: extractedStrings,
      binaryData,
    };

    // 5. Update Preview UI
    this.renderPreview();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'report-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Add Stylesheet if not already present
    if (!document.getElementById('report-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'report-panel-styles';
      style.textContent = `
        .report-panel-root {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }
        .report-header-controls {
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
        .report-btn-group {
          display: flex;
          gap: 0.75rem;
        }
        .report-tab-selector {
          display: flex;
          background: rgba(15, 17, 21, 0.5);
          border: 1px solid var(--border-color);
          padding: 0.25rem;
          border-radius: var(--radius-md);
          gap: 0.25rem;
          align-self: flex-start;
        }
        .report-tab-btn {
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
        .report-tab-btn:hover {
          color: var(--text-primary);
          background: rgba(255, 255, 255, 0.02);
        }
        .report-tab-btn.active {
          background: var(--gradient-accent);
          color: var(--text-primary) !important;
          box-shadow: var(--shadow-sm);
        }
        .report-preview-scroll {
          flex: 1;
          overflow-y: auto;
          background: rgba(10, 12, 16, 0.3);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1.5rem;
          font-family: var(--font-sans);
          color: var(--text-secondary);
        }
        .report-preview-scroll::-webkit-scrollbar {
          width: 8px;
        }
        .report-preview-scroll::-webkit-scrollbar-track {
          background: rgba(0, 0, 0, 0.05);
        }
        .report-preview-scroll::-webkit-scrollbar-thumb {
          background: rgba(255, 255, 255, 0.1);
          border-radius: 4px;
        }
        .report-preview-scroll::-webkit-scrollbar-thumb:hover {
          background: rgba(255, 255, 255, 0.2);
        }
        .report-section-card {
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.04);
          border-radius: var(--radius-md);
          padding: 1.25rem;
          margin-bottom: 1.25rem;
        }
        .report-section-card h3 {
          margin-top: 0;
          color: var(--text-primary);
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          padding-bottom: 0.5rem;
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }
        .report-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 1rem;
        }
        .report-grid-item {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }
        .report-grid-label {
          font-size: 0.75rem;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .report-grid-value {
          font-size: 0.95rem;
          color: var(--text-primary);
          font-family: var(--font-mono);
        }
        .report-table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 0.75rem;
          font-size: 0.85rem;
        }
        .report-table th, .report-table td {
          padding: 0.6rem 0.8rem;
          text-align: left;
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .report-table th {
          background: rgba(255, 255, 255, 0.03);
          color: var(--text-primary);
          font-weight: 600;
        }
        .report-table tr:hover {
          background: rgba(255, 255, 255, 0.01);
        }
        .badge-tag {
          display: inline-block;
          padding: 0.15rem 0.4rem;
          border-radius: 4px;
          font-size: 0.75rem;
          font-family: var(--font-mono);
          background: rgba(255, 255, 255, 0.06);
          color: var(--text-secondary);
        }
        .badge-read { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
        .badge-write { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
        .badge-execute { background: rgba(16, 185, 129, 0.15); color: #34d399; }

        /* Markdown & JSON Previews */
        .markdown-preview-container {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }
        .markdown-preview-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          background: rgba(255, 255, 255, 0.02);
          padding: 0.75rem 1rem;
          border-radius: var(--radius-sm);
          border: 1px solid rgba(255, 255, 255, 0.04);
        }
        .markdown-rendered-content {
          background: rgba(255, 255, 255, 0.01);
          border: 1px solid rgba(255, 255, 255, 0.02);
          border-radius: var(--radius-md);
          padding: 1.5rem;
          font-family: var(--font-sans);
          line-height: 1.6;
        }
        .markdown-rendered-content h1 {
          font-size: 1.5rem;
          margin-bottom: 1rem;
          padding-bottom: 0.5rem;
          border-bottom: 1px solid rgba(255, 255, 255, 0.08);
          color: var(--text-primary);
        }
        .markdown-rendered-content h2 {
          font-size: 1.25rem;
          margin-top: 1.5rem;
          margin-bottom: 0.75rem;
          padding-bottom: 0.35rem;
          border-bottom: 1px solid rgba(255, 255, 255, 0.04);
          color: var(--text-primary);
        }
        .markdown-rendered-content p {
          margin-bottom: 1rem;
          color: var(--text-secondary);
        }
        .markdown-rendered-content code {
          background: rgba(255, 255, 255, 0.06);
          padding: 0.2rem 0.4rem;
          border-radius: 4px;
          font-family: var(--font-mono);
          font-size: 0.85em;
          color: #fb7185;
        }
        .markdown-table {
          width: 100%;
          border-collapse: collapse;
          margin: 1rem 0;
          font-size: 0.85rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.05);
          border-radius: var(--radius-sm);
        }
        .markdown-table th, .markdown-table td {
          padding: 0.6rem 0.8rem;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .markdown-table th {
          background: rgba(255, 255, 255, 0.04);
          color: var(--text-primary);
          font-weight: 600;
        }
        .markdown-table tr:hover {
          background: rgba(255, 255, 255, 0.01);
        }
        .json-code-block {
          background: rgba(10, 12, 16, 0.5);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1.5rem;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          color: #a78bfa;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
          max-height: 600px;
        }
      `;
      document.head.appendChild(style);
    }

    // Header structure
    const headerEl = document.createElement('div');
    headerEl.className = 'report-header-controls';

    const titleArea = document.createElement('div');
    titleArea.style.cssText =
      'display: flex; flex-direction: column; gap: 0.25rem;';

    const title = document.createElement('h2');
    title.textContent = '📊 Binary Report Generator';
    title.style.cssText =
      'margin: 0; font-size: 1.25rem; color: var(--text-primary);';

    const subtitle = document.createElement('span');
    subtitle.textContent =
      'Generate and export full binary metadata and static analysis summaries';
    subtitle.style.cssText = 'font-size: 0.8rem; color: var(--text-muted);';

    titleArea.appendChild(title);
    titleArea.appendChild(subtitle);
    headerEl.appendChild(titleArea);

    // Button group
    const btnGroup = document.createElement('div');
    btnGroup.className = 'report-btn-group';

    const copyBtn = this.createButton('📋 Copy MD', 'btn-secondary', () =>
      this.handleCopy()
    );
    const exportMDBtn = this.createButton('📥 Save MD', 'btn-secondary', () =>
      this.handleExportMD()
    );
    const exportJSONBtn = this.createButton(
      '📥 Save JSON',
      'btn-secondary',
      () => this.handleExportJSON()
    );
    const printBtn = this.createButton('🖨️ Print PDF', 'btn-primary', () =>
      this.handlePrint()
    );

    btnGroup.appendChild(copyBtn);
    btnGroup.appendChild(exportMDBtn);
    btnGroup.appendChild(exportJSONBtn);
    btnGroup.appendChild(printBtn);
    headerEl.appendChild(btnGroup);

    // Tab selector container
    const tabSelector = document.createElement('div');
    tabSelector.className = 'report-tab-selector';

    const tabs = [
      { id: 'interactive', label: '📊 Interactive Dashboard' },
      { id: 'markdown', label: '📝 Markdown Preview' },
      { id: 'json', label: '⚙️ JSON View' },
    ];

    tabs.forEach((tab) => {
      const btn = document.createElement('button');
      btn.className = `report-tab-btn ${this.activeTab === tab.id ? 'active' : ''}`;
      btn.textContent = tab.label;
      btn.addEventListener('click', () => {
        this.setActiveTab(tab.id as 'interactive' | 'markdown' | 'json');
      });
      tabSelector.appendChild(btn);
    });

    // Preview area
    this.previewContentEl = document.createElement('div');
    this.previewContentEl.className = 'report-preview-scroll';
    this.previewContentEl.innerHTML = `<div style="text-align: center; padding: 3rem; color: var(--text-muted);">Please load a binary to generate an analysis report.</div>`;

    this.rootEl.appendChild(headerEl);
    this.rootEl.appendChild(tabSelector);
    this.rootEl.appendChild(this.previewContentEl);
    this.container.appendChild(this.rootEl);
  }

  private createButton(
    text: string,
    className: string,
    onClick: () => void
  ): HTMLButtonElement {
    const btn = document.createElement('button');
    btn.className = `btn ${className}`;
    btn.textContent = text;
    btn.style.cssText = 'padding: 0.5rem 1rem; font-size: 0.85rem;';
    btn.addEventListener('click', onClick);
    return btn;
  }

  private setActiveTab(tabId: 'interactive' | 'markdown' | 'json') {
    this.activeTab = tabId;

    // Update button active states
    const buttons = this.rootEl.querySelectorAll('.report-tab-btn');
    buttons.forEach((btn, idx) => {
      const ids = ['interactive', 'markdown', 'json'];
      if (ids[idx] === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    this.renderPreview();
  }

  private renderPreview() {
    if (!this.currentReportData) return;
    const data = this.currentReportData;

    if (this.activeTab === 'interactive') {
      this.renderInteractive(data);
    } else if (this.activeTab === 'markdown') {
      this.renderMarkdownPreview(data);
    } else if (this.activeTab === 'json') {
      this.renderJsonPreview(data);
    }
  }

  private renderInteractive(data: ReportData) {
    const formatSize = (bytes: number) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    let html = '';

    // Card 1: File Metadata
    html += `
      <div class="report-section-card">
        <h3>📋 File Metadata</h3>
        <div class="report-grid">
          <div class="report-grid-item">
            <span class="report-grid-label">File Name</span>
            <span class="report-grid-value">${data.fileName}</span>
          </div>
          <div class="report-grid-item">
            <span class="report-grid-label">File Size</span>
            <span class="report-grid-value">${formatSize(data.fileSize)} (${data.fileSize} bytes)</span>
          </div>
          <div class="report-grid-item">
            <span class="report-grid-label">Architecture</span>
            <span class="report-grid-value">${data.architecture.toUpperCase()}</span>
          </div>
          <div class="report-grid-item">
            <span class="report-grid-label">Entry Point</span>
            <span class="report-grid-value">0x${data.entryPoint.toString(16).toUpperCase()}</span>
          </div>
          <div class="report-grid-item">
            <span class="report-grid-label">Overall Entropy</span>
            <span class="report-grid-value">${data.entropy.overall.toFixed(4)}</span>
          </div>
        </div>
      </div>
    `;

    // Card 2: Sections
    if (data.sections && data.sections.length > 0) {
      let secRows = '';
      for (const sec of data.sections) {
        const flagsStr = [
          sec.flags.read ? '<span class="badge-tag badge-read">R</span>' : '',
          sec.flags.write ? '<span class="badge-tag badge-write">W</span>' : '',
          sec.flags.execute
            ? '<span class="badge-tag badge-execute">X</span>'
            : '',
        ].join(' ');
        const entropyVal =
          sec.entropy !== undefined ? sec.entropy.toFixed(4) : 'N/A';
        secRows += `
          <tr>
            <td style="font-family: var(--font-mono); font-weight: bold;">${sec.name}</td>
            <td style="font-family: var(--font-mono);">0x${sec.virtualAddress.toString(16).toUpperCase()}</td>
            <td>${formatSize(sec.virtualSize)}</td>
            <td style="font-family: var(--font-mono);">0x${sec.fileOffset.toString(16).toUpperCase()}</td>
            <td>${formatSize(sec.fileSize)}</td>
            <td style="font-family: var(--font-mono);">${entropyVal}</td>
            <td>${flagsStr}</td>
          </tr>
        `;
      }
      html += `
        <div class="report-section-card">
          <h3>📦 Sections (${data.sections.length})</h3>
          <div style="overflow-x: auto;">
            <table class="report-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Virtual Address</th>
                  <th>Virtual Size</th>
                  <th>File Offset</th>
                  <th>File Size</th>
                  <th>Entropy</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                ${secRows}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Card 3: Symbols
    if (data.symbols && data.symbols.length > 0) {
      const funcSyms = data.symbols.filter((s) => s.type === 'function');
      let symRows = '';
      const displayed = data.symbols.slice(0, 10);
      for (const sym of displayed) {
        const sizeStr = sym.size !== undefined ? sym.size.toString() : 'N/A';
        symRows += `
          <tr>
            <td style="font-family: var(--font-mono); font-weight: bold;">${sym.name}</td>
            <td style="font-family: var(--font-mono);">0x${sym.address.toString(16).toUpperCase()}</td>
            <td><span class="badge-tag">${sym.type}</span></td>
            <td><span class="badge-tag">${sym.binding}</span></td>
            <td>${sizeStr}</td>
          </tr>
        `;
      }
      html += `
        <div class="report-section-card">
          <h3>🏷️ Symbols</h3>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0 0 0.5rem 0;">
            Total Symbols: <strong>${data.symbols.length}</strong> (Functions: ${funcSyms.length}, Other: ${data.symbols.length - funcSyms.length})
          </p>
          <div style="overflow-x: auto;">
            <table class="report-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Address</th>
                  <th>Type</th>
                  <th>Binding</th>
                  <th>Size</th>
                </tr>
              </thead>
              <tbody>
                ${symRows}
                ${data.symbols.length > 10 ? `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">... and ${data.symbols.length - 10} more symbols ...</td></tr>` : ''}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Card 4: Signatures
    if (data.signatures && data.signatures.length > 0) {
      let sigRows = '';
      for (const sig of data.signatures) {
        const offsets = sig.matches
          .map((m) => `0x${m.offset.toString(16).toUpperCase()}`)
          .join(', ');
        sigRows += `
          <tr>
            <td style="font-weight: bold; color: var(--text-primary);">${sig.ruleName}</td>
            <td><span class="badge-tag">${sig.category}</span></td>
            <td style="font-family: var(--font-mono);">${offsets}</td>
          </tr>
        `;
      }
      html += `
        <div class="report-section-card">
          <h3>🛡️ Signature Scan Results (${data.signatures.length})</h3>
          <table class="report-table">
            <thead>
              <tr>
                <th>Rule Name</th>
                <th>Category</th>
                <th>Matched Offsets</th>
              </tr>
            </thead>
            <tbody>
              ${sigRows}
            </tbody>
          </table>
        </div>
      `;
    }

    // Card 5: High-Entropy Blocks
    if (
      data.entropy.highEntropyBlocks &&
      data.entropy.highEntropyBlocks.length > 0
    ) {
      let entropyRows = '';
      const highBlocks = data.entropy.highEntropyBlocks.filter(
        (b) => b.isHighEntropy
      );
      const displayedBlocks = highBlocks.slice(0, 10);
      for (const block of displayedBlocks) {
        entropyRows += `
          <tr>
            <td style="font-family: var(--font-mono);">0x${block.start.toString(16).toUpperCase()}</td>
            <td style="font-family: var(--font-mono);">0x${block.end.toString(16).toUpperCase()}</td>
            <td>${block.length} B</td>
            <td style="font-family: var(--font-mono); font-weight: bold; color: #f87171;">${block.entropy.toFixed(4)}</td>
          </tr>
        `;
      }
      html += `
        <div class="report-section-card">
          <h3>📈 High Entropy Blocks</h3>
          <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0 0 0.5rem 0;">
            Found ${highBlocks.length} block(s) with entropy >= 7.2. (Showing top 10)
          </p>
          <table class="report-table">
            <thead>
              <tr>
                <th>Start Offset</th>
                <th>End Offset</th>
                <th>Length</th>
                <th>Entropy</th>
              </tr>
            </thead>
            <tbody>
              ${entropyRows}
              ${highBlocks.length > 10 ? `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">... and ${highBlocks.length - 10} more blocks ...</td></tr>` : ''}
            </tbody>
          </table>
        </div>
      `;
    }

    // Card 6: Extracted Strings
    if (data.strings && data.strings.length > 0) {
      let stringRows = '';
      const displayedStrings = data.strings.slice(0, 15);
      for (const str of displayedStrings) {
        const tags =
          str.tags
            .map((t) => `<span class="badge-tag">${t}</span>`)
            .join(' ') || '-';
        const escaped = str.value
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;');
        stringRows += `
          <tr>
            <td style="font-family: var(--font-mono);">0x${str.offset.toString(16).toUpperCase()}</td>
            <td style="font-family: var(--font-mono);">0x${str.virtualAddress.toString(16).toUpperCase()}</td>
            <td><span class="badge-tag">${str.encoding}</span></td>
            <td>${tags}</td>
            <td style="font-family: var(--font-mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;" title="${escaped}">${escaped}</td>
          </tr>
        `;
      }
      html += `
        <div class="report-section-card">
          <h3>💬 Extracted Strings (Top 15 of ${data.strings.length})</h3>
          <table class="report-table">
            <thead>
              <tr>
                <th>Offset</th>
                <th>Address</th>
                <th>Encoding</th>
                <th>Tags</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              ${stringRows}
              ${data.strings.length > 15 ? `<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">... and ${data.strings.length - 15} more strings ...</td></tr>` : ''}
            </tbody>
          </table>
        </div>
      `;
    }

    this.previewContentEl.innerHTML = html;
  }

  private renderMarkdownPreview(data: ReportData) {
    const md = ReportGenerator.generateMarkdown(data);
    const renderedHtml = this.renderMarkdownToHTML(md);

    this.previewContentEl.innerHTML = `
      <div class="markdown-preview-container">
        <div class="markdown-preview-header">
          <span style="font-size: 0.9rem; color: var(--text-muted); font-weight: 500;">Markdown Rendered Preview</span>
          <button class="btn btn-secondary btn-sm-copy" style="padding: 0.25rem 0.75rem; font-size: 0.75rem;">📋 Copy Raw Markdown</button>
        </div>
        <div class="markdown-rendered-content">
          ${renderedHtml}
        </div>
      </div>
    `;

    const copyBtn = this.previewContentEl.querySelector('.btn-sm-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => this.handleCopy());
    }
  }

  private renderJsonPreview(data: ReportData) {
    const jsonStr = ReportGenerator.generateJSON(data);
    this.previewContentEl.innerHTML = `
      <div class="json-preview-container">
        <div class="json-preview-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <span style="font-size: 0.9rem; color: var(--text-muted); font-weight: 500;">JSON Output Data</span>
          <button class="btn btn-secondary btn-sm-json-copy" style="padding: 0.25rem 0.75rem; font-size: 0.75rem;">📋 Copy JSON</button>
        </div>
        <pre class="json-code-block"><code>${this.escapeHtml(jsonStr)}</code></pre>
      </div>
    `;

    const copyBtn = this.previewContentEl.querySelector('.btn-sm-json-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard
          .writeText(jsonStr)
          .then(() => {
            alert('JSON report copied to clipboard!');
          })
          .catch((err) => {
            console.error('Could not copy JSON: ', err);
          });
      });
    }
  }

  private renderMarkdownToHTML(markdown: string): string {
    let html = markdown;

    html = this.escapeHtml(html);

    // Headings
    html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
    html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
    html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');

    // Bold
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Tables
    const lines = html.split('\n');
    let inTable = false;
    let tableHtml = '';
    const outputLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('|')) {
        if (!inTable) {
          inTable = true;
          tableHtml = '<table class="markdown-table">';
        }

        const cells = line
          .split('|')
          .map((c) => c.trim())
          .filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
        const isSeparator = cells.every(
          (c) => /^:-*|-+:?|:-+:?$/.test(c) || c === '---' || c === ''
        );

        if (isSeparator) {
          continue;
        }

        const tag = tableHtml.includes('<thead>') ? 'td' : 'th';
        if (tag === 'th') {
          tableHtml += '<thead><tr>';
          cells.forEach((c) => {
            tableHtml += `<th>${c}</th>`;
          });
          tableHtml += '</tr></thead><tbody>';
        } else {
          tableHtml += '<tr>';
          cells.forEach((c) => {
            tableHtml += `<td>${c}</td>`;
          });
          tableHtml += '</tr>';
        }
      } else {
        if (inTable) {
          inTable = false;
          tableHtml += '</tbody></table>';
          outputLines.push(tableHtml);
          tableHtml = '';
        }
        outputLines.push(lines[i]);
      }
    }
    if (inTable) {
      tableHtml += '</tbody></table>';
      outputLines.push(tableHtml);
    }

    html = outputLines.join('\n');

    // Paragraphs & newlines
    html = html
      .split('\n\n')
      .map((p) => {
        p = p.trim();
        if (!p) return '';
        if (
          p.startsWith('<h') ||
          p.startsWith('<table') ||
          p.startsWith('<ul') ||
          p.startsWith('<li')
        ) {
          return p;
        }
        return `<p>${p.replace(/\n/g, '<br>')}</p>`;
      })
      .join('\n');

    return html;
  }

  private escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Public render method to re-initialize layout and preview.
   */
  public render() {
    this.initLayout();
    if (this.currentReportData) {
      this.renderPreview();
    }
  }

  /**
   * Public preview method to select a specific tab view.
   */
  public preview(type: 'interactive' | 'markdown' | 'json') {
    this.setActiveTab(type);
  }

  /**
   * Public method to download the Markdown report.
   */
  public downloadMarkdown() {
    this.handleExportMD();
  }

  /**
   * Public method to download the JSON report.
   */
  public downloadJSON() {
    this.handleExportJSON();
  }

  /**
   * Public method to copy report content to clipboard.
   */
  public copyToClipboard() {
    this.handleCopy();
  }

  private handleCopy() {
    if (!this.currentReportData) return;
    const md = ReportGenerator.generateMarkdown(this.currentReportData);
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard
        .writeText(md)
        .then(() => {
          if (typeof alert !== 'undefined') {
            alert('Markdown report copied to clipboard!');
          }
        })
        .catch((err) => {
          console.error('Could not copy text: ', err);
        });
    }
  }

  private handleExportMD() {
    if (!this.currentReportData) return;
    const md = ReportGenerator.generateMarkdown(this.currentReportData);
    this.downloadFile(
      md,
      `${this.currentReportData.fileName}_report.md`,
      'text/markdown'
    );
  }

  private handleExportJSON() {
    if (!this.currentReportData) return;
    const json = ReportGenerator.generateJSON(this.currentReportData);
    this.downloadFile(
      json,
      `${this.currentReportData.fileName}_report.json`,
      'application/json'
    );
  }

  private handlePrint() {
    if (!this.currentReportData) return;
    const md = ReportGenerator.generateMarkdown(this.currentReportData);

    if (typeof window === 'undefined' || !window.open) return;
    // Create print-friendly content window
    const printWindow = window.open('', '_blank');
    if (!printWindow) {
      if (typeof alert !== 'undefined') {
        alert('Popup blocker prevented opening the print view.');
      }
      return;
    }

    printWindow.document.write(`
      <html>
        <head>
          <title>Binary Analysis Report - ${this.currentReportData.fileName}</title>
          <style>
            body {
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
              color: #1a202c;
              line-height: 1.6;
              padding: 2rem;
              max-width: 800px;
              margin: 0 auto;
            }
            h1, h2, h3 {
              color: #2d3748;
              border-bottom: 1px solid #e2e8f0;
              padding-bottom: 0.5rem;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              margin: 1.5rem 0;
            }
            th, td {
              border: 1px solid #cbd5e0;
              padding: 0.5rem 0.75rem;
              text-align: left;
              font-size: 0.9rem;
            }
            th {
              background-color: #f7fafc;
            }
            code {
              font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
              background-color: #edf2f7;
              padding: 0.2rem 0.4rem;
              border-radius: 3px;
              font-size: 0.85em;
            }
            @media print {
              body {
                padding: 0;
              }
              button {
                display: none;
              }
            }
          </style>
        </head>
        <body>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
            <button onclick="window.print()" style="padding: 0.5rem 1rem; font-size: 1rem; cursor: pointer;">Print / Save as PDF</button>
          </div>
          <div>
            \${md.replace(/\\n/g, '<br>').replace(/\\|/g, ' ')} 
          </div>
          <script>
            // Convert markdown tables/sections to clean HTML for display
            // A simple renderer since we printed clean Markdown to raw text
            document.body.innerHTML = document.body.innerHTML
              .replace(/# (.*?)<br>/g, '<h1>$1</h1>')
              .replace(/## (.*?)<br>/g, '<h2>$1</h2>')
              .replace(/\`\`\`/g, '')
              .replace(/\`([\s\S]*?)\`/g, '<code>$1</code>');
          </script>
        </body>
      </html>
    `);
    printWindow.document.close();
  }

  private downloadFile(content: string, fileName: string, contentType: string) {
    if (typeof document === 'undefined') return;
    const a = document.createElement('a');
    const file = new Blob([content], { type: contentType });
    const url =
      typeof URL !== 'undefined' && URL.createObjectURL
        ? URL.createObjectURL(file)
        : '';
    if (url) {
      a.href = url;
      a.download = fileName;
      a.click();
      if (URL.revokeObjectURL) {
        URL.revokeObjectURL(url);
      }
    }
  }
}
