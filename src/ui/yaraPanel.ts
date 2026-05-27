/**
 * Premium YARA Editor & Runner Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides real-time YARA scanning capabilities.
 */

import { Section } from '../disassembler/types.js';
import { YaraEngine, YaraScanResult, YaraRule, parseYaraRules } from '../analyzer/yara.js';

export interface YaraPanelOptions {
  onNavigate: (targetView: 'assembly' | 'hex' | 'decompiler', address: number) => void;
}

export class YaraPanel {
  private container: HTMLElement;
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private options: YaraPanelOptions;
  private yaraEngine: YaraEngine;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private editorEl!: HTMLTextAreaElement;
  private compileStatusEl!: HTMLDivElement;
  private resultsListEl!: HTMLDivElement;
  private runBtn!: HTMLButtonElement;
  private rulesCountEl!: HTMLSpanElement;

  private currentRulesSource: string = `rule Detect_MZ_Header {
    meta:
        description = "Detects DOS MZ executable header"
        author = "Antigravity Agent"
        category = "executable"
    strings:
        $mz = { 4d 5a }
    condition:
        $mz
}

rule Common_Strings {
    meta:
        description = "Detects common PE binary patterns and strings"
        author = "Antigravity Agent"
    strings:
        $pe_sig = "PE" ascii wide
        $libc = "libc" nocase
    condition:
        $pe_sig or $libc
}`;

  constructor(
    container: HTMLElement,
    options: YaraPanelOptions
  ) {
    this.container = container;
    this.options = options;
    this.yaraEngine = new YaraEngine();

    this.initLayout();
    this.setupEvents();
  }

  /**
   * Updates the YARA panel data
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[]
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    
    // Automatically trigger scan if we have rules compiled and binary loaded
    if (this.binaryData.length > 0) {
      this.runScan();
    }
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'yara-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Inject styles matching the rest of the app
    if (!document.getElementById('yara-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'yara-panel-styles';
      style.textContent = `
        .yara-panel-root {
          background: var(--bg-glass);
          backdrop-filter: blur(20px);
          -webkit-backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          box-shadow: var(--shadow-lg);
        }

        .yara-header-controls {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 1rem;
          background: var(--bg-glass);
          border: 1px solid var(--border-color);
          padding: 1.25rem;
          border-radius: var(--radius-md);
          flex-wrap: wrap;
        }

        .yara-title-area {
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
        }

        .yara-title {
          font-size: 1.15rem;
          font-weight: 700;
          color: var(--text-primary);
          display: flex;
          align-items: center;
          gap: 0.5rem;
        }

        .yara-subtitle {
          font-size: 0.8rem;
          color: var(--text-muted);
        }

        .yara-workspace {
          display: flex;
          flex: 1;
          gap: 1.5rem;
          min-height: 0;
        }

        .yara-editor-container {
          flex: 1;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-width: 320px;
        }

        .yara-editor-label {
          font-size: 0.85rem;
          font-weight: 600;
          color: var(--text-secondary);
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .yara-textarea {
          flex: 1;
          background: rgba(10, 12, 16, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          color: var(--text-secondary);
          font-family: var(--font-mono);
          font-size: 0.85rem;
          padding: 1rem;
          resize: none;
          outline: none;
          line-height: 1.5;
          transition: all var(--transition-fast);
        }

        .yara-textarea:focus {
          border-color: var(--accent-start);
          box-shadow: 0 0 10px rgba(99, 102, 241, 0.15);
        }

        .yara-compile-status {
          font-size: 0.8rem;
          padding: 0.5rem 0.75rem;
          border-radius: var(--radius-sm);
          font-family: var(--font-mono);
        }

        .yara-compile-status.success {
          background: var(--success-glow);
          color: var(--success);
          border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .yara-compile-status.error {
          background: rgba(239, 68, 68, 0.1);
          color: var(--error);
          border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .yara-results-container {
          flex: 1.2;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          min-width: 360px;
          min-height: 0;
        }

        .yara-results-label {
          font-size: 0.85rem;
          font-weight: 600;
          color: var(--text-secondary);
        }

        .yara-results-list {
          flex: 1;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
          gap: 1rem;
          padding-right: 6px;
        }

        .yara-card {
          background: var(--bg-glass);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          transition: all var(--transition-fast);
        }

        .yara-card:hover {
          background: var(--bg-glass-hover);
          border-color: var(--border-hover);
        }

        .yara-card-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .yara-card-title {
          font-weight: 700;
          font-size: 0.95rem;
          color: var(--accent-start);
        }

        .yara-card-badge {
          font-size: 0.7rem;
          text-transform: uppercase;
          font-weight: 700;
          padding: 2px 6px;
          border-radius: 4px;
        }

        .yara-card-badge.matched {
          background: var(--success-glow);
          color: var(--success);
          border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .yara-card-badge.no-match {
          background: rgba(255, 255, 255, 0.05);
          color: var(--text-muted);
          border: 1px solid var(--border-color);
        }

        .yara-meta-list {
          font-size: 0.8rem;
          color: var(--text-muted);
          display: flex;
          flex-direction: column;
          gap: 0.25rem;
          background: rgba(0, 0, 0, 0.15);
          padding: 0.5rem;
          border-radius: var(--radius-sm);
        }

        .yara-match-table {
          width: 100%;
          border-collapse: collapse;
          font-size: 0.8rem;
          margin-top: 0.5rem;
        }

        .yara-match-table th, .yara-match-table td {
          text-align: left;
          padding: 0.4rem;
          border-bottom: 1px solid var(--border-color);
        }

        .yara-match-table th {
          color: var(--text-muted);
          font-weight: 600;
        }

        .yara-match-id {
          font-family: var(--font-mono);
          color: var(--warning);
        }

        .yara-match-offset {
          font-family: var(--font-mono);
          color: var(--accent-start);
        }

        .yara-match-val {
          font-family: var(--font-mono);
          color: var(--text-secondary);
          word-break: break-all;
        }

        .yara-btn-group {
          display: flex;
          gap: 0.25rem;
        }

        .yara-action-btn {
          background: rgba(255, 255, 255, 0.03);
          border: 1px solid var(--border-color);
          color: var(--text-secondary);
          padding: 0.2rem 0.5rem;
          border-radius: var(--radius-sm);
          font-size: 0.7rem;
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .yara-action-btn:hover {
          background: rgba(99, 102, 241, 0.15);
          border-color: var(--accent-start);
          color: var(--text-primary);
        }
      `;
      document.head.appendChild(style);
    }

    // Header Controls
    const headerControls = document.createElement('div');
    headerControls.className = 'yara-header-controls';

    const titleArea = document.createElement('div');
    titleArea.className = 'yara-title-area';

    const title = document.createElement('div');
    title.className = 'yara-title';
    title.innerHTML = '🧪 Custom YARA Editor & Runner';

    const subtitle = document.createElement('div');
    subtitle.className = 'yara-subtitle';
    subtitle.innerHTML = 'Write custom YARA rules and scan the loaded binary instantly';

    titleArea.appendChild(title);
    titleArea.appendChild(subtitle);
    headerControls.appendChild(titleArea);

    this.runBtn = document.createElement('button');
    this.runBtn.className = 'btn btn-primary';
    this.runBtn.style.padding = '0.5rem 1.25rem';
    this.runBtn.style.borderRadius = 'var(--radius-md)';
    this.runBtn.innerHTML = '⚡ Run Scanner';
    headerControls.appendChild(this.runBtn);

    this.rootEl.appendChild(headerControls);

    // Workspace
    const workspace = document.createElement('div');
    workspace.className = 'yara-workspace';

    // Left side: Editor
    const editorContainer = document.createElement('div');
    editorContainer.className = 'yara-editor-container';

    const editorLabel = document.createElement('div');
    editorLabel.className = 'yara-editor-label';
    editorLabel.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      width: 100%;
    `;
    
    const labelTitle = document.createElement('span');
    labelTitle.textContent = 'YARA Rules Definition';
    editorLabel.appendChild(labelTitle);

    const editorBtnGroup = document.createElement('div');
    editorBtnGroup.className = 'yara-btn-group';

    const importBtn = document.createElement('button');
    importBtn.className = 'yara-action-btn';
    importBtn.id = 'yara-import-btn';
    importBtn.textContent = '📥 Import';
    importBtn.title = 'Import YARA rules from file';

    const exportBtn = document.createElement('button');
    exportBtn.className = 'yara-action-btn';
    exportBtn.id = 'yara-export-btn';
    exportBtn.textContent = '📤 Export';
    exportBtn.title = 'Export YARA rules to file';

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.id = 'yara-file-input';
    fileInput.accept = '.yar,.yara,.txt';
    fileInput.style.display = 'none';

    editorBtnGroup.appendChild(importBtn);
    editorBtnGroup.appendChild(exportBtn);
    editorBtnGroup.appendChild(fileInput);
    editorLabel.appendChild(editorBtnGroup);

    this.editorEl = document.createElement('textarea');
    this.editorEl.className = 'yara-textarea';
    this.editorEl.value = this.currentRulesSource;
    this.editorEl.placeholder = '// Write YARA rules here...\nrule RuleName {\n  strings:\n    $a = "test"\n  condition:\n    $a\n}';

    this.compileStatusEl = document.createElement('div');
    this.compileStatusEl.className = 'yara-compile-status success';
    this.compileStatusEl.textContent = 'Status: Ready';

    editorContainer.appendChild(editorLabel);
    editorContainer.appendChild(this.editorEl);
    editorContainer.appendChild(this.compileStatusEl);
    workspace.appendChild(editorContainer);

    // Right side: Results
    const resultsContainer = document.createElement('div');
    resultsContainer.className = 'yara-results-container';

    const resultsLabel = document.createElement('div');
    resultsLabel.className = 'yara-results-label';
    resultsLabel.textContent = 'Scan Results';

    this.resultsListEl = document.createElement('div');
    this.resultsListEl.className = 'yara-results-list';
    this.resultsListEl.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
        🔍 Enter YARA rules and click "Run Scanner" to see results.
      </div>
    `;

    resultsContainer.appendChild(resultsLabel);
    resultsContainer.appendChild(this.resultsListEl);
    workspace.appendChild(resultsContainer);

    this.rootEl.appendChild(workspace);
    this.container.appendChild(this.rootEl);
  }

  /**
   * Imports YARA rules source code, updates the editor UI, and runs validation.
   */
  public importRules(rules: string): void {
    this.currentRulesSource = rules;
    if (this.editorEl) {
      this.editorEl.value = rules;
    }
    this.runScan();
  }

  /**
   * Exports the current YARA rules source code.
   */
  public exportRules(): string {
    return this.currentRulesSource;
  }

  /**
   * Triggers a browser download of the current YARA rules.
   */
  public downloadRules(filename = 'rules.yar'): void {
    const rules = this.exportRules();
    const blob = new Blob([rules], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  private setupEvents() {
    this.runBtn.addEventListener('click', () => {
      this.runScan();
    });

    this.editorEl.addEventListener('input', () => {
      this.currentRulesSource = this.editorEl.value;
    });

    const importBtn = this.container.querySelector('#yara-import-btn');
    const exportBtn = this.container.querySelector('#yara-export-btn');
    const fileInput = this.container.querySelector('#yara-file-input') as HTMLInputElement | null;

    if (importBtn && fileInput) {
      importBtn.addEventListener('click', () => {
        fileInput.click();
      });

      fileInput.addEventListener('change', () => {
        const file = fileInput.files?.[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
          const content = event.target?.result as string;
          if (content !== undefined) {
            this.importRules(content);
          }
        };
        reader.readAsText(file);
        // Clear input value to allow importing the same file again
        fileInput.value = '';
      });
    }

    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        this.downloadRules();
      });
    }
  }

  private runScan() {
    this.yaraEngine.clear();
    const source = this.editorEl.value.trim();

    if (!source) {
      this.compileStatusEl.className = 'yara-compile-status error';
      this.compileStatusEl.textContent = 'Error: Editor is empty';
      return;
    }

    // Try parsing first to capture syntax errors cleanly
    try {
      this.yaraEngine.compile(source);
      this.compileStatusEl.className = 'yara-compile-status success';
      this.compileStatusEl.textContent = `Success: Compiled ${this.yaraEngine.getRules().length} rules`;
    } catch (err: any) {
      this.compileStatusEl.className = 'yara-compile-status error';
      this.compileStatusEl.textContent = `Compilation failed: ${err.message || err}`;
      return;
    }

    if (this.binaryData.length === 0) {
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          ⚠️ No binary file loaded. Load a file to run the compiled rules.
        </div>
      `;
      return;
    }

    try {
      const results = this.yaraEngine.scan(this.binaryData);
      this.renderResults(results);
    } catch (err: any) {
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: #f87171; margin-top: 4rem; font-size: 0.95rem;">
          Scan execution error: ${err.message || err}
        </div>
      `;
    }
  }

  private getAddressFromOffset(offset: number): number {
    const sec = this.sections.find(s => offset >= s.fileOffset && offset < s.fileOffset + s.fileSize);
    if (sec) {
      return sec.virtualAddress + (offset - sec.fileOffset);
    }
    const executeSection = this.sections.find(s => s.flags.execute);
    const textBaseAddress = executeSection ? executeSection.virtualAddress : 0x1000;
    return textBaseAddress + offset;
  }

  private renderResults(results: YaraScanResult[]) {
    this.resultsListEl.innerHTML = '';

    if (results.length === 0) {
      this.resultsListEl.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); margin-top: 4rem; font-size: 0.95rem;">
          No rules compiled to run.
        </div>
      `;
      return;
    }

    const compiledRules = this.yaraEngine.getRules();

    results.forEach(res => {
      const ruleDef = compiledRules.find(r => r.name === res.ruleName);

      const card = document.createElement('div');
      card.className = 'yara-card';

      const header = document.createElement('div');
      header.className = 'yara-card-header';

      const title = document.createElement('div');
      title.className = 'yara-card-title';
      title.textContent = `rule ${res.ruleName}`;

      const badge = document.createElement('span');
      badge.className = `yara-card-badge ${res.matched ? 'matched' : 'no-match'}`;
      badge.textContent = res.matched ? 'MATCHED' : 'NO MATCH';

      header.appendChild(title);
      header.appendChild(badge);
      card.appendChild(header);

      // Render Metadata if present
      if (ruleDef && ruleDef.meta && Object.keys(ruleDef.meta).length > 0) {
        const metaList = document.createElement('div');
        metaList.className = 'yara-meta-list';
        for (const [k, v] of Object.entries(ruleDef.meta)) {
          const metaItem = document.createElement('div');
          metaItem.innerHTML = `<strong style="color: var(--text-secondary);">${k}:</strong> ${v}`;
          metaList.appendChild(metaItem);
        }
        card.appendChild(metaList);
      }

      // Render Matches
      if (res.matched && res.matches.length > 0) {
        const table = document.createElement('table');
        table.className = 'yara-match-table';
        table.innerHTML = `
          <thead>
            <tr>
              <th style="width: 15%">String ID</th>
              <th style="width: 25%">Offset</th>
              <th style="width: 40%">Value</th>
              <th style="width: 20%">Action</th>
            </tr>
          </thead>
          <tbody></tbody>
        `;

        const tbody = table.querySelector('tbody')!;
        res.matches.forEach(match => {
          const virtualAddress = this.getAddressFromOffset(match.offset);
          
          const row = document.createElement('tr');
          
          const tdId = document.createElement('td');
          tdId.className = 'yara-match-id';
          tdId.textContent = match.stringId;
          
          const tdOffset = document.createElement('td');
          tdOffset.className = 'yara-match-offset';
          tdOffset.innerHTML = `0x${match.offset.toString(16).toUpperCase()}<br/><span style="color: var(--text-muted); font-size: 0.7rem;">VA: 0x${virtualAddress.toString(16).toUpperCase()}</span>`;
          
          const tdVal = document.createElement('td');
          tdVal.className = 'yara-match-val';
          tdVal.textContent = match.matchedValue;

          const tdActions = document.createElement('td');
          const btnGroup = document.createElement('div');
          btnGroup.className = 'yara-btn-group';

          const asmBtn = document.createElement('button');
          asmBtn.className = 'yara-action-btn';
          asmBtn.textContent = 'ASM';
          asmBtn.title = 'Navigate in Assembly View';
          asmBtn.addEventListener('click', () => this.options.onNavigate('assembly', virtualAddress));

          const hexBtn = document.createElement('button');
          hexBtn.className = 'yara-action-btn';
          hexBtn.textContent = 'HEX';
          hexBtn.title = 'Navigate in Hex Viewer';
          hexBtn.addEventListener('click', () => this.options.onNavigate('hex', virtualAddress));

          btnGroup.appendChild(asmBtn);
          btnGroup.appendChild(hexBtn);
          tdActions.appendChild(btnGroup);

          row.appendChild(tdId);
          row.appendChild(tdOffset);
          row.appendChild(tdVal);
          row.appendChild(tdActions);
          tbody.appendChild(row);
        });

        card.appendChild(table);
      } else if (res.matched) {
        const info = document.createElement('div');
        info.style.fontSize = '0.8rem';
        info.style.color = 'var(--text-muted)';
        info.style.fontStyle = 'italic';
        info.textContent = 'Rule matched but did not report any matching strings (condition-only match).';
        card.appendChild(info);
      }

      this.resultsListEl.appendChild(card);
    });
  }
}
