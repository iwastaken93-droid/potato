/**
 * Layout and style injection utilities for the Universal Reverse Engineering Tool (URET).
 */

export function injectStyles(): void {
  if (document.getElementById('coordinator-custom-styles')) return;
  const style = document.createElement('style');
  style.id = 'coordinator-custom-styles';
  style.textContent = `
    .search-input {
      width: 100%;
      padding: 0.75rem 1rem;
      background: rgba(15, 17, 21, 0.6);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 0.9rem;
      transition: all var(--transition-fast);
    }
    .search-input:focus {
      outline: none;
      border-color: var(--accent-start);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
    }
    .sidebar-list {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      overflow-y: auto;
      flex: 1;
      padding-right: 4px;
    }
    .sidebar-item {
      display: flex;
      flex-direction: column;
      padding: 0.75rem 1rem;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      cursor: pointer;
      transition: all var(--transition-fast);
    }
    .sidebar-item:hover {
      background: rgba(255, 255, 255, 0.06);
      border-color: var(--border-hover);
      transform: translateX(2px);
    }
    .sidebar-item.active {
      background: rgba(99, 102, 241, 0.1);
      border-color: var(--accent-start);
    }
    .sidebar-item-name {
      font-weight: 600;
      font-size: 0.85rem;
      color: var(--text-primary);
      word-break: break-all;
    }
    .sidebar-item-meta {
      font-size: 0.7rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      margin-top: 0.25rem;
    }
    .metadata-container {
      display: flex;
      gap: 1.5rem;
      align-items: center;
    }
    .metadata-item {
      display: flex;
      flex-direction: column;
    }
    .metadata-label {
      font-size: 0.7rem;
      text-transform: uppercase;
      color: var(--text-disabled);
      font-weight: 700;
      letter-spacing: 0.05em;
    }
    .metadata-value {
      font-size: 0.85rem;
      font-weight: 600;
      color: var(--text-secondary);
      max-width: 150px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .file-upload-zone {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
      border: 2px dashed var(--border-color);
      border-radius: var(--radius-md);
      background: rgba(22, 26, 33, 0.2);
      cursor: pointer;
      transition: all var(--transition-normal);
    }
    .file-upload-zone:hover, .file-upload-zone.dragover {
      border-color: var(--accent-start);
      background: rgba(99, 102, 241, 0.05);
    }
    .tab-content {
      width: 100%;
      height: calc(100vh - var(--header-height) - 4rem);
      position: relative;
    }
    .tab-selector-container {
      display: flex;
      gap: 0.5rem;
      background: var(--bg-tertiary);
      padding: 0.25rem;
      border-radius: var(--radius-md);
      border: 1px solid var(--border-color);
    }
    .tab-btn {
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
    .tab-btn:hover {
      color: var(--text-primary);
    }
    .tab-btn.active {
      background: var(--bg-secondary);
      color: var(--text-primary);
      box-shadow: var(--shadow-sm);
    }
    .sidebar-brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 700;
      font-size: 1.2rem;
      color: var(--text-primary);
      background: var(--gradient-accent);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
  `;
  document.head.appendChild(style);
}

export function createLayout(): void {
  const appEl = document.getElementById('app');
  if (!appEl) return;

  appEl.innerHTML = `
    <div class="app-container">
      <!-- Sidebar -->
      <aside class="sidebar" role="complementary" aria-label="Sidebar">
        <div class="sidebar-brand">
          🌌 Universal RE Tool
        </div>
        
        <!-- Dropzone -->
        <div class="file-upload-zone" id="file-dropzone" role="button" tabindex="0" aria-label="Upload Binary file">
          <input type="file" id="file-input" style="display: none;" aria-hidden="true" />
          <button class="btn btn-primary" id="upload-btn" tabindex="-1" style="padding: 0.5rem 1rem; font-size: 0.85rem;">Upload Binary</button>
          <span style="font-size: 0.75rem; color: var(--text-muted); display: block; margin-top: 0.5rem; text-align: center;">Drag & drop or click</span>
        </div>

        <!-- Search Bar -->
        <input type="text" class="search-input" id="sidebar-search" placeholder="Search functions/symbols..." aria-label="Search functions and symbols" />

        <!-- Symbols / Sections List -->
        <div class="sidebar-list" id="sidebar-list" role="listbox" aria-label="Symbols and Sections"></div>
      </aside>

      <!-- Header -->
      <header class="header" role="banner">
        <div class="metadata-container" role="region" aria-label="Binary Metadata">
          <div class="metadata-item">
            <span class="metadata-label">File</span>
            <span class="metadata-value" id="status-filename">No file loaded</span>
          </div>
          <div class="metadata-item">
            <span class="metadata-label">Format</span>
            <span class="metadata-value" id="status-filetype">-</span>
          </div>
          <div class="metadata-item">
            <span class="metadata-label">Entry Point</span>
            <span class="metadata-value" id="status-entryval">-</span>
          </div>
          <div class="metadata-item">
            <span class="metadata-label">Sections</span>
            <span class="metadata-value" id="status-sectionsval">-</span>
          </div>
        </div>

        <!-- Navigation Tab Selector -->
        <div style="display: flex; gap: 0.75rem; align-items: center;">
          <div class="tab-selector-container" role="tablist" aria-label="Navigation tabs">
            <button class="tab-btn active" data-tab="hex" role="tab" id="tab-hex" aria-selected="true" aria-controls="panel-hex" tabindex="0">Hex Viewer</button>
            <button class="tab-btn" data-tab="assembly" role="tab" id="tab-assembly" aria-selected="false" aria-controls="panel-assembly" tabindex="-1">Assembly</button>
            <button class="tab-btn" data-tab="cfg" role="tab" id="tab-cfg" aria-selected="false" aria-controls="panel-cfg" tabindex="-1">CFG Graph</button>
            <button class="tab-btn" data-tab="decompiler" role="tab" id="tab-decompiler" aria-selected="false" aria-controls="panel-decompiler" tabindex="-1">Decompile / AI</button>
            <button class="tab-btn" data-tab="strings" role="tab" id="tab-strings" aria-selected="false" aria-controls="panel-strings" tabindex="-1">Strings</button>
            <button class="tab-btn" data-tab="search" role="tab" id="tab-search" aria-selected="false" aria-controls="panel-search" tabindex="-1">Search Panel</button>
            <button class="tab-btn" data-tab="signatures" role="tab" id="tab-signatures" aria-selected="false" aria-controls="panel-signatures" tabindex="-1">Signatures</button>
            <button class="tab-btn" data-tab="dependencies" role="tab" id="tab-dependencies" aria-selected="false" aria-controls="panel-dependencies" tabindex="-1">Dependency Graph</button>
            <button class="tab-btn" data-tab="emulator" role="tab" id="tab-emulator" aria-selected="false" aria-controls="panel-emulator" tabindex="-1">Emulator</button>
            <button class="tab-btn" data-tab="gdb" role="tab" id="tab-gdb" aria-selected="false" aria-controls="panel-gdb" tabindex="-1">GDB Debugger</button>
            <button class="tab-btn" data-tab="report" role="tab" id="tab-report" aria-selected="false" aria-controls="panel-report" tabindex="-1">Report</button>
            <button class="tab-btn" data-tab="xrefs" role="tab" id="tab-xrefs" aria-selected="false" aria-controls="panel-xrefs" tabindex="-1">XRefs</button>
            <button class="tab-btn" data-tab="metadata" role="tab" id="tab-metadata" aria-selected="false" aria-controls="panel-metadata" tabindex="-1">Metadata</button>
            <button class="tab-btn" data-tab="fcg" role="tab" id="tab-fcg" aria-selected="false" aria-controls="panel-fcg" tabindex="-1">FCG Graph</button>
            <button class="tab-btn" data-tab="collab" role="tab" id="tab-collab" aria-selected="false" aria-controls="panel-collab" tabindex="-1">Collab</button>
            <button class="tab-btn" data-tab="yara" role="tab" id="tab-yara" aria-selected="false" aria-controls="panel-yara" tabindex="-1">YARA</button>
            <button class="tab-btn" data-tab="typeSystem" role="tab" id="tab-typeSystem" aria-selected="false" aria-controls="panel-typeSystem" tabindex="-1">Type System</button>
            <button class="tab-btn" data-tab="demangler" role="tab" id="tab-demangler" aria-selected="false" aria-controls="panel-demangler" tabindex="-1">Demangler</button>
            <button class="tab-btn" data-tab="diff" role="tab" id="tab-diff" aria-selected="false" aria-controls="panel-diff" tabindex="-1">Diff Viewer</button>
            <button class="tab-btn" data-tab="plugins" role="tab" id="tab-plugins" aria-selected="false" aria-controls="panel-plugins" tabindex="-1">Plugins</button>
            <button class="tab-btn" data-tab="machoObjc" role="tab" id="tab-machoObjc" aria-selected="false" aria-controls="panel-machoObjc" tabindex="-1">Mach-O ObjC</button>
            <button class="tab-btn" data-tab="importsExports" role="tab" id="tab-importsExports" aria-selected="false" aria-controls="panel-importsExports" tabindex="-1">Imports/Exports</button>
            <button class="tab-btn" data-tab="patcher" role="tab" id="tab-patcher" aria-selected="false" aria-controls="panel-patcher" tabindex="-1">Patcher</button>
          </div>
          <button class="btn btn-secondary" id="open-mem-map-btn" style="padding: 0.5rem 1rem; font-size: 0.85rem; display: flex; align-items: center; gap: 0.35rem; border-radius: var(--radius-md);">
            🗺️ Memory Map
          </button>
        </div>
      </header>

      <!-- Main Workspace Contents -->
      <main class="main-content" role="main">
        <!-- Hex Viewer Tab Panel -->
        <div class="tab-content" id="panel-hex" role="tabpanel" aria-labelledby="tab-hex" tabindex="0" style="display: block;">
          <div id="hex-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Assembly Viewer Tab Panel -->
        <div class="tab-content" id="panel-assembly" role="tabpanel" aria-labelledby="tab-assembly" tabindex="0" style="display: none;">
          <div id="assembly-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- CFG Viewer Tab Panel -->
        <div class="tab-content" id="panel-cfg" role="tabpanel" aria-labelledby="tab-cfg" tabindex="0" style="display: none;">
          <div id="cfg-viewer-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Decompile / AI Tab Panel -->
        <div class="tab-content" id="panel-decompiler" role="tabpanel" aria-labelledby="tab-decompiler" tabindex="0" style="display: none;">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; height: 100%;">
            <div class="glass-panel" style="display: flex; flex-direction: column; height: 100%; padding: 1.5rem; box-sizing: border-box; overflow: hidden;">
              <h3 style="margin: 0 0 1rem 0; font-size: 1rem; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 0.5rem;">⚙️ Decompiled C-like Code</h3>
              <pre id="decompiler-viewer-container" style="flex: 1; font-family: var(--font-mono); font-size: 0.85rem; overflow: auto; white-space: pre-wrap; margin: 0; color: var(--text-secondary); line-height: 1.5; background: rgba(0, 0, 0, 0.2); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-color);"></pre>
            </div>
            <div id="ai-panel-container" style="height: 100%;"></div>
          </div>
        </div>

        <!-- Strings Viewer Tab Panel -->
        <div class="tab-content" id="panel-strings" role="tabpanel" aria-labelledby="tab-strings" tabindex="0" style="display: none;">
          <div id="strings-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Search Panel Tab Panel -->
        <div class="tab-content" id="panel-search" role="tabpanel" aria-labelledby="tab-search" tabindex="0" style="display: none;">
          <div id="search-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Signatures Tab Panel -->
        <div class="tab-content" id="panel-signatures" role="tabpanel" aria-labelledby="tab-signatures" tabindex="0" style="display: none;">
          <div id="signatures-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Dependency Graph Tab Panel -->
        <div class="tab-content" id="panel-dependencies" role="tabpanel" aria-labelledby="tab-dependencies" tabindex="0" style="display: none;">
          <div id="dependency-graph-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Emulator Tab Panel -->
        <div class="tab-content" id="panel-emulator" role="tabpanel" aria-labelledby="tab-emulator" tabindex="0" style="display: none;">
          <div id="emulator-panel-container" style="height: 100%;"></div>
        </div>

        <!-- GDB Tab Panel -->
        <div class="tab-content" id="panel-gdb" role="tabpanel" aria-labelledby="tab-gdb" tabindex="0" style="display: none;">
          <div id="gdb-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Report Tab Panel -->
        <div class="tab-content" id="panel-report" role="tabpanel" aria-labelledby="tab-report" tabindex="0" style="display: none;">
          <div id="report-panel-container" style="height: 100%;"></div>
        </div>

        <!-- XRefs Tab Panel -->
        <div class="tab-content" id="panel-xrefs" role="tabpanel" aria-labelledby="tab-xrefs" tabindex="0" style="display: none;">
          <div id="xrefs-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Imports/Exports Tab Panel -->
        <div class="tab-content" id="panel-importsExports" role="tabpanel" aria-labelledby="tab-importsExports" tabindex="0" style="display: none;">
          <div id="imports-exports-container" style="height: 100%;"></div>
        </div>

        <!-- Patcher Tab Panel -->
        <div class="tab-content" id="panel-patcher" role="tabpanel" aria-labelledby="tab-patcher" tabindex="0" style="display: none;">
          <div id="patcher-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Metadata Tab Panel -->
        <div class="tab-content" id="panel-metadata" role="tabpanel" aria-labelledby="tab-metadata" tabindex="0" style="display: none;">
          <div id="metadata-panel-container" style="height: 100%;"></div>
        </div>

        <!-- FCG Tab Panel -->
        <div class="tab-content" id="panel-fcg" role="tabpanel" aria-labelledby="tab-fcg" tabindex="0" style="display: none;">
          <div id="fcg-viewer-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Collab Tab Panel -->
        <div class="tab-content" id="panel-collab" role="tabpanel" aria-labelledby="tab-collab" tabindex="0" style="display: none;">
          <div id="collab-panel-container" style="height: 100%;"></div>
        </div>

        <!-- YARA Tab Panel -->
        <div class="tab-content" id="panel-yara" role="tabpanel" aria-labelledby="tab-yara" tabindex="0" style="display: none;">
          <div id="yara-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Type System Tab Panel -->
        <div class="tab-content" id="panel-typeSystem" role="tabpanel" aria-labelledby="tab-typeSystem" tabindex="0" style="display: none;">
          <div id="type-system-container" style="height: 100%;"></div>
        </div>

         <!-- Demangler Tab Panel -->
        <div class="tab-content" id="panel-demangler" role="tabpanel" aria-labelledby="tab-demangler" tabindex="0" style="display: none;">
          <div id="demangler-panel-container" style="height: 100%;"></div>
        </div>

         <!-- Diff Tab Panel -->
        <div class="tab-content" id="panel-diff" role="tabpanel" aria-labelledby="tab-diff" tabindex="0" style="display: none;">
          <div id="diff-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Plugins Tab Panel -->
        <div class="tab-content" id="panel-plugins" role="tabpanel" aria-labelledby="tab-plugins" tabindex="0" style="display: none;">
          <div id="plugins-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Mach-O ObjC Tab Panel -->
        <div class="tab-content" id="panel-machoObjc" role="tabpanel" aria-labelledby="tab-machoObjc" tabindex="0" style="display: none;">
          <div id="macho-objc-container" style="height: 100%;"></div>
        </div>
      </main>
    </div>
  `;

  // Keyboard accessibility for file dropzone
  const dropzone = document.getElementById('file-dropzone');
  if (dropzone) {
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const fileInput = document.getElementById('file-input') as HTMLInputElement;
        if (fileInput) {
          fileInput.click();
        }
      }
    });
  }

  // Keyboard navigation & programmatic ARIA state synchronization for tabs
  const tabSelector = appEl.querySelector('.tab-selector-container');
  if (tabSelector) {
    const getTabs = () => Array.from(tabSelector.querySelectorAll('.tab-btn')) as HTMLButtonElement[];

    const updateTabAttrs = (activeBtn: HTMLButtonElement) => {
      getTabs().forEach((btn) => {
        const isSelected = btn === activeBtn;
        btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
        btn.setAttribute('tabindex', isSelected ? '0' : '-1');
      });
    };

    tabSelector.addEventListener('click', (e) => {
      const btn = (e.target as HTMLElement).closest('.tab-btn') as HTMLButtonElement;
      if (btn) {
        updateTabAttrs(btn);
      }
    });

    tabSelector.addEventListener('keydown', (e: any) => {
      const activeElement = document.activeElement as HTMLButtonElement;
      if (!activeElement || !activeElement.classList.contains('tab-btn')) return;

      const tabs = getTabs();
      const index = tabs.indexOf(activeElement);
      if (index === -1) return;

      let nextIndex = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        nextIndex = (index + 1) % tabs.length;
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        nextIndex = (index - 1 + tabs.length) % tabs.length;
      } else if (e.key === 'Home') {
        nextIndex = 0;
      } else if (e.key === 'End') {
        nextIndex = tabs.length - 1;
      }

      if (nextIndex !== -1) {
        e.preventDefault();
        const targetBtn = tabs[nextIndex];
        targetBtn.focus();
        targetBtn.click();
        updateTabAttrs(targetBtn);
      }
    });

    // Observer to watch TabManager changes on active class
    const observer = new MutationObserver(() => {
      const activeBtn = tabSelector.querySelector('.tab-btn.active') as HTMLButtonElement;
      if (activeBtn) {
        updateTabAttrs(activeBtn);
      }
    });
    observer.observe(tabSelector, { subtree: true, attributes: true, attributeFilter: ['class'] });
  }
}
