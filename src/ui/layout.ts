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
      <aside class="sidebar">
        <div class="sidebar-brand">
          🌌 Universal RE Tool
        </div>
        
        <!-- Dropzone -->
        <div class="file-upload-zone" id="file-dropzone">
          <input type="file" id="file-input" style="display: none;" />
          <button class="btn btn-primary" id="upload-btn" style="padding: 0.5rem 1rem; font-size: 0.85rem;">Upload Binary</button>
          <span style="font-size: 0.75rem; color: var(--text-muted); display: block; margin-top: 0.5rem; text-align: center;">Drag & drop or click</span>
        </div>

        <!-- Search Bar -->
        <input type="text" class="search-input" id="sidebar-search" placeholder="Search functions/symbols..." />

        <!-- Symbols / Sections List -->
        <div class="sidebar-list" id="sidebar-list"></div>
      </aside>

      <!-- Header -->
      <header class="header">
        <div class="metadata-container">
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
          <div class="tab-selector-container">
            <button class="tab-btn active" data-tab="hex">Hex Viewer</button>
            <button class="tab-btn" data-tab="assembly">Assembly</button>
            <button class="tab-btn" data-tab="cfg">CFG Graph</button>
            <button class="tab-btn" data-tab="decompiler">Decompile / AI</button>
            <button class="tab-btn" data-tab="strings">Strings</button>
            <button class="tab-btn" data-tab="search">Search Panel</button>
            <button class="tab-btn" data-tab="signatures">Signatures</button>
            <button class="tab-btn" data-tab="dependencies">Dependency Graph</button>
            <button class="tab-btn" data-tab="emulator">Emulator</button>
            <button class="tab-btn" data-tab="gdb">GDB Debugger</button>
            <button class="tab-btn" data-tab="report">Report</button>
            <button class="tab-btn" data-tab="xrefs">XRefs</button>
            <button class="tab-btn" data-tab="metadata">Metadata</button>
            <button class="tab-btn" data-tab="fcg">FCG Graph</button>
            <button class="tab-btn" data-tab="collab">Collab</button>
            <button class="tab-btn" data-tab="yara">YARA</button>
            <button class="tab-btn" data-tab="typeSystem">Type System</button>
            <button class="tab-btn" data-tab="demangler">Demangler</button>
            <button class="tab-btn" data-tab="diff">Diff Viewer</button>
            <button class="tab-btn" data-tab="plugins">Plugins</button>
            <button class="tab-btn" data-tab="machoObjc">Mach-O ObjC</button>
            <button class="tab-btn" data-tab="importsExports">Imports/Exports</button>
            <button class="tab-btn" data-tab="patcher">Patcher</button>
          </div>
          <button class="btn btn-secondary" id="open-mem-map-btn" style="padding: 0.5rem 1rem; font-size: 0.85rem; display: flex; align-items: center; gap: 0.35rem; border-radius: var(--radius-md);">
            🗺️ Memory Map
          </button>
        </div>
      </header>

      <!-- Main Workspace Contents -->
      <main class="main-content">
        <!-- Hex Viewer Tab Panel -->
        <div class="tab-content" id="panel-hex" style="display: block;">
          <div id="hex-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Assembly Viewer Tab Panel -->
        <div class="tab-content" id="panel-assembly" style="display: none;">
          <div id="assembly-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- CFG Viewer Tab Panel -->
        <div class="tab-content" id="panel-cfg" style="display: none;">
          <div id="cfg-viewer-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Decompile / AI Tab Panel -->
        <div class="tab-content" id="panel-decompiler" style="display: none;">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; height: 100%;">
            <div class="glass-panel" style="display: flex; flex-direction: column; height: 100%; padding: 1.5rem; box-sizing: border-box; overflow: hidden;">
              <h3 style="margin: 0 0 1rem 0; font-size: 1rem; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 0.5rem;">⚙️ Decompiled C-like Code</h3>
              <pre id="decompiler-viewer-container" style="flex: 1; font-family: var(--font-mono); font-size: 0.85rem; overflow: auto; white-space: pre-wrap; margin: 0; color: var(--text-secondary); line-height: 1.5; background: rgba(0, 0, 0, 0.2); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-color);"></pre>
            </div>
            <div id="ai-panel-container" style="height: 100%;"></div>
          </div>
        </div>

        <!-- Strings Viewer Tab Panel -->
        <div class="tab-content" id="panel-strings" style="display: none;">
          <div id="strings-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Search Panel Tab Panel -->
        <div class="tab-content" id="panel-search" style="display: none;">
          <div id="search-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Signatures Tab Panel -->
        <div class="tab-content" id="panel-signatures" style="display: none;">
          <div id="signatures-viewer-container" style="height: 100%;"></div>
        </div>

        <!-- Dependency Graph Tab Panel -->
        <div class="tab-content" id="panel-dependencies" style="display: none;">
          <div id="dependency-graph-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Emulator Tab Panel -->
        <div class="tab-content" id="panel-emulator" style="display: none;">
          <div id="emulator-panel-container" style="height: 100%;"></div>
        </div>

        <!-- GDB Tab Panel -->
        <div class="tab-content" id="panel-gdb" style="display: none;">
          <div id="gdb-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Report Tab Panel -->
        <div class="tab-content" id="panel-report" style="display: none;">
          <div id="report-panel-container" style="height: 100%;"></div>
        </div>

        <!-- XRefs Tab Panel -->
        <div class="tab-content" id="panel-xrefs" style="display: none;">
          <div id="xrefs-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Imports/Exports Tab Panel -->
        <div class="tab-content" id="panel-importsExports" style="display: none;">
          <div id="imports-exports-container" style="height: 100%;"></div>
        </div>

        <!-- Patcher Tab Panel -->
        <div class="tab-content" id="panel-patcher" style="display: none;">
          <div id="patcher-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Metadata Tab Panel -->
        <div class="tab-content" id="panel-metadata" style="display: none;">
          <div id="metadata-panel-container" style="height: 100%;"></div>
        </div>

        <!-- FCG Tab Panel -->
        <div class="tab-content" id="panel-fcg" style="display: none;">
          <div id="fcg-viewer-container" style="height: 100%; width: 100%;"></div>
        </div>

        <!-- Collab Tab Panel -->
        <div class="tab-content" id="panel-collab" style="display: none;">
          <div id="collab-panel-container" style="height: 100%;"></div>
        </div>

        <!-- YARA Tab Panel -->
        <div class="tab-content" id="panel-yara" style="display: none;">
          <div id="yara-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Type System Tab Panel -->
        <div class="tab-content" id="panel-typeSystem" style="display: none;">
          <div id="type-system-container" style="height: 100%;"></div>
        </div>

         <!-- Demangler Tab Panel -->
        <div class="tab-content" id="panel-demangler" style="display: none;">
          <div id="demangler-panel-container" style="height: 100%;"></div>
        </div>

         <!-- Diff Tab Panel -->
        <div class="tab-content" id="panel-diff" style="display: none;">
          <div id="diff-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Plugins Tab Panel -->
        <div class="tab-content" id="panel-plugins" style="display: none;">
          <div id="plugins-panel-container" style="height: 100%;"></div>
        </div>

        <!-- Mach-O ObjC Tab Panel -->
        <div class="tab-content" id="panel-machoObjc" style="display: none;">
          <div id="macho-objc-container" style="height: 100%;"></div>
        </div>
      </main>
    </div>
  `;
}
