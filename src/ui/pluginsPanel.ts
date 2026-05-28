/**
 * Premium Plugins Management & Configuration Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides plugin discovery, config UI, and lifecycle hook results.
 */

import { Section, Symbol, Instruction } from '../disassembler/types.js';
import { PluginManager, AnalyzerPlugin, AnalyzerContext, AnalyzerResult, AnalysisFinding } from '../analyzer/plugins.js';

export interface PluginsPanelOptions {
  onNavigate?: (targetView: 'assembly' | 'hex' | 'decompiler', address: number) => void;
}

export class PluginsPanel {
  private container: HTMLElement;
  private binaryData: Uint8Array = new Uint8Array(0);
  private sections: Section[] = [];
  private symbols: Symbol[] = [];
  private instructions: Instruction[] = [];
  private options: PluginsPanelOptions;
  private manager: PluginManager;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private activeTab: 'manage' | 'findings' = 'manage';
  private runAllBtn!: HTMLButtonElement;
  private findingsListEl!: HTMLDivElement;
  private activePluginsListEl!: HTMLDivElement;
  private discoverPluginsListEl!: HTMLDivElement;
  private statusMessageEl!: HTMLDivElement;

  private lastResults: AnalyzerResult[] = [];

  constructor(container: HTMLElement, options: PluginsPanelOptions = {}) {
    this.container = container;
    this.options = options;
    this.manager = PluginManager.getInstance();

    this.initLayout();
    this.setupEvents();
    this.render();
  }

  /**
   * Updates the data context for plugins execution.
   */
  public updateData(
    binaryData: Uint8Array,
    sections: Section[],
    symbols: Symbol[],
    instructions: Instruction[]
  ) {
    this.binaryData = binaryData;
    this.sections = sections;
    this.symbols = symbols;
    this.instructions = instructions;

    if (this.binaryData.length > 0) {
      this.runAllBtn.disabled = false;
    } else {
      this.runAllBtn.disabled = true;
    }
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'plugins-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
      overflow: hidden;
    `;

    // Inject styles matching the premium dark theme
    if (!document.getElementById('plugins-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'plugins-panel-styles';
      style.textContent = `
        .plugins-panel-root {
          background: var(--bg-glass);
          backdrop-filter: blur(20px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-lg);
          color: var(--text-primary);
        }
        .plugin-card {
          background: rgba(30, 41, 59, 0.4);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: var(--radius-md);
          padding: 1rem;
          margin-bottom: 0.75rem;
          transition: all 0.2s ease-in-out;
        }
        .plugin-card:hover {
          border-color: var(--primary-color);
          box-shadow: 0 4px 20px rgba(99, 102, 241, 0.15);
          background: rgba(30, 41, 59, 0.6);
        }
        .plugin-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 0.5rem;
        }
        .plugin-title {
          font-weight: 600;
          font-size: 1rem;
          color: var(--text-primary);
        }
        .plugin-meta {
          font-size: 0.75rem;
          color: var(--text-muted);
        }
        .plugin-desc {
          font-size: 0.85rem;
          color: var(--text-secondary);
          margin-bottom: 0.75rem;
          line-height: 1.4;
        }
        .plugin-config-section {
          background: rgba(0, 0, 0, 0.2);
          border-radius: var(--radius-sm);
          padding: 0.75rem;
          margin-top: 0.5rem;
          border-left: 2px solid var(--primary-color);
        }
        .plugin-config-title {
          font-size: 0.8rem;
          font-weight: 700;
          color: var(--text-primary);
          margin-bottom: 0.5rem;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .config-field {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 0.5rem;
          font-size: 0.8rem;
        }
        .config-field:last-child {
          margin-bottom: 0;
        }
        .config-label-container {
          display: flex;
          flex-direction: column;
          max-width: 70%;
        }
        .config-field-label {
          color: var(--text-primary);
          font-weight: 500;
        }
        .config-field-desc {
          color: var(--text-muted);
          font-size: 0.7rem;
        }
        .config-input {
          background: rgba(15, 23, 42, 0.6);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          color: var(--text-primary);
          padding: 0.25rem 0.5rem;
          font-family: var(--font-mono);
          outline: none;
        }
        .config-input:focus {
          border-color: var(--primary-color);
        }
        .finding-row {
          background: rgba(220, 38, 38, 0.05);
          border: 1px solid rgba(220, 38, 38, 0.15);
          border-radius: var(--radius-md);
          padding: 0.75rem 1rem;
          margin-bottom: 0.5rem;
          transition: transform 0.1s ease;
        }
        .finding-row:hover {
          transform: translateX(3px);
        }
        .finding-row.severity-critical {
          background: rgba(220, 38, 38, 0.1);
          border-color: rgba(220, 38, 38, 0.3);
        }
        .finding-row.severity-high {
          background: rgba(249, 115, 22, 0.1);
          border-color: rgba(249, 115, 22, 0.3);
        }
        .finding-row.severity-medium {
          background: rgba(234, 179, 8, 0.08);
          border-color: rgba(234, 179, 8, 0.25);
        }
        .finding-row.severity-low {
          background: rgba(59, 130, 246, 0.08);
          border-color: rgba(59, 130, 246, 0.25);
        }
        .finding-row.severity-info {
          background: rgba(16, 185, 129, 0.08);
          border-color: rgba(16, 185, 129, 0.25);
        }
        .finding-badge {
          font-size: 0.7rem;
          font-weight: 700;
          text-transform: uppercase;
          padding: 0.15rem 0.4rem;
          border-radius: 4px;
          display: inline-block;
          margin-right: 0.5rem;
        }
        .badge-critical { background: #dc2626; color: #fff; }
        .badge-high { background: #ea580c; color: #fff; }
        .badge-medium { background: #ca8a04; color: #fff; }
        .badge-low { background: #2563eb; color: #fff; }
        .badge-info { background: #059669; color: #fff; }
      `;
      document.head.appendChild(style);
    }

    // Header Area
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1rem;
    `;

    const titleContainer = document.createElement('div');
    titleContainer.innerHTML = `
      <h2 style="margin: 0; font-size: 1.25rem; font-weight: 700; background: linear-gradient(135deg, #6366F1, #8B5CF6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">🔌 Extended Plugin Architecture</h2>
      <p style="margin: 0.25rem 0 0 0; font-size: 0.8rem; color: var(--text-muted);">Manage custom analyzers, dynamically discover new plugins, configure thresholds, and run lifecycles.</p>
    `;
    header.appendChild(titleContainer);

    const actionContainer = document.createElement('div');
    actionContainer.style.cssText = `
      display: flex;
      gap: 0.75rem;
    `;

    this.runAllBtn = document.createElement('button');
    this.runAllBtn.className = 'btn btn-primary';
    this.runAllBtn.innerHTML = '⚡ Run All Enabled Plugins';
    this.runAllBtn.disabled = this.binaryData.length === 0;
    actionContainer.appendChild(this.runAllBtn);

    header.appendChild(actionContainer);
    this.rootEl.appendChild(header);

    // Navigation Tabs for Panel
    const tabNav = document.createElement('div');
    tabNav.style.cssText = `
      display: flex;
      gap: 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      padding-bottom: 0.5rem;
    `;

    const createTabBtn = (tabName: 'manage' | 'findings', label: string) => {
      const btn = document.createElement('button');
      btn.style.cssText = `
        background: none;
        border: none;
        color: var(--text-secondary);
        font-weight: 600;
        font-size: 0.85rem;
        cursor: pointer;
        padding: 0.5rem 0;
        border-bottom: 2px solid transparent;
        transition: all 0.2s ease;
      `;
      if (tabName === this.activeTab) {
        btn.style.borderBottomColor = 'var(--primary-color)';
        btn.style.color = 'var(--text-primary)';
      }
      btn.textContent = label;
      btn.addEventListener('click', () => {
        this.activeTab = tabName;
        Array.from(tabNav.children).forEach((child: any) => {
          child.style.borderBottomColor = 'transparent';
          child.style.color = 'var(--text-secondary)';
        });
        btn.style.borderBottomColor = 'var(--primary-color)';
        btn.style.color = 'var(--text-primary)';
        this.renderTabContent();
      });
      return btn;
    };

    tabNav.appendChild(createTabBtn('manage', '🔌 Plugin Manager & Config'));
    tabNav.appendChild(createTabBtn('findings', '🔎 Analysis Findings'));
    this.rootEl.appendChild(tabNav);

    // Status Message / Notification bar
    this.statusMessageEl = document.createElement('div');
    this.statusMessageEl.style.cssText = `
      padding: 0.75rem 1rem;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.2);
      border-radius: var(--radius-md);
      font-size: 0.85rem;
      display: none;
    `;
    this.rootEl.appendChild(this.statusMessageEl);

    // Main workspace content layout
    const contentArea = document.createElement('div');
    contentArea.style.cssText = `
      flex: 1;
      display: flex;
      gap: 1.5rem;
      overflow: hidden;
      min-height: 0;
    `;

    // Manage tab contents
    this.activePluginsListEl = document.createElement('div');
    this.activePluginsListEl.style.cssText = `
      flex: 1;
      overflow-y: auto;
      padding-right: 0.5rem;
    `;

    this.discoverPluginsListEl = document.createElement('div');
    this.discoverPluginsListEl.style.cssText = `
      width: 320px;
      border-left: 1px solid var(--border-color);
      padding-left: 1.5rem;
      overflow-y: auto;
    `;

    // Findings tab contents
    this.findingsListEl = document.createElement('div');
    this.findingsListEl.style.cssText = `
      flex: 1;
      overflow-y: auto;
      display: none;
    `;

    contentArea.appendChild(this.activePluginsListEl);
    contentArea.appendChild(this.discoverPluginsListEl);
    contentArea.appendChild(this.findingsListEl);

    this.rootEl.appendChild(contentArea);
    this.container.appendChild(this.rootEl);
  }

  private showStatus(msg: string, type: 'info' | 'success' | 'error' = 'info') {
    this.statusMessageEl.style.display = 'block';
    this.statusMessageEl.textContent = msg;
    if (type === 'success') {
      this.statusMessageEl.style.background = 'rgba(16, 185, 129, 0.1)';
      this.statusMessageEl.style.borderColor = 'rgba(16, 185, 129, 0.2)';
      this.statusMessageEl.style.color = '#34d399';
    } else if (type === 'error') {
      this.statusMessageEl.style.background = 'rgba(239, 68, 68, 0.1)';
      this.statusMessageEl.style.borderColor = 'rgba(239, 68, 68, 0.2)';
      this.statusMessageEl.style.color = '#f87171';
    } else {
      this.statusMessageEl.style.background = 'rgba(99, 102, 241, 0.1)';
      this.statusMessageEl.style.borderColor = 'rgba(99, 102, 241, 0.2)';
      this.statusMessageEl.style.color = '#c7d2fe';
    }
  }

  private setupEvents() {
    this.runAllBtn.addEventListener('click', async () => {
      if (this.binaryData.length === 0) return;
      this.showStatus('Running all enabled plugins...', 'info');
      try {
        const context: AnalyzerContext = {
          binaryData: this.binaryData,
          sections: this.sections,
          symbols: this.symbols,
          instructions: this.instructions
        };

        this.lastResults = await this.manager.runAll(context);
        this.showStatus(`Completed analysis with ${this.lastResults.length} plugins. Check the Findings tab!`, 'success');
        this.renderFindings();
      } catch (err: any) {
        this.showStatus(`Analysis failed: ${err?.message || err}`, 'error');
      }
    });
  }

  private renderTabContent() {
    if (this.activeTab === 'manage') {
      this.activePluginsListEl.style.display = 'block';
      this.discoverPluginsListEl.style.display = 'block';
      this.findingsListEl.style.display = 'none';
      this.renderManagement();
    } else {
      this.activePluginsListEl.style.display = 'none';
      this.discoverPluginsListEl.style.display = 'none';
      this.findingsListEl.style.display = 'block';
      this.renderFindings();
    }
  }

  private render() {
    this.renderTabContent();
  }

  private renderManagement() {
    this.activePluginsListEl.innerHTML = `
      <h3 style="margin: 0 0 1rem 0; font-size: 1rem; font-weight: 700; color: var(--text-primary);">Installed / Registered Plugins</h3>
    `;

    const activePlugins = this.manager.getPlugins();

    if (activePlugins.length === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.style.cssText = 'color: var(--text-muted); font-size: 0.85rem; font-style: italic; margin-top: 1rem;';
      emptyMsg.textContent = 'No plugins currently installed. Install from the discoverable list on the right!';
      this.activePluginsListEl.appendChild(emptyMsg);
    } else {
      activePlugins.forEach(plugin => {
        const card = document.createElement('div');
        card.className = 'plugin-card';

        const header = document.createElement('div');
        header.className = 'plugin-header';

        const titleDiv = document.createElement('div');
        titleDiv.innerHTML = `
          <span class="plugin-title">${plugin.metadata.name}</span>
          <span class="plugin-meta">v${plugin.metadata.version} by ${plugin.metadata.author}</span>
        `;

        const toggleContainer = document.createElement('div');
        toggleContainer.style.cssText = 'display: flex; gap: 0.5rem; align-items: center;';

        const statusLabel = document.createElement('span');
        statusLabel.style.cssText = 'font-size: 0.75rem; font-weight: bold;';
        statusLabel.textContent = plugin.enabled ? 'ACTIVE' : 'DISABLED';
        statusLabel.style.color = plugin.enabled ? '#10b981' : '#64748b';

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = plugin.enabled ?? true;
        checkbox.style.cursor = 'pointer';
        checkbox.addEventListener('change', async () => {
          await this.manager.togglePlugin(plugin.metadata.id, checkbox.checked);
          statusLabel.textContent = checkbox.checked ? 'ACTIVE' : 'DISABLED';
          statusLabel.style.color = checkbox.checked ? '#10b981' : '#64748b';
          this.showStatus(`Plugin "${plugin.metadata.name}" ${checkbox.checked ? 'enabled' : 'disabled'}.`, 'info');
        });

        const uninstallBtn = document.createElement('button');
        uninstallBtn.className = 'btn btn-secondary';
        uninstallBtn.style.padding = '0.2rem 0.5rem';
        uninstallBtn.style.fontSize = '0.75rem';
        uninstallBtn.textContent = 'Uninstall';
        uninstallBtn.addEventListener('click', async () => {
          await this.manager.uninstallPlugin(plugin.metadata.id);
          this.showStatus(`Plugin "${plugin.metadata.name}" uninstalled.`, 'success');
          this.renderManagement();
        });

        toggleContainer.appendChild(statusLabel);
        toggleContainer.appendChild(checkbox);
        toggleContainer.appendChild(uninstallBtn);

        header.appendChild(titleDiv);
        header.appendChild(toggleContainer);
        card.appendChild(header);

        const desc = document.createElement('div');
        desc.className = 'plugin-desc';
        desc.textContent = plugin.metadata.description;
        card.appendChild(desc);

        // Render configuration fields if schema exists
        if (plugin.configSchema) {
          const configSec = document.createElement('div');
          configSec.className = 'plugin-config-section';
          configSec.innerHTML = `<div class="plugin-config-title">Settings & Thresholds</div>`;

          Object.keys(plugin.configSchema).forEach(key => {
            const schema = plugin.configSchema![key];
            const currentValue = plugin.config?.[key] ?? schema.default;

            const field = document.createElement('div');
            field.className = 'config-field';

            const labelContainer = document.createElement('div');
            labelContainer.className = 'label-container';
            labelContainer.innerHTML = `
              <span class="config-field-label">${schema.label}</span>
              <span class="config-field-desc">${schema.description}</span>
            `;
            field.appendChild(labelContainer);

            if (schema.type === 'boolean') {
              const input = document.createElement('input');
              input.type = 'checkbox';
              input.checked = !!currentValue;
              input.addEventListener('change', () => {
                this.manager.setPluginConfig(plugin.metadata.id, { [key]: input.checked });
              });
              field.appendChild(input);
            } else if (schema.type === 'number') {
              const input = document.createElement('input');
              input.className = 'config-input';
              input.type = 'number';
              input.step = 'any';
              input.value = String(currentValue);
              input.style.width = '60px';
              input.addEventListener('input', () => {
                const val = parseFloat(input.value);
                if (!isNaN(val)) {
                  this.manager.setPluginConfig(plugin.metadata.id, { [key]: val });
                }
              });
              field.appendChild(input);
            } else if (schema.type === 'string' && schema.options) {
              const select = document.createElement('select');
              select.className = 'config-input';
              schema.options.forEach(opt => {
                const option = document.createElement('option');
                option.value = opt;
                option.textContent = opt;
                if (opt === currentValue) option.selected = true;
                select.appendChild(option);
              });
              select.addEventListener('change', () => {
                this.manager.setPluginConfig(plugin.metadata.id, { [key]: select.value });
              });
              field.appendChild(select);
            } else {
              const input = document.createElement('input');
              input.className = 'config-input';
              input.type = 'text';
              input.value = String(currentValue);
              input.addEventListener('input', () => {
                this.manager.setPluginConfig(plugin.metadata.id, { [key]: input.value });
              });
              field.appendChild(input);
            }

            configSec.appendChild(field);
          });

          card.appendChild(configSec);
        }

        this.activePluginsListEl.appendChild(card);
      });
    }

    // Render discoverable/installable plugins
    this.discoverPluginsListEl.innerHTML = `
      <h3 style="margin: 0 0 1rem 0; font-size: 1rem; font-weight: 700; color: var(--text-primary);">Discover Plugins</h3>
    `;

    const discoverable = this.manager.getDiscoverablePlugins();
    const installedIds = activePlugins.map(p => p.metadata.id);
    const uninstalled = discoverable.filter(p => !installedIds.includes(p.metadata.id));

    if (uninstalled.length === 0) {
      const emptyMsg = document.createElement('div');
      emptyMsg.style.cssText = 'color: var(--text-muted); font-size: 0.8rem; font-style: italic; margin-top: 1rem;';
      emptyMsg.textContent = 'All available plugins are installed.';
      this.discoverPluginsListEl.appendChild(emptyMsg);
    } else {
      uninstalled.forEach(plugin => {
        const item = document.createElement('div');
        item.style.cssText = `
          padding: 0.75rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          margin-bottom: 0.75rem;
        `;

        item.innerHTML = `
          <div style="font-weight: 600; font-size: 0.85rem; color: var(--text-primary); display: flex; justify-content: space-between; align-items: center;">
            <span>${plugin.metadata.name}</span>
            <span style="font-size: 0.7rem; color: var(--text-muted);">v${plugin.metadata.version}</span>
          </div>
          <div style="font-size: 0.75rem; color: var(--text-secondary); margin: 0.35rem 0 0.5rem 0; line-height: 1.3;">
            ${plugin.metadata.description}
          </div>
        `;

        const installBtn = document.createElement('button');
        installBtn.className = 'btn btn-primary';
        installBtn.style.width = '100%';
        installBtn.style.padding = '0.35rem';
        installBtn.style.fontSize = '0.75rem';
        installBtn.textContent = 'Install & Enable';
        installBtn.addEventListener('click', async () => {
          await this.manager.installPlugin(plugin.metadata.id);
          this.showStatus(`Installed and initialized "${plugin.metadata.name}"!`, 'success');
          this.renderManagement();
        });

        item.appendChild(installBtn);
        this.discoverPluginsListEl.appendChild(item);
      });
    }
  }

  private renderFindings() {
    this.findingsListEl.innerHTML = `
      <h3 style="margin: 0 0 1rem 0; font-size: 1rem; font-weight: 700; color: var(--text-primary);">Findings & Analytical Insights</h3>
    `;

    if (this.lastResults.length === 0) {
      const msg = document.createElement('div');
      msg.style.cssText = 'color: var(--text-muted); font-size: 0.85rem; font-style: italic; margin-top: 1rem; text-align: center;';
      msg.textContent = 'No findings to display. Load a binary and click "Run All Enabled Plugins".';
      this.findingsListEl.appendChild(msg);
      return;
    }

    let totalFindingsCount = 0;

    this.lastResults.forEach(res => {
      const plugin = this.manager.getPlugin(res.pluginId);
      const pluginName = plugin ? plugin.metadata.name : res.pluginId;

      const header = document.createElement('div');
      header.style.cssText = `
        margin-top: 1.25rem;
        margin-bottom: 0.5rem;
        font-weight: bold;
        font-size: 0.9rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        padding-bottom: 0.25rem;
        color: var(--primary-color);
        display: flex;
        justify-content: space-between;
        align-items: center;
      `;

      header.innerHTML = `
        <span>${pluginName} (${res.findings.length} findings)</span>
        <span style="font-size: 0.75rem; font-weight: normal; color: var(--text-muted);">${res.summary || ''}</span>
      `;
      this.findingsListEl.appendChild(header);

      if (!res.success && res.errors) {
        res.errors.forEach(err => {
          const errDiv = document.createElement('div');
          errDiv.style.cssText = `
            padding: 0.75rem;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: var(--radius-sm);
            color: #f87171;
            font-size: 0.8rem;
            margin-bottom: 0.5rem;
          `;
          errDiv.textContent = `Error during execution: ${err}`;
          this.findingsListEl.appendChild(errDiv);
        });
      }

      if (res.findings.length === 0) {
        const noFind = document.createElement('div');
        noFind.style.cssText = 'color: var(--text-muted); font-size: 0.8rem; font-style: italic; padding: 0.5rem 0 0.5rem 1rem;';
        noFind.textContent = 'No issues or insights detected by this plugin.';
        this.findingsListEl.appendChild(noFind);
      } else {
        res.findings.forEach(finding => {
          totalFindingsCount++;
          const row = document.createElement('div');
          row.className = `finding-row severity-${finding.severity}`;

          const topRow = document.createElement('div');
          topRow.style.cssText = 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;';

          const badge = document.createElement('span');
          badge.className = `finding-badge badge-${finding.severity}`;
          badge.textContent = finding.severity;

          const cat = document.createElement('span');
          cat.style.cssText = 'font-weight: 700; font-size: 0.8rem; color: var(--text-primary); text-transform: uppercase;';
          cat.textContent = finding.category;

          const left = document.createElement('div');
          left.appendChild(badge);
          left.appendChild(cat);

          topRow.appendChild(left);

          if (finding.address !== undefined && this.options.onNavigate) {
            const navBtn = document.createElement('button');
            navBtn.className = 'btn btn-secondary';
            navBtn.style.padding = '0.15rem 0.4rem';
            navBtn.style.fontSize = '0.7rem';
            navBtn.textContent = `Go to 0x${finding.address.toString(16).toUpperCase()}`;
            navBtn.addEventListener('click', () => {
              if (this.options.onNavigate) {
                this.options.onNavigate('assembly', finding.address!);
              }
            });
            topRow.appendChild(navBtn);
          }

          row.appendChild(topRow);

          const desc = document.createElement('div');
          desc.style.cssText = 'font-size: 0.85rem; color: var(--text-primary); margin-bottom: 0.25rem;';
          desc.textContent = finding.description;
          row.appendChild(desc);

          if (finding.evidence) {
            const ev = document.createElement('pre');
            ev.style.cssText = `
              margin: 0.35rem 0 0 0;
              padding: 0.5rem;
              background: rgba(0, 0, 0, 0.3);
              border: 1px solid rgba(255, 255, 255, 0.05);
              border-radius: var(--radius-sm);
              font-family: var(--font-mono);
              font-size: 0.75rem;
              color: var(--text-secondary);
              white-space: pre-wrap;
              word-break: break-all;
            `;
            ev.textContent = finding.evidence;
            row.appendChild(ev);
          }

          this.findingsListEl.appendChild(row);
        });
      }
    });

    if (totalFindingsCount > 0) {
      this.showStatus(`Completed plugin execution successfully. Detected ${totalFindingsCount} findings/issues.`, 'success');
    }
  }
}
