/**
 * Universal Reverse Engineering Tool (URET)
 * Tab Manager - Coordinates tab switching and panels display
 */

export type TabName =
  | 'hex'
  | 'assembly'
  | 'cfg'
  | 'decompiler'
  | 'strings'
  | 'search'
  | 'dependencies'
  | 'signatures'
  | 'emulator'
  | 'gdb'
  | 'report'
  | 'xrefs'
  | 'importsExports'
  | 'patcher'
  | 'fcg'
  | 'collab'
  | 'yara'
  | 'typeSystem'
  | 'metadata'
  | 'demangler'
  | 'diff'
  | 'plugins'
  | 'machoObjc';

export interface TabManagerOptions {
  onTabChange?: (tabName: TabName) => void;
  initialTab?: TabName;
}

export class TabManager {
  private activeTab: TabName;
  private tabButtons: Map<string, HTMLButtonElement> = new Map();
  private tabPanels: Map<string, HTMLElement> = new Map();
  private onTabChange?: (tabName: TabName) => void;

  constructor(options: TabManagerOptions = {}) {
    this.activeTab = options.initialTab || 'hex';
    this.onTabChange = options.onTabChange;
    this.cacheElements();
    this.setupEventListeners();
  }

  private cacheElements() {
    document.querySelectorAll('.tab-btn').forEach((btn) => {
      const b = btn as HTMLButtonElement;
      const tabName = b.dataset.tab;
      if (tabName) {
        this.tabButtons.set(tabName, b);
        const panel = document.getElementById(`panel-${tabName}`);
        if (panel) {
          this.tabPanels.set(tabName, panel);
        }
      }
    });
  }

  private setupEventListeners() {
    this.tabButtons.forEach((btn, tabName) => {
      btn.addEventListener('click', () => {
        this.switchTab(tabName as TabName);
      });
    });
  }

  public getActiveTab(): TabName {
    return this.activeTab;
  }

  public switchTab(tabName: TabName) {
    if (this.activeTab === tabName) return;

    // Toggle button active classes
    this.tabButtons.forEach((btn, name) => {
      if (name === tabName) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    // Toggle panels visible style
    this.tabPanels.forEach((panel, name) => {
      if (name === tabName) {
        panel.style.display = 'block';
      } else {
        panel.style.display = 'none';
      }
    });

    this.activeTab = tabName;

    if (this.onTabChange) {
      this.onTabChange(tabName);
    }
  }
}
