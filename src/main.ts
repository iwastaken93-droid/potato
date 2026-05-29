/**
 * Universal Reverse Engineering Tool (URET)
 * Application Coordinator / Main Entry Point
 */

import { Architecture } from './disassembler/router.js';
import { Section, Symbol, Instruction } from './disassembler/types.js';
import { TabManager, TabName } from './ui/tabManager.js';
import { BinaryLoader } from './ui/binaryLoader.js';
import { injectStyles, createLayout } from './ui/layout.js';
import { processBinaryData } from './analyzer/binaryProcessor.js';
import { PanelCoordinator } from './ui/panelCoordinator.js';
import { BinaryPatcher } from './analyzer/patcher.js';

// App state management
export interface AppState {
  fileName: string;
  fileSize: number;
  binaryData: Uint8Array;
  architecture: Architecture;
  entryPoint: number;
  sections: Section[];
  symbols: Symbol[];
  instructions: Instruction[];
  cfgBlocks: any[];
  activeTab: TabName;
  selectedSymbol: Symbol | null;
  searchQuery: string;
  extractedStrings: any[];
  dependencies?: {
    binaryName: string;
    imports: { library: string; name: string; address?: number }[];
    exports: { name: string; address?: number }[];
    locals: { name: string; address: number; calls: string[] }[];
  };
  lastModified?: number;
  objc?: any;
}

export class ApplicationCoordinator {
  public state!: AppState;
  private patcher: BinaryPatcher | null = null;
  public panelCoordinator!: PanelCoordinator;

  // DOM elements cache
  private appContainer!: HTMLDivElement;
  private searchInput!: HTMLInputElement;
  private sidebarList!: HTMLDivElement;
  private tabManager!: TabManager;
  private binaryLoader!: BinaryLoader;

  // Header status elements
  private statusFileName!: HTMLSpanElement;
  private statusFileType!: HTMLSpanElement;
  private statusEntryVal!: HTMLSpanElement;
  private statusSectionsVal!: HTMLSpanElement;

  constructor() {
    injectStyles();
    createLayout();
    this.cacheElements();
    this.setupEventListeners();

    this.tabManager = new TabManager({
      initialTab: 'hex',
      onTabChange: (tabName) => this.handleTabChange(tabName),
    });

    this.panelCoordinator = new PanelCoordinator(this);

    this.binaryLoader = new BinaryLoader({
      onBinaryLoaded: (fileName, arrayBuffer, lastModified) => {
        this.processBinary(fileName, arrayBuffer, lastModified);
      },
    });

    this.loadSampleBinary();
  }

  // Getters for test suite backward compatibility
  public get machoObjcPanel() { return this.panelCoordinator.machoObjcPanel; }
  public get hexViewer() { return this.panelCoordinator.hexViewer; }
  public get assemblyView() { return this.panelCoordinator.assemblyView; }
  public get stringsView() { return this.panelCoordinator.stringsView; }
  public get searchPanel() { return this.panelCoordinator.searchPanel; }
  public get signaturePanel() { return this.panelCoordinator.signaturePanel; }
  public get emulatorPanel() { return this.panelCoordinator.emulatorPanel; }
  public get gdbPanel() { return this.panelCoordinator.gdbPanel; }
  public get reportPanel() { return this.panelCoordinator.reportPanel; }
  public get xrefsPanel() { return this.panelCoordinator.xrefsPanel; }
  public get importsExportsPanel() { return this.panelCoordinator.importsExportsPanel; }
  public get aiPanel() { return this.panelCoordinator.aiPanel; }
  public get patcherPanel() { return this.panelCoordinator.patcherPanel; }
  public get fcgVisualizer() { return this.panelCoordinator.fcgVisualizer; }
  public get collabPanel() { return this.panelCoordinator.collabPanel; }
  public get yaraPanel() { return this.panelCoordinator.yaraPanel; }
  public get typeSystemPanel() { return this.panelCoordinator.typeSystemPanel; }
  public get metadataPanel() { return this.panelCoordinator.metadataPanel; }
  public get demanglerPanel() { return this.panelCoordinator.demanglerPanel; }
  public get pluginsPanel() { return this.panelCoordinator.pluginsPanel; }

  // Delegated panel init methods for test compatibility
  public initPluginsPanel() { return this.panelCoordinator.initPluginsPanel(); }
  public initImportsExportsPanel() { return this.panelCoordinator.initImportsExportsPanel(); }
  public initPatcherPanel() { return this.panelCoordinator.initPatcherPanel(this.patcher); }
  public initHexViewer() { return this.panelCoordinator.initHexViewer(); }
  public initStringsViewer() { return this.panelCoordinator.initStringsViewer(); }
  public initSearchPanel() { return this.panelCoordinator.initSearchPanel(); }
  public initSignaturePanel() { return this.panelCoordinator.initSignaturePanel(); }
  public initAssemblyViewer() { return this.panelCoordinator.initAssemblyViewer(); }
  public initCFGViewer() { return this.panelCoordinator.initCFGViewer(); }
  public initDependencyGraph() { return this.panelCoordinator.initDependencyGraph(); }
  public initReportPanel() { return this.panelCoordinator.initReportPanel(); }
  public initEmulatorPanel() { return this.panelCoordinator.initEmulatorPanel(); }
  public initGDBPanel() { return this.panelCoordinator.initGDBPanel(); }
  public initXRefsPanel() { return this.panelCoordinator.initXRefsPanel(); }
  public initFCGViewer() { return this.panelCoordinator.initFCGViewer(); }
  public initCollabPanel() { return this.panelCoordinator.initCollabPanel(); }
  public initYaraPanel() { return this.panelCoordinator.initYaraPanel(); }
  public initMetadataPanel() { return this.panelCoordinator.initMetadataPanel(); }
  public initTypeSystemPanel() { return this.panelCoordinator.initTypeSystemPanel(); }
  public initMachoObjcPanel() { return this.panelCoordinator.initMachoObjcPanel(); }
  public initDemanglerPanel() { return this.panelCoordinator.initDemanglerPanel(); }
  public updateDecompiler() { return this.panelCoordinator.updateDecompiler(); }

  private cacheElements() {
    this.appContainer = document.querySelector(
      '.app-container'
    ) as HTMLDivElement;
    this.searchInput = document.getElementById(
      'sidebar-search'
    ) as HTMLInputElement;
    this.sidebarList = document.getElementById(
      'sidebar-list'
    ) as HTMLDivElement;

    this.statusFileName = document.getElementById(
      'status-filename'
    ) as HTMLSpanElement;
    this.statusFileType = document.getElementById(
      'status-filetype'
    ) as HTMLSpanElement;
    this.statusEntryVal = document.getElementById(
      'status-entryval'
    ) as HTMLSpanElement;
    this.statusSectionsVal = document.getElementById(
      'status-sectionsval'
    ) as HTMLSpanElement;
  }

  private setupEventListeners() {
    // Search bar functionality
    this.searchInput.addEventListener('input', (e) => {
      const value = (e.target as HTMLInputElement).value;
      this.state.searchQuery = value;
      this.renderSidebarList();
    });

    // Memory map button hookup
    const openMemMapBtn = document.getElementById(
      'open-mem-map-btn'
    ) as HTMLButtonElement;
    openMemMapBtn?.addEventListener('click', () => {
      if (this.state && this.state.binaryData) {
        this.panelCoordinator.showMemoryMap();
      }
    });
  }

  public switchTab(tabName: TabName) {
    this.tabManager.switchTab(tabName);
  }

  private handleTabChange(tabName: TabName) {
    this.state.activeTab = tabName;
    this.panelCoordinator.handleTabChange(tabName);
    this.panelCoordinator.updateActiveTabPanel();
  }

  private processBinary(
    fileName: string,
    arrayBuffer: ArrayBuffer,
    lastModified?: number
  ) {
    const data = new Uint8Array(arrayBuffer);
    const fileSize = arrayBuffer.byteLength;

    const result = processBinaryData(fileName, data, arrayBuffer);

    // Update global state
    this.state = {
      fileName,
      fileSize,
      binaryData: data,
      architecture: result.architecture,
      entryPoint: result.entryPoint,
      sections: result.sections,
      symbols: result.symbols,
      instructions: result.instructions,
      cfgBlocks: result.cfgBlocks,
      activeTab: this.state ? this.state.activeTab : 'hex',
      selectedSymbol: result.symbols[0] || null,
      searchQuery: '',
      extractedStrings: result.extractedStrings,
      dependencies: result.dependencies,
      lastModified: lastModified || Date.now(),
      objc: result.objc,
    };

    // Update Header Status UI
    this.statusFileName.textContent = this.state.fileName;
    this.statusFileType.textContent = `${this.state.architecture.toUpperCase()} / Format`;
    this.statusEntryVal.textContent = `0x${this.state.entryPoint.toString(16).toUpperCase()}`;
    this.statusSectionsVal.textContent = this.state.sections.length.toString();

    this.searchInput.value = '';

    this.patcher = new BinaryPatcher(data);
    this.panelCoordinator.onBinaryLoaded(this.patcher);

    // Fill the sidebar list
    this.renderSidebarList();

    // Select the first function/symbol by default
    if (result.symbols.length > 0) {
      this.selectSymbol(result.symbols[0]);
    }
  }

  public renderSidebarList() {
    this.sidebarList.innerHTML = '';
    const query = this.state.searchQuery.toLowerCase();

    const filtered = this.state.symbols.filter(
      (s) =>
        s.name.toLowerCase().includes(query) ||
        `0x${s.address.toString(16)}`.includes(query)
    );

    filtered.forEach((sym: Symbol) => {
      const item = document.createElement('div');
      item.className = 'sidebar-item';
      if (
        this.state.selectedSymbol &&
        this.state.selectedSymbol.address === sym.address
      ) {
        item.classList.add('active');
      }

      item.innerHTML = `
        <span class="sidebar-item-name">${sym.name}</span>
        <span class="sidebar-item-meta">Address: 0x${sym.address.toString(16).toUpperCase()} (${sym.type})</span>
      `;

      item.addEventListener('click', () => {
        this.selectSymbol(sym);
      });

      this.sidebarList.appendChild(item);
    });
  }

  public selectSymbol(sym: Symbol) {
    this.state.selectedSymbol = sym;

    // Re-highlight active item in list
    const items = this.sidebarList.querySelectorAll('.sidebar-item');
    const filtered = this.state.symbols.filter(
      (s) =>
        s.name.toLowerCase().includes(this.state.searchQuery.toLowerCase()) ||
        `0x${s.address.toString(16)}`.includes(
          this.state.searchQuery.toLowerCase()
        )
    );

    items.forEach((item, idx: number) => {
      const s = filtered[idx];
      if (s && s.address === sym.address) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // Navigate viewers to the symbol's address
    if (this.panelCoordinator.assemblyView) {
      this.panelCoordinator.assemblyView.navigateToAddress(sym.address);
    }

    const executeSection = this.state.sections.find(
      (s: any) => s.flags.execute
    );
    if (executeSection && this.panelCoordinator.hexViewer) {
      const offset = sym.address - executeSection.virtualAddress;
      if (offset >= 0 && offset < this.state.binaryData.length) {
        this.panelCoordinator.hexViewer.setSelectedOffset(offset);
      }
    }

    // Refresh decompiler for this function scope
    this.panelCoordinator.updateDecompiler();

    if (this.panelCoordinator.xrefsPanel) {
      this.panelCoordinator.xrefsPanel.selectAddress(sym.address);
    }
  }

  private loadSampleBinary() {
    BinaryLoader.loadSampleBinary((fileName, arrayBuffer) => {
      this.processBinary(fileName, arrayBuffer);
    });
  }
}

// Instantiate the coordinator on window load
window.addEventListener('DOMContentLoaded', () => {
  new ApplicationCoordinator();
});
