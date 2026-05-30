// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createLayout } from '../src/ui/layout.js';
import { PanelCoordinator, CoordinatorHost } from '../src/ui/panelCoordinator.js';
import { TabName } from '../src/ui/tabManager.js';
import { Symbol } from '../src/disassembler/types.js';
import { GDBPanel } from '../src/ui/gdbPanel.js';
import { MachoObjcPanel } from '../src/ui/machoObjcPanel.js';
import { SearchPanel } from '../src/ui/searchPanel.js';
import { ReportPanel } from '../src/ui/reportPanel.js';
import { YaraPanel } from '../src/ui/yaraPanel.js';
import { MetadataPanel } from '../src/ui/metadataPanel.js';
import { TypeSystemPanel } from '../src/ui/typeSystemPanel.js';
import { DiffPanel } from '../src/ui/diffPanel.js';
import { EmulatorPanel } from '../src/ui/emulatorPanel.js';
import { CollabPanel } from '../src/ui/collabPanel.js';
import { PluginsPanel } from '../src/ui/pluginsPanel.js';
import { DemanglerPanel } from '../src/ui/demanglerPanel.js';
import { AIPanel } from '../src/ui/aiPanel.js';

const PANEL_REGISTRY = (globalThis as any).PANEL_REGISTRY || ((globalThis as any).PANEL_REGISTRY = {});
PANEL_REGISTRY['GDBPanel'] = GDBPanel;
PANEL_REGISTRY['MachoObjcPanel'] = MachoObjcPanel;
PANEL_REGISTRY['SearchPanel'] = SearchPanel;
PANEL_REGISTRY['ReportPanel'] = ReportPanel;
PANEL_REGISTRY['YaraPanel'] = YaraPanel;
PANEL_REGISTRY['MetadataPanel'] = MetadataPanel;
PANEL_REGISTRY['TypeSystemPanel'] = TypeSystemPanel;
PANEL_REGISTRY['DiffPanel'] = DiffPanel;
PANEL_REGISTRY['EmulatorPanel'] = EmulatorPanel;
PANEL_REGISTRY['CollabPanel'] = CollabPanel;
PANEL_REGISTRY['PluginsPanel'] = PluginsPanel;
PANEL_REGISTRY['DemanglerPanel'] = DemanglerPanel;
PANEL_REGISTRY['AIPanel'] = AIPanel;

// Setup required JSDOM mocks
if (typeof global.ResizeObserver === 'undefined') {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = vi.fn();
}

if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = function (type: string) {
    if (type === '2d') {
      return {
        clearRect: vi.fn(),
        save: vi.fn(),
        scale: vi.fn(),
        translate: vi.fn(),
        fillRect: vi.fn(),
        beginPath: vi.fn(),
        arc: vi.fn(),
        fill: vi.fn(),
        moveTo: vi.fn(),
        lineTo: vi.fn(),
        stroke: vi.fn(),
        closePath: vi.fn(),
        restore: vi.fn(),
        rect: vi.fn(),
        fillText: vi.fn(),
        measureText: vi.fn(() => ({ width: 10 })),
        strokeStyle: '',
        fillStyle: '',
        lineWidth: 1,
      } as any;
    }
    return null;
  };
}

const originalRAF = global.requestAnimationFrame;
beforeEach(() => {
  global.requestAnimationFrame = (callback: FrameRequestCallback) => {
    return setTimeout(() => callback(Date.now()), 0) as any;
  };
});
afterEach(() => {
  global.requestAnimationFrame = originalRAF;
});

describe('PanelCoordinator Unit Tests', () => {
  let appEl: HTMLDivElement;
  let mockHost: CoordinatorHost;
  let mockState: any;

  beforeEach(() => {
    // 1. Setup layout inside DOM
    appEl = document.createElement('div');
    appEl.id = 'app';
    document.body.appendChild(appEl);
    createLayout();

    // 2. Mock state and host callbacks
    mockState = {
      activeTab: 'hex' as TabName,
      binaryData: new Uint8Array([0x90, 0x90, 0x90, 0x90]),
      architecture: 'x86_64',
      fileName: 'test.bin',
      fileSize: 4,
      entryPoint: 0x1000,
      sections: [
        {
          name: '.text',
          virtualAddress: 0x1000,
          virtualSize: 4,
          fileOffset: 0,
          fileSize: 4,
          flags: { read: true, write: false, execute: true },
        },
      ],
      symbols: [
        { name: 'main', address: 0x1000, binding: 'global', type: 'function' },
      ],
      extractedStrings: [
        { string: 'hello', value: 'hello', fileOffset: 0, offset: 0, virtualAddress: 0x1000, length: 5, encoding: 'ascii', tags: [] },
      ],
      instructions: [
        { address: 0x1000, bytes: new Uint8Array([0x90]), mnemonic: 'nop', opStr: '', operands: [] },
      ],
      cfgBlocks: [
        { id: 'b1', startAddress: 0x1000, endAddress: 0x1001, instructions: [], predecessors: [], successors: [] },
      ],
      dependencies: {
        binaryName: 'test.bin',
        imports: [],
        exports: [],
        locals: [],
      },
      selectedSymbol: null as Symbol | null,
    };

    mockHost = {
      state: mockState,
      switchTab: vi.fn((tab) => {
        mockState.activeTab = tab;
      }),
      selectSymbol: vi.fn((sym) => {
        mockState.selectedSymbol = sym;
      }),
      renderSidebarList: vi.fn(),
    };
  });

  afterEach(() => {
    document.body.removeChild(appEl);
    vi.restoreAllMocks();
  });

  it('should construct, initialize views, and handle binary loading', () => {
    const coordinator = new PanelCoordinator(mockHost);
    expect(coordinator).toBeDefined();

    // Trigger onBinaryLoaded
    coordinator.onBinaryLoaded(null);

    // Verify sub-views are initialized
    expect(coordinator.hexViewer).not.toBeNull();
    expect(coordinator.assemblyView).not.toBeNull();
    expect(coordinator.stringsView).not.toBeNull();
    expect(coordinator.signaturePanel).not.toBeNull();
  });

  it('should switch tabs and invoke callbacks and navigate assemblies', () => {
    const coordinator = new PanelCoordinator(mockHost);
    coordinator.onBinaryLoaded(null);

    // Switch tab to assembly
    mockState.selectedSymbol = mockState.symbols[0];
    const navSpy = vi.spyOn(coordinator.assemblyView!, 'navigateToAddress');
    
    coordinator.handleTabChange('assembly');
    expect(navSpy).toHaveBeenCalledWith(0x1000);
  });

  it('should lazy load panels when updating active tab panel', () => {
    const coordinator = new PanelCoordinator(mockHost);
    coordinator.onBinaryLoaded(null);

    // Initial state tab is hex
    expect(coordinator.cfgVisualizer).toBeNull();

    // Change activeTab to cfg and update
    mockState.activeTab = 'cfg';
    coordinator.updateActiveTabPanel();

    expect(coordinator.cfgVisualizer).not.toBeNull();
    expect(coordinator.cfgNeedsUpdate).toBe(false);
  });
});
