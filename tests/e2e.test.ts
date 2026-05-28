// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ApplicationCoordinator } from '../src/main.js';

// Define globally required mocks for JSDOM
if (typeof global.ResizeObserver === 'undefined') {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (typeof Element !== 'undefined') {
  if (!Element.prototype.scrollIntoView) {
    Element.prototype.scrollIntoView = vi.fn();
  }
  if (!Element.prototype.scrollTo) {
    Element.prototype.scrollTo = vi.fn();
  }
}

if (typeof HTMLCanvasElement !== 'undefined') {
  HTMLCanvasElement.prototype.getContext = function (type: string) {
    if (type === '2d') {
      const mockContext = {
        measureText: () => ({ width: 10 }),
      };
      return new Proxy(mockContext, {
        get(target, prop) {
          if (prop in target) {
            return (target as any)[prop];
          }
          if (typeof prop === 'string') {
            if (['strokeStyle', 'fillStyle', 'font', 'textAlign', 'textBaseline', 'shadowColor'].includes(prop)) {
              return '';
            }
            if (['lineWidth', 'globalAlpha', 'shadowBlur'].includes(prop)) {
              return 1;
            }
            return () => {};
          }
          return undefined;
        },
        set(target, prop, value) {
          return true;
        }
      }) as any;
    }
    return null;
  };
}

if (typeof navigator !== 'undefined' && !navigator.clipboard) {
  (navigator as any).clipboard = {
    writeText: vi.fn().mockResolvedValue(undefined),
  };
}

// Simple requestAnimationFrame mock since we are running in JSDOM/Vitest environment
const originalRAF = global.requestAnimationFrame;
beforeEach(() => {
  global.requestAnimationFrame = (callback: FrameRequestCallback) => {
    return setTimeout(() => callback(Date.now()), 0) as any;
  };
});
afterEach(() => {
  global.requestAnimationFrame = originalRAF;
});

describe('E2E DOM Integration Tests', () => {
  let appEl: HTMLElement;

  beforeEach(() => {
    // Create the container element that main.ts expects
    appEl = document.createElement('div');
    appEl.id = 'app';
    document.body.appendChild(appEl);
  });

  afterEach(() => {
    document.body.removeChild(appEl);
    vi.clearAllMocks();
  });

  it('should initialize the application coordinator and render structural UI layout', () => {
    // Instantiate coordinator
    const coordinator = new ApplicationCoordinator();

    // Verify layout structure
    const container = document.querySelector('.app-container');
    expect(container).not.toBeNull();

    const sidebar = document.querySelector('.sidebar');
    expect(sidebar).not.toBeNull();

    const header = document.querySelector('.header');
    expect(header).not.toBeNull();

    const mainContent = document.querySelector('.main-content');
    expect(mainContent).not.toBeNull();
  });

  it('should display the default sample binary details in the header status', () => {
    const coordinator = new ApplicationCoordinator();

    // The loadSampleBinary should have been called during constructor
    const statusFileName = document.getElementById('status-filename');
    expect(statusFileName).not.toBeNull();
    expect(statusFileName?.textContent).toBe('sample_elf.bin');

    const statusFileType = document.getElementById('status-filetype');
    expect(statusFileType).not.toBeNull();
    expect(statusFileType?.textContent).toBe('X86_64 / Format');
  });

  it('should switch panels when tab buttons are clicked', () => {
    const coordinator = new ApplicationCoordinator();

    // Get all panels
    const panelHex = document.getElementById('panel-hex');
    const panelAssembly = document.getElementById('panel-assembly');

    // Default active tab should show panel-hex and hide panel-assembly
    expect(panelHex?.style.display).toBe('block');
    expect(panelAssembly?.style.display).toBe('none');

    // Find the assembly tab button
    const tabButtons = document.querySelectorAll('.tab-btn');
    const assemblyBtn = Array.from(tabButtons).find(btn => (btn as HTMLButtonElement).dataset.tab === 'assembly') as HTMLButtonElement | undefined;
    expect(assemblyBtn).toBeDefined();

    // Simulate click
    assemblyBtn?.click();

    // After click, panel-assembly should be block and panel-hex should be none
    expect(panelHex?.style.display).toBe('none');
    expect(panelAssembly?.style.display).toBe('block');
  });

  it('should filter symbols list in the sidebar when search is typed', () => {
    const coordinator = new ApplicationCoordinator();

    const searchInput = document.getElementById('sidebar-search') as HTMLInputElement;
    expect(searchInput).not.toBeNull();

    // Simulate typing a search query that matches nothing
    searchInput.value = 'non_existent_symbol_xyz';
    searchInput.dispatchEvent(new Event('input'));

    // Check that the sidebar lists no items
    const sidebarList = document.getElementById('sidebar-list');
    expect(sidebarList?.querySelectorAll('.sidebar-item').length).toBe(0);
  });

  it('should switch through all major panels when clicked during tab navigation', () => {
    const coordinator = new ApplicationCoordinator();

    const tabs = [
      'hex', 'assembly', 'cfg', 'decompiler', 'strings', 
      'search', 'signatures', 'dependencies', 'emulator', 
      'report', 'xrefs', 'metadata', 'fcg', 'collab', 
      'yara', 'typeSystem', 'demangler', 'diff'
    ];

    const tabButtons = document.querySelectorAll('.tab-btn');

    for (const tab of tabs) {
      const btn = Array.from(tabButtons).find(b => (b as HTMLButtonElement).dataset.tab === tab) as HTMLButtonElement;
      expect(btn).toBeDefined();

      btn.click();

      // Verify button has active class
      expect(btn.classList.contains('active')).toBe(true);

      // Verify panel has display: block and others display: none
      const panel = document.getElementById(`panel-${tab}`);
      expect(panel).not.toBeNull();
      expect(panel?.style.display).toBe('block');

      for (const otherTab of tabs) {
        if (otherTab !== tab) {
          const otherPanel = document.getElementById(`panel-${otherTab}`);
          expect(otherPanel?.style.display).toBe('none');
        }
      }
    }
  }, 30000);

  it('should load a custom ELF binary file via input upload workflow', async () => {
    // Stub FileReader to immediately call onload with the mock buffer
    const mockFileReader = vi.fn().mockImplementation(function(this: any) {
      this.readAsArrayBuffer = vi.fn().mockImplementation((blob: Blob) => {
        setTimeout(() => {
          const buffer = (blob as any)._mockBuffer || new ArrayBuffer(0);
          if (this.onload) {
            this.onload({ target: { result: buffer } });
          }
        }, 0);
      });
    });
    vi.stubGlobal('FileReader', mockFileReader);

    const coordinator = new ApplicationCoordinator();

    // Create a mock ELF file (valid 64-bit Little Endian ELF header, size 64)
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0; // System V
    view.setUint16(16, 2, true); // EXEC
    view.setUint16(18, 62, true); // AMD64
    view.setBigUint64(24, 0x1000n, true); // Entry point
    view.setBigUint64(32, 0n, true);
    view.setBigUint64(40, 0n, true);
    view.setUint32(48, 0, true);
    view.setUint16(52, 64, true);

    const file = new File([buffer], 'custom_elf.bin', { type: 'application/octet-stream' });
    (file as any)._mockBuffer = buffer;

    // Find the file input
    const fileInput = document.getElementById('file-input') as HTMLInputElement;
    expect(fileInput).not.toBeNull();

    const fileList = {
      0: file,
      length: 1,
      item: (index: number) => file
    } as unknown as FileList;

    Object.defineProperty(fileInput, 'files', {
      value: fileList,
      writable: true,
      configurable: true
    });

    // Dispatch change event
    fileInput.dispatchEvent(new Event('change'));

    // Wait for FileReader async process
    await new Promise(resolve => setTimeout(resolve, 50));

    // Assert header status has been updated
    const statusFileName = document.getElementById('status-filename');
    expect(statusFileName?.textContent).toBe('custom_elf.bin');
    const statusFileType = document.getElementById('status-filetype');
    expect(statusFileType?.textContent).toBe('X86_64 / Format');
  }, 30000);

  it('should load a custom binary via drag and drop workflow', async () => {
    // Stub FileReader to immediately call onload with the mock buffer
    const mockFileReader = vi.fn().mockImplementation(function(this: any) {
      this.readAsArrayBuffer = vi.fn().mockImplementation((blob: Blob) => {
        setTimeout(() => {
          const buffer = (blob as any)._mockBuffer || new ArrayBuffer(0);
          if (this.onload) {
            this.onload({ target: { result: buffer } });
          }
        }, 0);
      });
    });
    vi.stubGlobal('FileReader', mockFileReader);

    const coordinator = new ApplicationCoordinator();

    // Create a mock ELF file (valid 64-bit Little Endian ELF header, size 64)
    const buffer = new ArrayBuffer(64);
    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    bytes[0] = 0x7f;
    bytes[1] = 0x45;
    bytes[2] = 0x4c;
    bytes[3] = 0x46;
    bytes[4] = 2; // 64-bit
    bytes[5] = 1; // Little Endian
    bytes[7] = 0; // System V
    view.setUint16(16, 2, true); // EXEC
    view.setUint16(18, 62, true); // AMD64
    view.setBigUint64(24, 0x1000n, true); // Entry point
    view.setBigUint64(32, 0n, true);
    view.setBigUint64(40, 0n, true);
    view.setUint32(48, 0, true);
    view.setUint16(52, 64, true);

    const file = new File([buffer], 'dragged_elf.bin', { type: 'application/octet-stream' });
    (file as any)._mockBuffer = buffer;

    const fileDropzone = document.getElementById('file-dropzone') as HTMLDivElement;
    expect(fileDropzone).not.toBeNull();

    // Create a mock drop event
    const dropEvent = new Event('drop') as any;
    dropEvent.preventDefault = vi.fn();
    dropEvent.dataTransfer = {
      files: {
        0: file,
        length: 1,
        item: (index: number) => file
      }
    };

    fileDropzone.dispatchEvent(dropEvent);

    // Wait for FileReader
    await new Promise(resolve => setTimeout(resolve, 50));

    const statusFileName = document.getElementById('status-filename');
    expect(statusFileName?.textContent).toBe('dragged_elf.bin');
  }, 30000);

  it('should perform search query and mode switches in SearchPanel workflows', async () => {
    const coordinator = new ApplicationCoordinator();

    // Switch to search panel tab
    const tabButtons = document.querySelectorAll('.tab-btn');
    const searchBtn = Array.from(tabButtons).find(btn => (btn as HTMLButtonElement).dataset.tab === 'search') as HTMLButtonElement;
    expect(searchBtn).toBeDefined();
    searchBtn.click();

    // Verify search panel is active
    const searchPanel = document.getElementById('panel-search');
    expect(searchPanel?.style.display).toBe('block');

    // Type query
    const searchField = searchPanel?.querySelector('.search-field') as HTMLInputElement;
    expect(searchField).not.toBeNull();
    searchField.value = 'Welcome';
    searchField.dispatchEvent(new Event('input'));

    await new Promise(resolve => setTimeout(resolve, 50));

    const resultsList = searchPanel?.querySelector('.search-results-list');
    expect(resultsList).not.toBeNull();
    const resultCards = resultsList?.querySelectorAll('.search-result-card');
    expect(resultCards?.length).toBeGreaterThan(0);

    // Switch to Hex Search Mode
    const searchModeButtons = searchPanel?.querySelectorAll('.search-mode-btn') || [];
    const hexModeBtn = Array.from(searchModeButtons).find(btn => btn.textContent?.includes('Hex')) as HTMLButtonElement;
    expect(hexModeBtn).toBeDefined();
    hexModeBtn.click();

    // Perform Hex wildcard search
    searchField.value = '90 55 ?? 89';
    searchField.dispatchEvent(new Event('input'));

    await new Promise(resolve => setTimeout(resolve, 50));

    const hexResultCards = resultsList?.querySelectorAll('.search-result-card');
    expect(hexResultCards?.length).toBeGreaterThan(0);
  }, 30000);
});


