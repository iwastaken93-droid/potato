// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { injectStyles, createLayout } from '../src/ui/layout.js';

describe('Layout Unit Tests', () => {
  let appEl: HTMLDivElement;

  beforeEach(() => {
    // Setup app root element
    appEl = document.createElement('div');
    appEl.id = 'app';
    document.body.appendChild(appEl);
  });

  afterEach(() => {
    if (appEl && appEl.parentNode) {
      document.body.removeChild(appEl);
    }
    // Cleanup any styles injected during tests
    const styleEl = document.getElementById('coordinator-custom-styles');
    if (styleEl && styleEl.parentNode) {
      styleEl.parentNode.removeChild(styleEl);
    }
  });

  it('should inject styles into head', () => {
    expect(document.getElementById('coordinator-custom-styles')).toBeNull();
    injectStyles();
    
    const styleEl = document.getElementById('coordinator-custom-styles') as HTMLStyleElement;
    expect(styleEl).not.toBeNull();
    expect(styleEl.textContent).toContain('.search-input');
    expect(styleEl.textContent).toContain('.sidebar-brand');

    // Calling it again should not add a duplicate style sheet
    const initialStyleCount = document.querySelectorAll('#coordinator-custom-styles').length;
    injectStyles();
    const finalStyleCount = document.querySelectorAll('#coordinator-custom-styles').length;
    expect(initialStyleCount).toBe(1);
    expect(finalStyleCount).toBe(1);
  });

  it('should create initial layout inside #app element', () => {
    createLayout();
    
    // Check key structural elements exist
    const fileDropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('file-input');
    const uploadBtn = document.getElementById('upload-btn');
    const sidebarSearch = document.getElementById('sidebar-search');
    const sidebarList = document.getElementById('sidebar-list');
    
    expect(fileDropzone).not.toBeNull();
    expect(fileInput).not.toBeNull();
    expect(uploadBtn).not.toBeNull();
    expect(sidebarSearch).not.toBeNull();
    expect(sidebarList).not.toBeNull();

    // Check status values inside header
    const filenameStatus = document.getElementById('status-filename');
    const filetypeStatus = document.getElementById('status-filetype');
    const entryvalStatus = document.getElementById('status-entryval');
    
    expect(filenameStatus).not.toBeNull();
    expect(filenameStatus?.textContent).toBe('No file loaded');
    expect(filetypeStatus?.textContent).toBe('-');
    expect(entryvalStatus?.textContent).toBe('-');

    // Check tab panels
    const panelHex = document.getElementById('panel-hex');
    const panelAssembly = document.getElementById('panel-assembly');
    const panelCfg = document.getElementById('panel-cfg');
    
    expect(panelHex).not.toBeNull();
    expect(panelHex?.style.display).toBe('block');
    expect(panelAssembly?.style.display).toBe('none');
    expect(panelCfg?.style.display).toBe('none');
  });

  it('should do nothing if #app element is not present', () => {
    document.body.removeChild(appEl);
    
    // This should run without throwing errors
    expect(() => createLayout()).not.toThrow();
  });
});
