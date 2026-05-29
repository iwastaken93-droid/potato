// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TabManager, TabName } from '../src/ui/tabManager.js';

describe('TabManager Unit Tests', () => {
  let container: HTMLDivElement;

  beforeEach(() => {
    container = document.createElement('div');
    container.innerHTML = `
      <div class="tab-selector-container">
        <button class="tab-btn active" data-tab="hex">Hex Viewer</button>
        <button class="tab-btn" data-tab="assembly">Assembly</button>
        <button class="tab-btn" data-tab="cfg">CFG Graph</button>
      </div>
      <div class="tab-content" id="panel-hex" style="display: block;"></div>
      <div class="tab-content" id="panel-assembly" style="display: none;"></div>
      <div class="tab-content" id="panel-cfg" style="display: none;"></div>
    `;
    document.body.appendChild(container);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should initialize and switch tabs', () => {
    const tabChangeSpy = vi.fn();
    const manager = new TabManager({
      initialTab: 'hex',
      onTabChange: tabChangeSpy,
    });

    expect(manager.getActiveTab()).toBe('hex');

    // Perform switch
    manager.switchTab('assembly');

    expect(manager.getActiveTab()).toBe('assembly');
    expect(tabChangeSpy).toHaveBeenCalledWith('assembly');

    const hexPanel = document.getElementById('panel-hex');
    const assemblyPanel = document.getElementById('panel-assembly');

    expect(hexPanel?.style.display).toBe('none');
    expect(assemblyPanel?.style.display).toBe('block');
  });

  it('should trigger switch when tab buttons are clicked', () => {
    const tabChangeSpy = vi.fn();
    new TabManager({
      initialTab: 'hex',
      onTabChange: tabChangeSpy,
    });

    const assemblyBtn = container.querySelector('[data-tab="assembly"]') as HTMLButtonElement;
    expect(assemblyBtn).not.toBeNull();

    assemblyBtn.click();

    expect(tabChangeSpy).toHaveBeenCalledWith('assembly');
  });
});
