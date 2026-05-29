// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MachoObjcPanel } from '../src/ui/machoObjcPanel.js';
import type { ParsedObjcMetadata } from '../src/parser/machoObjc.js';

describe('MachoObjcPanel Unit Tests', () => {
  let container: HTMLElement;
  let panel: MachoObjcPanel;
  const mockNavigate = vi.fn();

  const mockMetadata: ParsedObjcMetadata = {
    classes: [
      {
        name: 'MyTestClass',
        superclassName: 'NSObject',
        protocols: ['MyProtocol'],
        methods: [
          {
            name: 'doSomething',
            types: 'v@:',
            imp: 0x1000n,
          },
        ],
        properties: [
          {
            name: 'myProp',
            attributes: 'T@"NSString",C,N',
          },
        ],
        ivars: [
          {
            name: '_myIvar',
            type: 'NSString',
            offset: 8,
            size: 8,
          },
        ],
      },
    ],
    protocols: [
      {
        name: 'MyProtocol',
        instanceMethods: [
          {
            name: 'protoMethod',
            types: 'v@:',
          },
        ],
        classMethods: [],
        properties: [],
      },
    ],
  };

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new MachoObjcPanel(container, { onNavigate: mockNavigate });
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.clearAllMocks();
  });

  it('should render the initial structure and show placeholder when metadata is null', () => {
    const root = container.querySelector('.objc-panel-root');
    expect(root).not.toBeNull();

    const noDataEls = container.querySelectorAll('.objc-no-data');
    expect(noDataEls.length).toBeGreaterThan(0);
    expect(noDataEls[0].textContent).toContain('No binary metadata loaded');
  });

  it('should render stats and lists when parsed metadata is updated', () => {
    panel.updateData(mockMetadata);

    const statsClasses = container.querySelector('#objc-stats-classes');
    const statsProtocols = container.querySelector('#objc-stats-protocols');
    const statsMethods = container.querySelector('#objc-stats-methods');
    const statsProps = container.querySelector('#objc-stats-props');

    expect(statsClasses?.textContent).toBe('1');
    expect(statsProtocols?.textContent).toBe('1');
    expect(statsMethods?.textContent).toBe('2'); // 1 class method + 1 protocol method
    expect(statsProps?.textContent).toBe('1');

    const sidebarItems = container.querySelectorAll('.objc-list-item');
    expect(sidebarItems.length).toBe(1);
    expect(sidebarItems[0].textContent).toContain('MyTestClass');
  });

  it('should switch active tab between classes and protocols', () => {
    panel.updateData(mockMetadata);

    const classesBtn = container.querySelector(
      '.objc-tab-btn:nth-child(1)'
    ) as HTMLButtonElement;
    const protocolsBtn = container.querySelector(
      '.objc-tab-btn:nth-child(2)'
    ) as HTMLButtonElement;

    expect(classesBtn.classList.contains('active')).toBe(true);
    expect(protocolsBtn.classList.contains('active')).toBe(false);

    // Switch to protocols
    protocolsBtn.click();
    expect(classesBtn.classList.contains('active')).toBe(false);
    expect(protocolsBtn.classList.contains('active')).toBe(true);

    const sidebarItems = container.querySelectorAll('.objc-list-item');
    expect(sidebarItems.length).toBe(1);
    expect(sidebarItems[0].textContent).toContain('MyProtocol');
  });

  it('should filter entries in the sidebar list when search input query changes', () => {
    panel.updateData(mockMetadata);

    const searchInput = container.querySelector(
      '.objc-search-input'
    ) as HTMLInputElement;
    expect(searchInput).not.toBeNull();

    // Set search query that won't match
    searchInput.value = 'NonExistentClass';
    searchInput.dispatchEvent(new Event('input'));

    let sidebarItems = container.querySelectorAll('.objc-list-item');
    expect(sidebarItems.length).toBe(0);

    const noData = container.querySelector('.objc-sidebar .objc-no-data');
    expect(noData?.textContent).toContain('No matches found');

    // Set search query that matches MyTestClass
    searchInput.value = 'MyTestClass';
    searchInput.dispatchEvent(new Event('input'));
    sidebarItems = container.querySelectorAll('.objc-list-item');
    expect(sidebarItems.length).toBe(1);
  });

  it('should display class details, methods table, properties table, and ivars table when a class is selected', () => {
    panel.updateData(mockMetadata);

    const header = container.querySelector('.objc-detail-header');
    expect(header?.textContent).toContain('MyTestClass');
    expect(header?.textContent).toContain('NSObject');

    const methodTable = container.querySelector(
      '.objc-meta-section:nth-of-type(2) .objc-table'
    );
    expect(methodTable).not.toBeNull();
    expect(methodTable?.textContent).toContain('doSomething');
    expect(methodTable?.textContent).toContain('v@:');

    const propTable = container.querySelector(
      '.objc-meta-section:nth-of-type(3) .objc-table'
    );
    expect(propTable).not.toBeNull();
    expect(propTable?.textContent).toContain('myProp');
    expect(propTable?.textContent).toContain('T@"NSString",C,N');

    const ivarTable = container.querySelector(
      '.objc-meta-section:nth-of-type(4) .objc-table'
    );
    expect(ivarTable).not.toBeNull();
    expect(ivarTable?.textContent).toContain('_myIvar');
  });

  it('should trigger navigate callback when IMP address button is clicked', () => {
    panel.updateData(mockMetadata);

    const addrBtn = container.querySelector(
      '.objc-addr-btn'
    ) as HTMLButtonElement;
    expect(addrBtn).not.toBeNull();
    expect(addrBtn.textContent).toBe('0x1000');

    addrBtn.click();
    expect(mockNavigate).toHaveBeenCalledWith('assembly', 0x1000);
  });
});
