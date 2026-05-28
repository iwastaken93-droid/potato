// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryMapOverlay } from '../src/ui/memoryMap.js';
import type { Section } from '../src/disassembler/types.js';

describe('MemoryMapOverlay Unit Tests', () => {
  let binaryData: Uint8Array;
  let sections: Section[];
  let onNavigateSpy: any;
  let onCloseSpy: any;

  beforeEach(() => {
    // Clear DOM before each test
    document.body.innerHTML = '';
    const styleEl = document.getElementById('memory-map-styles');
    if (styleEl) {
      styleEl.remove();
    }

    // 1 KB of dummy data
    binaryData = new Uint8Array(1024);
    // Fill with some pattern to produce entropy
    for (let i = 0; i < binaryData.length; i++) {
      binaryData[i] = i % 256;
    }

    sections = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 512,
        fileOffset: 0,
        fileSize: 512,
        flags: { read: true, write: false, execute: true },
        entropy: 4.5,
      },
      {
        name: '.data',
        virtualAddress: 0x2000,
        virtualSize: 512,
        fileOffset: 512,
        fileSize: 512,
        flags: { read: true, write: true, execute: false },
        entropy: 5.5,
      }
    ];

    onNavigateSpy = vi.fn();
    onCloseSpy = vi.fn();
  });

  afterEach(() => {
    // Cleanup any lingering overlays
    const overlays = document.querySelectorAll('.mem-map-overlay');
    overlays.forEach((el) => el.remove());
    document.body.innerHTML = '';
  });

  it('should initialize and insert styles and DOM', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    // Check stylesheet
    const styleEl = document.getElementById('memory-map-styles');
    expect(styleEl).not.toBeNull();
    expect(styleEl?.textContent).toContain('.mem-map-overlay');

    // Check overlay DOM
    const overlayEl = document.querySelector('.mem-map-overlay');
    expect(overlayEl).not.toBeNull();
    expect(overlayEl?.querySelector('.mem-map-title h3')?.textContent).toContain('Binary Memory Map');
  });

  it('should show and hide overlay', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    expect(overlayEl.classList.contains('active')).toBe(false);

    overlay.show();
    expect(overlayEl.classList.contains('active')).toBe(true);

    overlay.hide();
    expect(overlayEl.classList.contains('active')).toBe(false);
    expect(onCloseSpy).toHaveBeenCalled();
  });

  it('should handle close events via click', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    expect(overlayEl.classList.contains('active')).toBe(true);

    // Click close button
    const closeBtn = overlayEl.querySelector('.close-btn') as HTMLButtonElement;
    closeBtn.click();
    expect(overlayEl.classList.contains('active')).toBe(false);
    expect(onCloseSpy).toHaveBeenCalled();
  });

  it('should close when clicking on overlay background', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    
    // Dispatch click directly on overlay container
    overlayEl.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(overlayEl.classList.contains('active')).toBe(false);
    expect(onCloseSpy).toHaveBeenCalled();
  });

  it('should switch color mode when control buttons are clicked', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    const entropyBtn = overlayEl.querySelector('button[data-mode="entropy"]') as HTMLButtonElement;
    const permissionBtn = overlayEl.querySelector('button[data-mode="permission"]') as HTMLButtonElement;
    const sectionBtn = overlayEl.querySelector('button[data-mode="section"]') as HTMLButtonElement;

    // Check default active button
    expect(sectionBtn.classList.contains('active')).toBe(true);

    // Switch to entropy
    entropyBtn.click();
    expect(entropyBtn.classList.contains('active')).toBe(true);
    expect(sectionBtn.classList.contains('active')).toBe(false);
    
    // Switch to permission
    permissionBtn.click();
    expect(permissionBtn.classList.contains('active')).toBe(true);
    expect(entropyBtn.classList.contains('active')).toBe(false);
  });

  it('should navigate to offset when cell is clicked', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    
    // Click the first cell in grid
    const firstCell = overlayEl.querySelector('.grid-cell') as HTMLDivElement;
    expect(firstCell).not.toBeNull();
    firstCell.click();

    expect(onNavigateSpy).toHaveBeenCalledWith(0, 0x1000);
    expect(overlayEl.classList.contains('active')).toBe(false);
  });

  it('should navigate to offset when section bar segment is clicked', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    
    // Click the second section bar segment
    const segments = overlayEl.querySelectorAll('.mem-map-bar-segment');
    expect(segments.length).toBe(2);
    (segments[1] as HTMLDivElement).click();

    expect(onNavigateSpy).toHaveBeenCalledWith(512, 0x2000);
    expect(overlayEl.classList.contains('active')).toBe(false);
  });

  it('should update inspector on hover and handle hover leave', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    const cells = overlayEl.querySelectorAll('.grid-cell');
    
    // Hover the first cell (which belongs to .text section, offset 0)
    const firstCell = cells[0] as HTMLDivElement;
    firstCell.dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));

    const secEl = overlayEl.querySelector('#inspect-section')!;
    const offsetsEl = overlayEl.querySelector('#inspect-offsets')!;
    const addrsEl = overlayEl.querySelector('#inspect-addresses')!;
    const permsEl = overlayEl.querySelector('#inspect-perms')!;
    const entrEl = overlayEl.querySelector('#inspect-entropy')!;
    const previewEl = overlayEl.querySelector('#inspect-preview')!;

    expect(secEl.textContent).toBe('.text');
    expect(offsetsEl.textContent).toContain('0x0');
    expect(addrsEl.textContent).toContain('0x1000');
    expect(permsEl.textContent).toBe('R-X');
    expect(entrEl.textContent).not.toBe('-');
    expect(previewEl.querySelectorAll('.bytes-preview-cell').length).toBe(16);

    // Hover a cell outside of sections (e.g. if we had binaryData longer than sections, but here binaryData is exactly covered by sections).
    // Clean up the first overlay first to avoid duplicate ID issues in JSDOM
    overlay.hide();
    overlayEl.remove();

    // Let's create an overlay with empty sections to test non-section behaviour.
    const emptySecOverlay = new MemoryMapOverlay(binaryData, [], {
      onNavigate: onNavigateSpy,
    });
    emptySecOverlay.show();
    const emptyOverlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;
    const emptyCells = emptyOverlayEl.querySelectorAll('.grid-cell');
    (emptyCells[0] as HTMLDivElement).dispatchEvent(new MouseEvent('mouseenter', { bubbles: true }));

    expect(emptyOverlayEl.querySelector('#inspect-section')?.textContent).toBe('Raw binary (No Section)');
    expect(emptyOverlayEl.querySelector('#inspect-addresses')?.textContent).toBe('N/A');
    expect(emptyOverlayEl.querySelector('#inspect-perms')?.textContent).toBe('R--');
  });

  it('should render legends properly for each mode', () => {
    const overlay = new MemoryMapOverlay(binaryData, sections, {
      onNavigate: onNavigateSpy,
      onClose: onCloseSpy,
    });

    overlay.show();
    const overlayEl = document.querySelector('.mem-map-overlay') as HTMLElement;

    // Check legend for section mode
    let legendItems = overlayEl.querySelectorAll('.legend-item');
    expect(legendItems.length).toBe(2);
    expect(legendItems[0].textContent).toContain('.text');
    expect(legendItems[1].textContent).toContain('.data');

    // Switch to entropy mode and check legend
    const entropyBtn = overlayEl.querySelector('button[data-mode="entropy"]') as HTMLButtonElement;
    entropyBtn.click();
    legendItems = overlayEl.querySelectorAll('.legend-item');
    expect(legendItems.length).toBe(4);
    expect(legendItems[0].textContent).toContain('Low');
    expect(legendItems[3].textContent).toContain('Packed/Encrypted');

    // Switch to permission mode and check legend
    const permissionBtn = overlayEl.querySelector('button[data-mode="permission"]') as HTMLButtonElement;
    permissionBtn.click();
    legendItems = overlayEl.querySelectorAll('.legend-item');
    expect(legendItems.length).toBe(4);
    expect(legendItems[0].textContent).toContain('R-X');
  });
});
