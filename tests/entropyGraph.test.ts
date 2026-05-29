// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { EntropyGraph } from '../src/ui/entropyGraph.js';
import type { Section } from '../src/disassembler/types.js';

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};

describe('EntropyGraph Component Tests', () => {
  let container: HTMLElement;
  let graph: EntropyGraph;
  let mockCtx: any;
  let navigateSpy: any;

  beforeEach(() => {
    // Mock canvas context
    mockCtx = {
      resetTransform: vi.fn(),
      scale: vi.fn(),
      clearRect: vi.fn(),
      beginPath: vi.fn(),
      moveTo: vi.fn(),
      lineTo: vi.fn(),
      stroke: vi.fn(),
      fillText: vi.fn(),
      createLinearGradient: vi.fn().mockReturnValue({
        addColorStop: vi.fn(),
      }),
      fillStyle: '',
      strokeStyle: '',
      lineWidth: 1,
      setLineDash: vi.fn(),
      fill: vi.fn(),
      closePath: vi.fn(),
      fillRect: vi.fn(),
      arc: vi.fn(),
      roundRect: vi.fn(),
    };

    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(
      (type) => {
        if (type === '2d') return mockCtx;
        return null;
      }
    );

    // Mock parent element dimensions for canvas resizing
    Object.defineProperty(HTMLCanvasElement.prototype, 'parentElement', {
      value: {
        clientWidth: 800,
        clientHeight: 400,
      },
      writable: true,
      configurable: true,
    });

    container = document.createElement('div');
    document.body.appendChild(container);
    navigateSpy = vi.fn();
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.restoreAllMocks();
  });

  const createSampleData = () => {
    // 512 bytes: first half 0x00 (low entropy), second half random-like (high entropy)
    const data = new Uint8Array(512);
    for (let i = 256; i < 512; i++) {
      data[i] = i % 256;
    }
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 256,
        fileOffset: 0,
        fileSize: 256,
        flags: { read: true, write: false, execute: true },
        entropy: 0,
      },
      {
        name: '.data',
        virtualAddress: 0x2000,
        virtualSize: 256,
        fileOffset: 256,
        fileSize: 256,
        flags: { read: true, write: true, execute: false },
        entropy: 8,
      },
    ];
    return { data, sections };
  };

  it('should initialize and render layout structure', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    const root = container.querySelector('.entropy-graph-root');
    expect(root).not.toBeNull();

    // Check if controls are rendered
    const windowSelect = container.querySelector('#entropy-window-select');
    expect(windowSelect).not.toBeNull();
    const thresholdInput = container.querySelector('#entropy-threshold-input');
    expect(thresholdInput).not.toBeNull();

    // Check canvas existence
    const canvas = container.querySelector('#entropy-canvas');
    expect(canvas).not.toBeNull();
  });

  it('should display sections in sidebar with calculated/mapped entropy values', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    const sectionsList = container.querySelector('#entropy-sections-list');
    expect(sectionsList).not.toBeNull();
    expect(sectionsList?.textContent).toContain('.text');
    expect(sectionsList?.textContent).toContain('.data');
  });

  it('should respond to window size changes and recalculate', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    const windowSelect = container.querySelector(
      '#entropy-window-select'
    ) as HTMLSelectElement;
    expect(windowSelect.value).toBe('256');

    // Simulate change event
    windowSelect.value = '512';
    windowSelect.dispatchEvent(new Event('change'));

    // Check that we recalculate and redraw
    expect(mockCtx.clearRect).toHaveBeenCalled();
  });

  it('should respond to threshold adjustments and update sidebar/canvas', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    const thresholdInput = container.querySelector(
      '#entropy-threshold-input'
    ) as HTMLInputElement;
    expect(thresholdInput.value).toBe('7.2');

    // Simulate input event with new threshold
    thresholdInput.value = '7.5';
    thresholdInput.dispatchEvent(new Event('input'));

    expect(mockCtx.clearRect).toHaveBeenCalled();
  });

  it('should trigger navigation callback when jumping to locations from sidebar', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    // Find the jump button inside sidebar lists
    const hexJumpButton = container.querySelector(
      '.entropy-sections-list button[data-action="hex"]'
    ) as HTMLButtonElement;
    expect(hexJumpButton).not.toBeNull();

    hexJumpButton.click();
    expect(navigateSpy).toHaveBeenCalledWith(0, 'hex');
  });

  it('should update data correctly via updateData method', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, [], { onNavigate: navigateSpy });

    // Initially no sections text
    let sectionsList = container.querySelector('#entropy-sections-list');
    expect(sectionsList?.textContent).toContain('No section details available');

    // Update with section data
    graph.updateData(data, sections);
    sectionsList = container.querySelector('#entropy-sections-list');
    expect(sectionsList?.textContent).toContain('.text');
  });

  it('should handle mouse events on canvas', () => {
    const { data, sections } = createSampleData();
    graph = new EntropyGraph(container, data, sections, {
      onNavigate: navigateSpy,
    });

    const canvas = container.querySelector(
      '#entropy-canvas'
    ) as HTMLCanvasElement;
    expect(canvas).not.toBeNull();

    // Mock bounding client rect for coordinate mapping
    vi.spyOn(canvas, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      right: 800,
      bottom: 400,
      width: 800,
      height: 400,
      x: 0,
      y: 0,
      toJSON: () => {},
    });

    // Simulate mousemove on chart area
    const mouseMoveEvent = new MouseEvent('mousemove', {
      clientX: 200, // within chart coordinates
      clientY: 200,
    });
    canvas.dispatchEvent(mouseMoveEvent);

    // Redraw should be called on mousemove
    expect(mockCtx.clearRect).toHaveBeenCalled();

    // Simulate click which triggers navigation on the hovered block
    const clickEvent = new MouseEvent('click');
    canvas.dispatchEvent(clickEvent);
    expect(navigateSpy).toHaveBeenCalled();

    // Simulate mouseleave
    const mouseLeaveEvent = new MouseEvent('mouseleave');
    canvas.dispatchEvent(mouseLeaveEvent);
    expect(mockCtx.clearRect).toHaveBeenCalled();
  });
});
