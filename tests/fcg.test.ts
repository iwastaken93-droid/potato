// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { buildFCG } from '../src/analyzer/fcg.js';
import { FCGVisualizer } from '../src/ui/fcgVisualizer.js';
import type { Symbol, Instruction } from '../src/disassembler/types.js';

describe('Function Call Graph (FCG) Analyzer Unit Tests', () => {
  it('should return an empty graph if there are no functions', () => {
    const symbols: Symbol[] = [
      {
        name: 'data_val',
        address: 0x1000,
        type: 'object',
        binding: 'global',
        size: 4,
      },
    ];
    const instructions: Instruction[] = [];
    const graph = buildFCG(symbols, instructions);
    expect(graph.nodes).toEqual([]);
    expect(graph.edges).toEqual([]);
  });

  it('should construct nodes for functions and ignore non-functions', () => {
    const symbols: Symbol[] = [
      {
        name: 'funcA',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
      {
        name: 'data_val',
        address: 0x1050,
        type: 'object',
        binding: 'global',
        size: 4,
      },
      {
        name: 'funcB',
        address: 0x2000,
        type: 'function',
        binding: 'global',
        size: 0x30,
      },
    ];
    const instructions: Instruction[] = [];
    const graph = buildFCG(symbols, instructions);

    expect(graph.nodes.length).toBe(2);
    expect(graph.nodes[0].name).toBe('funcA');
    expect(graph.nodes[0].id).toBe('func_0x1000');
    expect(graph.nodes[1].name).toBe('funcB');
    expect(graph.nodes[1].id).toBe('func_0x2000');
    expect(graph.edges).toEqual([]);
  });

  it('should identify direct function calls using immediate operand', () => {
    const symbols: Symbol[] = [
      {
        name: 'funcA',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
      {
        name: 'funcB',
        address: 0x2000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
    ];

    const instructions: Instruction[] = [
      // Call inside funcA calling funcB
      {
        address: 0x1004,
        mnemonic: 'call',
        opStr: '0x2000',
        bytes: [0xe8, 0xf7, 0x0f, 0x00, 0x00],
        operands: [{ type: 'imm', imm: BigInt(0x2000) }],
      },
    ];

    const graph = buildFCG(symbols, instructions);

    expect(graph.nodes.length).toBe(2);
    expect(graph.edges.length).toBe(1);
    expect(graph.edges[0]).toEqual({
      from: 'func_0x1000',
      to: 'func_0x2000',
      count: 1,
    });

    const nodeA = graph.nodes.find((n) => n.id === 'func_0x1000')!;
    const nodeB = graph.nodes.find((n) => n.id === 'func_0x2000')!;
    expect(nodeA.callees).toContain('func_0x2000');
    expect(nodeB.callers).toContain('func_0x1000');
  });

  it('should fallback to parsing address from opStr if direct operand has no imm', () => {
    const symbols: Symbol[] = [
      {
        name: 'funcA',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
      {
        name: 'funcB',
        address: 0x2000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
    ];

    const instructions: Instruction[] = [
      {
        address: 0x1004,
        mnemonic: 'bl',
        opStr: 'funcB (0x2000)',
        bytes: [],
      },
    ];

    const graph = buildFCG(symbols, instructions);

    expect(graph.edges.length).toBe(1);
    expect(graph.edges[0].to).toBe('func_0x2000');
  });

  it('should ignore self calls', () => {
    const symbols: Symbol[] = [
      {
        name: 'funcA',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
    ];

    const instructions: Instruction[] = [
      {
        address: 0x1008,
        mnemonic: 'call',
        opStr: '0x1000',
        bytes: [],
        operands: [{ type: 'imm', imm: BigInt(0x1000) }],
      },
    ];

    const graph = buildFCG(symbols, instructions);
    expect(graph.edges.length).toBe(0);
    expect(graph.nodes[0].callees).toEqual([]);
    expect(graph.nodes[0].callers).toEqual([]);
  });

  it('should correctly increment call counts on multiple calls', () => {
    const symbols: Symbol[] = [
      {
        name: 'funcA',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
      {
        name: 'funcB',
        address: 0x2000,
        type: 'function',
        binding: 'global',
        size: 0x20,
      },
    ];

    const instructions: Instruction[] = [
      {
        address: 0x1004,
        mnemonic: 'call',
        opStr: '0x2000',
        bytes: [],
        operands: [{ type: 'imm', imm: BigInt(0x2000) }],
      },
      {
        address: 0x100c,
        mnemonic: 'call',
        opStr: '0x2000',
        bytes: [],
        operands: [{ type: 'imm', imm: BigInt(0x2000) }],
      },
    ];

    const graph = buildFCG(symbols, instructions);
    expect(graph.edges.length).toBe(1);
    expect(graph.edges[0].count).toBe(2);
  });
});

describe('FCGVisualizer Component Unit & Integration Tests', () => {
  let container: HTMLElement;
  let sampleGraph: any;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);

    sampleGraph = {
      nodes: [
        {
          id: 'func_0x1000',
          name: 'main',
          address: 0x1000,
          size: 0x50,
          callers: [],
          callees: ['func_0x2000'],
        },
        {
          id: 'func_0x2000',
          name: 'helper',
          address: 0x2000,
          size: 0x30,
          callers: ['func_0x1000'],
          callees: [],
        },
      ],
      edges: [{ from: 'func_0x1000', to: 'func_0x2000', count: 1 }],
    };

    // Mock getBoundingClientRect for layout computations
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
      x: 0,
      y: 0,
      width: 800,
      height: 600,
      top: 0,
      left: 0,
      bottom: 600,
      right: 800,
      toJSON: () => {},
    });
  });

  afterEach(() => {
    document.body.removeChild(container);
    vi.restoreAllMocks();
  });

  it('should show placeholder if the graph is empty', () => {
    const emptyGraph = { nodes: [], edges: [] };
    new FCGVisualizer(container, emptyGraph);

    expect(container.textContent).toContain(
      'No functions available to construct Call Graph'
    );
    expect(container.querySelector('svg')).toBeNull();
  });

  it('should initialize and render nodes/edges in SVG when graph is provided', () => {
    new FCGVisualizer(container, sampleGraph);

    const svg = container.querySelector('svg');
    expect(svg).not.toBeNull();

    // Check stylesheet has been appended
    expect(document.getElementById('fcg-visualizer-styles')).not.toBeNull();

    // Check SVG nodes are rendered
    const nodeElements = container.querySelectorAll('g[id^="func_"]');
    expect(nodeElements.length).toBe(2);

    expect(
      nodeElements[0].querySelector('.fcg-node-text-title')?.textContent
    ).toBe('main');
    expect(
      nodeElements[0].querySelector('.fcg-node-text-subtitle')?.textContent
    ).toBe('0x1000');

    expect(
      nodeElements[1].querySelector('.fcg-node-text-title')?.textContent
    ).toBe('helper');
    expect(
      nodeElements[1].querySelector('.fcg-node-text-subtitle')?.textContent
    ).toBe('0x2000');

    // Check SVG edges are rendered
    const edgePaths = container.querySelectorAll('path.fcg-edge');
    expect(edgePaths.length).toBe(1);
    expect(edgePaths[0].getAttribute('data-from')).toBe('func_0x1000');
    expect(edgePaths[0].getAttribute('data-to')).toBe('func_0x2000');
  });

  it('should call onNodeSelect when a node is clicked', () => {
    const onNodeSelectSpy = vi.fn();
    const visualizer = new FCGVisualizer(container, sampleGraph, {
      onNodeSelect: onNodeSelectSpy,
    });

    const mainNodeRect = container.querySelector(
      '#func_0x1000 .fcg-node-rect'
    ) as SVGRectElement;
    expect(mainNodeRect).not.toBeNull();

    mainNodeRect.dispatchEvent(new MouseEvent('click'));

    expect(onNodeSelectSpy).toHaveBeenCalledWith(0x1000);
  });

  it('should highlight caller/callee connections on mouse hover and clear on leave', () => {
    new FCGVisualizer(container, sampleGraph);

    const mainNodeRect = container.querySelector(
      '#func_0x1000 .fcg-node-rect'
    ) as SVGRectElement;
    expect(mainNodeRect).not.toBeNull();

    // Trigger enter hover
    mainNodeRect.dispatchEvent(new MouseEvent('mouseenter'));

    const helperNodeRect = container.querySelector(
      '#func_0x2000 .fcg-node-rect'
    ) as SVGRectElement;
    const edgePath = container.querySelector('path.fcg-edge') as SVGPathElement;

    // The hovered node and connected node should NOT be dimmed
    expect(mainNodeRect.classList.contains('dimmed')).toBe(false);
    expect(helperNodeRect.classList.contains('dimmed')).toBe(false);
    // The edge should be highlighted
    expect(edgePath.classList.contains('highlighted-callee')).toBe(true);

    // Trigger leave hover
    mainNodeRect.dispatchEvent(new MouseEvent('mouseleave'));
    expect(edgePath.classList.contains('highlighted-callee')).toBe(false);
    expect(edgePath.classList.contains('dimmed')).toBe(false);
  });

  it('should support selection by address and update view centering', () => {
    const visualizer = new FCGVisualizer(container, sampleGraph);

    const selectSpy = vi.spyOn(visualizer, 'selectNode');
    visualizer.selectNodeByAddress(0x2000);

    expect(selectSpy).toHaveBeenCalled();
    const helperNodeRect = container.querySelector(
      '#func_0x2000 .fcg-node-rect'
    ) as SVGRectElement;
    expect(helperNodeRect.classList.contains('selected')).toBe(true);
  });

  it('should update visualizer options and custom themes', () => {
    new FCGVisualizer(container, sampleGraph, {
      theme: {
        background: '#111',
        nodeBg: '#222',
        nodeBorder: '#333',
        accentColor: '#444',
        selectedColor: '#555',
      },
    });

    expect(container.style.getPropertyValue('--fcg-bg')).toBe('#111');
    expect(container.style.getPropertyValue('--fcg-node-bg')).toBe('#222');
    expect(container.style.getPropertyValue('--fcg-node-border')).toBe('#333');
    expect(container.style.getPropertyValue('--fcg-accent')).toBe('#444');
    expect(container.style.getPropertyValue('--fcg-selected')).toBe('#555');
  });

  it('should respond to controls zoom and reset buttons', () => {
    const visualizer = new FCGVisualizer(container, sampleGraph);

    const buttons = container.querySelectorAll('.fcg-btn');
    expect(buttons.length).toBe(3);

    const btnReset = buttons[0] as HTMLButtonElement;
    const btnZoomIn = buttons[1] as HTMLButtonElement;
    const btnZoomOut = buttons[2] as HTMLButtonElement;

    // Click Zoom In
    btnZoomIn.click();
    // Zoom factor increases
    expect((visualizer as any).zoomScale).toBeGreaterThan(1.0);

    // Click Reset
    btnReset.click();
    expect((visualizer as any).zoomScale).toBe(1.0);

    // Click Zoom Out
    btnZoomOut.click();
    expect((visualizer as any).zoomScale).toBeLessThan(1.0);
  });

  it('should support mouse dragging and zooming via events', () => {
    const visualizer = new FCGVisualizer(container, sampleGraph);
    const svg = container.querySelector('svg') as SVGSVGElement;

    const initialPanX = (visualizer as any).panX;
    const initialPanY = (visualizer as any).panY;

    // Simulate drag start
    svg.dispatchEvent(
      new MouseEvent('mousedown', { button: 0, clientX: 100, clientY: 100 })
    );
    expect((visualizer as any).isDragging).toBe(true);

    // Simulate drag move
    window.dispatchEvent(
      new MouseEvent('mousemove', { clientX: 150, clientY: 120 })
    );
    expect((visualizer as any).panX).toBe(initialPanX + 50);
    expect((visualizer as any).panY).toBe(initialPanY + 20);

    // Simulate drag end
    window.dispatchEvent(new MouseEvent('mouseup'));
    expect((visualizer as any).isDragging).toBe(false);

    // Simulate wheel event for zooming
    const wheelEvent = new WheelEvent('wheel', {
      deltaY: -100,
      clientX: 400,
      clientY: 300,
    });
    svg.dispatchEvent(wheelEvent);
    expect((visualizer as any).zoomScale).toBeGreaterThan(1.0);
  });
});
