import { FunctionCallGraph, FCGNode } from '../analyzer/fcg.js';

export interface FCGVisualizerOptions {
  onNodeSelect?: (address: number) => void;
  theme?: {
    background?: string;
    nodeBg?: string;
    nodeBorder?: string;
    nodeHeaderBg?: string;
    nodeTextColor?: string;
    accentColor?: string;
    selectedColor?: string;
  };
}

export class FCGVisualizer {
  private container: HTMLElement;
  private graph: FunctionCallGraph;
  private options: FCGVisualizerOptions;

  // SVG elements
  private svg!: SVGSVGElement;
  private zoomGroup!: SVGGElement;
  private edgesGroup!: SVGGElement;
  private nodesGroup!: SVGGElement;

  // Interaction State
  private zoomScale = 1.0;
  private panX = 0;
  private panY = 0;
  private isDragging = false;
  private startDragX = 0;
  private startDragY = 0;
  private startPanX = 0;
  private startPanY = 0;
  private selectedNodeId: string | null = null;
  private hoveredNodeId: string | null = null;

  // Layout Config
  private readonly nodeWidth = 220;
  private readonly nodeHeight = 60;
  private readonly horizontalGap = 80;
  private readonly verticalGap = 120;

  // Cached positions
  private nodePositions = new Map<string, { x: number; y: number }>();

  constructor(
    container: HTMLElement,
    graph: FunctionCallGraph,
    options: FCGVisualizerOptions = {}
  ) {
    this.container = container;
    this.graph = graph;
    this.options = options;

    this.initStyles();
    this.initDOM();
    this.render();
  }

  private initStyles() {
    const styleId = 'fcg-visualizer-styles';
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style');
      style.id = styleId;
      style.textContent = `
        .fcg-visualizer-root {
          width: 100%;
          height: 100%;
          position: relative;
          background-color: var(--fcg-bg, #0B0F19);
          overflow: hidden;
          font-family: 'Outfit', system-ui, -apple-system, sans-serif;
          user-select: none;
          box-sizing: border-box;
        }

        .fcg-svg-canvas {
          width: 100%;
          height: 100%;
          display: block;
          cursor: grab;
        }

        .fcg-svg-canvas:active {
          cursor: grabbing;
        }

        /* SVG Node Styling */
        .fcg-node-rect {
          fill: var(--fcg-node-bg, #161B26);
          stroke: var(--fcg-node-border, #283145);
          stroke-width: 1.5px;
          rx: 8px;
          ry: 8px;
          transition: all 0.2s ease;
          cursor: pointer;
        }

        .fcg-node-rect:hover {
          stroke: var(--fcg-accent, #6366F1);
          filter: drop-shadow(0px 4px 10px rgba(99, 102, 241, 0.2));
        }

        .fcg-node-rect.selected {
          stroke: var(--fcg-selected, #8B5CF6);
          stroke-width: 2.5px;
          filter: drop-shadow(0px 4px 15px rgba(139, 92, 246, 0.35));
        }

        .fcg-node-rect.dimmed {
          opacity: 0.3;
        }

        .fcg-node-text-title {
          font-size: 13px;
          font-weight: 600;
          fill: var(--fcg-text-primary, #E2E8F0);
          pointer-events: none;
          transition: opacity 0.2s;
        }

        .fcg-node-text-subtitle {
          font-size: 11px;
          font-family: 'Fira Code', 'Courier New', monospace;
          fill: var(--fcg-text-muted, #94A3B8);
          pointer-events: none;
          transition: opacity 0.2s;
        }

        .fcg-node-text-title.dimmed,
        .fcg-node-text-subtitle.dimmed {
          opacity: 0.3;
        }

        /* Edge Styling */
        .fcg-edge {
          fill: none;
          stroke: #334155;
          stroke-width: 1.5px;
          transition: stroke 0.2s, stroke-width 0.2s, opacity 0.2s;
        }

        .fcg-edge.dimmed {
          opacity: 0.1;
        }

        .fcg-edge.highlighted-callee {
          stroke: #6366F1;
          stroke-width: 2.5px;
          opacity: 1;
        }

        .fcg-edge.highlighted-caller {
          stroke: #10B981;
          stroke-width: 2.5px;
          opacity: 1;
        }

        /* Controls Panel */
        .fcg-controls {
          position: absolute;
          bottom: 16px;
          right: 16px;
          display: flex;
          gap: 8px;
          background: rgba(15, 23, 42, 0.85);
          backdrop-filter: blur(12px);
          padding: 8px;
          border-radius: 8px;
          border: 1px solid rgba(255, 255, 255, 0.08);
          z-index: 10;
        }

        .fcg-btn {
          background: #1E293B;
          border: 1px solid #475569;
          color: #E2E8F0;
          padding: 6px 12px;
          font-size: 12px;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 500;
          transition: background 0.15s, border-color 0.15s;
        }

        .fcg-btn:hover {
          background: #334155;
          border-color: #64748b;
        }

        .fcg-btn:active {
          background: #475569;
        }

        .fcg-placeholder {
          display: flex;
          align-items: center;
          justify-content: center;
          height: 100%;
          color: #94A3B8;
          font-size: 14px;
        }
      `;
      document.head.appendChild(style);
    }
  }

  private initDOM() {
    this.container.innerHTML = '';
    this.container.classList.add('fcg-visualizer-root');

    if (this.graph.nodes.length === 0) {
      const placeholder = document.createElement('div');
      placeholder.className = 'fcg-placeholder';
      placeholder.textContent =
        'No functions available to construct Call Graph';
      this.container.appendChild(placeholder);
      return;
    }

    const theme = this.options.theme || {};
    if (theme.background)
      this.container.style.setProperty('--fcg-bg', theme.background);
    if (theme.nodeBg)
      this.container.style.setProperty('--fcg-node-bg', theme.nodeBg);
    if (theme.nodeBorder)
      this.container.style.setProperty('--fcg-node-border', theme.nodeBorder);
    if (theme.nodeTextColor)
      this.container.style.setProperty(
        '--fcg-text-primary',
        theme.nodeTextColor
      );
    if (theme.accentColor)
      this.container.style.setProperty('--fcg-accent', theme.accentColor);
    if (theme.selectedColor)
      this.container.style.setProperty('--fcg-selected', theme.selectedColor);

    // SVG Element
    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('class', 'fcg-svg-canvas');
    this.container.appendChild(this.svg);

    // Arrow markers
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.appendChild(this.createArrowMarker('fcg-arrow-default', '#334155'));
    defs.appendChild(this.createArrowMarker('fcg-arrow-callee', '#6366F1'));
    defs.appendChild(this.createArrowMarker('fcg-arrow-caller', '#10B981'));
    this.svg.appendChild(defs);

    // Main Zoom Group
    this.zoomGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );
    this.svg.appendChild(this.zoomGroup);

    // Grid Background Pattern
    const gridPattern = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'pattern'
    );
    gridPattern.setAttribute('id', 'fcg-grid-pattern');
    gridPattern.setAttribute('width', '40');
    gridPattern.setAttribute('height', '40');
    gridPattern.setAttribute('patternUnits', 'userSpaceOnUse');

    const gridPath = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'path'
    );
    gridPath.setAttribute('d', 'M 40 0 L 0 0 0 40');
    gridPath.setAttribute('fill', 'none');
    gridPath.setAttribute('stroke', 'rgba(255, 255, 255, 0.02)');
    gridPath.setAttribute('stroke-width', '1');
    gridPattern.appendChild(gridPath);
    defs.appendChild(gridPattern);

    const gridRect = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'rect'
    );
    gridRect.setAttribute('width', '100%');
    gridRect.setAttribute('height', '100%');
    gridRect.setAttribute('fill', 'url(#fcg-grid-pattern)');
    this.svg.insertBefore(gridRect, this.zoomGroup);

    // Sub-layers
    this.edgesGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );
    this.zoomGroup.appendChild(this.edgesGroup);

    this.nodesGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );
    this.zoomGroup.appendChild(this.nodesGroup);

    // Controls Panel
    const controls = document.createElement('div');
    controls.className = 'fcg-controls';

    const btnReset = document.createElement('button');
    btnReset.className = 'fcg-btn';
    btnReset.textContent = '🎯 Reset view';
    btnReset.onclick = () => this.resetView();

    const btnZoomIn = document.createElement('button');
    btnZoomIn.className = 'fcg-btn';
    btnZoomIn.textContent = '➕ Zoom In';
    btnZoomIn.onclick = () => this.zoom(1.2);

    const btnZoomOut = document.createElement('button');
    btnZoomOut.className = 'fcg-btn';
    btnZoomOut.textContent = '➖ Zoom Out';
    btnZoomOut.onclick = () => this.zoom(0.8);

    controls.appendChild(btnReset);
    controls.appendChild(btnZoomIn);
    controls.appendChild(btnZoomOut);
    this.container.appendChild(controls);

    this.setupEventListeners();
  }

  private createArrowMarker(id: string, color: string): SVGMarkerElement {
    const marker = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'marker'
    );
    marker.setAttribute('id', id);
    marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '6');
    marker.setAttribute('refY', '5');
    marker.setAttribute('markerWidth', '6');
    marker.setAttribute('markerHeight', '6');
    marker.setAttribute('orient', 'auto-start-reverse');

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M 0 1 L 10 5 L 0 9 z');
    path.setAttribute('fill', color);
    marker.appendChild(path);

    return marker;
  }

  private handleMouseMove = (e: MouseEvent) => {
    if (this.isDragging) {
      const dx = e.clientX - this.startDragX;
      const dy = e.clientY - this.startDragY;
      this.panX = this.startPanX + dx;
      this.panY = this.startPanY + dy;
      this.updateTransform();
    }
  };

  private handleMouseUp = () => {
    this.isDragging = false;
  };

  private setupEventListeners() {
    this.svg.addEventListener('mousedown', (e) => {
      if (e.button === 0) {
        this.isDragging = true;
        this.startDragX = e.clientX;
        this.startDragY = e.clientY;
        this.startPanX = this.panX;
        this.startPanY = this.panY;
      }
    });

    window.addEventListener('mousemove', this.handleMouseMove);

    window.addEventListener('mouseup', this.handleMouseUp);

    this.svg.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const zoomFactor = 1.1;
        const nextScale =
          e.deltaY < 0
            ? this.zoomScale * zoomFactor
            : this.zoomScale / zoomFactor;

        // Restrict zoom limits
        if (nextScale < 0.1 || nextScale > 5.0) return;

        const rect = this.svg.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        // Zoom centered on cursor position
        this.panX =
          mouseX - (mouseX - this.panX) * (nextScale / this.zoomScale);
        this.panY =
          mouseY - (mouseY - this.panY) * (nextScale / this.zoomScale);
        this.zoomScale = nextScale;

        this.updateTransform();
      },
      { passive: false }
    );
  }

  /**
   * Clean up event listeners and empty container.
   */
  public destroy() {
    window.removeEventListener('mousemove', this.handleMouseMove);
    window.removeEventListener('mouseup', this.handleMouseUp);
    this.container.innerHTML = '';
  }

  private zoom(factor: number) {
    const nextScale = this.zoomScale * factor;
    if (nextScale < 0.1 || nextScale > 5.0) return;

    const rect = this.svg.getBoundingClientRect();
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    this.panX = centerX - (centerX - this.panX) * factor;
    this.panY = centerY - (centerY - this.panY) * factor;
    this.zoomScale = nextScale;

    this.updateTransform();
  }

  private resetView() {
    this.zoomScale = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.updateTransform();
  }

  private updateTransform() {
    this.zoomGroup.setAttribute(
      'transform',
      `translate(${this.panX}, ${this.panY}) scale(${this.zoomScale})`
    );
  }

  private computeLayout() {
    this.nodePositions.clear();

    const nodes = this.graph.nodes;
    const nodeMap = new Map<string, FCGNode>();
    nodes.forEach((n) => nodeMap.set(n.id, n));

    // Calculate level layers using simple relaxation
    const layers = new Map<string, number>();
    nodes.forEach((n) => layers.set(n.id, 0));

    const maxIterations = Math.min(nodes.length, 50);
    for (let iter = 0; iter < maxIterations; iter++) {
      let changed = false;
      for (const edge of this.graph.edges) {
        const fromLayer = layers.get(edge.from) || 0;
        const toLayer = layers.get(edge.to) || 0;

        if (fromLayer + 1 > toLayer) {
          layers.set(edge.to, fromLayer + 1);
          changed = true;
        }
      }
      if (!changed) break;
    }

    // Group by layers
    const layerGroups = new Map<number, string[]>();
    layers.forEach((layer, nodeId) => {
      if (!layerGroups.has(layer)) {
        layerGroups.set(layer, []);
      }
      layerGroups.get(layer)!.push(nodeId);
    });

    const sortedLayers = Array.from(layerGroups.keys()).sort((a, b) => a - b);

    // Compute coordinates
    let currentY = 50;
    sortedLayers.forEach((layer) => {
      const nodeIds = layerGroups.get(layer) || [];
      const totalWidth =
        nodeIds.length * this.nodeWidth +
        (nodeIds.length - 1) * this.horizontalGap;
      const startX = -totalWidth / 2 + 300; // Center graph layout horizontally

      nodeIds.forEach((nodeId, index) => {
        const x = startX + index * (this.nodeWidth + this.horizontalGap);
        this.nodePositions.set(nodeId, { x, y: currentY });
      });

      currentY += this.nodeHeight + this.verticalGap;
    });

    // Center view onto the root node
    if (nodes.length > 0) {
      const rootPos = this.nodePositions.get(nodes[0].id);
      if (rootPos) {
        const rect = this.svg.getBoundingClientRect();
        this.panX = rect.width / 2 - rootPos.x - this.nodeWidth / 2;
        this.panY = 60;
        this.updateTransform();
      }
    }
  }

  private render() {
    if (this.graph.nodes.length === 0) return;

    this.computeLayout();

    // Clear previous
    this.edgesGroup.innerHTML = '';
    this.nodesGroup.innerHTML = '';

    // Draw Edges
    this.graph.edges.forEach((edge, index) => {
      const fromPos = this.nodePositions.get(edge.from);
      const toPos = this.nodePositions.get(edge.to);

      if (fromPos && toPos) {
        const path = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'path'
        );
        path.setAttribute('id', `fcg-edge-${index}`);
        path.setAttribute('class', 'fcg-edge');
        path.setAttribute('data-from', edge.from);
        path.setAttribute('data-to', edge.to);

        // Control points for cubic Bezier curves
        const x1 = fromPos.x + this.nodeWidth / 2;
        const y1 = fromPos.y + this.nodeHeight;
        const x2 = toPos.x + this.nodeWidth / 2;
        const y2 = toPos.y;

        const controlOffset = Math.min(100, Math.abs(y2 - y1) * 0.5);
        const d = `M ${x1} ${y1} C ${x1} ${y1 + controlOffset}, ${x2} ${y2 - controlOffset}, ${x2} ${y2}`;

        path.setAttribute('d', d);
        path.setAttribute('marker-end', 'url(#fcg-arrow-default)');
        this.edgesGroup.appendChild(path);
      }
    });

    // Draw Nodes
    this.graph.nodes.forEach((node) => {
      const pos = this.nodePositions.get(node.id);
      if (pos) {
        const nodeG = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'g'
        );
        nodeG.setAttribute('id', node.id);

        // Rect
        const rect = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'rect'
        );
        rect.setAttribute('x', pos.x.toString());
        rect.setAttribute('y', pos.y.toString());
        rect.setAttribute('width', this.nodeWidth.toString());
        rect.setAttribute('height', this.nodeHeight.toString());
        rect.setAttribute('class', 'fcg-node-rect');
        if (node.id === this.selectedNodeId) {
          rect.classList.add('selected');
        }

        // Click selection
        rect.onclick = () => {
          this.selectNode(node);
        };

        // Hover effect for edges
        rect.onmouseenter = () => this.highlightNodeConnections(node.id);
        rect.onmouseleave = () => this.clearHighlights();

        nodeG.appendChild(rect);

        // Name text
        const titleText = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'text'
        );
        titleText.setAttribute('x', (pos.x + 12).toString());
        titleText.setAttribute('y', (pos.y + 24).toString());
        titleText.setAttribute('class', 'fcg-node-text-title');
        titleText.textContent = this.truncateText(node.name, 24);
        nodeG.appendChild(titleText);

        // Address subtitle text
        const subtitleText = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'text'
        );
        subtitleText.setAttribute('x', (pos.x + 12).toString());
        subtitleText.setAttribute('y', (pos.y + 45).toString());
        subtitleText.setAttribute('class', 'fcg-node-text-subtitle');
        subtitleText.textContent = `0x${node.address.toString(16).toUpperCase()}`;
        nodeG.appendChild(subtitleText);

        this.nodesGroup.appendChild(nodeG);
      }
    });
  }

  private truncateText(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
  }

  private highlightNodeConnections(nodeId: string) {
    this.hoveredNodeId = nodeId;

    // Highlight nodes
    const nodeElements = this.nodesGroup.children;
    for (let i = 0; i < nodeElements.length; i++) {
      const nodeG = nodeElements[i] as SVGGElement;
      const rect = nodeG.querySelector('.fcg-node-rect');
      const title = nodeG.querySelector('.fcg-node-text-title');
      const subtitle = nodeG.querySelector('.fcg-node-text-subtitle');

      const isConnected =
        nodeG.id === nodeId ||
        this.graph.edges.some(
          (e) =>
            (e.from === nodeId && e.to === nodeG.id) ||
            (e.to === nodeId && e.from === nodeG.id)
        );

      if (!isConnected) {
        rect?.classList.add('dimmed');
        title?.classList.add('dimmed');
        subtitle?.classList.add('dimmed');
      }
    }

    // Highlight edges
    const edgeElements = this.edgesGroup.children;
    for (let i = 0; i < edgeElements.length; i++) {
      const path = edgeElements[i] as SVGPathElement;
      const from = path.getAttribute('data-from');
      const to = path.getAttribute('data-to');

      if (from === nodeId) {
        path.classList.add('highlighted-callee');
        path.setAttribute('marker-end', 'url(#fcg-arrow-callee)');
      } else if (to === nodeId) {
        path.classList.add('highlighted-caller');
        path.setAttribute('marker-end', 'url(#fcg-arrow-caller)');
      } else {
        path.classList.add('dimmed');
      }
    }
  }

  private clearHighlights() {
    this.hoveredNodeId = null;

    // Reset nodes
    const nodeElements = this.nodesGroup.children;
    for (let i = 0; i < nodeElements.length; i++) {
      const nodeG = nodeElements[i] as SVGGElement;
      const rect = nodeG.querySelector('.fcg-node-rect');
      const title = nodeG.querySelector('.fcg-node-text-title');
      const subtitle = nodeG.querySelector('.fcg-node-text-subtitle');

      rect?.classList.remove('dimmed');
      title?.classList.remove('dimmed');
      subtitle?.classList.remove('dimmed');
    }

    // Reset edges
    const edgeElements = this.edgesGroup.children;
    for (let i = 0; i < edgeElements.length; i++) {
      const path = edgeElements[i] as SVGPathElement;
      path.classList.remove(
        'highlighted-callee',
        'highlighted-caller',
        'dimmed'
      );
      path.setAttribute('marker-end', 'url(#fcg-arrow-default)');
    }
  }

  public selectNode(node: FCGNode) {
    this.selectedNodeId = node.id;

    // Update styling
    const nodeElements = this.nodesGroup.children;
    for (let i = 0; i < nodeElements.length; i++) {
      const nodeG = nodeElements[i] as SVGGElement;
      const rect = nodeG.querySelector('.fcg-node-rect');
      if (nodeG.id === node.id) {
        rect?.classList.add('selected');
      } else {
        rect?.classList.remove('selected');
      }
    }

    // Callback
    if (this.options.onNodeSelect) {
      this.options.onNodeSelect(node.address);
    }
  }

  public selectNodeByAddress(address: number) {
    const node = this.graph.nodes.find((n) => n.address === address);
    if (node) {
      this.selectNode(node);
      const pos = this.nodePositions.get(node.id);
      if (pos) {
        // Center view on this node
        const rect = this.svg.getBoundingClientRect();
        this.panX = rect.width / 2 - pos.x - this.nodeWidth / 2;
        this.panY = rect.height / 2 - pos.y - this.nodeHeight / 2;
        this.updateTransform();
      }
    }
  }
}
