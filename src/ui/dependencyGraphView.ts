import { Symbol } from '../disassembler/types.js';

interface GraphNode {
  id: string;
  label: string;
  type: 'local' | 'import' | 'export';
  x: number;
  y: number;
  address?: number;
}

interface GraphEdge {
  source: string;
  target: string;
}

export class DependencyGraphView {
  private container: HTMLElement;
  private symbols: Symbol[];
  private onAddressSelect: (address: number) => void;

  private rootEl!: HTMLDivElement;
  private svgEl!: SVGSVGElement;
  private sidebarEl!: HTMLDivElement;

  private nodes: GraphNode[] = [];
  private edges: GraphEdge[] = [];

  constructor(
    container: HTMLElement,
    symbols: Symbol[],
    onAddressSelect: (address: number) => void
  ) {
    this.container = container;
    this.symbols = symbols;
    this.onAddressSelect = onAddressSelect;

    this.initLayout();
  }

  public updateData(symbols: Symbol[]) {
    this.symbols = symbols;
    this.buildGraph();
    this.render();
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'glass-panel dep-graph-panel';
    this.rootEl.style.height = '100%';
    this.rootEl.style.display = 'grid';
    this.rootEl.style.gridTemplateColumns = '1fr 240px';
    this.rootEl.style.gap = '1rem';
    this.rootEl.style.padding = '1.5rem';

    // Inject styles
    if (!document.getElementById('dep-graph-styles')) {
      const style = document.createElement('style');
      style.id = 'dep-graph-styles';
      style.textContent = `
        .dep-graph-panel {
          background: rgba(22, 26, 33, 0.45);
          backdrop-filter: blur(12px);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
        }
        .graph-viewport {
          position: relative;
          background: rgba(15, 17, 21, 0.5);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          overflow: hidden;
          width: 100%;
          height: 100%;
        }
        .dep-svg {
          width: 100%;
          height: 100%;
          cursor: grab;
        }
        .dep-svg:active {
          cursor: grabbing;
        }
        .dep-node {
          cursor: pointer;
          transition: filter 0.2s;
        }
        .dep-node:hover {
          filter: brightness(1.2) drop-shadow(0 0 6px rgba(99, 102, 241, 0.6));
        }
        .dep-edge {
          stroke: rgba(255, 255, 255, 0.15);
          stroke-width: 1.5;
          fill: none;
          marker-end: url(#arrow);
        }
        .dep-node-text {
          fill: var(--text-primary);
          font-family: var(--font-sans);
          font-size: 11px;
          pointer-events: none;
          text-anchor: middle;
          font-weight: 500;
        }
        .dep-sidebar {
          background: rgba(15, 17, 21, 0.3);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          padding: 1rem;
          display: flex;
          flex-direction: column;
          gap: 1rem;
          overflow-y: auto;
        }
        .dep-sidebar h4 {
          font-size: 0.9rem;
          margin-bottom: 0.5rem;
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 0.25rem;
        }
        .dep-list {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }
        .dep-list-item {
          font-size: 0.8rem;
          color: var(--text-secondary);
          display: flex;
          justify-content: space-between;
          padding: 4px 8px;
          background: rgba(255, 255, 255, 0.02);
          border-radius: 4px;
          font-family: var(--font-mono);
          cursor: pointer;
        }
        .dep-list-item:hover {
          background: rgba(99, 102, 241, 0.1);
        }
      `;
      document.head.appendChild(style);
    }

    const viewport = document.createElement('div');
    viewport.className = 'graph-viewport';

    this.svgEl = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'svg'
    ) as unknown as SVGSVGElement;
    this.svgEl.setAttribute('class', 'dep-svg');

    // Add arrow marker definitions
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'marker'
    );
    marker.setAttribute('id', 'arrow');
    marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '18');
    marker.setAttribute('refY', '5');
    marker.setAttribute('markerWidth', '6');
    marker.setAttribute('markerHeight', '6');
    marker.setAttribute('orient', 'auto-start-reverse');

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z');
    path.setAttribute('fill', 'rgba(255, 255, 255, 0.3)');

    marker.appendChild(path);
    defs.appendChild(marker);
    this.svgEl.appendChild(defs);
    viewport.appendChild(this.svgEl);

    this.sidebarEl = document.createElement('div');
    this.sidebarEl.className = 'dep-sidebar';

    this.rootEl.appendChild(viewport);
    this.rootEl.appendChild(this.sidebarEl);
    this.container.appendChild(this.rootEl);

    this.buildGraph();
    this.render();
  }

  private buildGraph() {
    this.nodes = [];
    this.edges = [];

    // Create a local node for every local function, and imports/exports
    const localSyms = this.symbols.filter(
      (s) => s.type === 'function' && s.binding !== 'global'
    );
    const globalSyms = this.symbols.filter(
      (s) => s.type === 'function' && s.binding === 'global'
    );

    // 1. Add Local Nodes
    localSyms.forEach((sym, idx) => {
      this.nodes.push({
        id: sym.name,
        label: sym.name,
        type: 'local',
        x: 100 + (idx % 3) * 150,
        y: 100 + Math.floor(idx / 3) * 120,
        address: sym.address,
      });
    });

    // 2. Add Export Nodes
    globalSyms.forEach((sym, idx) => {
      this.nodes.push({
        id: sym.name,
        label: sym.name,
        type: 'export',
        x: 450,
        y: 80 + idx * 90,
        address: sym.address,
      });
    });

    // 3. Add Mock Imports/System API Nodes
    const importApis = [
      'GetProcAddress',
      'VirtualAlloc',
      'LoadLibraryA',
      'ExitProcess',
      'MessageBoxA',
      'printf',
      'malloc',
    ];
    importApis.forEach((api, idx) => {
      this.nodes.push({
        id: api,
        label: api,
        type: 'import',
        x: 600,
        y: 80 + idx * 80,
      });
    });

    // 4. Create Mock Calls/Edges
    if (this.nodes.length > 0) {
      // Connect subroutines to main/exports
      localSyms.forEach((sym) => {
        const matchingExport =
          globalSyms[Math.floor(Math.random() * globalSyms.length)];
        if (matchingExport) {
          this.edges.push({
            source: matchingExport.name,
            target: sym.name,
          });
        }

        // Randomly call some import APIs
        const randomApi =
          importApis[Math.floor(Math.random() * importApis.length)];
        this.edges.push({
          source: sym.name,
          target: randomApi,
        });
      });
    }
  }

  private render() {
    // Clear old elements (keep defs)
    const elements = this.svgEl.querySelectorAll('g, line');
    elements.forEach((el) => el.remove());

    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');

    // Draw edges
    this.edges.forEach((edge) => {
      const srcNode = this.nodes.find((n) => n.id === edge.source);
      const tgtNode = this.nodes.find((n) => n.id === edge.target);

      if (srcNode && tgtNode) {
        const line = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'line'
        );
        line.setAttribute('class', 'dep-edge');
        line.setAttribute('x1', srcNode.x.toString());
        line.setAttribute('y1', srcNode.y.toString());
        line.setAttribute('x2', tgtNode.x.toString());
        line.setAttribute('y2', tgtNode.y.toString());
        group.appendChild(line);
      }
    });

    // Draw nodes
    this.nodes.forEach((node) => {
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('class', 'dep-node');
      if (node.address !== undefined) {
        g.setAttribute('data-addr', node.address.toString());
      }

      const rect = document.createElementNS(
        'http://www.w3.org/2000/svg',
        'rect'
      );
      rect.setAttribute('x', (node.x - 60).toString());
      rect.setAttribute('y', (node.y - 20).toString());
      rect.setAttribute('width', '120');
      rect.setAttribute('height', '40');
      rect.setAttribute('rx', '8');

      // Node color coding
      let fill = 'rgba(99, 102, 241, 0.2)'; // indigo
      let stroke = '#6366f1';
      if (node.type === 'import') {
        fill = 'rgba(245, 158, 11, 0.2)'; // orange
        stroke = '#f59e0b';
      } else if (node.type === 'export') {
        fill = 'rgba(16, 185, 129, 0.2)'; // green
        stroke = '#10b981';
      }

      rect.setAttribute('fill', fill);
      rect.setAttribute('stroke', stroke);
      rect.setAttribute('stroke-width', '1.5');

      const text = document.createElementNS(
        'http://www.w3.org/2000/svg',
        'text'
      );
      text.setAttribute('x', node.x.toString());
      text.setAttribute('y', (node.y + 4).toString());
      text.setAttribute('class', 'dep-node-text');

      // Truncate label if too long
      let label = node.label;
      if (label.length > 14) {
        label = label.substring(0, 11) + '...';
      }
      text.textContent = label;

      g.appendChild(rect);
      g.appendChild(text);
      group.appendChild(g);
    });

    this.svgEl.appendChild(group);

    // Setup Click Event to navigate
    this.svgEl.addEventListener('click', (e) => {
      const nodeEl = (e.target as HTMLElement).closest(
        '.dep-node'
      ) as HTMLElement;
      if (nodeEl && nodeEl.dataset.addr) {
        const addr = parseInt(nodeEl.dataset.addr, 10);
        this.onAddressSelect(addr);
      }
    });

    // Populate Sidebar Imports list
    this.sidebarEl.innerHTML = `
      <h4>Import Modules</h4>
      <div class="dep-list">
        <div class="dep-list-item">
          <span>kernel32.dll</span>
          <span style="color: #f59e0b;">5 APIs</span>
        </div>
        <div class="dep-list-item">
          <span>user32.dll</span>
          <span style="color: #f59e0b;">1 API</span>
        </div>
        <div class="dep-list-item">
          <span>ntdll.dll</span>
          <span style="color: var(--text-muted);">Internal</span>
        </div>
        <div class="dep-list-item">
          <span>libc.so</span>
          <span style="color: #f59e0b;">2 APIs</span>
        </div>
      </div>
      
      <h4 style="margin-top: 1.5rem;">Call Graph Stats</h4>
      <div style="font-size: 0.75rem; color: var(--text-muted); line-height: 1.4;">
        Nodes: ${this.nodes.length}<br/>
        Edges: ${this.edges.length}<br/>
        Graph Density: ${(this.edges.length / Math.max(1, this.nodes.length * (this.nodes.length - 1))).toFixed(4)}
      </div>
    `;
  }
}
