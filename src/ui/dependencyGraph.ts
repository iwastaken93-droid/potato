/**
 * Dependency Graph Visualization Component
 * Maps relations between imported libraries, local exported symbols, and local/imported functions.
 * Offers a premium interactive force-directed visual graph using HTML5 Canvas.
 */

export interface GraphNode {
  id: string;
  label: string;
  type: 'binary' | 'library' | 'import' | 'export' | 'local';
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx: number | null;
  fy: number | null;
  radius: number;
  color: string;
  glowColor: string;
  library?: string;
  address?: number;
  details?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: 'import-library' | 'library-symbol' | 'local-call' | 'local-export';
  value: number;
  particles?: { progress: number; speed: number }[];
}

export interface DependencyGraphOptions {
  theme?: {
    background?: string;
    grid?: string;
    binaryGlow?: string;
    libraryGlow?: string;
    importGlow?: string;
    exportGlow?: string;
    localGlow?: string;
  };
  onNodeSelect?: (node: GraphNode | null) => void;
}

export class DependencyGraph {
  private container: HTMLElement;
  private canvas!: HTMLCanvasElement;
  private ctx!: CanvasRenderingContext2D;
  private options: DependencyGraphOptions;

  // Graph Data
  private nodes: GraphNode[] = [];
  private edges: GraphEdge[] = [];
  private nodeMap: Map<string, GraphNode> = new Map();

  // Interaction State
  private scale = 1.0;
  private panX = 0;
  private panY = 0;
  private isDraggingCanvas = false;
  private draggedNode: GraphNode | null = null;
  private hoveredNode: GraphNode | null = null;
  private selectedNode: GraphNode | null = null;
  private lastMouseX = 0;
  private lastMouseY = 0;

  // Search filter
  private searchQuery = '';

  // Simulation Parameters
  private gravity = 0.05;
  private charge = -350;
  private linkDistance = 80;
  private linkStrength = 0.08;
  private friction = 0.9;
  private activeSimulations = true;
  private showParticles = true;

  // Animation Frame
  private animationFrameId: number | null = null;

  // Colors
  private colors = {
    bg: '#0f1115',
    grid: 'rgba(255, 255, 255, 0.03)',
    text: '#f8fafc',
    textMuted: '#94a3b8',
    binary: '#6366f1', // Indigo
    library: '#38bdf8', // Light blue
    import: '#f59e0b', // Amber/orange
    export: '#10b981', // Emerald
    local: '#a855f7', // Purple
  };

  constructor(
    container: HTMLElement,
    data: {
      binaryName: string;
      imports: { library: string; name: string; address?: number }[];
      exports: { name: string; address?: number }[];
      locals: { name: string; address: number; calls: string[] }[];
    },
    options: DependencyGraphOptions = {}
  ) {
    this.container = container;
    this.options = options;

    this.initDOM();
    this.setupData(data);
    this.setupEventListeners();
    this.startSimulation();
  }

  private initDOM() {
    this.container.innerHTML = '';
    this.container.style.position = 'relative';
    this.container.style.width = '100%';
    this.container.style.height = '100%';
    this.container.style.backgroundColor = this.colors.bg;
    this.container.style.overflow = 'hidden';

    // Canvas
    this.canvas = document.createElement('canvas');
    this.canvas.style.display = 'block';
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.container.appendChild(this.canvas);

    const ctx = this.canvas.getContext('2d');
    if (!ctx) throw new Error('Could not get 2D context');
    this.ctx = ctx;

    // Control Panel Overlay
    const controlPanel = document.createElement('div');
    controlPanel.className = 'dep-graph-controls';
    controlPanel.innerHTML = `
      <div class="control-row">
        <input type="text" class="dep-search-input" placeholder="Search nodes..." />
      </div>
      <div class="control-row">
        <label><input type="checkbox" id="chk-physics" checked /> Physics</label>
        <label><input type="checkbox" id="chk-particles" checked /> Flow Particles</label>
        <button class="btn-reset-zoom" title="Reset view">🎯 Reset</button>
        <button class="btn-export-png" title="Export as Image">💾 Export</button>
      </div>
    `;

    // Inject styles for the controls
    const styleId = 'dep-graph-styles';
    if (!document.getElementById(styleId)) {
      const style = document.createElement('style');
      style.id = styleId;
      style.textContent = `
        .dep-graph-controls {
          position: absolute;
          top: 16px;
          left: 16px;
          background: rgba(22, 26, 33, 0.85);
          backdrop-filter: blur(8px);
          border: 1px solid rgba(255, 255, 255, 0.08);
          border-radius: 8px;
          padding: 12px;
          display: flex;
          flex-direction: column;
          gap: 10px;
          z-index: 10;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          font-size: 12px;
          color: #f8fafc;
          width: 260px;
          pointer-events: auto;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }
        .control-row {
          display: flex;
          gap: 12px;
          align-items: center;
        }
        .dep-search-input {
          flex: 1;
          background: rgba(15, 17, 21, 0.7);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 4px;
          padding: 6px 10px;
          color: #f8fafc;
          font-size: 12px;
        }
        .dep-search-input:focus {
          outline: none;
          border-color: #6366f1;
        }
        .dep-graph-controls label {
          display: flex;
          align-items: center;
          gap: 4px;
          cursor: pointer;
          user-select: none;
        }
        .dep-graph-controls button {
          background: #1f242e;
          border: 1px solid rgba(255, 255, 255, 0.1);
          color: #f8fafc;
          padding: 4px 8px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 11px;
          transition: background 0.2s;
        }
        .dep-graph-controls button:hover {
          background: #2d3446;
          border-color: #6366f1;
        }
        .dep-tooltip {
          position: absolute;
          background: rgba(15, 17, 21, 0.95);
          border: 1px solid rgba(255, 255, 255, 0.15);
          border-radius: 6px;
          padding: 8px 12px;
          color: #f8fafc;
          font-family: var(--font-mono, monospace);
          font-size: 11px;
          pointer-events: none;
          display: none;
          z-index: 100;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
          max-width: 280px;
        }
      `;
      document.head.appendChild(style);
    }

    this.container.appendChild(controlPanel);

    // Create Tooltip
    const tooltip = document.createElement('div');
    tooltip.className = 'dep-tooltip';
    this.container.appendChild(tooltip);

    // Bind UI actions
    const searchInput = controlPanel.querySelector(
      '.dep-search-input'
    ) as HTMLInputElement;
    searchInput.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value.toLowerCase();
    });

    const chkPhysics = controlPanel.querySelector(
      '#chk-physics'
    ) as HTMLInputElement;
    chkPhysics.addEventListener('change', (e) => {
      this.activeSimulations = (e.target as HTMLInputElement).checked;
    });

    const chkParticles = controlPanel.querySelector(
      '#chk-particles'
    ) as HTMLInputElement;
    chkParticles.addEventListener('change', (e) => {
      this.showParticles = (e.target as HTMLInputElement).checked;
    });

    const btnReset = controlPanel.querySelector(
      '.btn-reset-zoom'
    ) as HTMLButtonElement;
    btnReset.addEventListener('click', () => {
      this.resetViewport();
    });

    const btnExport = controlPanel.querySelector(
      '.btn-export-png'
    ) as HTMLButtonElement;
    btnExport.addEventListener('click', () => {
      this.exportAsPNG();
    });

    this.resizeCanvas();
    window.addEventListener('resize', this.handleResize);
  }

  private handleResize = () => {
    this.resizeCanvas();
  };

  private resizeCanvas() {
    const rect = this.container.getBoundingClientRect();
    this.canvas.width = rect.width * window.devicePixelRatio;
    this.canvas.height = rect.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    this.draw();
  }

  private setupData(data: {
    binaryName: string;
    imports: { library: string; name: string; address?: number }[];
    exports: { name: string; address?: number }[];
    locals: { name: string; address: number; calls: string[] }[];
  }) {
    this.nodes = [];
    this.edges = [];
    this.nodeMap.clear();

    const cx = this.container.clientWidth / 2;
    const cy = this.container.clientHeight / 2;

    // 1. Central Binary Node
    const binaryNode: GraphNode = {
      id: 'binary_root',
      label: data.binaryName || 'Main Binary',
      type: 'binary',
      x: cx,
      y: cy,
      vx: 0,
      vy: 0,
      fx: cx, // Keep fixed at center
      fy: cy,
      radius: 28,
      color: this.colors.binary,
      glowColor: 'rgba(99, 102, 241, 0.4)',
      details: 'Current Active Target Binary',
    };
    this.addNode(binaryNode);

    // Keep track of imported libraries to create library group nodes
    const libraries = new Set<string>();
    data.imports.forEach((imp) => libraries.add(imp.library));

    // 2. Library Nodes
    const libraryNodesMap = new Map<string, GraphNode>();
    let index = 0;
    libraries.forEach((lib) => {
      const angle = (index / libraries.size) * Math.PI * 2;
      const rx = cx + Math.cos(angle) * 150;
      const ry = cy + Math.sin(angle) * 150;

      const libNode: GraphNode = {
        id: `lib_${lib}`,
        label: lib,
        type: 'library',
        x: rx,
        y: ry,
        vx: 0,
        vy: 0,
        fx: null,
        fy: null,
        radius: 18,
        color: this.colors.library,
        glowColor: 'rgba(56, 189, 248, 0.4)',
        details: `Imported Library`,
      };
      this.addNode(libNode);
      libraryNodesMap.set(lib, libNode);

      // Edge from local binary to the library node
      this.addEdge({
        source: 'binary_root',
        target: libNode.id,
        type: 'import-library',
        value: 2,
      });

      index++;
    });

    // 3. Import Symbol Nodes
    data.imports.forEach((imp) => {
      const libNode = libraryNodesMap.get(imp.library);
      if (!libNode) return;

      const angle = Math.random() * Math.PI * 2;
      const rx = libNode.x + Math.cos(angle) * 60;
      const ry = libNode.y + Math.sin(angle) * 60;

      const impNodeId = `imp_${imp.library}_${imp.name}`;
      const impNode: GraphNode = {
        id: impNodeId,
        label: imp.name,
        type: 'import',
        x: rx,
        y: ry,
        vx: 0,
        vy: 0,
        fx: null,
        fy: null,
        radius: 10,
        color: this.colors.import,
        glowColor: 'rgba(245, 158, 11, 0.4)',
        library: imp.library,
        address: imp.address,
        details: `Import symbol: ${imp.name}\nLibrary: ${imp.library}${imp.address ? `\nAddress: 0x${imp.address.toString(16)}` : ''}`,
      };
      this.addNode(impNode);

      // Edge from library to imported symbol node
      this.addEdge({
        source: libNode.id,
        target: impNodeId,
        type: 'library-symbol',
        value: 1,
      });
    });

    // 4. Export Nodes
    data.exports.forEach((exp, i) => {
      const angle = (i / (data.exports.length || 1)) * Math.PI * 2;
      const rx = cx + Math.cos(angle) * 120;
      const ry = cy + Math.sin(angle) * 120;

      const expNodeId = `exp_${exp.name}`;
      const expNode: GraphNode = {
        id: expNodeId,
        label: exp.name,
        type: 'export',
        x: rx,
        y: ry,
        vx: 0,
        vy: 0,
        fx: null,
        fy: null,
        radius: 11,
        color: this.colors.export,
        glowColor: 'rgba(16, 185, 129, 0.4)',
        address: exp.address,
        details: `Exported entry point symbol: ${exp.name}${exp.address ? `\nAddress: 0x${exp.address.toString(16)}` : ''}`,
      };
      this.addNode(expNode);

      // Edge from local binary to exported symbol
      this.addEdge({
        source: 'binary_root',
        target: expNodeId,
        type: 'local-export',
        value: 1.5,
      });
    });

    // 5. Local Function Nodes & Call connections
    data.locals.forEach((loc) => {
      const angle = Math.random() * Math.PI * 2;
      const rx = cx + Math.cos(angle) * 180;
      const ry = cy + Math.sin(angle) * 180;

      const locNodeId = `loc_${loc.name}`;
      // Check if already created as export
      let locNode = this.nodeMap.get(`exp_${loc.name}`);
      if (locNode) {
        // Upgrade to local code representation detail
        locNode.details = `Local Exported Function: ${loc.name}\nAddress: 0x${loc.address.toString(16)}\nCalls: ${loc.calls.length} symbols`;
        locNode.type = 'export'; // keep export type visually
      } else {
        locNode = {
          id: locNodeId,
          label: loc.name,
          type: 'local',
          x: rx,
          y: ry,
          vx: 0,
          vy: 0,
          fx: null,
          fy: null,
          radius: 10,
          color: this.colors.local,
          glowColor: 'rgba(168, 85, 247, 0.4)',
          address: loc.address,
          details: `Local Internal Function: ${loc.name}\nAddress: 0x${loc.address.toString(16)}\nCalls: ${loc.calls.length} symbols`,
        };
        this.addNode(locNode);

        // Edge from binary root to local function
        this.addEdge({
          source: 'binary_root',
          target: locNodeId,
          type: 'local-call',
          value: 1,
        });
      }
    });

    // Wire calls between local functions and imports/exports
    data.locals.forEach((loc) => {
      const locId = this.nodeMap.has(`exp_${loc.name}`)
        ? `exp_${loc.name}`
        : `loc_${loc.name}`;

      loc.calls.forEach((calledName) => {
        // 1. Check if it's an import symbol
        // The imported name might be inside various libraries, let's find it
        let targetId = '';
        for (const [id, node] of this.nodeMap.entries()) {
          if (node.type === 'import' && node.label === calledName) {
            targetId = id;
            break;
          }
        }

        // 2. Or is it another local/exported symbol?
        if (!targetId) {
          if (this.nodeMap.has(`exp_${calledName}`)) {
            targetId = `exp_${calledName}`;
          } else if (this.nodeMap.has(`loc_${calledName}`)) {
            targetId = `loc_${calledName}`;
          }
        }

        if (targetId && targetId !== locId) {
          this.addEdge({
            source: locId,
            target: targetId,
            type: 'local-call',
            value: 0.8,
          });
        }
      });
    });

    // Initialize particles on edges
    this.edges.forEach((edge) => {
      edge.particles = [];
      const numParticles = Math.floor(Math.random() * 2);
      for (let p = 0; p < numParticles; p++) {
        edge.particles.push({
          progress: Math.random(),
          speed: 0.004 + Math.random() * 0.006,
        });
      }
    });
  }

  private addNode(node: GraphNode) {
    this.nodes.push(node);
    this.nodeMap.set(node.id, node);
  }

  private addEdge(edge: GraphEdge) {
    // Avoid duplicates
    const duplicate = this.edges.find(
      (e) => e.source === edge.source && e.target === edge.target
    );
    if (!duplicate) {
      this.edges.push(edge);
    }
  }

  private setupEventListeners() {
    this.canvas.addEventListener('mousedown', this.handleMouseDown);
    this.canvas.addEventListener('mousemove', this.handleMouseMove);
    this.canvas.addEventListener('mouseup', this.handleMouseUp);
    this.canvas.addEventListener('wheel', this.handleWheel);

    // Prevent context menu
    this.canvas.addEventListener('contextmenu', (e) => e.preventDefault());
  }

  private handleMouseDown = (e: MouseEvent) => {
    const mousePos = this.getMousePos(e);
    this.lastMouseX = mousePos.x;
    this.lastMouseY = mousePos.y;

    // Find if clicked on a node
    const hitNode = this.getNodeAt(mousePos.x, mousePos.y);

    if (hitNode) {
      this.draggedNode = hitNode;
      this.selectedNode = hitNode;
      if (this.options.onNodeSelect) {
        this.options.onNodeSelect(hitNode);
      }

      // Pin the node position during drag
      hitNode.fx = hitNode.x;
      hitNode.fy = hitNode.y;
    } else {
      this.isDraggingCanvas = true;
      this.selectedNode = null;
      if (this.options.onNodeSelect) {
        this.options.onNodeSelect(null);
      }
    }
  };

  private handleMouseMove = (e: MouseEvent) => {
    const mousePos = this.getMousePos(e);
    const dx = mousePos.x - this.lastMouseX;
    const dy = mousePos.y - this.lastMouseY;

    if (this.draggedNode) {
      // Move dragged node
      // Convert screen movement back to canvas world coordinates
      const worldDx = dx / this.scale;
      const worldDy = dy / this.scale;

      this.draggedNode.fx =
        (this.draggedNode.fx || this.draggedNode.x) + worldDx;
      this.draggedNode.fy =
        (this.draggedNode.fy || this.draggedNode.y) + worldDy;
      this.draggedNode.x = this.draggedNode.fx;
      this.draggedNode.y = this.draggedNode.fy;
    } else if (this.isDraggingCanvas) {
      // Pan canvas
      this.panX += dx;
      this.panY += dy;
    } else {
      // Check hover
      const hitNode = this.getNodeAt(mousePos.x, mousePos.y);
      if (hitNode !== this.hoveredNode) {
        this.hoveredNode = hitNode;
        this.showTooltip(e, hitNode);
      } else if (hitNode) {
        // Move existing tooltip with mouse
        this.showTooltip(e, hitNode);
      }
    }

    this.lastMouseX = mousePos.x;
    this.lastMouseY = mousePos.y;
  };

  private handleMouseUp = () => {
    if (this.draggedNode) {
      // Release node unless pinned (we will unpin them to let them settle, or keep fixed if central)
      if (this.draggedNode.id !== 'binary_root') {
        this.draggedNode.fx = null;
        this.draggedNode.fy = null;
      }
      this.draggedNode = null;
    }
    this.isDraggingCanvas = false;
  };

  private handleWheel = (e: WheelEvent) => {
    e.preventDefault();

    const zoomIntensity = 0.1;
    const mousePos = this.getMousePos(e);

    // Zoom around mouse pointer
    const mouseWorldX = (mousePos.x - this.panX) / this.scale;
    const mouseWorldY = (mousePos.y - this.panY) / this.scale;

    const zoomFactor = e.deltaY < 0 ? 1 + zoomIntensity : 1 - zoomIntensity;
    const nextScale = Math.max(0.15, Math.min(4.0, this.scale * zoomFactor));

    this.scale = nextScale;
    this.panX = mousePos.x - mouseWorldX * this.scale;
    this.panY = mousePos.y - mouseWorldY * this.scale;
  };

  private getMousePos(e: MouseEvent) {
    const rect = this.canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    };
  }

  private getNodeAt(screenX: number, screenY: number): GraphNode | null {
    // Convert screen coordinates to world coordinates
    const worldX = (screenX - this.panX) / this.scale;
    const worldY = (screenY - this.panY) / this.scale;

    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const node = this.nodes[i];
      const dist = Math.hypot(node.x - worldX, node.y - worldY);
      if (dist <= node.radius + 6) {
        return node;
      }
    }
    return null;
  }

  private showTooltip(e: MouseEvent, node: GraphNode | null) {
    const tooltip = this.container.querySelector(
      '.dep-tooltip'
    ) as HTMLDivElement;
    if (!tooltip) return;

    if (!node) {
      tooltip.style.display = 'none';
      return;
    }

    const rect = this.container.getBoundingClientRect();
    const x = e.clientX - rect.left + 15;
    const y = e.clientY - rect.top + 15;

    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
    tooltip.style.display = 'block';
    tooltip.innerHTML = `
      <div style="font-weight:bold;color:${node.color};margin-bottom:4px;font-size:12px;">${node.label}</div>
      <div style="color:#94a3b8;font-size:10px;text-transform:uppercase;margin-bottom:6px;">Type: ${node.type}</div>
      <div style="white-space:pre-wrap;line-height:1.4;">${node.details || ''}</div>
    `;
  }

  private resetViewport() {
    this.scale = 1.0;
    this.panX = 0;
    this.panY = 0;
    const cx = this.container.clientWidth / 2;
    const cy = this.container.clientHeight / 2;

    // Reset center node
    const root = this.nodeMap.get('binary_root');
    if (root) {
      root.fx = cx;
      root.fy = cy;
      root.x = cx;
      root.y = cy;
    }

    // Spread other nodes out initially so they don't overlap completely
    this.nodes.forEach((node) => {
      if (node.id !== 'binary_root') {
        node.x = cx + (Math.random() - 0.5) * 200;
        node.y = cy + (Math.random() - 0.5) * 200;
        node.vx = 0;
        node.vy = 0;
      }
    });
  }

  private exportAsPNG() {
    // Generate image from canvas
    const dataURL = this.canvas.toDataURL('image/png');
    const link = document.createElement('a');
    link.download = `${this.nodes[0]?.label || 'dependency'}-graph.png`;
    link.href = dataURL;
    link.click();
  }

  private startSimulation() {
    const tick = () => {
      if (this.activeSimulations) {
        this.updateSimulation();
      }
      this.draw();
      this.animationFrameId = requestAnimationFrame(tick);
    };
    this.animationFrameId = requestAnimationFrame(tick);
  }

  public destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    window.removeEventListener('resize', this.handleResize);
  }

  private updateSimulation() {
    const cx = this.container.clientWidth / 2;
    const cy = this.container.clientHeight / 2;

    // 1. Charge / Repulsion force (n^2 but small n is fine here)
    for (let i = 0; i < this.nodes.length; i++) {
      const nodeA = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const nodeB = this.nodes[j];

        const dx = nodeB.x - nodeA.x;
        const dy = nodeB.y - nodeA.y;
        let dist = Math.hypot(dx, dy);
        if (dist === 0) dist = 0.1;

        // Force is inversely proportional to distance
        const force = this.charge / (dist * dist);

        const fx = force * (dx / dist);
        const fy = force * (dy / dist);

        if (nodeA.fx === null) {
          nodeA.vx += fx;
          nodeA.vy += fy;
        }
        if (nodeB.fx === null) {
          nodeB.vx -= fx;
          nodeB.vy -= fy;
        }
      }
    }

    // 2. Link Attraction force
    this.edges.forEach((edge) => {
      const sourceNode = this.nodeMap.get(edge.source);
      const targetNode = this.nodeMap.get(edge.target);

      if (!sourceNode || !targetNode) return;

      const dx = targetNode.x - sourceNode.x;
      const dy = targetNode.y - sourceNode.y;
      const dist = Math.hypot(dx, dy);
      if (dist === 0) return;

      // Spring force: Hooke's Law: F = -k * (x - d)
      const diff = dist - this.linkDistance;
      const force = diff * this.linkStrength * edge.value;

      const fx = force * (dx / dist);
      const fy = force * (dy / dist);

      if (sourceNode.fx === null) {
        sourceNode.vx += fx;
        sourceNode.vy += fy;
      }
      if (targetNode.fx === null) {
        targetNode.vx -= fx;
        targetNode.vy -= fy;
      }

      // Update flow particles along this edge
      if (this.showParticles && edge.particles) {
        edge.particles.forEach((p) => {
          p.progress += p.speed;
          if (p.progress > 1.0) {
            p.progress = 0;
          }
        });
      }
    });

    // 3. Gravity pulling to center of canvas & apply velocity
    this.nodes.forEach((node) => {
      if (node.fx !== null) return;

      // Gravity force pull to center
      const dx = cx - node.x;
      const dy = cy - node.y;
      node.vx += dx * this.gravity * 0.1;
      node.vy += dy * this.gravity * 0.1;

      // Apply friction and move
      node.x += node.vx;
      node.y += node.vy;
      node.vx *= this.friction;
      node.vy *= this.friction;

      // Basic bounds check to prevent flying off screen
      const border = 100;
      if (node.x < -border) node.x = -border;
      if (node.x > this.container.clientWidth + border)
        node.x = this.container.clientWidth + border;
      if (node.y < -border) node.y = -border;
      if (node.y > this.container.clientHeight + border)
        node.y = this.container.clientHeight + border;
    });

    // Central node always fixed at center
    const root = this.nodeMap.get('binary_root');
    if (root) {
      root.fx = cx;
      root.fy = cy;
      root.x = cx;
      root.y = cy;
    }
  }

  private draw() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    this.ctx.save();
    // Apply zoom and panning
    this.ctx.translate(this.panX, this.panY);
    this.ctx.scale(this.scale, this.scale);

    // Draw Grid background
    this.drawGrid();

    // Determine highlight/dim states based on search query or hovered node
    const isSearching = this.searchQuery.length > 0;
    const isHovering = this.hoveredNode !== null;

    // Build lists of highlighted nodes/edges
    const highlightedNodes = new Set<string>();
    const highlightedEdges = new Set<GraphEdge>();

    if (isSearching) {
      this.nodes.forEach((node) => {
        if (node.label.toLowerCase().includes(this.searchQuery)) {
          highlightedNodes.add(node.id);
        }
      });
    } else if (isHovering && this.hoveredNode) {
      const activeNodeId = this.hoveredNode.id;
      highlightedNodes.add(activeNodeId);

      this.edges.forEach((edge) => {
        if (edge.source === activeNodeId) {
          highlightedNodes.add(edge.target);
          highlightedEdges.add(edge);
        } else if (edge.target === activeNodeId) {
          highlightedNodes.add(edge.source);
          highlightedEdges.add(edge);
        }
      });
    }

    // 1. Draw Edges
    this.edges.forEach((edge) => {
      const sourceNode = this.nodeMap.get(edge.source);
      const targetNode = this.nodeMap.get(edge.target);

      if (!sourceNode || !targetNode) return;

      const isEdgeHighlighted = isSearching
        ? highlightedNodes.has(edge.source) && highlightedNodes.has(edge.target)
        : isHovering
          ? highlightedEdges.has(edge)
          : true;

      const alpha = isEdgeHighlighted ? 0.6 : 0.08;
      const strokeWidth = isEdgeHighlighted ? 1.8 : 0.8;

      this.ctx.beginPath();
      this.ctx.strokeStyle = sourceNode.color;
      this.ctx.globalAlpha = alpha;
      this.ctx.lineWidth = strokeWidth;

      // Draw smooth quadratic bezier curve or line
      this.ctx.moveTo(sourceNode.x, sourceNode.y);
      this.ctx.lineTo(targetNode.x, targetNode.y);
      this.ctx.stroke();

      // Draw flow particles
      if (this.showParticles && edge.particles && isEdgeHighlighted) {
        this.ctx.globalAlpha = 1.0;
        edge.particles.forEach((p) => {
          // Linear interpolation for simple line flow
          const px = sourceNode.x + (targetNode.x - sourceNode.x) * p.progress;
          const py = sourceNode.y + (targetNode.y - sourceNode.y) * p.progress;

          this.ctx.beginPath();
          this.ctx.arc(px, py, 2.5, 0, Math.PI * 2);
          this.ctx.fillStyle = sourceNode.color;
          this.ctx.shadowBlur = 8;
          this.ctx.shadowColor = sourceNode.color;
          this.ctx.fill();
          this.ctx.shadowBlur = 0; // reset
        });
      }
    });

    this.ctx.globalAlpha = 1.0;

    // 2. Draw Nodes
    this.nodes.forEach((node) => {
      const isNodeHighlighted = isSearching
        ? highlightedNodes.has(node.id)
        : isHovering
          ? highlightedNodes.has(node.id)
          : true;

      const alpha = isNodeHighlighted ? 1.0 : 0.25;

      this.ctx.save();
      this.ctx.globalAlpha = alpha;

      // Draw shadow glow for highlighted nodes
      if (isNodeHighlighted) {
        this.ctx.shadowBlur = node.radius * 0.7;
        this.ctx.shadowColor = node.color;
      }

      // Outer border circle (glassy overlay)
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius + 3, 0, Math.PI * 2);
      this.ctx.fillStyle = 'rgba(255, 255, 255, 0.03)';
      this.ctx.strokeStyle = node.color;
      this.ctx.lineWidth = 1.5;
      this.ctx.fill();
      this.ctx.stroke();

      // Inner filled circle
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = node.color;
      this.ctx.fill();

      this.ctx.restore();

      // Node Label Text
      this.ctx.save();
      this.ctx.globalAlpha = alpha;
      this.ctx.font =
        node.type === 'binary'
          ? 'bold 12px var(--font-sans, system-ui)'
          : '11px var(--font-mono, monospace)';
      this.ctx.fillStyle = this.colors.text;
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';

      // Draw label background for legibility
      const textWidth = this.ctx.measureText(node.label).width;
      this.ctx.fillStyle = 'rgba(15, 17, 21, 0.8)';
      this.ctx.fillRect(
        node.x - textWidth / 2 - 4,
        node.y + node.radius + 10,
        textWidth + 8,
        14
      );

      this.ctx.fillStyle = isNodeHighlighted
        ? this.colors.text
        : this.colors.textMuted;
      this.ctx.fillText(node.label, node.x, node.y + node.radius + 17);
      this.ctx.restore();
    });

    this.ctx.restore();
  }

  private drawGrid() {
    const size = 50;
    const width = this.canvas.width / this.scale + Math.abs(this.panX);
    const height = this.canvas.height / this.scale + Math.abs(this.panY);

    const startX = -Math.ceil(this.panX / this.scale) - size;
    const startY = -Math.ceil(this.panY / this.scale) - size;
    const endX = startX + width + size * 2;
    const endY = startY + height + size * 2;

    this.ctx.beginPath();
    this.ctx.strokeStyle = this.colors.grid;
    this.ctx.lineWidth = 0.5;

    for (let x = Math.floor(startX / size) * size; x < endX; x += size) {
      this.ctx.moveTo(x, startY);
      this.ctx.lineTo(x, endY);
    }
    for (let y = Math.floor(startY / size) * size; y < endY; y += size) {
      this.ctx.moveTo(startX, y);
      this.ctx.lineTo(endX, y);
    }
    this.ctx.stroke();
  }
}
