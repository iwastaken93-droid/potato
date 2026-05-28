import { BasicBlock } from '../disassembler/cfg.js';
import { Instruction } from '../disassembler/types.js';

export function parseCoverageTable(tableData: string): Record<string, number> {
  const result: Record<string, number> = {};
  if (!tableData) return result;

  const lines = tableData.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.includes('---')) {
      continue;
    }

    let parts: string[] = [];
    if (trimmed.includes('|')) {
      parts = trimmed.split('|');
    } else if (trimmed.includes(',')) {
      parts = trimmed.split(',');
    } else if (trimmed.includes(':')) {
      parts = trimmed.split(':');
    } else {
      const wsParts = trimmed.split(/\s+/);
      if (wsParts.length >= 2) {
        parts = wsParts;
      }
    }

    if (parts.length >= 2) {
      const key = parts[0].trim();
      const valStr = parts[1].trim();

      if (
        key.toLowerCase() === 'block' ||
        key.toLowerCase() === 'block id' ||
        key.toLowerCase() === 'address' ||
        valStr.toLowerCase() === 'count' ||
        valStr.toLowerCase() === 'hits'
      ) {
        continue;
      }

      const count = parseInt(valStr, 10);
      if (!isNaN(count)) {
        result[key] = count;
      }
    }
  }
  return result;
}

export interface CFGVisualizerOptions {
  layout?: 'layered' | 'sequential';
  theme?: {
    background?: string;
    blockBg?: string;
    blockBorder?: string;
    blockHeaderBg?: string;
    blockTitleColor?: string;
    textColor?: string;
    trueBranchColor?: string;
    falseBranchColor?: string;
    neutralBranchColor?: string;
    selectedColor?: string;
  };
  onBlockSelect?: (blockId: string | null) => void;
  coverageData?: Record<string, number> | string;
}

export class CFGVisualizer {
  private container: HTMLElement;
  private blocks: BasicBlock[];
  private options: CFGVisualizerOptions;
  private currentLayout: 'layered' | 'sequential';
  private coverage: Map<string, number> = new Map();

  // SVG Elements
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
  private selectedBlockId: string | null = null;

  // Layout parameters
  private readonly blockWidth = 280;
  private readonly instructionHeight = 20;
  private readonly blockHeaderHeight = 32;
  private readonly blockPadding = 16;
  private readonly verticalGap = 80;
  private readonly horizontalGap = 60;

  // Cached positions
  private blockPositions: Map<
    string,
    { x: number; y: number; width: number; height: number }
  > = new Map();

  constructor(
    container: HTMLElement,
    blocks: BasicBlock[],
    options: CFGVisualizerOptions = {}
  ) {
    this.container = container;
    this.blocks = blocks;
    this.options = options;
    this.currentLayout = options.layout || 'layered';

    this.initStyles();
    this.initDOM();
    if (options.coverageData) {
      this.applyCoverage(options.coverageData);
    } else {
      this.render();
    }
  }

  /**
   * Inject CSS styles for the CFG Visualizer.
   */
  private initStyles() {
    if (!document.getElementById('cfg-visualizer-styles')) {
      const style = document.createElement('style');
      style.id = 'cfg-visualizer-styles';
      style.textContent = `
        .cfg-visualizer-root {
          width: 100%;
          height: 100%;
          position: relative;
          background-color: var(--cfg-bg, #0f172a);
          overflow: hidden;
          font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
          user-select: none;
          box-sizing: border-box;
        }

        .cfg-svg-canvas {
          width: 100%;
          height: 100%;
          display: block;
          cursor: grab;
        }

        .cfg-svg-canvas:active {
          cursor: grabbing;
        }

        /* Basic Block ForeignObject Styles */
        .cfg-block-card {
          width: 100%;
          height: 100%;
          background: var(--cfg-block-bg, rgba(30, 41, 59, 0.95));
          border: 1px solid var(--cfg-block-border, #334155);
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
          overflow: hidden;
          display: flex;
          flex-direction: column;
          box-sizing: border-box;
          transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }

        .cfg-block-card:hover {
          border-color: var(--cfg-selected-color, #38bdf8);
          box-shadow: 0 4px 20px rgba(56, 189, 248, 0.2);
        }

        .cfg-block-card.selected {
          border-color: var(--cfg-selected-color, #38bdf8);
          box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.4), 0 4px 20px rgba(56, 189, 248, 0.25);
        }

        .cfg-block-header {
          height: 32px;
          min-height: 32px;
          background: var(--cfg-block-header-bg, #1e293b);
          border-bottom: 1px solid var(--cfg-block-border, #334155);
          padding: 0 12px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-family: 'Fira Code', 'Courier New', Courier, monospace;
          font-size: 11px;
          font-weight: 600;
          color: var(--cfg-block-title-color, #38bdf8);
        }

        .cfg-block-body {
          flex: 1;
          padding: 8px 12px;
          overflow-y: auto;
          overflow-x: hidden;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .cfg-instruction {
          display: flex;
          font-family: 'Fira Code', 'Courier New', Courier, monospace;
          font-size: 12px;
          line-height: 1.4;
          color: var(--cfg-text-color, #e2e8f0);
          white-space: nowrap;
        }

        .cfg-inst-addr {
          color: #64748b;
          margin-right: 12px;
          width: 70px;
          flex-shrink: 0;
        }

        .cfg-inst-op {
          color: #f43f5e;
          font-weight: 500;
          margin-right: 8px;
          flex-shrink: 0;
        }

        .cfg-inst-args {
          color: #e2e8f0;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        /* SVG Paths */
        .cfg-edge {
          fill: none;
          stroke-width: 2px;
          transition: stroke-width 0.2s, stroke 0.2s;
        }

        .cfg-edge:hover {
          stroke-width: 4px !important;
        }

        .cfg-edge.dimmed {
          opacity: 0.15;
        }

        .cfg-edge.highlighted {
          stroke-width: 3.5px;
          opacity: 1;
        }

        /* Controls Panel */
        .cfg-controls {
          position: absolute;
          bottom: 16px;
          right: 16px;
          display: flex;
          gap: 8px;
          background: rgba(15, 23, 42, 0.8);
          backdrop-filter: blur(8px);
          padding: 6px;
          border-radius: 6px;
          border: 1px solid #334155;
          z-index: 10;
        }

        .cfg-btn {
          background: #1e293b;
          border: 1px solid #475569;
          color: #e2e8f0;
          padding: 6px 10px;
          font-size: 12px;
          border-radius: 4px;
          cursor: pointer;
          font-weight: 500;
          transition: background 0.15s, border-color 0.15s;
        }

        .cfg-btn:hover {
          background: #334155;
          border-color: #64748b;
        }

        .cfg-btn:active {
          background: #475569;
        }
      `;
      document.head.appendChild(style);
    }
  }

  /**
   * Initializes the container elements.
   */
  private initDOM() {
    this.container.innerHTML = '';
    this.container.classList.add('cfg-visualizer-root');

    // Setup CSS Variable overrides for theme
    const theme = this.options.theme || {};
    if (theme.background)
      this.container.style.setProperty('--cfg-bg', theme.background);
    if (theme.blockBg)
      this.container.style.setProperty('--cfg-block-bg', theme.blockBg);
    if (theme.blockBorder)
      this.container.style.setProperty('--cfg-block-border', theme.blockBorder);
    if (theme.blockHeaderBg)
      this.container.style.setProperty(
        '--cfg-block-header-bg',
        theme.blockHeaderBg
      );
    if (theme.blockTitleColor)
      this.container.style.setProperty(
        '--cfg-block-title-color',
        theme.blockTitleColor
      );
    if (theme.textColor)
      this.container.style.setProperty('--cfg-text-color', theme.textColor);
    if (theme.selectedColor)
      this.container.style.setProperty(
        '--cfg-selected-color',
        theme.selectedColor
      );

    // Create main SVG canvas
    this.svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    this.svg.setAttribute('class', 'cfg-svg-canvas');

    // Create marker definitions for arrows
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');

    const trueColor = theme.trueBranchColor || '#10b981';
    const falseColor = theme.falseBranchColor || '#ef4444';
    const neutralColor = theme.neutralBranchColor || '#64748b';
    const selectedColor = theme.selectedColor || '#38bdf8';

    defs.appendChild(this.createArrowMarker('arrow-true', trueColor));
    defs.appendChild(this.createArrowMarker('arrow-false', falseColor));
    defs.appendChild(this.createArrowMarker('arrow-neutral', neutralColor));
    defs.appendChild(this.createArrowMarker('arrow-selected', selectedColor));
    defs.appendChild(this.createArrowMarker('arrow-unexecuted', '#475569'));
    this.svg.appendChild(defs);

    // Create layers group
    this.zoomGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );

    this.edgesGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );
    this.edgesGroup.setAttribute('class', 'cfg-edges');

    this.nodesGroup = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'g'
    );
    this.nodesGroup.setAttribute('class', 'cfg-nodes');

    this.zoomGroup.appendChild(this.edgesGroup);
    this.zoomGroup.appendChild(this.nodesGroup);
    this.svg.appendChild(this.zoomGroup);
    this.container.appendChild(this.svg);

    // Add controls overlay
    this.createControls();

    // Event listeners for Pan & Zoom
    this.setupInteractions();
  }

  private createArrowMarker(id: string, color: string): SVGMarkerElement {
    const marker = document.createElementNS(
      'http://www.w3.org/2000/svg',
      'marker'
    );
    marker.setAttribute('id', id);
    marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '8');
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

  private createControls() {
    const controls = document.createElement('div');
    controls.className = 'cfg-controls';

    const btnLayout = document.createElement('button');
    btnLayout.className = 'cfg-btn';
    btnLayout.textContent =
      this.currentLayout === 'layered' ? 'Layout: Layered' : 'Layout: Stack';
    btnLayout.addEventListener('click', () => {
      this.currentLayout =
        this.currentLayout === 'layered' ? 'sequential' : 'layered';
      btnLayout.textContent =
        this.currentLayout === 'layered' ? 'Layout: Layered' : 'Layout: Stack';
      this.render();
      this.fitToScreen();
    });

    const btnFit = document.createElement('button');
    btnFit.className = 'cfg-btn';
    btnFit.textContent = 'Fit Screen';
    btnFit.onclick = () => this.fitToScreen();

    const btnReset = document.createElement('button');
    btnReset.className = 'cfg-btn';
    btnReset.textContent = 'Reset Zoom';
    btnReset.onclick = () => {
      this.zoomScale = 1.0;
      this.panX = 0;
      this.panY = 0;
      this.updateTransform();
    };

    controls.appendChild(btnLayout);
    controls.appendChild(btnFit);
    controls.appendChild(btnReset);
    this.container.appendChild(controls);
  }

  /**
   * Computes the bounding box/height of each basic block.
   */
  private calculateBlockHeight(block: BasicBlock): number {
    const instCount = block.instructions.length;
    return (
      this.blockHeaderHeight +
      instCount * this.instructionHeight +
      this.blockPadding
    );
  }

  /**
   * Arranges blocks in the canvas based on chosen layout method.
   */
  private computeLayout() {
    this.blockPositions.clear();
    if (this.blocks.length === 0) return;

    if (this.currentLayout === 'sequential') {
      let currentY = 50;
      const centerX = 200; // base offset

      for (const block of this.blocks) {
        const height = this.calculateBlockHeight(block);
        this.blockPositions.set(block.id, {
          x: centerX,
          y: currentY,
          width: this.blockWidth,
          height: height,
        });
        currentY += height + this.verticalGap;
      }
    } else {
      // Layered layout (simplified Sugiyama layout using BFS levels)
      const blockMap = new Map<string, BasicBlock>();
      for (const b of this.blocks) {
        blockMap.set(b.id, b);
      }

      // Compute Layers
      const layers: Map<string, number> = new Map();
      for (const b of this.blocks) {
        layers.set(b.id, 0);
      }

      // Safe BFS/relax cycles to set level layers
      const maxIterations = this.blocks.length;
      for (let iter = 0; iter < maxIterations; iter++) {
        let changed = false;
        for (const block of this.blocks) {
          const currentLayer = layers.get(block.id) || 0;
          for (const succId of block.successors) {
            const succBlock = blockMap.get(succId);
            if (!succBlock) continue;

            // Simple back-edge prevention: do not propagate layers backward in address
            const isBackEdge = succBlock.startAddress <= block.startAddress;
            if (!isBackEdge) {
              const succLayer = layers.get(succId) || 0;
              if (currentLayer + 1 > succLayer) {
                layers.set(succId, currentLayer + 1);
                changed = true;
              }
            }
          }
        }
        if (!changed) break;
      }

      // Group blocks by layer
      const layerGroups: Map<number, string[]> = new Map();
      for (const [id, layerNum] of layers.entries()) {
        if (!layerGroups.has(layerNum)) {
          layerGroups.set(layerNum, []);
        }
        layerGroups.get(layerNum)!.push(id);
      }

      // Sort layers
      const sortedLayers = Array.from(layerGroups.keys()).sort((a, b) => a - b);

      // Determine starting Y coordinates per layer to prevent overlap of uneven heights
      const layerHeights: Map<number, number> = new Map();
      for (const layer of sortedLayers) {
        let maxHeight = 60;
        const ids = layerGroups.get(layer) || [];
        for (const id of ids) {
          const block = blockMap.get(id);
          if (block) {
            maxHeight = Math.max(maxHeight, this.calculateBlockHeight(block));
          }
        }
        layerHeights.set(layer, maxHeight);
      }

      const layerY: Map<number, number> = new Map();
      let currentY = 50;
      for (const layer of sortedLayers) {
        layerY.set(layer, currentY);
        const height = layerHeights.get(layer) || 80;
        currentY += height + this.verticalGap;
      }

      // Assign coordinates
      const blockTotalWidth = this.blockWidth + this.horizontalGap;
      for (const layer of sortedLayers) {
        const ids = layerGroups.get(layer) || [];
        const y = layerY.get(layer) || 50;
        const totalLayerWidth = (ids.length - 1) * blockTotalWidth;
        const startX = -totalLayerWidth / 2;

        ids.forEach((id, index) => {
          const block = blockMap.get(id)!;
          const x = startX + index * blockTotalWidth;
          const height = this.calculateBlockHeight(block);
          this.blockPositions.set(id, {
            x,
            y,
            width: this.blockWidth,
            height,
          });
        });
      }
    }
  }

  /**
   * Renders basic blocks and connection lines to SVG.
   */
  public render() {
    this.computeLayout();
    this.nodesGroup.innerHTML = '';
    this.edgesGroup.innerHTML = '';

    if (this.blocks.length === 0) return;

    // 1. Render Edges (Paths) first so they sit under blocks
    this.renderEdges();

    // 2. Render Nodes (Blocks)
    this.renderNodes();
  }

  private renderNodes() {
    let maxCount = 0;
    for (const val of this.coverage.values()) {
      if (val > maxCount) maxCount = val;
    }

    for (const block of this.blocks) {
      const pos = this.blockPositions.get(block.id);
      if (!pos) continue;

      // Wrap in standard SVG foreignObject
      const foreignObj = document.createElementNS(
        'http://www.w3.org/2000/svg',
        'foreignObject'
      );
      foreignObj.setAttribute('x', pos.x.toString());
      foreignObj.setAttribute('y', pos.y.toString());
      foreignObj.setAttribute('width', pos.width.toString());
      foreignObj.setAttribute('height', pos.height.toString());
      foreignObj.setAttribute('id', `node-${block.id}`);

      // Create main HTML Card
      const card = document.createElement('div');
      card.className = `cfg-block-card${this.selectedBlockId === block.id ? ' selected' : ''}`;
      card.onclick = (e) => {
        e.stopPropagation();
        this.selectBlock(block.id);
      };

      const hasCoverageInfo = this.coverage.size > 0;
      const count = this.coverage.get(block.id);

      if (hasCoverageInfo && count !== undefined) {
        if (count === 0) {
          card.style.background = 'rgba(239, 68, 68, 0.05)';
          card.style.borderColor = 'rgba(239, 68, 68, 0.3)';
        } else {
          const ratio = maxCount > 1 ? Math.log(count + 1) / Math.log(maxCount + 1) : 1;
          const hue = Math.round(120 - ratio * 120);
          card.style.background = `hsla(${hue}, 75%, 25%, 0.35)`;
          card.style.borderColor = `hsla(${hue}, 85%, 45%, 0.8)`;
        }
      }

      // Header
      const header = document.createElement('div');
      header.className = 'cfg-block-header';

      if (hasCoverageInfo && count !== undefined) {
        if (count > 0) {
          const ratio = maxCount > 1 ? Math.log(count + 1) / Math.log(maxCount + 1) : 1;
          const hue = Math.round(120 - ratio * 120);
          header.style.background = `hsla(${hue}, 75%, 20%, 0.7)`;
          header.style.borderBottomColor = `hsla(${hue}, 85%, 40%, 0.8)`;
        } else {
          header.style.background = 'rgba(239, 68, 68, 0.1)';
        }
      }

      const titleSpan = document.createElement('span');
      titleSpan.textContent = block.id;
      header.appendChild(titleSpan);

      const sizeSpan = document.createElement('span');
      if (hasCoverageInfo && count !== undefined) {
        sizeSpan.textContent = `${count} hits | ${block.instructions.length} insts`;
      } else {
        sizeSpan.textContent = `${block.instructions.length} insts`;
      }
      sizeSpan.style.opacity = '0.6';
      header.appendChild(sizeSpan);
      card.appendChild(header);

      // Body / Instructions
      const body = document.createElement('div');
      body.className = 'cfg-block-body';

      for (const inst of block.instructions) {
        const instDiv = document.createElement('div');
        instDiv.className = 'cfg-instruction';

        const addrSpan = document.createElement('span');
        addrSpan.className = 'cfg-inst-addr';
        addrSpan.textContent = `0x${inst.address.toString(16)}`;

        const opSpan = document.createElement('span');
        opSpan.className = 'cfg-inst-op';
        opSpan.textContent = inst.mnemonic;

        const argsSpan = document.createElement('span');
        argsSpan.className = 'cfg-inst-args';
        argsSpan.textContent = inst.opStr;

        instDiv.appendChild(addrSpan);
        instDiv.appendChild(opSpan);
        instDiv.appendChild(argsSpan);
        body.appendChild(instDiv);
      }

      card.appendChild(body);
      foreignObj.appendChild(card);
      this.nodesGroup.appendChild(foreignObj);
    }
  }

  private getEdgeCoverage(fromBlock: BasicBlock, toBlock: BasicBlock): number | null {
    if (this.coverage.size === 0) return null;

    const key1 = `${fromBlock.id}->${toBlock.id}`;
    if (this.coverage.has(key1)) return this.coverage.get(key1)!;

    const key2 = `0x${fromBlock.startAddress.toString(16)}->0x${toBlock.startAddress.toString(16)}`;
    if (this.coverage.has(key2)) return this.coverage.get(key2)!;

    const key3 = `${fromBlock.startAddress}->${toBlock.startAddress}`;
    if (this.coverage.has(key3)) return this.coverage.get(key3)!;

    const fromCount = this.coverage.get(fromBlock.id);
    const toCount = this.coverage.get(toBlock.id);

    if (fromCount === undefined && toCount === undefined) return null;

    const sCount = fromCount || 0;
    const tCount = toCount || 0;
    return Math.min(sCount, tCount);
  }

  public applyCoverage(coverageData: Record<string, number> | string | null) {
    this.coverage.clear();
    if (coverageData) {
      const parsed = typeof coverageData === 'string' ? parseCoverageTable(coverageData) : coverageData;
      
      const blockMap = new Map<string, BasicBlock>();
      for (const b of this.blocks) {
        blockMap.set(b.id, b);
      }

      for (const [key, val] of Object.entries(parsed)) {
        if (blockMap.has(key)) {
          this.coverage.set(key, val);
          continue;
        }

        const addr = parseInt(key, key.toLowerCase().startsWith('0x') ? 16 : 10);
        if (!isNaN(addr)) {
          const match = this.blocks.find(b => b.startAddress === addr);
          if (match) {
            this.coverage.set(match.id, val);
            continue;
          }
        }

        this.coverage.set(key, val);
      }
    }
    this.render();
  }

  private renderEdges() {
    const theme = this.options.theme || {};
    const trueColor = theme.trueBranchColor || '#10b981';
    const falseColor = theme.falseBranchColor || '#ef4444';
    const neutralColor = theme.neutralBranchColor || '#64748b';

    let maxCount = 0;
    for (const val of this.coverage.values()) {
      if (val > maxCount) maxCount = val;
    }

    const blockMap = new Map<string, BasicBlock>();
    for (const b of this.blocks) {
      blockMap.set(b.id, b);
    }

    for (const block of this.blocks) {
      const fromPos = this.blockPositions.get(block.id);
      if (!fromPos) continue;

      const isConditional = block.successors.length === 2;

      block.successors.forEach((succId: string, index: number) => {
        const toPos = this.blockPositions.get(succId);
        if (!toPos) return;

        const succBlock = blockMap.get(succId);
        let color = neutralColor;
        let markerId = 'arrow-neutral';
        let strokeDash: string | null = null;
        let strokeWidth = '2px';

        const hasCoverageInfo = this.coverage.size > 0 && succBlock !== undefined;
        let edgeCount: number | null = null;
        if (hasCoverageInfo) {
          edgeCount = this.getEdgeCoverage(block, succBlock!);
        }

        if (hasCoverageInfo && edgeCount !== null) {
          if (edgeCount === 0) {
            color = '#475569';
            markerId = 'arrow-unexecuted';
            strokeDash = '4,4';
            strokeWidth = '1.5px';
          } else {
            const edgeRatio = maxCount > 1 ? Math.log(edgeCount + 1) / Math.log(maxCount + 1) : 1;
            const edgeHue = Math.round(120 - edgeRatio * 120);
            color = `hsla(${edgeHue}, 85%, 45%, 0.85)`;
            markerId = `arrow-cov-${edgeHue}`;

            const defs = this.svg.querySelector('defs');
            if (defs && !document.getElementById(markerId)) {
              defs.appendChild(this.createArrowMarker(markerId, color));
            }
            strokeWidth = `${2 + edgeRatio * 3}px`;
          }
        } else {
          if (isConditional) {
            if (index === 0) {
              color = trueColor;
              markerId = 'arrow-true';
            } else {
              color = falseColor;
              markerId = 'arrow-false';
            }
          }
        }

        // Draw SVG Path
        const path = document.createElementNS(
          'http://www.w3.org/2000/svg',
          'path'
        );
        path.setAttribute(
          'class',
          `cfg-edge edge-from-${block.id} edge-to-${succId}`
        );
        path.setAttribute('stroke', color);
        path.setAttribute('marker-end', `url(#${markerId})`);
        path.setAttribute('stroke-width', strokeWidth);
        if (strokeDash) {
          path.setAttribute('stroke-dasharray', strokeDash);
        }

        // Calculate curve path
        const d = this.calculateEdgePath(
          fromPos,
          toPos,
          index,
          block.successors.length
        );
        path.setAttribute('d', d);

        this.edgesGroup.appendChild(path);
      });
    }
  }

  /**
   * Generates natural Bezier path for connecting edges.
   */
  private calculateEdgePath(
    from: { x: number; y: number; width: number; height: number },
    to: { x: number; y: number; width: number; height: number },
    succIndex: number,
    totalSuccs: number
  ): string {
    const fromBottomY = from.y + from.height;

    // Distribute source points along the bottom edge of the block
    let fromX = from.x + from.width / 2;
    if (totalSuccs > 1) {
      const fraction = (succIndex + 1) / (totalSuccs + 1);
      fromX = from.x + from.width * fraction;
    }

    const toTopY = to.y;
    const toX = to.x + to.width / 2;

    // Case 1: Standard flow downwards
    if (toTopY > fromBottomY) {
      const dy = toTopY - fromBottomY;
      const ctrlY1 = fromBottomY + Math.max(30, dy * 0.4);
      const ctrlY2 = toTopY - Math.max(30, dy * 0.4);
      return `M ${fromX} ${fromBottomY} C ${fromX} ${ctrlY1}, ${toX} ${ctrlY2}, ${toX} ${toTopY}`;
    }

    // Case 2: Same level or upward back-edge (loop)
    // Route from the side of the blocks
    const routeRight = toX >= fromX;

    const fromSideX = routeRight ? from.x + from.width : from.x;
    const fromSideY = from.y + from.height * 0.5;

    const toSideX = routeRight ? to.x + to.width : to.x;
    const toSideY = to.y + to.height * 0.5;

    const sideOffset = 50 + (routeRight ? succIndex * 15 : -succIndex * 15);
    const cX1 = fromSideX + (routeRight ? sideOffset : -sideOffset);
    const cX2 = toSideX + (routeRight ? sideOffset : -sideOffset);

    return `M ${fromSideX} ${fromSideY} C ${cX1} ${fromSideY}, ${cX2} ${toSideY}, ${toSideX} ${toSideY}`;
  }

  /**
   * Sets up mouse wheel zooming and click-and-drag panning.
   */
  private handleMouseMove = (e: MouseEvent) => {
    if (!this.isDragging) return;
    const dx = e.clientX - this.startDragX;
    const dy = e.clientY - this.startDragY;
    this.panX = this.startPanX + dx;
    this.panY = this.startPanY + dy;
    this.updateTransform();
  };

  private handleMouseUp = () => {
    this.isDragging = false;
  };

  /**
   * Sets up mouse wheel zooming and click-and-drag panning.
   */
  private setupInteractions() {
    // 1. Mouse wheel zoom centered on pointer
    this.svg.addEventListener('wheel', (e) => {
      e.preventDefault();

      const rect = this.svg.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      // Current position in coordinates space
      const localX = (mouseX - this.panX) / this.zoomScale;
      const localY = (mouseY - this.panY) / this.zoomScale;

      const factor = 1.15;
      let newScale = this.zoomScale;

      if (e.deltaY < 0) {
        newScale *= factor;
      } else {
        newScale /= factor;
      }

      // Clamp scale
      this.zoomScale = Math.max(0.15, Math.min(4.0, newScale));

      // Re-calculate panning to zoom into pointer
      this.panX = mouseX - localX * this.zoomScale;
      this.panY = mouseY - localY * this.zoomScale;

      this.updateTransform();
    });

    // 2. Drag Panning
    this.svg.addEventListener('mousedown', (e) => {
      // Only pan on left click
      if (e.button !== 0) return;
      this.isDragging = true;
      this.startDragX = e.clientX;
      this.startDragY = e.clientY;
      this.startPanX = this.panX;
      this.startPanY = this.panY;
    });

    window.addEventListener('mousemove', this.handleMouseMove);
    window.addEventListener('mouseup', this.handleMouseUp);

    // Clear selection when clicking empty space
    this.svg.addEventListener('click', () => {
      this.selectBlock(null);
    });
  }

  /**
   * Clean up event listeners and empty container.
   */
  public destroy() {
    window.removeEventListener('mousemove', this.handleMouseMove);
    window.removeEventListener('mouseup', this.handleMouseUp);
    this.container.innerHTML = '';
  }

  private updateTransform() {
    this.zoomGroup.setAttribute(
      'transform',
      `translate(${this.panX}, ${this.panY}) scale(${this.zoomScale})`
    );
  }

  /**
   * Highlights a selected block and dims/highlights connected edges.
   */
  public selectBlock(blockId: string | null) {
    if (this.selectedBlockId === blockId) return;
    this.selectedBlockId = blockId;

    // Update DOM card styles
    this.blocks.forEach((b) => {
      const card = this.container.querySelector(
        `#node-${b.id} .cfg-block-card`
      );
      if (card) {
        if (b.id === blockId) {
          card.classList.add('selected');
        } else {
          card.classList.remove('selected');
        }
      }
    });

    // Update SVG Edge styles
    const allEdges = this.edgesGroup.querySelectorAll('.cfg-edge');

    if (blockId === null) {
      // Reset all edges
      allEdges.forEach((el) => {
        el.classList.remove('dimmed', 'highlighted');
        el.setAttribute('stroke-width', '2px');
      });
    } else {
      allEdges.forEach((el) => {
        const isFrom = el.classList.contains(`edge-from-${blockId}`);
        const isTo = el.classList.contains(`edge-to-${blockId}`);

        el.classList.remove('highlighted', 'dimmed');
        if (isFrom || isTo) {
          el.classList.add('highlighted');
          el.setAttribute('stroke-width', '3.5px');
        } else {
          el.classList.add('dimmed');
          el.setAttribute('stroke-width', '1.5px');
        }
      });
    }

    if (this.options.onBlockSelect) {
      this.options.onBlockSelect(blockId);
    }
  }

  /**
   * Scales and pans the viewport to fully display the graph.
   */
  public fitToScreen() {
    if (this.blockPositions.size === 0) return;

    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;

    for (const pos of this.blockPositions.values()) {
      minX = Math.min(minX, pos.x);
      maxX = Math.max(maxX, pos.x + pos.width);
      minY = Math.min(minY, pos.y);
      maxY = Math.max(maxY, pos.y + pos.height);
    }

    const graphWidth = maxX - minX;
    const graphHeight = maxY - minY;
    const padding = 60;

    const containerWidth = this.container.clientWidth || 800;
    const containerHeight = this.container.clientHeight || 600;

    const scaleX = containerWidth / (graphWidth + padding * 2);
    const scaleY = containerHeight / (graphHeight + padding * 2);

    this.zoomScale = Math.max(0.2, Math.min(1.2, Math.min(scaleX, scaleY)));

    // Center alignment
    const midGraphX = minX + graphWidth / 2;
    const midGraphY = minY + graphHeight / 2;

    this.panX = containerWidth / 2 - midGraphX * this.zoomScale;
    this.panY = containerHeight / 2 - midGraphY * this.zoomScale;

    this.updateTransform();
  }
}
