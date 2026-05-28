/**
 * High-performance, interactive Hex Viewer UI component.
 * Renders hex offsets, hex bytes, and ASCII representations.
 * Supports highlighting, hovering, selection, and keyboard navigation.
 */

export interface HexViewerOptions {
  bytesPerLine?: number;
  theme?: {
    background?: string;
    text?: string;
    offsetText?: string;
    hexText?: string;
    asciiText?: string;
    hoverBg?: string;
    selectBg?: string;
    border?: string;
  };
  onOffsetHover?: (offset: number | null) => void;
  onOffsetSelect?: (offset: number | null) => void;
}

export class HexViewer {
  private container: HTMLElement;
  private data: Uint8Array;
  private bytesPerLine: number;
  private options: HexViewerOptions;
  private hoveredOffset: number | null = null;
  private selectedOffset: number | null = null;

  // DOM elements
  private viewportEl!: HTMLDivElement;
  private gridEl!: HTMLDivElement;
  private offsetCol!: HTMLDivElement;
  private hexCol!: HTMLDivElement;
  private asciiCol!: HTMLDivElement;

  // Elements by offset for fast DOM styling updates
  private byteElements: Map<number, HTMLSpanElement> = new Map();
  private asciiElements: Map<number, HTMLSpanElement> = new Map();

  constructor(
    container: HTMLElement,
    data: Uint8Array,
    options: HexViewerOptions = {}
  ) {
    this.container = container;
    this.data = data;
    this.bytesPerLine = options.bytesPerLine || 16;
    this.options = options;

    this.initLayout();
    this.render();

    this.container.addEventListener('scroll', () => {
      this.render();
    });
  }

  /**
   * Initializes the container layout with custom styled grid/flex columns.
   */
  private initLayout() {
    this.container.innerHTML = '';
    this.container.classList.add('hex-viewer-root');

    // Create style tag if not already present
    if (!document.getElementById('hex-viewer-styles')) {
      const style = document.createElement('style');
      style.id = 'hex-viewer-styles';
      style.textContent = `
        .hex-viewer-root {
          position: relative;
          font-family: 'Fira Code', 'Courier New', Courier, monospace;
          font-size: 14px;
          line-height: 1.5;
          color: var(--hex-text, #e2e8f0);
          background-color: var(--hex-bg, #0f172a);
          padding: 1rem;
          border-radius: 8px;
          border: 1px solid var(--hex-border, #334155);
          overflow: auto;
          user-select: none;
          max-height: 100%;
          box-sizing: border-box;
        }
        .hex-viewer-viewport {
          position: relative;
          width: 100%;
        }
        .hex-viewer-grid {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          display: grid;
          grid-template-columns: auto 1fr auto;
          gap: 1.5rem;
        }
        .hex-col, .offset-col, .ascii-col {
          display: flex;
          flex-direction: column;
        }
        .offset-col {
          color: var(--hex-offset-text, #64748b);
          text-align: right;
          font-weight: 500;
          border-right: 1px solid var(--hex-border, #334155);
          padding-right: 1rem;
        }
        .hex-line, .ascii-line {
          display: flex;
          align-items: center;
          height: 22px;
          box-sizing: border-box;
        }
        .hex-line {
          gap: 0.5rem;
        }
        .hex-byte {
          display: inline-block;
          width: 1.75rem;
          text-align: center;
          cursor: pointer;
          border-radius: 3px;
          transition: background-color 0.1s ease, color 0.1s ease;
        }
        .ascii-char {
          display: inline-block;
          width: 0.75rem;
          text-align: center;
          cursor: pointer;
          border-radius: 2px;
          transition: background-color 0.1s ease, color 0.1s ease;
        }
        /* Spacing spacer helper for visually separation of bytes (e.g. 8-byte chunk gap) */
        .hex-byte.gap-separator {
          margin-right: 0.5rem;
        }
        /* States */
        .hex-byte.hovered, .ascii-char.hovered {
          background-color: var(--hex-hover-bg, rgba(56, 189, 248, 0.2));
          color: var(--hex-hover-text, #38bdf8);
        }
        .hex-byte.selected, .ascii-char.selected {
          background-color: var(--hex-select-bg, rgba(56, 189, 248, 0.4));
          color: var(--hex-select-text, #38bdf8);
          outline: 1px solid var(--hex-hover-text, #38bdf8);
        }
      `;
      document.head.appendChild(style);
    }

    // Apply optional custom theme properties to container via CSS variables
    const theme = this.options.theme || {};
    if (theme.background)
      this.container.style.setProperty('--hex-bg', theme.background);
    if (theme.text) this.container.style.setProperty('--hex-text', theme.text);
    if (theme.offsetText)
      this.container.style.setProperty('--hex-offset-text', theme.offsetText);
    if (theme.hoverBg)
      this.container.style.setProperty('--hex-hover-bg', theme.hoverBg);
    if (theme.selectBg)
      this.container.style.setProperty('--hex-select-bg', theme.selectBg);
    if (theme.border)
      this.container.style.setProperty('--hex-border', theme.border);

    this.viewportEl = document.createElement('div');
    this.viewportEl.className = 'hex-viewer-viewport';

    this.gridEl = document.createElement('div');
    this.gridEl.className = 'hex-viewer-grid';

    this.offsetCol = document.createElement('div');
    this.offsetCol.className = 'offset-col';

    this.hexCol = document.createElement('div');
    this.hexCol.className = 'hex-col';

    this.asciiCol = document.createElement('div');
    this.asciiCol.className = 'ascii-col';

    this.gridEl.appendChild(this.offsetCol);
    this.gridEl.appendChild(this.hexCol);
    this.gridEl.appendChild(this.asciiCol);
    this.viewportEl.appendChild(this.gridEl);
    this.container.appendChild(this.viewportEl);
    this.setupEvents();
  }

  /**
   * Renders the data buffer to columns.
   */
  private render() {
    const len = this.data.length;
    const linesCount = Math.ceil(len / this.bytesPerLine);
    const lineHeight = 22; // px

    this.viewportEl.style.height = `${linesCount * lineHeight}px`;

    const scrollTop = this.container.scrollTop;
    const containerHeight = this.container.clientHeight || 400;

    const startIndex = Math.max(0, Math.floor(scrollTop / lineHeight) - 10);
    const endIndex = Math.min(linesCount, Math.ceil((scrollTop + containerHeight) / lineHeight) + 10);

    this.gridEl.style.transform = `translateY(${startIndex * lineHeight}px)`;

    this.offsetCol.innerHTML = '';
    this.hexCol.innerHTML = '';
    this.asciiCol.innerHTML = '';
    this.byteElements.clear();
    this.asciiElements.clear();

    // Document fragment for high performance insertion
    const offsetFrag = document.createDocumentFragment();
    const hexFrag = document.createDocumentFragment();
    const asciiFrag = document.createDocumentFragment();

    for (let lineIndex = startIndex; lineIndex < endIndex; lineIndex++) {
      const lineOffset = lineIndex * this.bytesPerLine;

      // 1. Offset column element
      const offsetDiv = document.createElement('div');
      offsetDiv.className = 'hex-line';
      offsetDiv.textContent = lineOffset
        .toString(16)
        .toUpperCase()
        .padStart(8, '0');
      offsetFrag.appendChild(offsetDiv);

      // 2. Hex bytes column elements
      const hexLineDiv = document.createElement('div');
      hexLineDiv.className = 'hex-line';

      // 3. ASCII column elements
      const asciiLineDiv = document.createElement('div');
      asciiLineDiv.className = 'ascii-line';

      for (let byteIndex = 0; byteIndex < this.bytesPerLine; byteIndex++) {
        const offset = lineOffset + byteIndex;
        if (offset < len) {
          const byteVal = this.data[offset];

          // Hex byte element
          const byteSpan = document.createElement('span');
          byteSpan.className = 'hex-byte';
          byteSpan.textContent = byteVal
            .toString(16)
            .toUpperCase()
            .padStart(2, '0');
          byteSpan.dataset.offset = offset.toString();

          // Add vertical separator gap in the middle of standard hex editor views (e.g. after 8 bytes)
          if (byteIndex === this.bytesPerLine / 2 - 1) {
            byteSpan.classList.add('gap-separator');
          }

          hexLineDiv.appendChild(byteSpan);
          this.byteElements.set(offset, byteSpan);

          // ASCII element
          const asciiSpan = document.createElement('span');
          asciiSpan.className = 'ascii-char';
          // Render non-printable characters as a dot
          asciiSpan.textContent =
            byteVal >= 32 && byteVal <= 126
              ? String.fromCharCode(byteVal)
              : '.';
          asciiSpan.dataset.offset = offset.toString();

          asciiLineDiv.appendChild(asciiSpan);
          this.asciiElements.set(offset, asciiSpan);
        }
      }

      hexFrag.appendChild(hexLineDiv);
      asciiFrag.appendChild(asciiLineDiv);
    }

    this.offsetCol.appendChild(offsetFrag);
    this.hexCol.appendChild(hexFrag);
    this.asciiCol.appendChild(asciiFrag);

    // Apply highlights to visible elements
    if (this.hoveredOffset !== null) {
      this.byteElements.get(this.hoveredOffset)?.classList.add('hovered');
      this.asciiElements.get(this.hoveredOffset)?.classList.add('hovered');
    }
    if (this.selectedOffset !== null) {
      this.byteElements.get(this.selectedOffset)?.classList.add('selected');
      this.asciiElements.get(this.selectedOffset)?.classList.add('selected');
    }
  }

  /**
   * Set up interactive event listeners.
   */
  private setupEvents() {
    const handleMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (
        target.classList.contains('hex-byte') ||
        target.classList.contains('ascii-char')
      ) {
        const offsetAttr = target.dataset.offset;
        if (offsetAttr) {
          this.setHoveredOffset(parseInt(offsetAttr, 10));
        }
      }
    };

    const handleMouseLeave = () => {
      this.setHoveredOffset(null);
    };

    const handleClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (
        target.classList.contains('hex-byte') ||
        target.classList.contains('ascii-char')
      ) {
        const offsetAttr = target.dataset.offset;
        if (offsetAttr) {
          this.setSelectedOffset(parseInt(offsetAttr, 10));
        }
      }
    };

    // Attach to columns
    this.hexCol.addEventListener('mouseover', handleMouseOver);
    this.asciiCol.addEventListener('mouseover', handleMouseOver);
    this.hexCol.addEventListener('mouseleave', handleMouseLeave);
    this.asciiCol.addEventListener('mouseleave', handleMouseLeave);
    this.hexCol.addEventListener('click', handleClick);
    this.asciiCol.addEventListener('click', handleClick);
  }

  /**
   * Highlights the hovered offset in both representation columns.
   */
  public setHoveredOffset(offset: number | null) {
    if (this.hoveredOffset === offset) return;

    // Clear previous hovered style
    if (this.hoveredOffset !== null) {
      this.byteElements.get(this.hoveredOffset)?.classList.remove('hovered');
      this.asciiElements.get(this.hoveredOffset)?.classList.remove('hovered');
    }

    this.hoveredOffset = offset;

    // Apply new hovered style
    if (this.hoveredOffset !== null) {
      this.byteElements.get(this.hoveredOffset)?.classList.add('hovered');
      this.asciiElements.get(this.hoveredOffset)?.classList.add('hovered');
    }

    if (this.options.onOffsetHover) {
      this.options.onOffsetHover(offset);
    }
  }

  /**
   * Selection highlight for an offset.
   */
  public setSelectedOffset(offset: number | null) {
    if (this.selectedOffset === offset) return;

    // Clear previous selected style
    if (this.selectedOffset !== null) {
      this.byteElements.get(this.selectedOffset)?.classList.remove('selected');
      this.asciiElements.get(this.selectedOffset)?.classList.remove('selected');
    }

    this.selectedOffset = offset;

    // Apply new selected style
    if (this.selectedOffset !== null) {
      this.byteElements.get(this.selectedOffset)?.classList.add('selected');
      this.asciiElements.get(this.selectedOffset)?.classList.add('selected');
    }

    if (this.options.onOffsetSelect) {
      this.options.onOffsetSelect(offset);
    }
  }

  /**
   * Cleanly updates the view's data without re-initializing full layout.
   */
  public setData(data: Uint8Array) {
    this.data = data;
    this.render();
  }
}
