import { Instruction } from '../disassembler/types.js';

export interface AssemblyViewOptions {
  theme?: {
    background?: string;
    text?: string;
    activeBg?: string;
    hoverBg?: string;
    commentColor?: string;
    mnemonicColor?: string;
    operandColor?: string;
    addressColor?: string;
    bytesColor?: string;
    jumpLineColor?: string;
    jumpLineHoverColor?: string;
    headerBg?: string;
    borderColor?: string;
  };
  onInstructionSelect?: (instruction: Instruction) => void;
  onCommentChange?: (address: number, comment: string) => void;
}

export class AssemblyView {
  private container: HTMLElement;
  private instructions: Instruction[] = [];
  private instructionMap: Map<number, Instruction> = new Map();
  private instructionIndices: Map<number, number> = new Map();
  private options: AssemblyViewOptions;

  // Custom comments storage
  private comments: Map<number, string> = new Map();

  // Navigation History stacks
  private historyStack: number[] = [];
  private forwardStack: number[] = [];
  private activeAddress: number | null = null;

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private headerEl!: HTMLDivElement;
  private contentEl!: HTMLDivElement;
  private canvasContainerEl!: HTMLDivElement;
  private canvasEl!: HTMLCanvasElement;
  private listViewportEl!: HTMLDivElement;
  private listEl!: HTMLDivElement;
  private backBtn!: HTMLButtonElement;
  private forwardBtn!: HTMLButtonElement;
  private statusText!: HTMLSpanElement;

  // Track row DOM elements for Y-offset calculations
  private rowElements: Map<number, HTMLDivElement> = new Map();
  private hoverAddress: number | null = null;
  private hoveredJumpLine: { source: number; target: number } | null = null;

  // ResizeObserver to handle canvas resizing
  private resizeObserver: ResizeObserver | null = null;

  constructor(
    container: HTMLElement,
    instructions: Instruction[],
    options: AssemblyViewOptions = {}
  ) {
    this.container = container;
    this.options = options;
    this.setInstructions(instructions);

    this.initLayout();
    this.setupEvents();
    this.scheduleRedraw();
  }

  /**
   * Sets new instructions and updates indexing map.
   */
  public setInstructions(instructions: Instruction[]) {
    this.instructions = instructions;
    this.instructionMap.clear();
    this.instructionIndices.clear();
    this.rowElements.clear();

    for (let i = 0; i < instructions.length; i++) {
      const inst = instructions[i];
      this.instructionMap.set(inst.address, inst);
      this.instructionIndices.set(inst.address, i);
    }

    if (this.listEl) {
      this.renderInstructions();
      this.scheduleRedraw();
    }
  }

  /**
   * Updates or sets a comment for a given instruction address.
   */
  public setComment(address: number, comment: string) {
    if (comment.trim()) {
      this.comments.set(address, comment);
    } else {
      this.comments.delete(address);
    }

    const commentEl = this.container.querySelector(
      `.row-comment[data-address="${address}"]`
    );
    if (commentEl) {
      commentEl.textContent = comment || '// ';
      if (comment) {
        commentEl.classList.add('has-comment');
      } else {
        commentEl.classList.remove('has-comment');
      }
    }

    if (this.options.onCommentChange) {
      this.options.onCommentChange(address, comment);
    }
  }

  /**
   * Retrieves a comment for a given instruction address.
   */
  public getComment(address: number): string {
    return this.comments.get(address) || '';
  }

  /**
   * Export all comments.
   */
  public getComments(): Map<number, string> {
    return new Map(this.comments);
  }

  /**
   * Import comments.
   */
  public setComments(comments: Map<number, string>) {
    this.comments = new Map(comments);
    if (this.listEl) {
      this.renderInstructions();
    }
  }

  /**
   * Highlights and navigates to the given instruction address.
   * Pushes the previous address onto the history stack.
   */
  public navigateToAddress(address: number, pushToHistory = true) {
    if (!this.instructionMap.has(address)) return;

    if (
      pushToHistory &&
      this.activeAddress !== null &&
      this.activeAddress !== address
    ) {
      this.historyStack.push(this.activeAddress);
      this.forwardStack = []; // Clear forward stack on new navigation
      this.updateHistoryButtons();
    }

    this.activeAddress = address;
    this.updateActiveRowHighlight();
    this.scrollToAddress(address);

    const inst = this.instructionMap.get(address);
    if (inst && this.options.onInstructionSelect) {
      this.options.onInstructionSelect(inst);
    }

    this.statusText.textContent = `Address: 0x${address.toString(16).toUpperCase()}`;
    this.scheduleRedraw();

    // Focus the newly active row
    setTimeout(() => {
      const activeEl = this.container.querySelector('.instruction-row.active') as HTMLElement;
      if (activeEl && document.activeElement && (document.activeElement.classList.contains('instruction-row') || document.activeElement === this.listEl)) {
        activeEl.focus();
      }
    }, 50);
  }

  /**
   * Goes back in navigation history.
   */
  public goBack() {
    if (this.historyStack.length === 0) return;
    if (this.activeAddress !== null) {
      this.forwardStack.push(this.activeAddress);
    }
    const prev = this.historyStack.pop()!;
    this.navigateToAddress(prev, false);
    this.updateHistoryButtons();
  }

  /**
   * Goes forward in navigation history.
   */
  public goForward() {
    if (this.forwardStack.length === 0) return;
    if (this.activeAddress !== null) {
      this.historyStack.push(this.activeAddress);
    }
    const next = this.forwardStack.pop()!;
    this.navigateToAddress(next, false);
    this.updateHistoryButtons();
  }

  /**
   * Sets up the DOM layout and styling.
   */
  private initLayout() {
    this.container.innerHTML = '';

    // Check and create style element if not already present
    if (!document.getElementById('assembly-viewer-styles')) {
      const style = document.createElement('style');
      style.id = 'assembly-viewer-styles';
      style.textContent = `
        .assembly-viewer-root {
          display: flex;
          flex-direction: column;
          font-family: 'Fira Code', 'Courier New', Courier, monospace;
          font-size: 13px;
          line-height: 1.6;
          color: var(--asm-text, #e2e8f0);
          background-color: var(--asm-bg, #0b0f19);
          border-radius: 12px;
          border: 1px solid var(--asm-border, #1e293b);
          width: 100%;
          height: 100%;
          overflow: hidden;
          box-sizing: border-box;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }
        
        .assembly-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 8px 16px;
          background-color: var(--asm-header-bg, #0f172a);
          border-bottom: 1px solid var(--asm-border, #1e293b);
          user-select: none;
        }

        .assembly-nav-controls {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .assembly-btn {
          background-color: #1e293b;
          border: 1px solid #334155;
          color: #94a3b8;
          border-radius: 6px;
          padding: 4px 10px;
          font-size: 11px;
          cursor: pointer;
          font-weight: 600;
          transition: all 0.2s ease;
          display: flex;
          align-items: center;
          gap: 4px;
        }

        .assembly-btn:hover:not(:disabled) {
          background-color: #334155;
          color: #f8fafc;
          border-color: #475569;
        }

        .assembly-btn:disabled {
          opacity: 0.3;
          cursor: not-allowed;
        }

        .assembly-status {
          font-size: 11px;
          font-weight: 500;
          color: #38bdf8;
          background: rgba(56, 189, 248, 0.1);
          padding: 3px 8px;
          border-radius: 4px;
          border: 1px solid rgba(56, 189, 248, 0.2);
        }

        .assembly-content {
          display: flex;
          flex: 1;
          position: relative;
          overflow-y: auto;
          overflow-x: hidden;
        }

        .canvas-container {
          position: sticky;
          left: 0;
          top: 0;
          width: 70px;
          min-width: 70px;
          height: 100%;
          z-index: 10;
          background-color: var(--asm-bg, #0b0f19);
          border-right: 1px solid rgba(30, 41, 59, 0.5);
          user-select: none;
        }

        .jump-canvas {
          position: absolute;
          left: 0;
          top: 0;
          width: 100%;
          height: 100%;
          pointer-events: all;
          cursor: pointer;
        }

        .instructions-list-viewport {
          position: relative;
          flex: 1;
          min-width: 500px;
        }

        .instructions-list {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          display: flex;
          flex-direction: column;
        }

        .instruction-row {
          display: flex;
          align-items: center;
          padding: 1px 16px;
          border-left: 3px solid transparent;
          transition: background-color 0.15s ease;
          cursor: pointer;
          height: 24px;
          box-sizing: border-box;
        }

        .instruction-row:hover {
          background-color: var(--asm-hover-bg, rgba(30, 41, 59, 0.4));
        }

        .instruction-row.active {
          background-color: var(--asm-active-bg, rgba(56, 189, 248, 0.15));
          border-left-color: #38bdf8;
        }

        .row-address {
          color: var(--asm-address-color, #64748b);
          width: 90px;
          min-width: 90px;
          font-weight: 500;
          user-select: none;
        }

        .row-bytes {
          color: var(--asm-bytes-color, #475569);
          width: 110px;
          min-width: 110px;
          padding-right: 12px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          user-select: none;
        }

        .row-mnemonic {
          color: var(--asm-mnemonic-color, #f43f5e);
          width: 70px;
          min-width: 70px;
          font-weight: 600;
        }

        .row-operands {
          color: var(--asm-operand-color, #e2e8f0);
          flex: 1;
          padding-right: 16px;
          white-space: pre-wrap;
          word-break: break-all;
        }

        .branch-link {
          color: #38bdf8;
          text-decoration: underline;
          cursor: pointer;
          font-weight: 600;
          transition: color 0.15s ease;
        }

        .branch-link:hover {
          color: #7dd3fc;
        }

        .row-comment {
          color: var(--asm-comment-color, #64748b);
          width: 250px;
          min-width: 250px;
          font-style: italic;
          cursor: text;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
          border-bottom: 1px dashed transparent;
          padding: 2px 4px;
          border-radius: 4px;
        }

        .row-comment.has-comment {
          color: var(--asm-comment-color-active, #10b981);
        }

        .row-comment:hover {
          border-bottom-color: #475569;
          background-color: rgba(30, 41, 59, 0.6);
        }

        .comment-input {
          font-family: inherit;
          font-size: inherit;
          color: #10b981;
          background: #1e293b;
          border: 1px solid #10b981;
          border-radius: 4px;
          padding: 1px 4px;
          width: 242px;
          outline: none;
        }

        /* Syntax Highlight overrides */
        .mnemonic-control { color: #f43f5e; } /* Control flow: jmp, je, call, ret */
        .mnemonic-arithmetic { color: #10b981; } /* add, sub, imul, etc. */
        .mnemonic-memory { color: #38bdf8; } /* mov, lea, push, pop */
        .mnemonic-logic { color: #a855f7; } /* xor, and, or, shl */

        .operand-reg { color: #fbbf24; } /* registers */
        .operand-imm { color: #22d3ee; } /* immediates */
        .operand-mem { color: #cbd5e1; } /* memory references */
      `;
      document.head.appendChild(style);
    }

    // Apply custom themes via CSS variables
    const theme = this.options.theme || {};
    if (theme.background)
      this.container.style.setProperty('--asm-bg', theme.background);
    if (theme.text) this.container.style.setProperty('--asm-text', theme.text);
    if (theme.activeBg)
      this.container.style.setProperty('--asm-active-bg', theme.activeBg);
    if (theme.hoverBg)
      this.container.style.setProperty('--asm-hover-bg', theme.hoverBg);
    if (theme.commentColor)
      this.container.style.setProperty(
        '--asm-comment-color',
        theme.commentColor
      );
    if (theme.mnemonicColor)
      this.container.style.setProperty(
        '--asm-mnemonic-color',
        theme.mnemonicColor
      );
    if (theme.operandColor)
      this.container.style.setProperty(
        '--asm-operand-color',
        theme.operandColor
      );
    if (theme.addressColor)
      this.container.style.setProperty(
        '--asm-address-color',
        theme.addressColor
      );
    if (theme.bytesColor)
      this.container.style.setProperty('--asm-bytes-color', theme.bytesColor);
    if (theme.headerBg)
      this.container.style.setProperty('--asm-header-bg', theme.headerBg);
    if (theme.borderColor)
      this.container.style.setProperty('--asm-border', theme.borderColor);

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'assembly-viewer-root';

    // 1. Header
    this.headerEl = document.createElement('div');
    this.headerEl.className = 'assembly-header';
    this.headerEl.setAttribute('role', 'toolbar');
    this.headerEl.setAttribute('aria-label', 'Assembly controls');

    const leftControls = document.createElement('div');
    leftControls.className = 'assembly-nav-controls';

    this.backBtn = document.createElement('button');
    this.backBtn.className = 'assembly-btn';
    this.backBtn.setAttribute('aria-label', 'Go back in history');
    this.backBtn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M15 18l-6-6 6-6"/></svg>
      Back
    `;
    this.backBtn.disabled = true;

    this.forwardBtn = document.createElement('button');
    this.forwardBtn.className = 'assembly-btn';
    this.forwardBtn.setAttribute('aria-label', 'Go forward in history');
    this.forwardBtn.innerHTML = `
      Forward
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 18l6-6-6-6"/></svg>
    `;
    this.forwardBtn.disabled = true;

    leftControls.appendChild(this.backBtn);
    leftControls.appendChild(this.forwardBtn);

    this.statusText = document.createElement('span');
    this.statusText.className = 'assembly-status';
    this.statusText.setAttribute('aria-live', 'polite');
    this.statusText.textContent = 'No selection';

    this.headerEl.appendChild(leftControls);
    this.headerEl.appendChild(this.statusText);

    // 2. Content area (Canvas + List)
    this.contentEl = document.createElement('div');
    this.contentEl.className = 'assembly-content';

    this.canvasContainerEl = document.createElement('div');
    this.canvasContainerEl.className = 'canvas-container';

    this.canvasEl = document.createElement('canvas');
    this.canvasEl.className = 'jump-canvas';
    this.canvasEl.setAttribute('role', 'img');
    this.canvasEl.setAttribute('aria-label', 'Assembly branch lines visualizer');
    this.canvasContainerEl.appendChild(this.canvasEl);

    this.listViewportEl = document.createElement('div');
    this.listViewportEl.className = 'instructions-list-viewport';

    this.listEl = document.createElement('div');
    this.listEl.className = 'instructions-list';
    this.listEl.setAttribute('role', 'listbox');
    this.listEl.setAttribute('aria-label', 'Assembly instructions list');

    this.listViewportEl.appendChild(this.listEl);

    this.contentEl.appendChild(this.canvasContainerEl);
    this.contentEl.appendChild(this.listViewportEl);

    this.rootEl.appendChild(this.headerEl);
    this.rootEl.appendChild(this.contentEl);
    this.container.appendChild(this.rootEl);

    this.renderInstructions();
    this.updateHistoryButtons();
  }

  /**
   * Renders the Instruction rows in the list column.
   */
  private renderInstructions() {
    const len = this.instructions.length;
    const rowHeight = 24; // px

    this.listViewportEl.style.height = `${len * rowHeight}px`;

    const scrollTop = this.contentEl.scrollTop;
    const containerHeight = this.contentEl.clientHeight || 500;

    const startIndex = Math.max(0, Math.floor(scrollTop / rowHeight) - 10);
    const endIndex = Math.min(
      len,
      Math.ceil((scrollTop + containerHeight) / rowHeight) + 10
    );

    this.listEl.style.transform = `translateY(${startIndex * rowHeight}px)`;

    this.listEl.innerHTML = '';
    this.rowElements.clear();

    const fragment = document.createDocumentFragment();

    for (let i = startIndex; i < endIndex; i++) {
      const inst = this.instructions[i];
      const row = document.createElement('div');
      row.className = 'instruction-row';
      row.dataset.address = inst.address.toString();
      row.setAttribute('role', 'option');
      if (this.activeAddress === inst.address) {
        row.classList.add('active');
        row.setAttribute('aria-selected', 'true');
        row.setAttribute('tabindex', '0');
      } else {
        row.setAttribute('aria-selected', 'false');
        row.setAttribute('tabindex', '-1');
      }

      // Address Column
      const addrCol = document.createElement('div');
      addrCol.className = 'row-address';
      addrCol.textContent = `0x${inst.address.toString(16).toUpperCase().padStart(8, '0')}`;

      // Bytes Column
      const bytesCol = document.createElement('div');
      bytesCol.className = 'row-bytes';
      bytesCol.textContent = Array.from(inst.bytes)
        .map((b: any) => b.toString(16).toUpperCase().padStart(2, '0'))
        .join(' ');
      bytesCol.title = bytesCol.textContent;

      // Mnemonic Column (with syntax styling)
      const mnemCol = document.createElement('div');
      mnemCol.className = 'row-mnemonic';
      const catClass = this.getMnemonicCategoryClass(inst.mnemonic);
      if (catClass) {
        mnemCol.classList.add(catClass);
      }
      mnemCol.textContent = inst.mnemonic;

      // Operands Column (with branch detection)
      const operCol = document.createElement('div');
      operCol.className = 'row-operands';
      this.renderOperands(operCol, inst);

      // Comments Column
      const commCol = document.createElement('div');
      commCol.className = 'row-comment';
      commCol.dataset.address = inst.address.toString();
      commCol.setAttribute('role', 'button');
      commCol.setAttribute('tabindex', '0');
      const existingComment = this.comments.get(inst.address);
      if (existingComment) {
        commCol.textContent = existingComment;
        commCol.classList.add('has-comment');
        commCol.setAttribute('aria-label', `Comment: ${existingComment}`);
      } else {
        commCol.textContent = '// ';
        commCol.setAttribute('aria-label', 'Add comment');
      }

      row.appendChild(addrCol);
      row.appendChild(bytesCol);
      row.appendChild(mnemCol);
      row.appendChild(operCol);
      row.appendChild(commCol);

      fragment.appendChild(row);
      this.rowElements.set(inst.address, row);
    }

    this.listEl.appendChild(fragment);
  }

  /**
   * Helper to categorize Mnemonics for styling.
   */
  private getMnemonicCategoryClass(mnemonic: string): string {
    const m = mnemonic.toLowerCase();

    // Control Flow
    if (/^(jmp|je|jne|jg|jl|ja|jb|j[a-z]{1,3}|call|ret|syscall|int)$/.test(m)) {
      return 'mnemonic-control';
    }
    // Arithmetic
    if (/^(add|sub|mul|imul|div|idiv|inc|dec|adc|sbb|neg)$/.test(m)) {
      return 'mnemonic-arithmetic';
    }
    // Logic/Shift
    if (/^(xor|and|or|not|shl|shr|sar|rol|ror|test|cmp)$/.test(m)) {
      return 'mnemonic-logic';
    }
    // Memory
    if (/^(mov|lea|push|pop|movsx|movzx|cld|std)$/.test(m)) {
      return 'mnemonic-memory';
    }

    return '';
  }

  /**
   * Renders operands, checking if any point to a valid branch address in instructions.
   */
  private renderOperands(container: HTMLElement, inst: Instruction) {
    // If there is a target immediate or branch-like operand, parse it
    // Check imm values in instruction operands
    const targetImmAddresses: number[] = [];
    if (inst.operands) {
      inst.operands.forEach((op: any) => {
        if (op.type === 'imm' && op.imm !== undefined) {
          const val = typeof op.imm === 'bigint' ? Number(op.imm) : op.imm;
          if (this.instructionMap.has(val)) {
            targetImmAddresses.push(val);
          }
        }
      });
    }

    // In case operands are not fully populated, check numeric address patterns in opStr
    const hexPattern = /0x([0-9a-fA-F]+)/g;
    let match;
    while ((match = hexPattern.exec(inst.opStr)) !== null) {
      const val = parseInt(match[1], 16);
      if (this.instructionMap.has(val) && !targetImmAddresses.includes(val)) {
        targetImmAddresses.push(val);
      }
    }

    const decPattern = /\b([0-9]{4,15})\b/g;
    while ((match = decPattern.exec(inst.opStr)) !== null) {
      const val = parseInt(match[1], 10);
      if (this.instructionMap.has(val) && !targetImmAddresses.includes(val)) {
        targetImmAddresses.push(val);
      }
    }

    if (targetImmAddresses.length === 0) {
      // Just render the text with basic styling
      container.textContent = inst.opStr;
      return;
    }

    // Tokenize/render target address as clickable link
    let renderedText = inst.opStr;
    container.innerHTML = '';

    // Simple parser: split string by the numeric values to insert links
    // To make it robust, replace target addresses with link elements
    targetImmAddresses.forEach((addr) => {
      const hexStr = `0x${addr.toString(16)}`;
      const decStr = addr.toString();

      const replaceToken = (token: string) => {
        const parts = renderedText.split(token);
        if (parts.length > 1) {
          // Rebuild HTML fragment
          const fragment = document.createDocumentFragment();
          parts.forEach((part: string, idx: number) => {
            if (part) fragment.appendChild(document.createTextNode(part));
            if (idx < parts.length - 1) {
              const link = document.createElement('span');
              link.className = 'branch-link';
              link.textContent = token;
              link.dataset.target = addr.toString();
              fragment.appendChild(link);
            }
          });
          container.innerHTML = '';
          container.appendChild(fragment);
          renderedText = container.textContent || '';
        }
      };

      // Try replacing the hex string first, then dec string
      if (renderedText.includes(hexStr)) {
        replaceToken(hexStr);
      } else if (renderedText.includes(hexStr.toUpperCase())) {
        replaceToken(hexStr.toUpperCase());
      } else if (renderedText.includes(decStr)) {
        replaceToken(decStr);
      }
    });

    if (container.children.length === 0) {
      container.textContent = inst.opStr;
    }
  }

  /**
   * Sets up event listeners for interactions.
   */
  private setupEvents() {
    // 1. Row selection & clicks
    this.listEl.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;

      // Check if clicking a branch link
      const branchLink = target.closest('.branch-link') as HTMLElement;
      if (branchLink && branchLink.dataset.target) {
        e.stopPropagation();
        const addr = parseInt(branchLink.dataset.target, 10);
        this.navigateToAddress(addr);
        return;
      }

      // Check if double clicking or clicking a comment
      const commentCol = target.closest('.row-comment') as HTMLElement;
      if (commentCol && commentCol.dataset.address) {
        e.stopPropagation();
        this.startEditingComment(commentCol);
        return;
      }

      // Default row selection
      const row = target.closest('.instruction-row') as HTMLDivElement;
      if (row && row.dataset.address) {
        const addr = parseInt(row.dataset.address, 10);
        this.navigateToAddress(addr);
      }
    });

    // Keyboard interaction on list elements
    this.listEl.addEventListener('keydown', (e) => {
      const target = e.target as HTMLElement;

      const commentCol = target.closest('.row-comment') as HTMLElement;
      if (commentCol && commentCol.dataset.address) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.stopPropagation();
          e.preventDefault();
          this.startEditingComment(commentCol);
          return;
        }
      }

      const row = target.closest('.instruction-row') as HTMLElement;
      if (row && row.dataset.address) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const currentIndex = this.instructions.findIndex((inst) => inst.address === this.activeAddress);
          if (currentIndex !== -1) {
            const nextIndex = e.key === 'ArrowDown' ? currentIndex + 1 : currentIndex - 1;
            if (nextIndex >= 0 && nextIndex < this.instructions.length) {
              const nextInst = this.instructions[nextIndex];
              this.navigateToAddress(nextInst.address);
              setTimeout(() => {
                const newActiveEl = this.container.querySelector('.instruction-row.active') as HTMLElement;
                if (newActiveEl) {
                  newActiveEl.focus();
                }
              }, 50);
            }
          }
        } else if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const addr = parseInt(row.dataset.address, 10);
          this.navigateToAddress(addr);
        }
      }
    });

    // 2. Navigation buttons
    this.backBtn.addEventListener('click', () => this.goBack());
    this.forwardBtn.addEventListener('click', () => this.goForward());

    // 3. Canvas Resizing and Scroll handling
    this.resizeObserver = new ResizeObserver(() => {
      this.resizeCanvas();
      this.drawJumpArrows();
    });
    this.resizeObserver.observe(this.canvasContainerEl);

    this.contentEl.addEventListener('scroll', () => {
      this.renderInstructions();
      this.drawJumpArrows();
    });

    // 4. Hover handling to highlight matching jump lines
    this.listEl.addEventListener('mousemove', (e) => {
      const target = e.target as HTMLElement;
      const row = target.closest('.instruction-row') as HTMLElement;
      if (row && row.dataset.address) {
        const addr = parseInt(row.dataset.address, 10);
        if (this.hoverAddress !== addr) {
          this.hoverAddress = addr;
          this.updateHoverJumpLine();
        }
      } else {
        if (this.hoverAddress !== null) {
          this.hoverAddress = null;
          this.updateHoverJumpLine();
        }
      }
    });

    this.listEl.addEventListener('mouseleave', () => {
      if (this.hoverAddress !== null) {
        this.hoverAddress = null;
        this.updateHoverJumpLine();
      }
    });

    // Canvas click branch navigation
    this.canvasEl.addEventListener('click', (e) => {
      const rect = this.canvasEl.getBoundingClientRect();
      const clickY = e.clientY - rect.top;
      const clickX = e.clientX - rect.left;

      // Find if we clicked near any vertical line
      const jumps = this.getVisibleJumps();
      let clickedJump: (typeof jumps)[0] | null = null;
      let minDistance = 6;

      jumps.forEach((j) => {
        const laneX = j.laneX;
        const startY = Math.min(j.ySource, j.yTarget);
        const endY = Math.max(j.ySource, j.yTarget);

        if (clickY >= startY - 4 && clickY <= endY + 4) {
          const dist = Math.abs(clickX - laneX);
          if (dist < minDistance) {
            minDistance = dist;
            clickedJump = j;
          }
        }
      });

      if (clickedJump) {
        const jump: (typeof jumps)[0] = clickedJump;
        this.navigateToAddress(jump.target);
      }
    });

    this.canvasEl.addEventListener('mousemove', (e) => {
      const rect = this.canvasEl.getBoundingClientRect();
      const hoverY = e.clientY - rect.top;
      const hoverX = e.clientX - rect.left;

      const jumps = this.getVisibleJumps();
      let activeJump: (typeof jumps)[0] | null = null;
      let minDistance = 6;

      jumps.forEach((j) => {
        const laneX = j.laneX;
        const startY = Math.min(j.ySource, j.yTarget);
        const endY = Math.max(j.ySource, j.yTarget);

        if (hoverY >= startY - 4 && hoverY <= endY + 4) {
          const dist = Math.abs(hoverX - laneX);
          if (dist < minDistance) {
            minDistance = dist;
            activeJump = j;
          }
        }
      });

      if (activeJump) {
        const jump: (typeof jumps)[0] = activeJump;
        if (
          !this.hoveredJumpLine ||
          this.hoveredJumpLine.source !== jump.source ||
          this.hoveredJumpLine.target !== jump.target
        ) {
          this.hoveredJumpLine = { source: jump.source, target: jump.target };
          this.canvasEl.title = `Jump from 0x${jump.source.toString(16).toUpperCase()} to 0x${jump.target.toString(16).toUpperCase()}`;
          this.drawJumpArrows();
        }
      } else {
        if (this.hoveredJumpLine !== null) {
          this.hoveredJumpLine = null;
          this.canvasEl.removeAttribute('title');
          this.drawJumpArrows();
        }
      }
    });
  }

  /**
   * Initiates editing mode for comments.
   */
  private startEditingComment(commentCol: HTMLElement) {
    const address = parseInt(commentCol.dataset.address!, 10);
    const currentText = this.comments.get(address) || '';

    commentCol.innerHTML = '';
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'comment-input';
    input.value = currentText;
    commentCol.appendChild(input);
    input.focus();

    let finished = false;
    const finishEdit = () => {
      if (finished) return;
      finished = true;
      const val = input.value.trim();
      this.setComment(address, val);
    };

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        finishEdit();
      } else if (e.key === 'Escape') {
        finished = true;
        this.setComment(address, currentText);
      }
    });

    input.addEventListener('blur', () => {
      finishEdit();
    });
  }

  /**
   * Resizes canvas to match container size.
   */
  private resizeCanvas() {
    const rect = this.canvasContainerEl.getBoundingClientRect();
    this.canvasEl.width = rect.width * window.devicePixelRatio;
    this.canvasEl.height = rect.height * window.devicePixelRatio;
    this.canvasEl.style.width = `${rect.width}px`;
    this.canvasEl.style.height = `${rect.height}px`;
  }

  /**
   * Updates state of navigation buttons.
   */
  private updateHistoryButtons() {
    this.backBtn.disabled = this.historyStack.length === 0;
    this.forwardBtn.disabled = this.forwardStack.length === 0;
  }

  /**
   * Highlights the active row and unhighlights others.
   */
  private updateActiveRowHighlight() {
    this.rowElements.forEach((el, addr) => {
      if (addr === this.activeAddress) {
        el.classList.add('active');
        el.setAttribute('aria-selected', 'true');
        el.setAttribute('tabindex', '0');
      } else {
        el.classList.remove('active');
        el.setAttribute('aria-selected', 'false');
        el.setAttribute('tabindex', '-1');
      }
    });
  }

  /**
   * Scrolls target address to center of viewport with pulse animation.
   */
  private scrollToAddress(address: number) {
    const idx = this.instructionIndices.get(address);
    if (idx === undefined) return;
    const rowHeight = 24;
    const targetScrollTop =
      idx * rowHeight - this.contentEl.clientHeight / 2 + rowHeight / 2;

    if (typeof this.contentEl.scrollTo === 'function') {
      this.contentEl.scrollTo({ top: targetScrollTop, behavior: 'smooth' });
    } else {
      this.contentEl.scrollTop = targetScrollTop;
    }

    setTimeout(() => {
      const row = this.rowElements.get(address);
      if (row) {
        row.style.transition = 'none';
        row.style.backgroundColor = 'rgba(56, 189, 248, 0.4)';
        setTimeout(() => {
          row.style.transition = 'background-color 0.8s ease';
          row.style.backgroundColor = '';
        }, 150);
      }
    }, 150);
  }

  /**
   * Detects if the hovered row is a jump instruction, or matches a jump line.
   */
  private updateHoverJumpLine() {
    let hoveredJump: { source: number; target: number } | null = null;
    const hexPattern = /0x([0-9a-fA-F]+)/;

    if (this.hoverAddress !== null) {
      const inst = this.instructionMap.get(this.hoverAddress);
      if (inst) {
        // Is this a jump instruction?
        const isJump =
          this.getMnemonicCategoryClass(inst.mnemonic) === 'mnemonic-control';
        if (isJump) {
          // Find target address
          const targets: number[] = [];

          if (inst.operands) {
            inst.operands.forEach((op: any) => {
              if (op.type === 'imm' && op.imm !== undefined) {
                const val =
                  typeof op.imm === 'bigint' ? Number(op.imm) : op.imm;
                if (this.instructionMap.has(val)) targets.push(val);
              }
            });
          }

          const match = hexPattern.exec(inst.opStr);
          if (match) {
            const val = parseInt(match[1], 16);
            if (this.instructionMap.has(val)) targets.push(val);
          }

          if (targets.length > 0) {
            hoveredJump = { source: this.hoverAddress, target: targets[0] };
          }
        } else {
          // Alternatively, is this address the target of some visible jump instruction?
          // Find any jump pointing here
          for (let i = 0; i < this.instructions.length; i++) {
            const potentialJump = this.instructions[i];
            const isControl =
              this.getMnemonicCategoryClass(potentialJump.mnemonic) ===
              'mnemonic-control';
            if (isControl) {
              let matchTarget = false;
              if (potentialJump.operands) {
                potentialJump.operands.forEach((op: any) => {
                  if (op.type === 'imm' && op.imm !== undefined) {
                    const val =
                      typeof op.imm === 'bigint' ? Number(op.imm) : op.imm;
                    if (val === this.hoverAddress) matchTarget = true;
                  }
                });
              }
              const hexMatch = /0x([0-9a-fA-F]+)/.exec(potentialJump.opStr);
              if (hexMatch && parseInt(hexMatch[1], 16) === this.hoverAddress) {
                matchTarget = true;
              }

              if (matchTarget) {
                hoveredJump = {
                  source: potentialJump.address,
                  target: this.hoverAddress,
                };
                break;
              }
            }
          }
        }
      }
    }

    this.hoveredJumpLine = hoveredJump;
    this.drawJumpArrows();
  }

  /**
   * Schedule canvas redraw on animation frame.
   */
  private scheduleRedraw() {
    requestAnimationFrame(() => this.drawJumpArrows());
  }

  /**
   * Gathers all jump lines that are visible, and computes coordinates and lanes.
   */
  private getVisibleJumps() {
    const containerRect = this.canvasContainerEl.getBoundingClientRect();
    const listRect = this.listEl.getBoundingClientRect();

    // Find all jump pairs with valid source and target row elements
    const jumps: Array<{
      source: number;
      target: number;
      ySource: number;
      yTarget: number;
      span: number;
      isConditional: boolean;
      laneIndex: number;
      laneX: number;
    }> = [];

    this.instructions.forEach((inst) => {
      const isControl =
        this.getMnemonicCategoryClass(inst.mnemonic) === 'mnemonic-control';
      if (!isControl) return;

      let targetAddress: number | null = null;

      // Extract target address
      if (inst.operands) {
        inst.operands.forEach((op: any) => {
          if (op.type === 'imm' && op.imm !== undefined) {
            const val = typeof op.imm === 'bigint' ? Number(op.imm) : op.imm;
            if (this.instructionMap.has(val)) targetAddress = val;
          }
        });
      }

      if (targetAddress === null) {
        const hexPattern = /0x([0-9a-fA-F]+)/;
        const match = hexPattern.exec(inst.opStr);
        if (match) {
          const val = parseInt(match[1], 16);
          if (this.instructionMap.has(val)) targetAddress = val;
        }
      }

      if (targetAddress === null) return;

      const sourceRow = this.rowElements.get(inst.address);
      const targetRow = this.rowElements.get(targetAddress);

      if (sourceRow && targetRow) {
        const sRect = sourceRow.getBoundingClientRect();
        const tRect = targetRow.getBoundingClientRect();

        // Compute Y offsets relative to the canvas container top
        const ySource = sRect.top + sRect.height / 2 - containerRect.top;
        const yTarget = tRect.top + tRect.height / 2 - containerRect.top;

        const sourceIndex = this.instructionIndices.get(inst.address)!;
        const targetIndex = this.instructionIndices.get(targetAddress)!;
        const span = Math.abs(sourceIndex - targetIndex);

        const isConditional = !/^(jmp|call|ret)$/i.test(inst.mnemonic);

        jumps.push({
          source: inst.address,
          target: targetAddress,
          ySource,
          yTarget,
          span,
          isConditional,
          laneIndex: -1,
          laneX: 0,
        });
      }
    });

    // Sort jumps by span descending (longer spans on outer lanes)
    jumps.sort((a, b) => b.span - a.span);

    // Assign lanes to prevent overlapping vertical lines
    const activeLanes: Array<{ startY: number; endY: number }[]> = [];

    jumps.forEach((j) => {
      const startY = Math.min(j.ySource, j.yTarget);
      const endY = Math.max(j.ySource, j.yTarget);

      let assignedLane = 0;
      while (true) {
        // Ensure lane exists
        if (activeLanes.length <= assignedLane) {
          activeLanes.push([]);
        }

        // Check for overlap in this lane
        const overlaps = activeLanes[assignedLane].some((laneSpan) => {
          return !(endY < laneSpan.startY || startY > laneSpan.endY);
        });

        if (!overlaps) {
          activeLanes[assignedLane].push({ startY, endY });
          j.laneIndex = assignedLane;
          break;
        }
        assignedLane++;
      }
    });

    // Map lane index to coordinates. Standard width of canvas is 70px.
    // Right margin at 60px where lines attach to rows. Left margin at 8px.
    // The lanes will distribute from X=12px to X=52px.
    const laneWidth = 8;
    const maxLanes = activeLanes.length;

    jumps.forEach((j) => {
      // Space lanes out. If there are few lanes, space them wider.
      const spacing = Math.min(laneWidth, 45 / Math.max(maxLanes, 1));
      j.laneX = 12 + j.laneIndex * spacing;
    });

    return jumps;
  }

  /**
   * Draws arrows on canvas for jumps.
   */
  private drawJumpArrows() {
    const ctx = this.canvasEl.getContext('2d');
    if (!ctx) return;

    const ratio = window.devicePixelRatio || 1;
    ctx.clearRect(0, 0, this.canvasEl.width, this.canvasEl.height);

    ctx.save();
    ctx.scale(ratio, ratio);

    const jumps = this.getVisibleJumps();
    const rightBoundary = 60; // where row starts

    jumps.forEach((j) => {
      const isHovered =
        this.hoveredJumpLine &&
        this.hoveredJumpLine.source === j.source &&
        this.hoveredJumpLine.target === j.target;

      const isActive =
        this.activeAddress === j.source || this.activeAddress === j.target;

      // Color selection
      let strokeStyle = '#334155'; // default muted line
      let lineWidth = 1.2;

      if (isHovered) {
        strokeStyle = j.isConditional ? '#10b981' : '#38bdf8'; // condition (green) vs unconditional (blue)
        lineWidth = 2.0;
      } else if (isActive) {
        strokeStyle = j.isConditional
          ? 'rgba(16, 185, 129, 0.7)'
          : 'rgba(56, 189, 248, 0.7)';
        lineWidth = 1.6;
      } else {
        strokeStyle = j.isConditional
          ? 'rgba(16, 185, 129, 0.3)'
          : 'rgba(56, 189, 248, 0.3)';
      }

      ctx.strokeStyle = strokeStyle;
      ctx.fillStyle = strokeStyle;
      ctx.lineWidth = lineWidth;

      // Draw connection at Source instruction
      ctx.beginPath();
      ctx.arc(rightBoundary, j.ySource, 3, 0, Math.PI * 2);
      ctx.fill();

      // Main lines path
      ctx.beginPath();
      ctx.moveTo(rightBoundary, j.ySource);
      ctx.lineTo(j.laneX, j.ySource);
      ctx.lineTo(j.laneX, j.yTarget);
      ctx.lineTo(rightBoundary - 4, j.yTarget);
      ctx.stroke();

      // Arrowhead at Target instruction
      ctx.beginPath();
      ctx.moveTo(rightBoundary, j.yTarget);
      ctx.lineTo(rightBoundary - 5, j.yTarget - 3.5);
      ctx.lineTo(rightBoundary - 5, j.yTarget + 3.5);
      ctx.closePath();
      ctx.fill();
    });

    ctx.restore();
  }

  /**
   * Destroys viewer and observers.
   */
  public destroy() {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
  }
}
