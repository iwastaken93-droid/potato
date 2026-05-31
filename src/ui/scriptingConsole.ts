import { ScriptingEngine, ScriptingContext } from '../analyzer/scripting.js';

export class ScriptingConsole {
  private container: HTMLElement;
  private engine: ScriptingEngine;
  private history: string[] = [];
  private historyIndex = -1;

  // DOM elements
  private rootEl!: HTMLDivElement;
  private outputArea!: HTMLDivElement;
  private inputEl!: HTMLInputElement;
  private runBtn!: HTMLButtonElement;
  private clearBtn!: HTMLButtonElement;

  constructor(container: HTMLElement, initialContext: ScriptingContext) {
    this.container = container;
    this.engine = new ScriptingEngine(initialContext);

    this.injectStyles();
    this.initDOM();
    this.setupHistory();
    this.showWelcomeMessage();
  }

  public updateContext(context: ScriptingContext) {
    this.engine.updateContext(context);
  }

  private injectStyles() {
    if (document.getElementById('scripting-console-styles')) return;

    const style = document.createElement('style');
    style.id = 'scripting-console-styles';
    style.textContent = `
      .scripting-console-root {
        display: grid;
        grid-template-rows: auto 1fr auto;
        height: 100%;
        padding: 1.5rem;
        box-sizing: border-box;
        font-family: var(--font-sans), system-ui, -apple-system, sans-serif;
        color: var(--text-primary);
        background: rgba(10, 12, 16, 0.2);
        overflow: hidden;
        gap: 1rem;
      }

      .console-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: rgba(25, 30, 40, 0.45);
        backdrop-filter: blur(16px) saturate(180%);
        -webkit-backdrop-filter: blur(16px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 0.75rem 1.25rem;
        border-radius: var(--radius-md, 8px);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
      }

      .console-title-group {
        display: flex;
        flex-direction: column;
      }

      .console-title {
        font-size: 1.15rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        background: linear-gradient(135deg, #a78bfa, #22d3ee);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
      }

      .console-subtitle {
        font-size: 0.75rem;
        opacity: 0.6;
        margin-top: 0.2rem;
      }

      .console-actions {
        display: flex;
        gap: 0.75rem;
      }

      .console-btn {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: var(--text-primary);
        padding: 0.5rem 1rem;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.85rem;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }

      .console-btn:hover {
        background: rgba(255, 255, 255, 0.12);
        border-color: rgba(255, 255, 255, 0.2);
        transform: translateY(-1px);
      }

      .console-btn:active {
        transform: translateY(0);
      }

      .console-btn.btn-accent {
        background: linear-gradient(135deg, rgba(167, 139, 250, 0.25), rgba(34, 211, 238, 0.25));
        border-color: rgba(34, 211, 238, 0.4);
      }

      .console-btn.btn-accent:hover {
        background: linear-gradient(135deg, rgba(167, 139, 250, 0.35), rgba(34, 211, 238, 0.35));
        box-shadow: 0 0 15px rgba(34, 211, 238, 0.2);
      }

      .console-body {
        background: rgba(15, 18, 25, 0.55);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: var(--radius-md, 8px);
        padding: 1.25rem;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
        box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.5);
        scrollbar-width: thin;
        scroll-behavior: smooth;
      }

      .console-entry {
        font-family: 'Fira Code', 'Courier New', Courier, monospace;
        font-size: 0.9rem;
        line-height: 1.5;
        white-space: pre-wrap;
        word-break: break-all;
        animation: fadeIn 0.15s ease-out;
      }

      @keyframes fadeIn {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
      }

      .entry-input {
        color: #e2e8f0;
        display: flex;
        align-items: flex-start;
      }

      .entry-input::before {
        content: "❯";
        color: #a78bfa;
        margin-right: 0.75rem;
        font-weight: bold;
        flex-shrink: 0;
      }

      .entry-output {
        padding-left: 1.5rem;
        margin-top: 0.25rem;
        margin-bottom: 0.75rem;
        border-left: 2px solid rgba(255, 255, 255, 0.05);
      }

      .output-success {
        color: #34d399;
      }

      .output-error {
        color: #f87171;
        background: rgba(248, 113, 113, 0.05);
        padding: 0.5rem;
        border-radius: 4px;
        border: 1px solid rgba(248, 113, 113, 0.1);
      }

      .output-log {
        color: #a7f3d0;
        font-style: italic;
      }

      .console-input-bar {
        display: flex;
        gap: 0.75rem;
        background: rgba(25, 30, 40, 0.45);
        backdrop-filter: blur(16px) saturate(180%);
        -webkit-backdrop-filter: blur(16px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 0.75rem 1rem;
        border-radius: var(--radius-md, 8px);
        align-items: center;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
      }

      .input-prompt {
        color: #34d399;
        font-family: monospace;
        font-weight: bold;
        font-size: 1.1rem;
        user-select: none;
      }

      .console-input {
        flex: 1;
        background: transparent;
        border: none;
        outline: none;
        color: #ffffff;
        font-family: 'Fira Code', 'Courier New', Courier, monospace;
        font-size: 0.95rem;
        caret-color: #34d399;
      }

      .console-input::placeholder {
        color: rgba(255, 255, 255, 0.3);
      }
    `;
    document.head.appendChild(style);
  }

  private initDOM() {
    this.rootEl = document.createElement('div');
    this.rootEl.className = 'scripting-console-root';

    // Header
    const header = document.createElement('div');
    header.className = 'console-header';
    header.innerHTML = `
      <div class="console-title-group">
        <h3 class="console-title">Interactive JS Shell</h3>
        <span class="console-subtitle">Query disassembler state, filter symbols, and execute custom binary analysis logic</span>
      </div>
      <div class="console-actions">
        <button class="console-btn" id="console-clear-btn">
          🧹 Clear Logs
        </button>
        <button class="console-btn btn-accent" id="console-help-btn">
          💡 Help Guide
        </button>
      </div>
    `;

    // Output area
    this.outputArea = document.createElement('div');
    this.outputArea.className = 'console-body';

    // Input Bar
    const inputBar = document.createElement('div');
    inputBar.className = 'console-input-bar';
    inputBar.innerHTML = `
      <span class="input-prompt">❯</span>
      <input type="text" class="console-input" id="console-input-field" placeholder="Type JS code here... e.g. help() or getFunctions().length" autocomplete="off" spellcheck="false" />
      <button class="console-btn btn-accent" id="console-run-btn">Run</button>
    `;

    this.rootEl.appendChild(header);
    this.rootEl.appendChild(this.outputArea);
    this.rootEl.appendChild(inputBar);

    this.container.appendChild(this.rootEl);

    // Cache elements
    this.inputEl = this.rootEl.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    this.runBtn = this.rootEl.querySelector(
      '#console-run-btn'
    ) as HTMLButtonElement;
    this.clearBtn = this.rootEl.querySelector(
      '#console-clear-btn'
    ) as HTMLButtonElement;

    // Event listeners
    this.runBtn.addEventListener('click', () => this.handleRun());
    this.clearBtn.addEventListener('click', () => this.clearLogs());
    this.rootEl
      .querySelector('#console-help-btn')
      ?.addEventListener('click', () => {
        this.executeCommand('help()');
      });

    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        this.handleRun();
      }
    });
  }

  private setupHistory() {
    this.inputEl.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (this.history.length === 0) return;
        if (this.historyIndex === -1) {
          this.historyIndex = this.history.length - 1;
        } else if (this.historyIndex > 0) {
          this.historyIndex--;
        }
        this.inputEl.value = this.history[this.historyIndex];
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (this.historyIndex === -1) return;
        if (this.historyIndex < this.history.length - 1) {
          this.historyIndex++;
          this.inputEl.value = this.history[this.historyIndex];
        } else {
          this.historyIndex = -1;
          this.inputEl.value = '';
        }
      }
    });
  }

  private showWelcomeMessage() {
    this.appendLog(
      `Welcome to Universal Disassembler Scripting Console.
Type JavaScript commands to inspect and query the current binary.
Examples:
  - help() (Get standard guide)
  - data.length (Total binary size in bytes)
  - getFunctions().map(f => f.name) (Get names of all functions)
  - searchInstructions("mov") (Filter instructions containing "mov")
  - findStrings("flag") (Find extracted strings containing "flag")`,
      'output-log'
    );
  }

  private handleRun() {
    const code = this.inputEl.value.trim();
    if (!code) return;

    this.history.push(code);
    this.historyIndex = -1;
    this.inputEl.value = '';

    this.executeCommand(code);
  }

  private executeCommand(code: string) {
    // 1. Log input command
    const cmdEl = document.createElement('div');
    cmdEl.className = 'console-entry entry-input';
    cmdEl.textContent = code;
    this.outputArea.appendChild(cmdEl);

    // 2. Execute
    const response = this.engine.execute(code);

    // 3. Log console.log messages if any
    if (response.logs && response.logs.length > 0) {
      response.logs.forEach((log) => {
        this.appendLog(log, 'output-log');
      });
    }

    // 4. Log returned result
    if (response.success) {
      this.appendLog(this.formatResult(response.result), 'output-success');
    } else {
      this.appendLog(`Error: ${response.result}`, 'output-error');
    }

    this.outputArea.scrollTop = this.outputArea.scrollHeight;
  }

  private appendLog(text: string, className: string) {
    const el = document.createElement('div');
    el.className = `console-entry entry-output ${className}`;
    el.textContent = text;
    this.outputArea.appendChild(el);
    this.outputArea.scrollTop = this.outputArea.scrollHeight;
  }

  private formatResult(result: unknown): string {
    if (result === undefined) return 'undefined';
    if (result === null) return 'null';
    if (typeof result === 'object') {
      try {
        if (result instanceof Uint8Array) {
          return `Uint8Array(len=${result.length}) [ ${Array.from(
            result.slice(0, 10)
          )
            .map((x) => x.toString(16).padStart(2, '0'))
            .join(' ')} ... ]`;
        }
        return JSON.stringify(result, null, 2);
      } catch {
        return String(result);
      }
    }
    return String(result);
  }

  private clearLogs() {
    this.outputArea.innerHTML = '';
    this.showWelcomeMessage();
  }
}
