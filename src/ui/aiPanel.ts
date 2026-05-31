/**
 * Premium AI Explainer Panel UI Component
 * Part of the Universal Reverse Engineering Tool (URET)
 * Displays explanations, detected patterns, pseudocode, and security recommendations.
 */

import { Symbol } from '../disassembler/types.js';
import { AIExplanationEngine, AIExplanationResult } from '../analyzer/ai.js';

export interface AIPanelOptions {
  onNavigateToAddress?: (address: number) => void;
}

export class AIPanel {
  private container: HTMLElement;
  private options: AIPanelOptions;

  // State
  private currentSymbol: Symbol | null = null;
  private currentCode: string = '';
  private isAnalyzing: boolean = false;
  private explanationResult: AIExplanationResult | null = null;

  // DOM Elements
  private rootEl!: HTMLDivElement;
  private statusHeaderEl!: HTMLDivElement;
  private contentEl!: HTMLDivElement;
  private customCodeTextarea!: HTMLTextAreaElement;

  constructor(container: HTMLElement, options: AIPanelOptions = {}) {
    this.container = container;
    this.options = options;
    this.initLayout();
    this.injectCustomStyles();
  }

  /**
   * Updates the panel with the currently active symbol and its code block (decompiled/disassembled)
   */
  public updateSymbolData(symbol: Symbol | null, code: string) {
    this.currentSymbol = symbol;
    this.currentCode = code;
    this.renderHeader();

    // Automatically trigger explanation when symbol changes, unless empty
    if (code && code.trim()) {
      this.triggerAnalysis(code);
    } else {
      this.explanationResult = null;
      this.renderResults();
    }
  }

  private injectCustomStyles() {
    if (document.getElementById('ai-panel-custom-styles')) return;
    const style = document.createElement('style');
    style.id = 'ai-panel-custom-styles';
    style.textContent = `
      .ai-panel-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1.5rem;
        height: 100%;
        overflow: hidden;
      }
      @media (max-width: 1024px) {
        .ai-panel-grid {
          grid-template-columns: 1fr;
          overflow-y: auto;
        }
      }
      .ai-column {
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
        overflow-y: auto;
        height: 100%;
        padding-right: 0.5rem;
      }
      .ai-card {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-lg);
        padding: 1.25rem;
        transition: all var(--transition-normal);
      }
      .ai-card:hover {
        border-color: rgba(99, 102, 241, 0.25);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
      }
      .ai-card-title {
        font-size: 0.95rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
      }
      .ai-badge {
        display: inline-flex;
        align-items: center;
        padding: 0.25rem 0.6rem;
        font-size: 0.75rem;
        font-weight: 600;
        border-radius: 9999px;
        background: rgba(99, 102, 241, 0.15);
        color: var(--accent-start);
        border: 1px solid rgba(99, 102, 241, 0.25);
      }
      .ai-badge-complexity {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.25);
      }
      .pattern-item {
        padding: 0.75rem;
        background: rgba(255, 255, 255, 0.01);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        margin-bottom: 0.75rem;
      }
      .pattern-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 0.35rem;
      }
      .pattern-name {
        font-weight: 600;
        font-size: 0.85rem;
        color: var(--text-primary);
      }
      .pattern-bar-container {
        height: 4px;
        background: rgba(255, 255, 255, 0.05);
        border-radius: 2px;
        overflow: hidden;
        margin-top: 0.5rem;
      }
      .pattern-bar {
        height: 100%;
        background: linear-gradient(90deg, var(--accent-start), var(--accent-end));
        border-radius: 2px;
      }
      .suggestion-box {
        background: rgba(245, 158, 11, 0.05);
        border-left: 3px solid #f59e0b;
        padding: 0.75rem 1rem;
        border-radius: 0 var(--radius-md) var(--radius-md) 0;
        margin-bottom: 0.5rem;
        font-size: 0.85rem;
        color: var(--text-secondary);
      }
      .ai-loading {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 1rem;
        height: 100%;
        color: var(--text-muted);
      }
      .ai-spinner {
        width: 40px;
        height: 40px;
        border: 3px solid rgba(99, 102, 241, 0.1);
        border-top: 3px solid var(--accent-start);
        border-radius: 50%;
        animation: ai-spin 1s linear infinite;
      }
      @keyframes ai-spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .code-container {
        position: relative;
        font-family: var(--font-mono);
        font-size: 0.85rem;
        background: #090B0F;
        border: 1px solid var(--border-color);
        border-radius: var(--radius-md);
        padding: 1rem;
        margin: 0;
        white-space: pre-wrap;
        overflow: auto;
        max-height: 350px;
        color: #E2E8F0;
        line-height: 1.5;
      }
      .copy-btn {
        position: absolute;
        top: 0.5rem;
        right: 0.5rem;
        padding: 0.25rem 0.5rem;
        font-size: 0.75rem;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--border-color);
        border-radius: var(--radius-sm);
        color: var(--text-secondary);
        cursor: pointer;
        transition: all var(--transition-fast);
      }
      .copy-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        color: var(--text-primary);
      }
    `;
    document.head.appendChild(style);
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'ai-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: flex;
      flex-direction: column;
      height: 100%;
      padding: 1.5rem;
      gap: 1.25rem;
      box-sizing: border-box;
    `;

    // Header Status Section
    this.statusHeaderEl = document.createElement('div');
    this.statusHeaderEl.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.75rem;
    `;
    this.rootEl.appendChild(this.statusHeaderEl);

    // Main Content Panel
    this.contentEl = document.createElement('div');
    this.contentEl.style.cssText = `
      flex: 1;
      overflow: hidden;
    `;
    this.rootEl.appendChild(this.contentEl);

    this.container.appendChild(this.rootEl);
    this.renderHeader();
    this.renderResults();
  }

  private renderHeader() {
    if (this.currentSymbol) {
      this.statusHeaderEl.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.25rem;">
          <div style="display: flex; align-items: center; gap: 0.5rem;">
            <h2 style="margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">🤖 AI Assistant Analysis</h2>
            <span class="ai-badge">${this.currentSymbol.type}</span>
          </div>
          <span style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-mono);">
            Scope: ${this.currentSymbol.name} | Address: 0x${this.currentSymbol.address.toString(16)} | Binding: ${this.currentSymbol.binding}
          </span>
        </div>
        <div style="display: flex; gap: 0.50rem;">
          <button class="btn btn-secondary" id="reanalyze-btn" style="padding: 0.4rem 0.75rem; font-size: 0.8rem;">
            🔄 Re-Analyze
          </button>
        </div>
      `;

      const reBtn = this.statusHeaderEl.querySelector('#reanalyze-btn');
      reBtn?.addEventListener('click', () => {
        if (this.currentCode) {
          this.triggerAnalysis(this.currentCode);
        }
      });
    } else {
      this.statusHeaderEl.innerHTML = `
        <div>
          <h2 style="margin: 0; font-size: 1.1rem; font-weight: 700; color: var(--text-primary);">🤖 AI Explainer Sandbox</h2>
          <span style="font-size: 0.8rem; color: var(--text-muted);">Paste arbitrary decompiled or disassembled code blocks to explain them.</span>
        </div>
      `;
    }
  }

  private triggerAnalysis(code: string) {
    this.isAnalyzing = true;
    this.renderResults();

    // Simulate loading/computation micro-delay for premium feel
    setTimeout(() => {
      try {
        const symbolContext = this.currentSymbol
          ? {
              functionName: this.currentSymbol.name,
              arch: 'x86_64',
            }
          : undefined;
        this.explanationResult = AIExplanationEngine.analyze(
          code,
          symbolContext
        );
      } catch (err) {
        console.error(err);
      } finally {
        this.isAnalyzing = false;
        this.renderResults();
      }
    }, 450);
  }

  private renderResults() {
    if (this.isAnalyzing) {
      this.contentEl.innerHTML = `
        <div class="ai-loading">
          <div class="ai-spinner"></div>
          <div>Analyzing registers, instruction flows, and compiling pseudocode...</div>
        </div>
      `;
      return;
    }

    if (!this.explanationResult) {
      this.renderSandbox();
      return;
    }

    const {
      summary,
      functionality,
      patterns,
      pseudocode,
      complexity,
      suggestions,
    } = this.explanationResult;

    this.contentEl.innerHTML = `
      <div class="ai-panel-grid">
        <!-- Left Column: Explanation and Patterns -->
        <div class="ai-column">
          <!-- Summary card -->
          <div class="ai-card">
            <div class="ai-card-title">
              💡 Function Summary
            </div>
            <div style="font-size: 0.9rem; color: var(--text-secondary); line-height: 1.6; margin-bottom: 1rem;">
              ${summary}
            </div>
            <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
              <span class="ai-badge ai-badge-complexity">⏳ Time: ${complexity.time}</span>
              <span class="ai-badge ai-badge-complexity">💾 Space: ${complexity.space}</span>
            </div>
          </div>

          <!-- Functionality Bullets -->
          <div class="ai-card">
            <div class="ai-card-title">
              📋 Detailed Functionality
            </div>
            <ul style="margin: 0; padding-left: 1.25rem; font-size: 0.85rem; color: var(--text-secondary); display: flex; flex-direction: column; gap: 0.5rem;">
              ${functionality.map((f) => `<li>${f}</li>`).join('')}
            </ul>
          </div>

          <!-- Identified Patterns -->
          <div class="ai-card">
            <div class="ai-card-title">
              🔍 Identified Code Patterns
            </div>
            ${
              patterns.length === 0
                ? `
              <div style="font-size: 0.85rem; color: var(--text-muted);">No highly confident cryptographic, system, or algorithmic signatures found. Just standard control loop structure.</div>
            `
                : patterns
                    .map(
                      (p) => `
              <div class="pattern-item">
                <div class="pattern-header">
                  <span class="pattern-name">${p.name}</span>
                  <span class="ai-badge" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2);">${p.confidence}% match</span>
                </div>
                <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.4rem;">${p.description}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-sans);">
                  <strong>Indicators:</strong> ${p.matchedElements.join(', ')}
                </div>
                <div class="pattern-bar-container">
                  <div class="pattern-bar" style="width: ${p.confidence}%;"></div>
                </div>
              </div>
            `
                    )
                    .join('')
            }
          </div>
        </div>

        <!-- Right Column: Reconstructed Pseudocode and Security suggestions -->
        <div class="ai-column">
          <!-- High-Level Pseudocode -->
          <div class="ai-card" style="display: flex; flex-direction: column; flex: 1; min-height: 0;">
            <div class="ai-card-title">
              📝 High-Level Reconstructed Pseudocode
            </div>
            <div style="flex: 1; min-height: 0; position: relative;">
              <pre class="code-container"><button class="copy-btn" id="ai-copy-pseudocode-btn">Copy</button><code>${this.escapeHtml(pseudocode)}</code></pre>
            </div>
          </div>

          <!-- Security Suggestions -->
          <div class="ai-card">
            <div class="ai-card-title">
              ⚠️ Architecture & Security Warnings
            </div>
            ${
              suggestions.length === 0
                ? `
              <div style="font-size: 0.85rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.35rem;">
                ✅ No immediate security concerns or simple vulnerabilities found in this structure.
              </div>
            `
                : suggestions
                    .map(
                      (s) => `
              <div class="suggestion-box">
                ${s}
              </div>
            `
                    )
                    .join('')
            }
          </div>
          
          <!-- Paste New Code Button to reset sandbox -->
          <button class="btn btn-secondary" id="ai-open-sandbox-btn" style="width: 100%; padding: 0.6rem; font-size: 0.85rem;">
            🧪 Open Explainer Sandbox
          </button>
        </div>
      </div>
    `;

    // Add event listeners
    this.contentEl
      .querySelector('#ai-open-sandbox-btn')
      ?.addEventListener('click', () => {
        this.currentSymbol = null;
        this.explanationResult = null;
        this.renderHeader();
        this.renderResults();
      });

    const copyBtn = this.contentEl.querySelector(
      '#ai-copy-pseudocode-btn'
    ) as HTMLButtonElement;
    copyBtn?.addEventListener('click', () => {
      navigator.clipboard.writeText(pseudocode).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 1500);
      });
    });
  }

  private renderSandbox() {
    this.contentEl.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 1rem; height: 100%;">
        <div style="font-size: 0.9rem; color: var(--text-secondary);">
          Provide any target assembly language dump, JVM instructions, Dalvik instructions, WASM text format, or decompiled C-like pseudocode block. The engine will inspect references, constants, and flow syntax to generate a comprehensive AI breakdown.
        </div>
        <textarea id="ai-sandbox-textarea" placeholder="Paste code here (e.g. loops, XOR math, x86 assembly, etc.)..." style="
          flex: 1;
          background: #090B0F;
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          color: #E2E8F0;
          font-family: var(--font-mono);
          font-size: 0.85rem;
          padding: 1rem;
          resize: none;
          outline: none;
          box-sizing: border-box;
          line-height: 1.5;
        "></textarea>
        <button class="btn btn-primary" id="ai-sandbox-explain-btn" style="padding: 0.75rem; font-size: 0.9rem; font-weight: 600;">
          🚀 Explain Code Block
        </button>
      </div>
    `;

    this.customCodeTextarea = this.contentEl.querySelector(
      '#ai-sandbox-textarea'
    ) as HTMLTextAreaElement;

    // Provide a default example block so the user can easily test it
    this.customCodeTextarea.value = `// Paste decompiled functions here. Example:
void encrypt_block(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9e3779b9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0] = v0; v[1] = v1;
}`;

    this.contentEl
      .querySelector('#ai-sandbox-explain-btn')
      ?.addEventListener('click', () => {
        const code = this.customCodeTextarea.value;
        if (code && code.trim()) {
          this.triggerAnalysis(code);
        }
      });
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
}
