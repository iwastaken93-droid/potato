/**
 * Universal Reverse Engineering Tool (URET)
 * Loading Screen UI Component
 */

export class LoadingScreen {
  private overlay: HTMLDivElement | null = null;
  private progressBar: HTMLDivElement | null = null;
  private progressText: HTMLDivElement | null = null;
  private chunkCounter: HTMLDivElement | null = null;
  private cancelButton: HTMLButtonElement | null = null;
  private titleElement: HTMLDivElement | null = null;
  private cancelCallbacks: (() => void)[] = [];

  constructor() {
    this.createElements();
  }

  private injectStyles() {
    if (document.getElementById('loading-screen-styles')) return;
    const style = document.createElement('style');
    style.id = 'loading-screen-styles';
    style.textContent = `
      .premium-loader-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: radial-gradient(circle at center, rgba(18, 21, 28, 0.96) 0%, rgba(10, 12, 16, 0.99) 100%);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        z-index: 99999;
        transition: opacity 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        color: #f8fafc;
        font-family: var(--font-sans, sans-serif);
        opacity: 0;
        pointer-events: none;
      }
      .premium-loader-overlay.active {
        opacity: 1;
        pointer-events: auto;
      }
      .premium-loader-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        max-width: 450px;
        width: 90%;
        text-align: center;
        padding: 2.5rem;
        background: rgba(255, 255, 255, 0.01);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 24px;
        box-shadow: 0 30px 60px rgba(0, 0, 0, 0.8), inset 0 1px 0 rgba(255, 255, 255, 0.05);
      }
      .premium-spinner {
        width: 90px;
        height: 90px;
        border-radius: 50%;
        position: relative;
        background: conic-gradient(from 0deg, transparent 30%, #6366f1 100%);
        animation: premium-spin 1.2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
        margin-bottom: 2rem;
        box-shadow: 0 0 40px rgba(99, 102, 241, 0.25);
      }
      .premium-spinner::before {
        content: "";
        position: absolute;
        top: 6px;
        left: 6px;
        right: 6px;
        bottom: 6px;
        background: #0a0c10;
        border-radius: 50%;
      }
      .premium-spinner::after {
        content: "";
        position: absolute;
        top: 0;
        left: 50%;
        width: 10px;
        height: 10px;
        background: #8b5cf6;
        border-radius: 50%;
        transform: translateX(-50%);
        box-shadow: 0 0 20px #8b5cf6, 0 0 30px #8b5cf6;
      }
      @keyframes premium-spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      .premium-loader-title {
        font-size: 1.6rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 0.05em;
      }
      .premium-loader-status {
        font-size: 0.9rem;
        color: #94a3b8;
        font-family: var(--font-mono, monospace);
        margin-bottom: 1rem;
        height: 1.5rem;
        font-weight: 500;
      }
      .premium-chunk-counter {
        font-size: 0.8rem;
        color: #64748b;
        margin-bottom: 1.5rem;
        font-family: var(--font-mono, monospace);
      }
      .premium-progress-bg {
        width: 100%;
        height: 8px;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 9999px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
        position: relative;
        margin-bottom: 2rem;
      }
      .premium-progress-bar {
        width: 0%;
        height: 100%;
        background: linear-gradient(90deg, #6366f1, #8b5cf6);
        border-radius: 9999px;
        transition: width 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
        box-shadow: 0 0 15px rgba(99, 102, 241, 0.6);
      }
      .premium-cancel-btn {
        background: rgba(239, 68, 68, 0.1);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.2);
        padding: 0.5rem 1.5rem;
        border-radius: 9999px;
        font-size: 0.85rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
      }
      .premium-cancel-btn:hover {
        background: rgba(239, 68, 68, 0.25);
        border-color: rgba(239, 68, 68, 0.4);
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.25);
      }
    `;
    document.head.appendChild(style);
  }

  private createElements() {
    if (typeof document === 'undefined') return;
    this.injectStyles();

    this.overlay = document.createElement('div');
    this.overlay.className = 'premium-loader-overlay';
    this.overlay.innerHTML = `
      <div class="premium-loader-container">
        <div class="premium-spinner"></div>
        <div class="premium-loader-title">Analyzing Binary</div>
        <div class="premium-loader-status">Initializing...</div>
        <div class="premium-chunk-counter">Chunks: 0 / 0</div>
        <div class="premium-progress-bg">
          <div class="premium-progress-bar" id="premium-loader-bar"></div>
        </div>
        <button class="premium-cancel-btn" id="premium-loader-cancel">Cancel</button>
      </div>
    `;

    document.body.appendChild(this.overlay);

    this.progressBar = this.overlay.querySelector('#premium-loader-bar');
    this.progressText = this.overlay.querySelector('.premium-loader-status');
    this.chunkCounter = this.overlay.querySelector('.premium-chunk-counter');
    this.cancelButton = this.overlay.querySelector('#premium-loader-cancel');
    this.titleElement = this.overlay.querySelector('.premium-loader-title');

    this.cancelButton?.addEventListener('click', () => {
      this.triggerCancel();
    });
  }

  public show(fileName: string) {
    if (!this.overlay) {
      this.createElements();
    }
    if (this.titleElement) {
      this.titleElement.textContent = `Analyzing ${fileName}`;
    }
    this.update(0, 0, 0, 'Preparing binary...');
    this.overlay?.classList.add('active');
  }

  public update(percent: number, loadedChunks: number, totalChunks: number, statusText: string) {
    if (!this.overlay) {
      this.createElements();
    }
    if (this.progressBar) {
      this.progressBar.style.width = `${percent}%`;
    }
    if (this.progressText) {
      this.progressText.textContent = statusText;
    }
    if (this.chunkCounter) {
      if (totalChunks > 0) {
        this.chunkCounter.textContent = `Processed Chunks: ${loadedChunks} / ${totalChunks}`;
        this.chunkCounter.style.display = 'block';
      } else {
        this.chunkCounter.style.display = 'none';
      }
    }
  }

  public hide() {
    this.overlay?.classList.remove('active');
  }

  public onCancel(callback: () => void) {
    this.cancelCallbacks.push(callback);
  }

  private triggerCancel() {
    this.cancelCallbacks.forEach((cb) => {
      try {
        cb();
      } catch (e) {
        console.error('Error in cancel callback:', e);
      }
    });
    this.hide();
  }

  public destroy() {
    if (this.overlay && this.overlay.parentNode) {
      this.overlay.parentNode.removeChild(this.overlay);
    }
    this.overlay = null;
    this.progressBar = null;
    this.progressText = null;
    this.chunkCounter = null;
    this.cancelButton = null;
    this.titleElement = null;
    this.cancelCallbacks = [];
  }
}
