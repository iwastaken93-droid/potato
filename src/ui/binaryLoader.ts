/**
 * Universal Reverse Engineering Tool (URET)
 * Binary Loader - Manages uploading, drag-and-drop, and mock data loading
 */

export interface BinaryLoaderOptions {
  onBinaryLoaded: (
    fileName: string,
    arrayBuffer: ArrayBuffer,
    lastModified?: number
  ) => void | Promise<void>;
  fileInputId?: string;
  uploadBtnId?: string;
  dropzoneId?: string;
}

export class BinaryLoader {
  private fileInput: HTMLInputElement | null = null;
  private uploadBtn: HTMLButtonElement | null = null;
  private fileDropzone: HTMLDivElement | null = null;
  private onBinaryLoaded: (
    fileName: string,
    arrayBuffer: ArrayBuffer,
    lastModified?: number
  ) => void | Promise<void>;

  private loaderOverlay: HTMLDivElement | null = null;
  private progressBar: HTMLDivElement | null = null;
  private loaderStatus: HTMLDivElement | null = null;

  constructor(options: BinaryLoaderOptions) {
    this.onBinaryLoaded = options.onBinaryLoaded;
    this.cacheElements(options);
    this.setupEventListeners();
  }

  private injectLoaderStyles() {
    if (document.getElementById('premium-loader-styles')) return;
    const style = document.createElement('style');
    style.id = 'premium-loader-styles';
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
        margin-bottom: 2rem;
        height: 1.5rem;
        font-weight: 500;
      }
      .premium-progress-bg {
        width: 100%;
        height: 8px;
        background: rgba(255, 255, 255, 0.03);
        border-radius: 9999px;
        overflow: hidden;
        border: 1px solid rgba(255, 255, 255, 0.08);
        position: relative;
      }
      .premium-progress-bar {
        width: 0%;
        height: 100%;
        background: linear-gradient(90deg, #6366f1, #8b5cf6);
        border-radius: 9999px;
        transition: width 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
        box-shadow: 0 0 15px rgba(99, 102, 241, 0.6);
      }
    `;
    document.head.appendChild(style);
  }

  private createLoaderOverlay() {
    this.injectLoaderStyles();
    this.loaderOverlay = document.createElement('div');
    this.loaderOverlay.className = 'premium-loader-overlay';
    this.loaderOverlay.innerHTML = `
      <div class="premium-loader-container">
        <div class="premium-spinner"></div>
        <div class="premium-loader-title">Analyzing Binary</div>
        <div class="premium-loader-status">Initializing analyzer...</div>
        <div class="premium-progress-bg">
          <div class="premium-progress-bar" id="premium-loader-bar"></div>
        </div>
      </div>
    `;
    document.body.appendChild(this.loaderOverlay);
    this.progressBar = this.loaderOverlay.querySelector('#premium-loader-bar');
    this.loaderStatus = this.loaderOverlay.querySelector('.premium-loader-status');
  }

  public showLoader(fileName: string) {
    if (!this.loaderOverlay) {
      this.createLoaderOverlay();
    }
    const titleEl = this.loaderOverlay!.querySelector('.premium-loader-title');
    if (titleEl) {
      titleEl.textContent = `Analyzing ${fileName}`;
    }
    this.updateProgress(0, 'Preparing binary parser...');
    this.loaderOverlay!.classList.add('active');
  }

  public updateProgress(percent: number, status: string) {
    if (!this.loaderOverlay) {
      this.createLoaderOverlay();
    }
    if (this.progressBar) {
      this.progressBar.style.width = `${percent}%`;
    }
    if (this.loaderStatus) {
      this.loaderStatus.textContent = status;
    }
  }

  public hideLoader() {
    if (this.loaderOverlay) {
      this.loaderOverlay.classList.remove('active');
    }
  }

  private cacheElements(options: BinaryLoaderOptions) {
    this.fileInput = document.getElementById(
      options.fileInputId || 'file-input'
    ) as HTMLInputElement;
    this.uploadBtn = document.getElementById(
      options.uploadBtnId || 'upload-btn'
    ) as HTMLButtonElement;
    this.fileDropzone = document.getElementById(
      options.dropzoneId || 'file-dropzone'
    ) as HTMLDivElement;
  }

  private setupEventListeners() {
    if (this.uploadBtn && this.fileInput) {
      this.uploadBtn.addEventListener('click', () => this.fileInput!.click());
    }

    if (this.fileDropzone && this.fileInput) {
      this.fileDropzone.addEventListener('click', (e) => {
        if (e.target !== this.uploadBtn) {
          this.fileInput!.click();
        }
      });

      this.fileDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        this.fileDropzone!.classList.add('dragover');
      });

      this.fileDropzone.addEventListener('dragleave', () => {
        this.fileDropzone!.classList.remove('dragover');
      });

      this.fileDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        this.fileDropzone!.classList.remove('dragover');
        if (e.dataTransfer && e.dataTransfer.files.length > 0) {
          this.handleUploadedFile(e.dataTransfer.files[0]);
        }
      });
    }

    if (this.fileInput) {
      this.fileInput.addEventListener('change', (e) => {
        const target = e.target as HTMLInputElement;
        if (target.files && target.files.length > 0) {
          this.handleUploadedFile(target.files[0]);
        }
      });
    }
  }

  private handleUploadedFile(file: File) {
    const reader = new FileReader();
    this.showLoader(file.name);

    reader.onprogress = (e) => {
      if (e.lengthComputable) {
        const percent = Math.round((e.loaded / e.total) * 15);
        this.updateProgress(percent, `Reading file stream (${percent}%)...`);
      }
    };

    reader.onload = async (event) => {
      if (event.target && event.target.result instanceof ArrayBuffer) {
        this.updateProgress(15, 'File loaded. Starting parser...');
        await this.onBinaryLoaded(file.name, event.target.result, file.lastModified);
        this.updateProgress(100, 'Done!');
        setTimeout(() => this.hideLoader(), 400);
      }
    };
    reader.readAsArrayBuffer(file);
  }

  public static loadSampleBinary(
    onLoad: (fileName: string, arrayBuffer: ArrayBuffer) => void
  ) {
    const textEncoder = new TextEncoder();
    const stringsToAppend: number[] = [];

    // Helper to add null-terminated ASCII string
    const addAscii = (str: string) => {
      const bytes = textEncoder.encode(str);
      stringsToAppend.push(...Array.from(bytes), 0);
    };

    // Helper to add null-terminated UTF-16LE string
    const addUtf16Le = (str: string) => {
      for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        stringsToAppend.push(code & 0xff, (code >> 8) & 0xff);
      }
      stringsToAppend.push(0, 0); // null terminator
    };

    addAscii('GetProcAddress');
    addAscii('VirtualAlloc');
    addAscii('https://github.com/google/antigravity');
    addAscii('/usr/local/bin/antigravity');
    addAscii('Welcome to Universal RE Tool!');
    addUtf16Le('ImportantUnicodeSecret');

    const mockBytes = new Uint8Array([
      0x7f,
      0x45,
      0x4c,
      0x46, // ELF Magic
      0x02, // 64-bit
      0x01, // Little Endian
      0x01, // Version 1
      0x00, // OS ABI (System V)
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // Padding
      0x02,
      0x00, // Type (EXEC)
      0x3e,
      0x00, // Machine (AMD64)
      0x01,
      0x00,
      0x00,
      0x00, // Version
      0x00,
      0x10,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // Entry Point (0x1000)
      0x40,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // PH Offset (64)
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // SH Offset
      0x00,
      0x00,
      0x00,
      0x00,
      0x40,
      0x00,
      0x38,
      0x00, // Flags + Sizes

      // Instruction block at 0x1000
      0x90, // nop
      0x55, // push rbp
      0x48,
      0x89,
      0xe5, // mov rbp, rsp
      0x48,
      0x83,
      0xec,
      0x10, // sub rsp, 16
      0xc7,
      0x45,
      0xfc,
      0x00,
      0x00,
      0x00,
      0x00, // mov dword ptr [rbp - 4], 0
      0x83,
      0x7d,
      0xfc,
      0x0a, // cmp dword ptr [rbp - 4], 10
      0x7f,
      0x0c, // jg +12 (0x102b)
      0x8b,
      0x45,
      0xfc, // mov eax, [rbp - 4]
      0x01,
      0xc0, // add eax, eax
      0x89,
      0x45,
      0xf8, // mov [rbp - 8], eax
      0xff,
      0x45,
      0xfc, // inc dword ptr [rbp - 4]
      0xeb,
      0xeb, // jmp -21 (0x1013)
      0xb8,
      0x2a,
      0x00,
      0x00,
      0x00, // mov eax, 42
      0xc9, // leave
      0xc3, // ret

      // Pad remaining to look like a realistic raw dump
      ...Array.from({ length: 64 }, (_, i) => (i * 3) % 256),
      ...stringsToAppend,
    ]);

    onLoad('sample_elf.bin', mockBytes.buffer);
  }
}
