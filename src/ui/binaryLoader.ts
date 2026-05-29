/**
 * Universal Reverse Engineering Tool (URET)
 * Binary Loader - Manages uploading, drag-and-drop, and mock data loading
 */

export interface BinaryLoaderOptions {
  onBinaryLoaded: (
    fileName: string,
    arrayBuffer: ArrayBuffer,
    lastModified?: number
  ) => void;
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
  ) => void;

  constructor(options: BinaryLoaderOptions) {
    this.onBinaryLoaded = options.onBinaryLoaded;
    this.cacheElements(options);
    this.setupEventListeners();
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
    reader.onload = (event) => {
      if (event.target && event.target.result instanceof ArrayBuffer) {
        this.onBinaryLoaded(file.name, event.target.result, file.lastModified);
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
