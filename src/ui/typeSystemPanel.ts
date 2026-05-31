/**
 * Premium Type System Viewer & Struct Editor Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides struct definition & relationship visualizations.
 */

import { renderSidebarItems, renderStructDetails } from './typeRenderers.js';
import {
  createNewStructPrompt,
  deleteStruct,
  addFieldToStruct,
  removeField,
  showImportCDialog,
  parseCStructs,
} from './typeEditors.js';

export interface StructField {
  name: string;
  type: string;
  offset: number;
  size: number;
  arrayLength?: number;
  description?: string;
}

export interface StructDefinition {
  name: string;
  size: number;
  fields: StructField[];
  description?: string;
  isUnion?: boolean;
  isEnum?: boolean;
  enumValues?: { name: string; value: number }[];
}

export interface TypeSystemPanelOptions {
  onNavigate?: (
    targetView: 'assembly' | 'hex' | 'decompiler',
    address: number
  ) => void;
}

export class TypeSystemPanel {
  private container: HTMLElement;
  private options: TypeSystemPanelOptions;
  private structs: StructDefinition[] = [];
  private selectedStructName: string = '';
  private searchQuery: string = '';
  private pointerSize: number = 8; // Default 64-bit
  private typedefs: Record<string, string> = {};

  // DOM elements
  private rootEl!: HTMLDivElement;
  private structListEl!: HTMLDivElement;
  private structDetailEl!: HTMLDivElement;
  private searchInputEl!: HTMLInputElement;

  constructor(container: HTMLElement, options: TypeSystemPanelOptions = {}) {
    this.container = container;
    this.options = options;
    this.typedefs = {};

    this.initDefaultStructs();
    this.initLayout();
    this.setupEvents();
    this.render();
  }


  /**
   * Updates pointer size based on architecture
   */
  public updateArchitecture(arch: string) {
    if (arch.includes('32') || (arch.includes('86') && !arch.includes('64'))) {
      this.pointerSize = 4;
    } else {
      this.pointerSize = 8;
    }
    this.recalculateAllStructSizes();
    this.render();
  }

  private initDefaultStructs() {
    this.structs = [
      {
        name: 'Point2D',
        size: 8,
        description: 'Simple 2D coordinate representation',
        fields: [
          {
            name: 'x',
            type: 'int32_t',
            offset: 0,
            size: 4,
            description: 'X coordinate',
          },
          {
            name: 'y',
            type: 'int32_t',
            offset: 4,
            size: 4,
            description: 'Y coordinate',
          },
        ],
      },
      {
        name: 'Rect',
        size: 16,
        description: 'Rectangle definition using 2D points and dimensions',
        fields: [
          {
            name: 'origin',
            type: 'Point2D',
            offset: 0,
            size: 8,
            description: 'Top-left origin corner',
          },
          {
            name: 'width',
            type: 'int32_t',
            offset: 8,
            size: 4,
            description: 'Width dimension',
          },
          {
            name: 'height',
            type: 'int32_t',
            offset: 12,
            size: 4,
            description: 'Height dimension',
          },
        ],
      },
      {
        name: 'Node',
        size: 16,
        description: 'Single node element in a linked list structure',
        fields: [
          {
            name: 'value',
            type: 'int32_t',
            offset: 0,
            size: 4,
            description: 'Payload value',
          },
          {
            name: 'padding',
            type: 'uint8_t[4]',
            offset: 4,
            size: 4,
            description: 'Structure padding alignment',
          },
          {
            name: 'next',
            type: 'Node*',
            offset: 8,
            size: 8,
            description: 'Pointer to the next Node element',
          },
        ],
      },
    ];

    if (this.structs.length > 0) {
      this.selectedStructName = this.structs[0].name;
    }
  }

  private initLayout() {
    this.container.innerHTML = '';

    this.rootEl = document.createElement('div');
    this.rootEl.className = 'type-system-panel-root glass-panel';
    this.rootEl.style.cssText = `
      display: grid;
      grid-template-columns: 320px 1fr;
      height: 100%;
      gap: 1.5rem;
      box-sizing: border-box;
      background: rgba(22, 26, 33, 0.45);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      box-shadow: var(--shadow-lg);
      padding: 1.5rem;
      overflow: hidden;
    `;

    // Inject styles
    if (!document.getElementById('type-system-panel-styles')) {
      const style = document.createElement('style');
      style.id = 'type-system-panel-styles';
      style.textContent = `
        .type-list-container {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          border-right: 1px solid var(--border-color);
          padding-right: 1.25rem;
          height: 100%;
          overflow: hidden;
        }

        .type-detail-container {
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
          height: 100%;
          overflow-y: auto;
          padding-right: 0.5rem;
        }

        .type-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0.75rem 1rem;
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-md);
          cursor: pointer;
          transition: all var(--transition-fast);
        }

        .type-item:hover {
          background: rgba(255, 255, 255, 0.06);
          border-color: var(--border-hover);
        }

        .type-item.active {
          background: rgba(99, 102, 241, 0.15);
          border-color: var(--accent-start);
        }

        .layout-visualizer-grid {
          display: flex;
          flex-wrap: wrap;
          gap: 0.35rem;
          background: rgba(0, 0, 0, 0.2);
          padding: 1rem;
          border-radius: var(--radius-md);
          border: 1px solid var(--border-color);
        }

        .layout-cell {
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          min-height: 48px;
          border-radius: var(--radius-sm);
          font-family: var(--font-mono);
          font-size: 0.75rem;
          padding: 0.25rem 0.5rem;
          box-sizing: border-box;
          text-align: center;
          transition: all var(--transition-fast);
          cursor: help;
        }

        .layout-cell.field {
          background: linear-gradient(135deg, rgba(99, 102, 241, 0.25), rgba(139, 92, 246, 0.25));
          border: 1px solid var(--accent-start);
          color: var(--text-primary);
        }

        .layout-cell.padding {
          background: rgba(255, 255, 255, 0.03);
          border: 1px dashed var(--border-color);
          color: var(--text-muted);
        }

        .form-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
          gap: 0.75rem;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 0.35rem;
        }

        .form-group label {
          font-size: 0.8rem;
          color: var(--text-secondary);
        }

        .type-badge {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid var(--border-color);
          border-radius: var(--radius-sm);
          padding: 0.15rem 0.35rem;
          font-family: var(--font-mono);
          font-size: 0.75rem;
          color: var(--text-secondary);
        }
      `;
      document.head.appendChild(style);
    }

    this.container.appendChild(this.rootEl);
  }

  private setupEvents() {
    // We will bind dynamic events inside render to keep elements properly targeted
  }

  private getSelectedStruct(): StructDefinition | undefined {
    return this.structs.find((s) => s.name === this.selectedStructName);
  }

  private recalculateAllStructSizes() {
    for (const s of this.structs) {
      this.recalculateStructSize(s);
    }
  }

  private recalculateStructSize(s: StructDefinition) {
    if (s.isEnum) {
      s.size = 4;
      return;
    }
    if (s.isUnion) {
      let maxSize = 0;
      for (const field of s.fields) {
        field.offset = 0;
        field.size = this.resolveFieldSize(field.type);
        if (field.size > maxSize) {
          maxSize = field.size;
        }
      }
      s.size = maxSize;
      return;
    }

    let currentOffset = 0;
    for (const field of s.fields) {
      field.offset = currentOffset;
      field.size = this.resolveFieldSize(field.type);
      currentOffset += field.size;
    }
    s.size = currentOffset;
  }

  private resolveFieldSize(type: string): number {
    let baseType = type.trim();
    let arrayLength = 1;

    // Check array brackets
    const arrayMatch = baseType.match(/^([^[]+)\[(\d+)\]$/);
    if (arrayMatch) {
      baseType = arrayMatch[1].trim();
      arrayLength = parseInt(arrayMatch[2], 10);
    }

    if (baseType.endsWith('*')) {
      return this.pointerSize * arrayLength;
    }

    const lower = baseType.toLowerCase();
    let unitSize = 4; // default

    if (
      lower === 'char' ||
      lower === 'uint8_t' ||
      lower === 'int8_t' ||
      lower === 'byte'
    ) {
      unitSize = 1;
    } else if (
      lower === 'short' ||
      lower === 'uint16_t' ||
      lower === 'int16_t'
    ) {
      unitSize = 2;
    } else if (
      lower === 'int' ||
      lower === 'uint32_t' ||
      lower === 'int32_t' ||
      lower === 'float'
    ) {
      unitSize = 4;
    } else if (
      lower === 'long' ||
      lower === 'uint64_t' ||
      lower === 'int64_t' ||
      lower === 'double' ||
      lower === 'long long'
    ) {
      unitSize = 8;
    } else {
      // Custom struct check (avoid infinite recursion by not resolving self)
      const found = this.structs.find((s) => s.name === baseType);
      if (found) {
        unitSize = found.size;
      }
    }

    return unitSize * arrayLength;
  }

  private render() {
    this.rootEl.innerHTML = '';

    // Create Left sidebar list
    const sidebar = document.createElement('div');
    sidebar.className = 'type-list-container';
    sidebar.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.5rem;">
        <h3 style="margin: 0; font-size: 1.1rem; color: var(--text-primary);">Type System</h3>
        <span style="font-size: 0.75rem; color: var(--text-muted);">Define binary data layouts and parse structs</span>
      </div>

      <input type="text" id="type-search" class="search-input" placeholder="Search structures..." value="${this.searchQuery}" style="width: 100%; box-sizing: border-box;">

      <div style="display: flex; gap: 0.5rem;">
        <button class="btn btn-primary" id="btn-create-struct" style="flex: 1; padding: 0.5rem; font-size: 0.85rem;">+ Create</button>
        <button class="btn btn-secondary" id="btn-import-c" style="flex: 1; padding: 0.5rem; font-size: 0.85rem;">Parse C</button>
      </div>

      <div id="type-list-items" style="flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 0.5rem; padding-right: 4px;">
      </div>
    `;

    // Create Right main detail area
    const detailArea = document.createElement('div');
    detailArea.className = 'type-detail-container';
    detailArea.id = 'type-detail-area';

    this.rootEl.appendChild(sidebar);
    this.rootEl.appendChild(detailArea);

    this.renderSidebarItems();
    this.renderStructDetails();

    // Setup input event for search
    const searchInput = sidebar.querySelector(
      '#type-search'
    ) as HTMLInputElement;
    searchInput.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value;
      this.renderSidebarItems();
    });

    // Create struct event
    sidebar
      .querySelector('#btn-create-struct')!
      .addEventListener('click', () => {
        this.createNewStructPrompt();
      });

    // Import C struct event
    sidebar.querySelector('#btn-import-c')!.addEventListener('click', () => {
      this.showImportCDialog();
    });
  }

  private renderSidebarItems() {
    renderSidebarItems(this);
  }

  private renderStructDetails() {
    renderStructDetails(this);
  }

  private createNewStructPrompt() {
    createNewStructPrompt(this);
  }

  private deleteStruct(name: string) {
    deleteStruct(this, name);
  }

  private addFieldToStruct(structName: string, field: StructField) {
    addFieldToStruct(this, structName, field);
  }

  private removeField(structName: string, fieldIndex: number) {
    removeField(this, structName, fieldIndex);
  }

  private showImportCDialog() {
    showImportCDialog(this);
  }

  public parseCStructs(source: string): StructDefinition[] {
    return parseCStructs(this, source);
  }

  // Get currently loaded structures
  public getStructs(): StructDefinition[] {
    return this.structs;
  }
}
