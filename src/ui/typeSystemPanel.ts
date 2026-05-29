/**
 * Premium Type System Viewer & Struct Editor Panel
 * Part of the Universal Reverse Engineering Tool
 * Matches a dark, glassmorphic layout and provides struct definition & relationship visualizations.
 */

import { Section } from '../disassembler/types.js';

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

  // DOM elements
  private rootEl!: HTMLDivElement;
  private structListEl!: HTMLDivElement;
  private structDetailEl!: HTMLDivElement;
  private searchInputEl!: HTMLInputElement;

  constructor(container: HTMLElement, options: TypeSystemPanelOptions = {}) {
    this.container = container;
    this.options = options;

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
    const arrayMatch = baseType.match(/^([^\[]+)\[(\d+)\]$/);
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
    const listContainer = this.rootEl.querySelector('#type-list-items')!;
    listContainer.innerHTML = '';

    const filtered = this.structs.filter((s) =>
      s.name.toLowerCase().includes(this.searchQuery.toLowerCase())
    );

    if (filtered.length === 0) {
      listContainer.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); font-size: 0.85rem; padding-top: 1.5rem;">
          No structures found.
        </div>
      `;
      return;
    }

    filtered.forEach((s) => {
      const item = document.createElement('div');
      item.className = `type-item ${s.name === this.selectedStructName ? 'active' : ''}`;
      item.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.15rem;">
          <span style="font-weight: 600; color: var(--text-primary); font-size: 0.9rem;">${s.name}</span>
          <span style="font-size: 0.75rem; color: var(--text-muted);">${s.fields.length} fields</span>
        </div>
        <span class="type-badge">${s.size} B</span>
      `;
      item.addEventListener('click', () => {
        this.selectedStructName = s.name;
        this.render();
      });
      listContainer.appendChild(item);
    });
  }

  private renderStructDetails() {
    const detailArea = this.rootEl.querySelector('#type-detail-area')!;
    detailArea.innerHTML = '';

    const struct = this.getSelectedStruct();
    if (!struct) {
      detailArea.innerHTML = `
        <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100%; color: var(--text-muted);">
          <span>Select or create a structure to inspect its layout</span>
        </div>
      `;
      return;
    }

    // Main detail container
    const header = document.createElement('div');
    header.style.cssText = `
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1rem;
    `;
    header.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.25rem;">
        <h2 style="margin: 0; font-size: 1.5rem; color: var(--text-primary); display: flex; align-items: center; gap: 0.5rem;">
          📦 struct ${struct.name}
          <span class="type-badge" style="font-size: 0.85rem; padding: 0.25rem 0.5rem;">Size: ${struct.size} bytes</span>
        </h2>
        <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary);">${struct.description || 'No description provided.'}</p>
      </div>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn btn-secondary" id="btn-delete-struct" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;">Delete Struct</button>
      </div>
    `;
    header
      .querySelector('#btn-delete-struct')!
      .addEventListener('click', () => {
        this.deleteStruct(struct.name);
      });

    // Code Preview section & Visualizer section container
    const layoutContainer = document.createElement('div');
    layoutContainer.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    `;
    layoutContainer.innerHTML = `
      <h3 style="margin: 0; font-size: 0.95rem; color: var(--text-primary);">Visual Offset Layout Map</h3>
    `;

    // Render cells in Visualizer
    const visualizer = document.createElement('div');
    visualizer.className = 'layout-visualizer-grid';

    if (struct.fields.length === 0) {
      visualizer.innerHTML = `
        <div style="color: var(--text-muted); font-size: 0.85rem; padding: 0.5rem;">
          No fields defined. Add fields below to visualize layout.
        </div>
      `;
    } else {
      let currentOffset = 0;
      struct.fields.forEach((field) => {
        // If there's padding before this field
        if (field.offset > currentOffset) {
          const padSize = field.offset - currentOffset;
          const cell = document.createElement('div');
          cell.className = 'layout-cell padding';
          cell.style.flexGrow = padSize.toString();
          cell.title = `Padding bytes: +${padSize} (offset: ${currentOffset})`;
          cell.innerHTML = `
            <span>Padding</span>
            <span style="font-size: 0.65rem;">+${padSize}B (0x${currentOffset.toString(16)})</span>
          `;
          visualizer.appendChild(cell);
        }

        const cell = document.createElement('div');
        cell.className = 'layout-cell field';
        cell.style.flexGrow = field.size.toString();
        cell.title = `${field.name} (${field.type})\nOffset: 0x${field.offset.toString(16)} (${field.offset})\nSize: ${field.size} bytes\n${field.description || ''}`;
        cell.innerHTML = `
          <strong style="text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 120px;">${field.name}</strong>
          <span style="font-size: 0.65rem; opacity: 0.8;">${field.type} (${field.size}B)</span>
        `;
        visualizer.appendChild(cell);
        currentOffset = field.offset + field.size;
      });
    }
    layoutContainer.appendChild(visualizer);

    // Fields list section
    const fieldsListSection = document.createElement('div');
    fieldsListSection.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    `;
    fieldsListSection.innerHTML = `
      <h3 style="margin: 0; font-size: 0.95rem; color: var(--text-primary);">Members & Fields Table</h3>
      <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; background: rgba(0, 0, 0, 0.1); border-radius: var(--radius-md); overflow: hidden; border: 1px solid var(--border-color);">
        <thead>
          <tr style="background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border-color); color: var(--text-secondary);">
            <th style="padding: 0.75rem 1rem;">Offset</th>
            <th style="padding: 0.75rem 1rem;">Name</th>
            <th style="padding: 0.75rem 1rem;">Type</th>
            <th style="padding: 0.75rem 1rem;">Size (Bytes)</th>
            <th style="padding: 0.75rem 1rem;">Description</th>
            <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody id="fields-table-body">
        </tbody>
      </table>
    `;

    const tableBody = fieldsListSection.querySelector('#fields-table-body')!;
    if (struct.fields.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
            No fields defined. Add fields using the form below.
          </td>
        </tr>
      `;
    } else {
      struct.fields.forEach((field, index) => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid rgba(255, 255, 255, 0.03)';
        row.innerHTML = `
          <td style="padding: 0.75rem 1rem; font-family: var(--font-mono); color: var(--text-muted);">0x${field.offset.toString(16).toUpperCase()} (${field.offset})</td>
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: var(--text-primary);">${field.name}</td>
          <td style="padding: 0.75rem 1rem;"><span class="type-badge">${field.type}</span></td>
          <td style="padding: 0.75rem 1rem; font-family: var(--font-mono);">${field.size}</td>
          <td style="padding: 0.75rem 1rem; color: var(--text-secondary); max-width: 200px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap;">${field.description || '-'}</td>
          <td style="padding: 0.75rem 1rem; text-align: right;">
            <button class="btn btn-secondary btn-delete-field" data-index="${index}" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">Remove</button>
          </td>
        `;
        row
          .querySelector('.btn-delete-field')!
          .addEventListener('click', () => {
            this.removeField(struct.name, index);
          });
        tableBody.appendChild(row);
      });
    }

    // Add field form
    const addFieldForm = document.createElement('div');
    addFieldForm.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 1rem;
      background: rgba(255, 255, 255, 0.01);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 1.25rem;
    `;
    addFieldForm.innerHTML = `
      <h4 style="margin: 0; font-size: 0.9rem; color: var(--text-primary);">+ Add Member Field</h4>
      <div class="form-row">
        <div class="form-group">
          <label for="new-field-name">Field Name</label>
          <input type="text" id="new-field-name" class="search-input" placeholder="e.g. data_len" style="padding: 0.5rem;">
        </div>
        <div class="form-group">
          <label for="new-field-type">Field Type</label>
          <select id="new-field-type" class="search-input" style="padding: 0.5rem; background: rgba(15, 17, 21, 0.8);">
            <option value="uint8_t">uint8_t (1B)</option>
            <option value="uint16_t">uint16_t (2B)</option>
            <option value="uint32_t">uint32_t (4B)</option>
            <option value="uint64_t">uint64_t (8B)</option>
            <option value="int32_t">int32_t (4B)</option>
            <option value="float">float (4B)</option>
            <option value="char">char (1B)</option>
            <option value="void*">void* (Pointer)</option>
            ${this.structs
              .filter((s) => s.name !== struct.name)
              .map(
                (s) =>
                  `<option value="${s.name}">${s.name} (struct, ${s.size}B)</option>`
              )
              .join('')}
          </select>
        </div>
        <div class="form-group">
          <label for="new-field-array">Array Length (Optional)</label>
          <input type="number" id="new-field-array" class="search-input" placeholder="1" min="1" style="padding: 0.5rem;">
        </div>
      </div>
      <div class="form-group">
        <label for="new-field-desc">Description</label>
        <input type="text" id="new-field-desc" class="search-input" placeholder="Optional description..." style="padding: 0.5rem;">
      </div>
      <button class="btn btn-primary" id="btn-add-field" style="padding: 0.5rem; font-size: 0.85rem; align-self: flex-start;">Add Field</button>
    `;

    addFieldForm
      .querySelector('#btn-add-field')!
      .addEventListener('click', () => {
        const nameEl = addFieldForm.querySelector(
          '#new-field-name'
        ) as HTMLInputElement;
        const typeEl = addFieldForm.querySelector(
          '#new-field-type'
        ) as HTMLSelectElement;
        const arrayEl = addFieldForm.querySelector(
          '#new-field-array'
        ) as HTMLInputElement;
        const descEl = addFieldForm.querySelector(
          '#new-field-desc'
        ) as HTMLInputElement;

        const fieldName = nameEl.value.trim();
        let fieldType = typeEl.value;
        const arrayLen = arrayEl.value
          ? parseInt(arrayEl.value, 10)
          : undefined;
        const description = descEl.value.trim();

        if (!fieldName) {
          alert('Field name is required.');
          return;
        }

        if (arrayLen && arrayLen > 1) {
          fieldType = `${fieldType}[${arrayLen}]`;
        }

        this.addFieldToStruct(struct.name, {
          name: fieldName,
          type: fieldType,
          offset: 0, // will be auto-calculated
          size: 0, // will be auto-calculated
          arrayLength: arrayLen,
          description,
        });
      });

    // Relationship visualizer
    const relationshipsSection = document.createElement('div');
    relationshipsSection.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      border-top: 1px solid var(--border-color);
      padding-top: 1.5rem;
    `;
    relationshipsSection.innerHTML = `
      <h3 style="margin: 0; font-size: 0.95rem; color: var(--text-primary);">Type Relationships & Dependents</h3>
      <div style="background: rgba(0,0,0,0.15); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 1rem; display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem;">
        <div id="relations-embedded"><strong>Directly embeds:</strong> <span style="color: var(--text-secondary);">None</span></div>
        <div id="relations-pointers"><strong>References via pointer:</strong> <span style="color: var(--text-secondary);">None</span></div>
        <div id="relations-dependents"><strong>Structures depending on this type:</strong> <span style="color: var(--text-secondary);">None</span></div>
      </div>
    `;

    // Compute relationships
    const embeds: string[] = [];
    const pointers: string[] = [];
    struct.fields.forEach((f) => {
      let base = f.type.trim();
      const match = base.match(/^([^\[]+)\[(\d+)\]$/);
      if (match) base = match[1].trim();

      if (base.endsWith('*')) {
        const ptrTarget = base.slice(0, -1);
        if (
          this.structs.some((s) => s.name === ptrTarget) &&
          !pointers.includes(ptrTarget)
        ) {
          pointers.push(ptrTarget);
        }
      } else if (
        this.structs.some((s) => s.name === base) &&
        !embeds.includes(base)
      ) {
        embeds.push(base);
      }
    });

    const dependents: string[] = [];
    this.structs.forEach((s) => {
      if (s.name === struct.name) return;
      s.fields.forEach((f) => {
        let base = f.type.trim();
        const match = base.match(/^([^\[]+)\[(\d+)\]$/);
        if (match) base = match[1].trim();

        if (base === struct.name || base === `${struct.name}*`) {
          if (!dependents.includes(s.name)) {
            dependents.push(s.name);
          }
        }
      });
    });

    if (embeds.length > 0) {
      relationshipsSection.querySelector('#relations-embedded')!.innerHTML = `
        <strong>Directly embeds:</strong> ${embeds.map((e) => `<span class="type-badge" style="cursor: pointer; border-color: var(--accent-start);">${e}</span>`).join(' ')}
      `;
      relationshipsSection
        .querySelectorAll('#relations-embedded span')
        .forEach((el) => {
          el.addEventListener('click', () => {
            this.selectedStructName = el.textContent || '';
            this.render();
          });
        });
    }
    if (pointers.length > 0) {
      relationshipsSection.querySelector('#relations-pointers')!.innerHTML = `
        <strong>References via pointer:</strong> ${pointers.map((p) => `<span class="type-badge" style="cursor: pointer; border-color: var(--accent-start);">${p}*</span>`).join(' ')}
      `;
      relationshipsSection
        .querySelectorAll('#relations-pointers span')
        .forEach((el) => {
          el.addEventListener('click', () => {
            this.selectedStructName = (el.textContent || '').replace('*', '');
            this.render();
          });
        });
    }
    if (dependents.length > 0) {
      relationshipsSection.querySelector('#relations-dependents')!.innerHTML = `
        <strong>Structures depending on this type:</strong> ${dependents.map((d) => `<span class="type-badge" style="cursor: pointer; border-color: var(--accent-start);">${d}</span>`).join(' ')}
      `;
      relationshipsSection
        .querySelectorAll('#relations-dependents span')
        .forEach((el) => {
          el.addEventListener('click', () => {
            this.selectedStructName = el.textContent || '';
            this.render();
          });
        });
    }

    // Append all blocks to detailArea
    detailArea.appendChild(header);
    detailArea.appendChild(layoutContainer);
    detailArea.appendChild(fieldsListSection);
    detailArea.appendChild(addFieldForm);
    detailArea.appendChild(relationshipsSection);
  }

  private createNewStructPrompt() {
    const name = prompt('Enter the name of the new structure:');
    if (!name) return;
    const cleanName = name.replace(/[^a-zA-Z0-9_]/g, '');
    if (!cleanName) {
      alert('Invalid structure name.');
      return;
    }

    if (
      this.structs.some((s) => s.name.toLowerCase() === cleanName.toLowerCase())
    ) {
      alert('A structure with this name already exists.');
      return;
    }

    const newStruct: StructDefinition = {
      name: cleanName,
      size: 0,
      fields: [],
      description: 'Custom user defined structure',
    };

    this.structs.push(newStruct);
    this.selectedStructName = cleanName;
    this.render();
  }

  private deleteStruct(name: string) {
    if (confirm(`Are you sure you want to delete structure '${name}'?`)) {
      this.structs = this.structs.filter((s) => s.name !== name);
      if (this.structs.length > 0) {
        this.selectedStructName = this.structs[0].name;
      } else {
        this.selectedStructName = '';
      }
      this.render();
    }
  }

  private addFieldToStruct(structName: string, field: StructField) {
    const s = this.structs.find((st) => st.name === structName);
    if (!s) return;

    // Check duplicate name
    if (s.fields.some((f) => f.name === field.name)) {
      alert(`A field with name '${field.name}' already exists in this struct.`);
      return;
    }

    s.fields.push(field);
    this.recalculateStructSize(s);
    this.render();
  }

  private removeField(structName: string, fieldIndex: number) {
    const s = this.structs.find((st) => st.name === structName);
    if (!s) return;

    s.fields.splice(fieldIndex, 1);
    this.recalculateStructSize(s);
    this.render();
  }

  private showImportCDialog() {
    const backdrop = document.createElement('div');
    backdrop.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(0,0,0,0.6);
      backdrop-filter: blur(8px);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
    `;

    const dialog = document.createElement('div');
    dialog.className = 'glass-panel';
    dialog.style.cssText = `
      width: 600px;
      max-width: 90%;
      background: rgba(22, 26, 33, 0.95);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-lg);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    `;

    dialog.innerHTML = `
      <h3 style="margin:0; color:var(--text-primary);">Parse C Structure Definitions</h3>
      <span style="font-size:0.75rem; color:var(--text-muted);">Paste one or more C struct declarations below. Simple primitive types, custom types, pointers, and array lengths are supported.</span>
      <textarea id="import-c-source" style="width:100%; height:250px; background:rgba(0,0,0,0.3); border:1px solid var(--border-color); border-radius:var(--radius-md); color:var(--text-primary); font-family:var(--font-mono); font-size:0.8rem; padding:0.75rem; resize:vertical; outline:none; box-sizing:border-box;">struct Vector3 {
    float x;
    float y;
    float z;
};

struct PlayerInfo {
    int id;
    char username[32];
    struct Vector3 position;
    struct PlayerInfo* targetPlayer;
};</textarea>
      <div style="display:flex; justify-content:flex-end; gap:0.5rem;">
        <button class="btn btn-secondary" id="btn-import-cancel" style="padding:0.5rem 1rem;">Cancel</button>
        <button class="btn btn-primary" id="btn-import-parse" style="padding:0.5rem 1rem;">Parse & Import</button>
      </div>
    `;

    backdrop.appendChild(dialog);
    document.body.appendChild(backdrop);

    dialog
      .querySelector('#btn-import-cancel')!
      .addEventListener('click', () => {
        document.body.removeChild(backdrop);
      });

    dialog.querySelector('#btn-import-parse')!.addEventListener('click', () => {
      const source = (
        dialog.querySelector('#import-c-source') as HTMLTextAreaElement
      ).value;
      const parsed = this.parseCStructs(source);
      if (parsed.length > 0) {
        // Add parsed structs
        parsed.forEach((p) => {
          // Remove existing with same name if any
          this.structs = this.structs.filter((s) => s.name !== p.name);
          this.structs.push(p);
        });
        this.selectedStructName = parsed[0].name;
        this.recalculateAllStructSizes();
        this.render();
        document.body.removeChild(backdrop);
      } else {
        alert('No valid structures could be parsed. Check syntax.');
      }
    });
  }

  /**
   * Simple parser for C structs
   */
  public parseCStructs(source: string): StructDefinition[] {
    const structs: StructDefinition[] = [];

    // Strip comments
    let cleanSource = source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');

    // Find struct definitions
    const structRegex = /struct\s+(\w+)\s*\{([^}]+)\}/g;
    let match;

    while ((match = structRegex.exec(cleanSource)) !== null) {
      const structName = match[1];
      const fieldsBody = match[2];
      const fields: StructField[] = [];

      const fieldLines = fieldsBody.split(';');
      let currentOffset = 0;

      for (let line of fieldLines) {
        line = line.trim();
        if (!line) continue;

        // Match type, pointer indicator, field name, array brackets
        // e.g. "unsigned int flags" or "struct Vector3 pos" or "char name[32]" or "struct Player* target"
        const fieldRegex =
          /^(struct\s+\w+|\w+)\s*(\*+)?\s*(\w+)(?:\[(\d+)\])?$/;
        const fieldMatch = line.match(fieldRegex);

        if (fieldMatch) {
          let typeName = fieldMatch[1].replace(/^struct\s+/, '').trim();
          const isPointer = !!fieldMatch[2];
          const fieldName = fieldMatch[3];
          const arraySizeStr = fieldMatch[4];

          let size = 0;
          let arrayLength = arraySizeStr
            ? parseInt(arraySizeStr, 10)
            : undefined;

          if (isPointer) {
            size = this.pointerSize;
            typeName = typeName + '*';
          } else {
            // Find base size
            const lower = typeName.toLowerCase();
            if (
              lower === 'char' ||
              lower === 'uint8_t' ||
              lower === 'int8_t' ||
              lower === 'byte'
            ) {
              size = 1;
            } else if (
              lower === 'short' ||
              lower === 'uint16_t' ||
              lower === 'int16_t'
            ) {
              size = 2;
            } else if (
              lower === 'int' ||
              lower === 'uint32_t' ||
              lower === 'int32_t' ||
              lower === 'float'
            ) {
              size = 4;
            } else if (
              lower === 'long' ||
              lower === 'uint64_t' ||
              lower === 'int64_t' ||
              lower === 'double' ||
              lower === 'long long'
            ) {
              size = 8;
            } else {
              // check parsed or existing structs
              const found = [...structs, ...this.structs].find(
                (s) => s.name === typeName
              );
              if (found) {
                size = found.size;
              } else {
                size = 4; // fallback
              }
            }

            if (arrayLength !== undefined) {
              size *= arrayLength;
            }
          }

          fields.push({
            name: fieldName,
            type:
              typeName + (arrayLength !== undefined ? `[${arrayLength}]` : ''),
            offset: currentOffset,
            size: size,
            arrayLength: arrayLength,
            description: `Parsed field of type ${typeName}`,
          });

          currentOffset += size;
        }
      }

      structs.push({
        name: structName,
        size: currentOffset,
        fields: fields,
        description: `Parsed from C struct definition`,
      });
    }

    return structs;
  }

  // Get currently loaded structures
  public getStructs(): StructDefinition[] {
    return this.structs;
  }
}
