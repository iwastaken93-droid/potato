import { StructDefinition } from './typeSystemPanel.js';

export function renderSidebarItems(panel: any) {
  const listContainer = panel.rootEl.querySelector('#type-list-items')!;
  listContainer.innerHTML = '';

  const filtered = panel.structs.filter((s: StructDefinition) =>
    s.name.toLowerCase().includes(panel.searchQuery.toLowerCase())
  );

  if (filtered.length === 0) {
    listContainer.innerHTML = `
      <div style="text-align: center; color: var(--text-muted); font-size: 0.85rem; padding-top: 1.5rem;">
        No structures found.
      </div>
    `;
    return;
  }

  filtered.forEach((s: StructDefinition) => {
    const item = document.createElement('div');
    item.className = `type-item ${s.name === panel.selectedStructName ? 'active' : ''}`;
    item.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.15rem;">
        <span style="font-weight: 600; color: var(--text-primary); font-size: 0.9rem;">${s.name}</span>
        <span style="font-size: 0.75rem; color: var(--text-muted);">${s.fields.length} fields</span>
      </div>
      <span class="type-badge">${s.size} B</span>
    `;
    item.addEventListener('click', () => {
      panel.selectedStructName = s.name;
      panel.render();
    });
    listContainer.appendChild(item);
  });
}

export function renderStructDetails(panel: any) {
  const detailArea = panel.rootEl.querySelector('#type-detail-area')!;
  detailArea.innerHTML = '';

  const struct = panel.getSelectedStruct();
  if (!struct) {
    detailArea.innerHTML = `
      <div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100%; color: var(--text-muted);">
        <span>Select or create a structure to inspect its layout</span>
      </div>
    `;
    return;
  }

  const typeKind = struct.isEnum ? 'enum' : (struct.isUnion ? 'union' : 'struct');

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
        📦 ${typeKind} ${struct.name}
        <span class="type-badge" style="font-size: 0.85rem; padding: 0.25rem 0.5rem;">Size: ${struct.size} bytes</span>
      </h2>
      <p style="margin: 0; font-size: 0.85rem; color: var(--text-secondary);">${struct.description || 'No description provided.'}</p>
    </div>
    <div style="display: flex; gap: 0.5rem;">
      <button class="btn btn-secondary" id="btn-delete-struct" style="padding: 0.4rem 0.8rem; font-size: 0.8rem;">Delete Type</button>
    </div>
  `;
  header
    .querySelector('#btn-delete-struct')!
    .addEventListener('click', () => {
      panel.deleteStruct(struct.name);
    });

  if (struct.isEnum) {
    // Render Enum values table and form to add enum value
    const enumValuesSection = document.createElement('div');
    enumValuesSection.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    `;
    enumValuesSection.innerHTML = `
      <h3 style="margin: 0; font-size: 0.95rem; color: var(--text-primary);">Enum Constants</h3>
      <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; background: rgba(0, 0, 0, 0.1); border-radius: var(--radius-md); overflow: hidden; border: 1px solid var(--border-color);">
        <thead>
          <tr style="background: rgba(255, 255, 255, 0.02); border-bottom: 1px solid var(--border-color); color: var(--text-secondary);">
            <th style="padding: 0.75rem 1rem;">Constant Name</th>
            <th style="padding: 0.75rem 1rem;">Value (Dec)</th>
            <th style="padding: 0.75rem 1rem;">Value (Hex)</th>
            <th style="padding: 0.75rem 1rem; text-align: right;">Actions</th>
          </tr>
        </thead>
        <tbody id="enum-values-body">
        </tbody>
      </table>
    `;
    
    const valBody = enumValuesSection.querySelector('#enum-values-body')!;
    if (!struct.enumValues || struct.enumValues.length === 0) {
      valBody.innerHTML = `
        <tr>
          <td colspan="4" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
            No constants defined. Add values below.
          </td>
        </tr>
      `;
    } else {
      struct.enumValues.forEach((ev: { name: string; value: number }, index: number) => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid rgba(255, 255, 255, 0.03)';
        row.innerHTML = `
          <td style="padding: 0.75rem 1rem; font-weight: 600; color: var(--text-primary);">${ev.name}</td>
          <td style="padding: 0.75rem 1rem; font-family: var(--font-mono);">${ev.value}</td>
          <td style="padding: 0.75rem 1rem; font-family: var(--font-mono); color: var(--text-muted);">0x${ev.value.toString(16).toUpperCase()}</td>
          <td style="padding: 0.75rem 1rem; text-align: right;">
            <button class="btn btn-secondary btn-delete-enum-val" data-index="${index}" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">Remove</button>
          </td>
        `;
        row.querySelector('.btn-delete-enum-val')!.addEventListener('click', () => {
          struct.enumValues!.splice(index, 1);
          panel.render();
        });
        valBody.appendChild(row);
      });
    }
    
    // Add enum constant form
    const addEnumValForm = document.createElement('div');
    addEnumValForm.style.cssText = `
      display: flex;
      flex-direction: column;
      gap: 1rem;
      background: rgba(255, 255, 255, 0.01);
      border: 1px solid var(--border-color);
      border-radius: var(--radius-md);
      padding: 1.25rem;
    `;
    addEnumValForm.innerHTML = `
      <h4 style="margin: 0; font-size: 0.9rem; color: var(--text-primary);">+ Add Enum Constant</h4>
      <div class="form-row">
        <div class="form-group">
          <label for="new-enum-name">Constant Name</label>
          <input type="text" id="new-enum-name" class="search-input" placeholder="e.g. VAL_MAX" style="padding: 0.5rem;">
        </div>
        <div class="form-group">
          <label for="new-enum-value">Value (Optional)</label>
          <input type="number" id="new-enum-value" class="search-input" placeholder="Auto" style="padding: 0.5rem;">
        </div>
      </div>
      <button class="btn btn-primary" id="btn-add-enum-val" style="padding: 0.5rem; font-size: 0.85rem; align-self: flex-start;">Add Constant</button>
    `;
    
    addEnumValForm.querySelector('#btn-add-enum-val')!.addEventListener('click', () => {
      const nameEl = addEnumValForm.querySelector('#new-enum-name') as HTMLInputElement;
      const valEl = addEnumValForm.querySelector('#new-enum-value') as HTMLInputElement;
      const cName = nameEl.value.trim();
      if (!cName) {
        alert('Constant name is required.');
        return;
      }
      let nextVal = 0;
      if (struct.enumValues && struct.enumValues.length > 0) {
        nextVal = struct.enumValues[struct.enumValues.length - 1].value + 1;
      }
      const finalVal = valEl.value ? parseInt(valEl.value, 10) : nextVal;
      
      if (!struct.enumValues) struct.enumValues = [];
      struct.enumValues.push({ name: cName, value: finalVal });
      panel.render();
    });
    
    detailArea.appendChild(header);
    detailArea.appendChild(enumValuesSection);
    detailArea.appendChild(addEnumValForm);
    return;
  }

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
    struct.fields.forEach((field: any) => {
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
    struct.fields.forEach((field: any, index: number) => {
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
          panel.removeField(struct.name, index);
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
          ${panel.structs
            .filter((s: StructDefinition) => s.name !== struct.name)
            .map(
              (s: StructDefinition) =>
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

      panel.addFieldToStruct(struct.name, {
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
  struct.fields.forEach((f: any) => {
    let base = f.type.trim();
    const match = base.match(/^([^\[]+)\[(\d+)\]$/);
    if (match) base = match[1].trim();

    if (base.endsWith('*')) {
      const ptrTarget = base.slice(0, -1);
      if (
        panel.structs.some((s: StructDefinition) => s.name === ptrTarget) &&
        !pointers.includes(ptrTarget)
      ) {
        pointers.push(ptrTarget);
      }
    } else if (
      panel.structs.some((s: StructDefinition) => s.name === base) &&
      !embeds.includes(base)
    ) {
      embeds.push(base);
    }
  });

  const dependents: string[] = [];
  panel.structs.forEach((s: StructDefinition) => {
    if (s.name === struct.name) return;
    s.fields.forEach((f: any) => {
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
          panel.selectedStructName = el.textContent || '';
          panel.render();
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
          panel.selectedStructName = (el.textContent || '').replace('*', '');
          panel.render();
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
          panel.selectedStructName = el.textContent || '';
          panel.render();
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
