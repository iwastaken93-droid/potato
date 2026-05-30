import { StructDefinition, StructField } from './typeSystemPanel.js';

export function createNewStructPrompt(panel: any) {
  const name = prompt('Enter the name of the new structure:');
  if (!name) return;
  const cleanName = name.replace(/[^a-zA-Z0-9_]/g, '');
  if (!cleanName) {
    alert('Invalid structure name.');
    return;
  }

  if (
    panel.structs.some((s: StructDefinition) => s.name.toLowerCase() === cleanName.toLowerCase())
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

  panel.structs.push(newStruct);
  panel.selectedStructName = cleanName;
  panel.render();
}

export function deleteStruct(panel: any, name: string) {
  if (confirm(`Are you sure you want to delete structure '${name}'?`)) {
    panel.structs = panel.structs.filter((s: StructDefinition) => s.name !== name);
    if (panel.structs.length > 0) {
      panel.selectedStructName = panel.structs[0].name;
    } else {
      panel.selectedStructName = '';
    }
    panel.render();
  }
}

export function addFieldToStruct(panel: any, structName: string, field: StructField) {
  const s = panel.structs.find((st: StructDefinition) => st.name === structName);
  if (!s) return;

  // Check duplicate name
  if (s.fields.some((f: StructField) => f.name === field.name)) {
    alert(`A field with name '${field.name}' already exists in this struct.`);
    return;
  }

  s.fields.push(field);
  panel.recalculateStructSize(s);
  panel.render();
}

export function removeField(panel: any, structName: string, fieldIndex: number) {
  const s = panel.structs.find((st: StructDefinition) => st.name === structName);
  if (!s) return;

  s.fields.splice(fieldIndex, 1);
  panel.recalculateStructSize(s);
  panel.render();
}

export function showImportCDialog(panel: any) {
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
    const parsed = panel.parseCStructs(source);
    if (parsed.length > 0) {
      // Add parsed structs
      parsed.forEach((p: StructDefinition) => {
        // Remove existing with same name if any
        panel.structs = panel.structs.filter((s: StructDefinition) => s.name !== p.name);
        panel.structs.push(p);
      });
      panel.selectedStructName = parsed[0].name;
      panel.recalculateAllStructSizes();
      panel.render();
      document.body.removeChild(backdrop);
    } else {
      alert('No valid structures could be parsed. Check syntax.');
    }
  });
}

export function parseCStructs(panel: any, source: string): StructDefinition[] {
  const structs: StructDefinition[] = [];

  // Strip comments
  const cleanSource = source.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '');

  const tokenRegex = /\b(?:struct|union|enum|typedef)\b|[a-zA-Z_]\w*|0[xX][0-9a-fA-F]+|-?\d+|[*{}[\],;=]/g;
  const tokens = cleanSource.match(tokenRegex) || [];
  let i = 0;

  const peek = (offset = 0) => tokens[i + offset] || '';
  const consume = (expected?: string) => {
    const tok = tokens[i++];
    if (expected && tok !== expected) {
      // syntax error or fallback
    }
    return tok;
  };

  const isDefinition = (): boolean => {
    let lookahead = 0;
    while (tokens[i + lookahead] && tokens[i + lookahead] !== ';') {
      if (tokens[i + lookahead] === '{') {
        return true;
      }
      lookahead++;
    }
    return false;
  };

  const parseStructOrUnion = (isTypedef = false): StructDefinition | null => {
    const kind = consume(); // 'struct' or 'union'
    let name = '';
    if (peek() !== '{') {
      name = consume();
    }

    if (peek() === '{') {
      consume('{');
      const fields: StructField[] = [];

      while (i < tokens.length && peek() !== '}') {
        if ((peek() === 'struct' || peek() === 'union') && isDefinition()) {
          const nested = parseStructOrUnion(false);
          if (nested) {
            structs.push(nested);
            let fieldName = '';
            let arrayLength: number | undefined;
            let isPointer = false;
            while (peek() === '*') {
              consume();
              isPointer = true;
            }
            if (peek() !== ';') {
              fieldName = consume();
            }
            if (peek() === '[') {
              consume('[');
              const sizeTok = consume();
              arrayLength = parseInt(sizeTok, 10);
              consume(']');
            }
            consume(';');

            if (fieldName) {
              fields.push({
                name: fieldName,
                type: nested.name + (isPointer ? '*' : '') + (arrayLength !== undefined ? `[${arrayLength}]` : ''),
                offset: 0,
                size: 0,
                arrayLength,
                description: `Nested ${nested.isUnion ? 'union' : 'struct'} field`
              });
            }
          }
        } else if (peek() === 'enum' && isDefinition()) {
          const nestedEnum = parseEnum(false);
          if (nestedEnum) {
            structs.push(nestedEnum);
            let fieldName = '';
            if (peek() !== ';') {
              fieldName = consume();
            }
            consume(';');
            if (fieldName) {
              fields.push({
                name: fieldName,
                type: nestedEnum.name,
                offset: 0,
                size: 4,
                description: `Nested enum field`
              });
            }
          }
        } else {
          // Regular field
          const fieldTokens: string[] = [];
          while (i < tokens.length && peek() !== ';' && peek() !== '}') {
            fieldTokens.push(consume());
          }
          if (peek() === ';') {
            consume(';');
          }

          if (fieldTokens.length > 0) {
            let arrayLength: number | undefined;
            if (fieldTokens[fieldTokens.length - 1] === ']') {
              fieldTokens.pop(); // ]
              const lenStr = fieldTokens.pop(); // length
              fieldTokens.pop(); // [
              if (lenStr) {
                arrayLength = parseInt(lenStr, 10);
              }
            }

            let isPointer = false;
            const fieldName = fieldTokens.pop() || '';
            while (fieldTokens.length > 0 && fieldTokens[fieldTokens.length - 1] === '*') {
              fieldTokens.pop();
              isPointer = true;
            }

            let fieldType = fieldTokens.join(' ');
            fieldType = fieldType.replace(/^(struct|union)\s+/, '');
            if (isPointer) {
              fieldType += '*';
            }

            if (fieldName) {
              fields.push({
                name: fieldName,
                type: fieldType + (arrayLength !== undefined ? `[${arrayLength}]` : ''),
                offset: 0,
                size: 0,
                arrayLength,
                description: `Parsed field of type ${fieldType}`
              });
            }
          }
        }
      }

      consume('}');

      let alias = '';
      if (isTypedef) {
        if (peek() !== ';') {
          alias = consume();
        }
        if (peek() === ';') {
          consume(';');
        }
      }

      const structName = isTypedef ? (alias || name) : (name || alias);
      if (structName) {
        const isUnion = kind === 'union';
        const def: StructDefinition = {
          name: structName,
          size: 0,
          fields,
          description: `Parsed from C ${kind} definition`,
          isUnion
        };
        if (isTypedef && name && alias && name !== alias) {
          panel.typedefs[alias] = name;
        }
        return def;
      }
    } else {
      if (peek() === ';') {
        consume(';');
      }
    }
    return null;
  };

  const parseEnum = (isTypedef = false): StructDefinition | null => {
    consume('enum');
    let name = '';
    if (peek() !== '{') {
      name = consume();
    }

    if (peek() === '{') {
      consume('{');
      const enumValues: { name: string; value: number }[] = [];
      let currentValue = 0;

      while (i < tokens.length && peek() !== '}') {
        const valName = consume();
        let val = currentValue;
        if (peek() === '=') {
          consume('=');
          const valStr = consume();
          if (valStr.startsWith('0x') || valStr.startsWith('0X')) {
            val = parseInt(valStr, 16);
          } else {
            val = parseInt(valStr, 10);
          }
          currentValue = val;
        }
        enumValues.push({ name: valName, value: val });
        currentValue++;

        if (peek() === ',') {
          consume(',');
        }
      }
      consume('}');

      let alias = '';
      if (isTypedef) {
        if (peek() !== ';') {
          alias = consume();
        }
        if (peek() === ';') {
          consume(';');
        }
      }

      const enumName = isTypedef ? (alias || name) : (name || alias);
      if (enumName) {
        const def: StructDefinition = {
          name: enumName,
          size: 4,
          fields: [],
          enumValues,
          description: `Parsed from C enum definition`,
          isEnum: true
        };
        if (isTypedef && name && alias && name !== alias) {
          panel.typedefs[alias] = name;
        }
        return def;
      }
    } else {
      if (peek() === ';') {
        consume(';');
      }
    }
    return null;
  };

  const parseTypedef = () => {
    consume('typedef');
    if ((peek() === 'struct' || peek() === 'union') && isDefinition()) {
      const s = parseStructOrUnion(true);
      if (s) structs.push(s);
    } else if (peek() === 'enum' && isDefinition()) {
      const e = parseEnum(true);
      if (e) structs.push(e);
    } else {
      const typeTokens: string[] = [];
      while (i < tokens.length && peek() !== ';') {
        typeTokens.push(consume());
      }
      if (peek() === ';') {
        consume(';');
      }

      if (typeTokens.length >= 2) {
        const alias = typeTokens.pop()!;
        const underlying = typeTokens.join(' ');
        panel.typedefs[alias] = underlying;
      }
    }
  };

  while (i < tokens.length) {
    const tok = peek();
    if (tok === 'typedef') {
      parseTypedef();
    } else if ((tok === 'struct' || tok === 'union') && isDefinition()) {
      const s = parseStructOrUnion();
      if (s) structs.push(s);
    } else if (tok === 'enum' && isDefinition()) {
      const e = parseEnum();
      if (e) structs.push(e);
    } else {
      i++;
    }
  }

  // Temporarily merge for size recalculation
  const originalStructs = [...panel.structs];
  panel.structs = [...originalStructs, ...structs];
  for (const s of structs) {
    panel.recalculateStructSize(s);
  }
  panel.structs = originalStructs;

  return structs;
}
