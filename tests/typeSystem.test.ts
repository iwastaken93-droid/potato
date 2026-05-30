// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TypeSystemPanel } from '../src/ui/typeSystemPanel.js';

describe('TypeSystemPanel Unit Tests', () => {
  let container: HTMLElement;
  let panel: TypeSystemPanel;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    panel = new TypeSystemPanel(container);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should render the initial structure and show type system list', () => {
    const root = container.querySelector('.type-system-panel-root');
    expect(root).not.toBeNull();
    expect(container.textContent).toContain('Type System');
    expect(container.textContent).toContain('Point2D');
    expect(container.textContent).toContain('Rect');
    expect(container.textContent).toContain('Node');
  });

  it('should support architecture updates and resize pointers', () => {
    // Default pointer size should be 8
    const defaultStructs = panel.getStructs();
    const nodeStructBefore = defaultStructs.find((s) => s.name === 'Node');
    expect(nodeStructBefore).toBeDefined();
    // value (4) + padding (4) + next (8 ptr) = 16
    expect(nodeStructBefore!.size).toBe(16);

    // Update to 32-bit architecture
    panel.updateArchitecture('x86');
    const nodeStructAfter = panel.getStructs().find((s) => s.name === 'Node');
    expect(nodeStructAfter).toBeDefined();
    // value (4) + padding (4) + next (4 ptr) = 12
    expect(nodeStructAfter!.size).toBe(12);
  });

  it('should search/filter structures correctly', () => {
    const searchInput = container.querySelector(
      '#type-search'
    ) as HTMLInputElement;
    expect(searchInput).not.toBeNull();

    // Set search query and trigger input event
    searchInput.value = 'Rect';
    searchInput.dispatchEvent(new Event('input'));

    const listItems = container.querySelector('#type-list-items')!;
    expect(listItems.textContent).toContain('Rect');
    expect(listItems.textContent).not.toContain('Point2D');
  });

  it('should parse C struct definitions correctly', () => {
    const source = `
      struct Vector3D {
        float x;
        float y;
        float z;
      };

      struct Player {
        int id;
        char name[16];
        struct Vector3D pos;
        struct Player* next;
      };
    `;

    const parsed = panel.parseCStructs(source);
    expect(parsed.length).toBe(2);

    const vec3 = parsed.find((s) => s.name === 'Vector3D');
    expect(vec3).toBeDefined();
    expect(vec3!.fields.length).toBe(3);
    expect(vec3!.size).toBe(12); // 3 * float (4 bytes) = 12

    const player = parsed.find((s) => s.name === 'Player');
    expect(player).toBeDefined();
    expect(player!.fields.length).toBe(4);

    const idField = player!.fields.find((f) => f.name === 'id');
    expect(idField!.type).toBe('int');
    expect(idField!.size).toBe(4);

    const nameField = player!.fields.find((f) => f.name === 'name');
    expect(nameField!.type).toBe('char[16]');
    expect(nameField!.size).toBe(16);

    const posField = player!.fields.find((f) => f.name === 'pos');
    expect(posField!.type).toBe('Vector3D');
    // In our parser Vector3D is in the parsed structs, so it resolves to 12
    expect(posField!.size).toBe(12);
  });

  it('should parse C union definitions correctly', () => {
    const source = `
      union Value {
        int i;
        float f;
        char buf[8];
      };
    `;

    const parsed = panel.parseCStructs(source);
    expect(parsed.length).toBe(1);

    const valUnion = parsed[0];
    expect(valUnion.name).toBe('Value');
    expect(valUnion.isUnion).toBe(true);
    expect(valUnion.size).toBe(8); // max(4, 4, 8) = 8

    valUnion.fields.forEach((field) => {
      expect(field.offset).toBe(0);
    });
  });

  it('should parse C enum definitions correctly', () => {
    const source = `
      enum Color {
        RED = 0,
        GREEN = 2,
        BLUE
      };
    `;

    const parsed = panel.parseCStructs(source);
    expect(parsed.length).toBe(1);

    const colorEnum = parsed[0];
    expect(colorEnum.name).toBe('Color');
    expect(colorEnum.isEnum).toBe(true);
    expect(colorEnum.size).toBe(4);
    expect(colorEnum.enumValues).toBeDefined();
    expect(colorEnum.enumValues!.length).toBe(3);
    expect(colorEnum.enumValues![0]).toEqual({ name: 'RED', value: 0 });
    expect(colorEnum.enumValues![1]).toEqual({ name: 'GREEN', value: 2 });
    expect(colorEnum.enumValues![2]).toEqual({ name: 'BLUE', value: 3 });
  });

  it('should parse C typedefs and resolve aliases correctly', () => {
    const source = `
      typedef unsigned int DWORD;
      typedef struct {
        DWORD code;
        char name[8];
      } Message;
    `;

    const parsed = panel.parseCStructs(source);
    // Message structure should be parsed
    expect(parsed.length).toBe(1);

    const msg = parsed[0];
    expect(msg.name).toBe('Message');
    expect(msg.size).toBe(12); // DWORD (4) + name[8] (8) = 12

    const codeField = msg.fields.find((f) => f.name === 'code');
    expect(codeField).toBeDefined();
    expect(codeField!.type).toBe('DWORD');
    expect(codeField!.size).toBe(4);
  });

  it('should parse inline nested structures correctly', () => {
    const source = `
      struct Outer {
        int a;
        struct Inner {
          char b;
        } nested;
      };
    `;

    const parsed = panel.parseCStructs(source);
    // Should parse both Inner and Outer
    expect(parsed.length).toBe(2);

    const inner = parsed.find((s) => s.name === 'Inner');
    const outer = parsed.find((s) => s.name === 'Outer');

    expect(inner).toBeDefined();
    expect(inner!.size).toBe(1);

    expect(outer).toBeDefined();
    expect(outer!.size).toBe(5); // int a (4) + Inner nested (1) = 5
    const nestedField = outer!.fields.find((f) => f.name === 'nested');
    expect(nestedField).toBeDefined();
    expect(nestedField!.type).toBe('Inner');
    expect(nestedField!.size).toBe(1);
  });
});
