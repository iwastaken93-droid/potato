// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  ScriptingEngine,
  ScriptingContext,
} from '../src/analyzer/scripting.js';
import { ScriptingConsole } from '../src/ui/scriptingConsole.js';
import type {
  Instruction,
  Section,
  Symbol,
} from '../src/disassembler/types.js';
import type { ExtractedString } from '../src/analyzer/strings.js';

describe('ScriptingEngine', () => {
  let context: ScriptingContext;
  let engine: ScriptingEngine;

  beforeEach(() => {
    const binaryData = new Uint8Array([
      0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x90, 0xc3,
    ]);
    const sections: Section[] = [
      {
        name: '.text',
        virtualAddress: 0x1000,
        virtualSize: 10,
        fileOffset: 0,
        fileSize: 10,
        flags: { read: true, write: false, execute: true },
        entropy: 3.5,
      },
    ];
    const symbols: Symbol[] = [
      {
        name: 'main',
        address: 0x1000,
        type: 'function',
        binding: 'global',
        size: 8,
      },
      {
        name: 'helper',
        address: 0x1008,
        type: 'function',
        binding: 'local',
        size: 2,
      },
    ];
    const instructions: Instruction[] = [
      {
        address: 0x1000,
        bytes: new Uint8Array([0x55]),
        mnemonic: 'push',
        opStr: 'rbp',
        operands: [],
        size: 1,
      },
      {
        address: 0x1001,
        bytes: new Uint8Array([0x48, 0x89, 0xe5]),
        mnemonic: 'mov',
        opStr: 'rbp, rsp',
        operands: [],
        size: 3,
      },
      {
        address: 0x1004,
        bytes: new Uint8Array([0x48, 0x83, 0xec, 0x10]),
        mnemonic: 'sub',
        opStr: 'rsp, 0x10',
        operands: [],
        size: 4,
      },
      {
        address: 0x1008,
        bytes: new Uint8Array([0x90]),
        mnemonic: 'nop',
        opStr: '',
        operands: [],
        size: 1,
      },
      {
        address: 0x1009,
        bytes: new Uint8Array([0xc3]),
        mnemonic: 'ret',
        opStr: '',
        operands: [],
        size: 1,
      },
    ];
    const extractedStrings: ExtractedString[] = [
      {
        offset: 0,
        virtualAddress: 0x1000,
        encoding: 'ascii',
        tags: [],
        value: 'hello',
      },
    ];
    const dependencies = {
      binaryName: 'test.bin',
      imports: [{ library: 'libc.so', name: 'puts', address: 0x2000 }],
      exports: [{ name: 'main', address: 0x1000 }],
      locals: [],
    };

    context = {
      binaryData,
      entryPoint: 0x1000,
      sections,
      symbols,
      instructions,
      extractedStrings,
      dependencies,
    };

    engine = new ScriptingEngine(context);
  });

  it('should execute basic js expression and return a value', () => {
    const res = engine.execute('1 + 2');
    expect(res.success).toBe(true);
    expect(res.result).toBe(3);
  });

  it('should execute multiple lines and return correctly', () => {
    const res = engine.execute(`
      const a = 10;
      const b = 20;
      return a + b;
    `);
    expect(res.success).toBe(true);
    expect(res.result).toBe(30);
  });

  it('should capture custom console logs', () => {
    const res = engine.execute(`
      console.log('hello', 'world');
      console.info('info message');
      console.warn('warn message');
      console.error('error message');
    `);
    expect(res.success).toBe(true);
    expect(res.logs).toContain('hello world');
    expect(res.logs).toContain('[INFO] info message');
    expect(res.logs).toContain('[WARN] warn message');
    expect(res.logs).toContain('[ERROR] error message');
  });

  it('should handle errors in execution', () => {
    const res = engine.execute('nonExistentVar.foo');
    expect(res.success).toBe(false);
    expect(res.result).toContain('nonExistentVar is not defined');
  });

  it('should support updating context', () => {
    engine.updateContext({ ...context, entryPoint: 0x2000 });
    const res = engine.execute('entryPoint');
    expect(res.success).toBe(true);
    expect(res.result).toBe(0x2000);
  });

  it('should provide binary data and entry point', () => {
    const res = engine.execute('data.length + entryPoint');
    expect(res.success).toBe(true);
    expect(res.result).toBe(10 + 0x1000);
  });

  it('should provide helper: getFunctions', () => {
    const res = engine.execute('getFunctions()');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(2);
    expect(res.result[0].name).toBe('main');
  });

  it('should provide helper: findSymbol', () => {
    // By name
    let res = engine.execute('findSymbol("main")');
    expect(res.success).toBe(true);
    expect(res.result.address).toBe(0x1000);

    // By address
    res = engine.execute('findSymbol(0x1008)');
    expect(res.success).toBe(true);
    expect(res.result.name).toBe('helper');

    // Not found
    res = engine.execute('findSymbol("missing")');
    expect(res.success).toBe(true);
    expect(res.result).toBeNull();
  });

  it('should provide helper: searchInstructions', () => {
    let res = engine.execute('searchInstructions("mov")');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(1);
    expect(res.result[0].address).toBe(0x1001);

    // By address string
    res = engine.execute('searchInstructions("0x1009")');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(1);
    expect(res.result[0].mnemonic).toBe('ret');
  });

  it('should provide helper: filterImports and filterExports', () => {
    let res = engine.execute('filterImports("puts")');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(1);

    res = engine.execute('filterExports("main")');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(1);
  });

  it('should provide helper: findStrings', () => {
    const res = engine.execute('findStrings("hell")');
    expect(res.success).toBe(true);
    expect(res.result).toHaveLength(1);
    expect(res.result[0].value).toBe('hello');
  });

  it('should provide helper: readBytes', () => {
    let res = engine.execute('readBytes(0x1000, 4)');
    expect(res.success).toBe(true);
    expect(res.result).toBeInstanceOf(Uint8Array);
    expect(Array.from(res.result)).toEqual([0x55, 0x48, 0x89, 0xe5]);

    // Out of bounds
    res = engine.execute('readBytes(0x3000, 2)');
    expect(res.success).toBe(false);
    expect(res.result).toContain('out of binary bounds');
  });

  it('should provide helper: hex', () => {
    let res = engine.execute('hex(255)');
    expect(res.success).toBe(true);
    expect(res.result).toBe('0xFF');

    res = engine.execute('hex(new Uint8Array([1, 2, 15]))');
    expect(res.success).toBe(true);
    expect(res.result).toBe('01 02 0f');
  });

  it('should provide helper: help', () => {
    const res = engine.execute('help()');
    expect(res.success).toBe(true);
    expect(res.logs.length).toBeGreaterThan(0);
    expect(res.result).toContain('Use help() for available commands');
  });
});

describe('ScriptingConsole', () => {
  let container: HTMLElement;
  let context: ScriptingContext;
  let consoleComponent: ScriptingConsole;

  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);

    context = {
      binaryData: new Uint8Array([0x90]),
      entryPoint: 0x1000,
      sections: [],
      symbols: [],
      instructions: [],
      extractedStrings: [],
    };

    consoleComponent = new ScriptingConsole(container, context);
  });

  afterEach(() => {
    document.body.removeChild(container);
  });

  it('should inject styles and render structural DOM elements', () => {
    expect(document.getElementById('scripting-console-styles')).not.toBeNull();
    const root = container.querySelector('.scripting-console-root');
    expect(root).not.toBeNull();
    const outputArea = container.querySelector('.console-body');
    expect(outputArea).not.toBeNull();
    const inputField = container.querySelector('#console-input-field');
    expect(inputField).not.toBeNull();
  });

  it('should show welcome message initially', () => {
    const outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain(
      'Welcome to Universal Disassembler Scripting Console'
    );
  });

  it('should update context correctly', () => {
    consoleComponent.updateContext({ ...context, entryPoint: 0x3000 });
    const inputField = container.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    const runBtn = container.querySelector(
      '#console-run-btn'
    ) as HTMLButtonElement;

    inputField.value = 'hex(entryPoint)';
    runBtn.click();

    const outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('0x3000');
  });

  it('should execute command when Enter is pressed', () => {
    const inputField = container.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    inputField.value = '5 + 5';

    const event = new KeyboardEvent('keydown', { key: 'Enter' });
    inputField.dispatchEvent(event);

    const outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('10');
  });

  it('should display console logs and execution errors', () => {
    const inputField = container.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    const runBtn = container.querySelector(
      '#console-run-btn'
    ) as HTMLButtonElement;

    // Log message
    inputField.value = 'console.log("test-log")';
    runBtn.click();

    let outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('test-log');

    // Error
    inputField.value = 'undefinedVariable.prop';
    runBtn.click();

    outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('Error:');
  });

  it('should clear logs and re-show welcome message when clear button is clicked', () => {
    const inputField = container.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    const runBtn = container.querySelector(
      '#console-run-btn'
    ) as HTMLButtonElement;
    const clearBtn = container.querySelector(
      '#console-clear-btn'
    ) as HTMLButtonElement;

    inputField.value = '1 + 1';
    runBtn.click();

    let outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('2');

    clearBtn.click();

    outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).not.toContain('2');
    expect(outputArea.textContent).toContain(
      'Welcome to Universal Disassembler Scripting Console'
    );
  });

  it('should navigate command history using ArrowUp and ArrowDown', () => {
    const inputField = container.querySelector(
      '#console-input-field'
    ) as HTMLInputElement;
    const runBtn = container.querySelector(
      '#console-run-btn'
    ) as HTMLButtonElement;

    inputField.value = 'commandOne';
    runBtn.click();

    inputField.value = 'commandTwo';
    runBtn.click();

    // ArrowUp -> commandTwo
    inputField.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    expect(inputField.value).toBe('commandTwo');

    // ArrowUp -> commandOne
    inputField.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    expect(inputField.value).toBe('commandOne');

    // ArrowDown -> commandTwo
    inputField.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown' })
    );
    expect(inputField.value).toBe('commandTwo');

    // ArrowDown -> empty
    inputField.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'ArrowDown' })
    );
    expect(inputField.value).toBe('');
  });

  it('should trigger help when clicking help guide button', () => {
    const helpBtn = container.querySelector(
      '#console-help-btn'
    ) as HTMLButtonElement;
    helpBtn.click();

    const outputArea = container.querySelector('.console-body')!;
    expect(outputArea.textContent).toContain('=== Scripting Console Help ===');
  });
});
