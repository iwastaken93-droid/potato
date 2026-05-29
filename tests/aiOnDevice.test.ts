import { describe, it, expect, vi } from 'vitest';
import { OnDeviceLLMManager } from '../src/analyzer/aiOnDevice.js';

describe('OnDeviceLLMManager (ONNX / WebNN Mock LLM Wrapper)', () => {
  it('should construct with default configuration parameters', () => {
    const manager = new OnDeviceLLMManager();
    const config = manager.getConfig();
    expect(config.modelName).toBe('TinyLlama-1.1B-Chat-v1.0-ONNX');
    expect(config.vocabSize).toBe(32000);
    expect(config.hiddenSize).toBe(2048);
    expect(config.contextLength).toBe(2048);
    expect(config.modelUrlOrPath).toContain('tiny_llama_quantized.onnx');
    expect(manager.isModelLoaded()).toBe(false);
  });

  it('should allow custom configuration parameters', () => {
    const manager = new OnDeviceLLMManager({
      modelName: 'Custom-3B-Model',
      vocabSize: 10000,
      hiddenSize: 1024,
      contextLength: 512,
      modelUrlOrPath: '/custom.onnx',
    });
    const config = manager.getConfig();
    expect(config.modelName).toBe('Custom-3B-Model');
    expect(config.vocabSize).toBe(10000);
    expect(config.hiddenSize).toBe(1024);
    expect(config.contextLength).toBe(512);
    expect(config.modelUrlOrPath).toBe('/custom.onnx');
  });

  it('should support checking WebNN capability status', () => {
    // Should return false in Node / JSDOM test environments unless mocked
    const status = OnDeviceLLMManager.isWebNNSupported();
    expect(typeof status).toBe('boolean');
  });

  it('should support checking WebGPU capability status', async () => {
    const status = await OnDeviceLLMManager.isWebGPUSupported();
    expect(typeof status).toBe('boolean');
  });

  it('should throw an error if explainFunction is called before loading model', async () => {
    const manager = new OnDeviceLLMManager();
    await expect(
      manager.explainFunction('test_func', 'xor eax, eax')
    ).rejects.toThrow(
      'On-device LLM model is not loaded. Call loadModel() first.'
    );
  });

  it('should successfully load a mock model and update progress using ORT/WASM backend', async () => {
    const manager = new OnDeviceLLMManager();
    const progressSpy = vi.fn();

    await manager.loadModel('mock-model-path.onnx', 'wasm', progressSpy);

    expect(manager.isModelLoaded()).toBe(true);
    expect(progressSpy).toHaveBeenCalledWith(0.1);
    expect(progressSpy).toHaveBeenCalledWith(0.4);
    expect(progressSpy).toHaveBeenCalledWith(0.8);
    expect(progressSpy).toHaveBeenCalledWith(1.0);
  });

  it('should successfully load a mock model using WebNN backend', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel(new ArrayBuffer(128), 'webnn-cpu');
    expect(manager.isModelLoaded()).toBe(true);
  });

  it('should encode and decode tokens deterministically (tokenize / detokenize)', () => {
    const manager = new OnDeviceLLMManager();

    // Test known words
    const tokens = manager.tokenize('function loop encryption');
    expect(tokens.length).toBe(3);

    const text = manager.detokenize(tokens);
    expect(text).toBe('function loop encryption');

    // Test unknown hash fallback words
    const randomTokens = manager.tokenize('xyzunknownword');
    expect(randomTokens.length).toBe(1);
    expect(randomTokens[0]).toBeGreaterThanOrEqual(0);
    expect(randomTokens[0]).toBeLessThan(32000);
  });

  it('should generate accurate explanations and invoke token callback for RC4 code', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const rc4Code = `
      // Setup S-box
      for (i = 0; i < 256; i++) s[i] = i;
      // Key stream XOR swap loop
      swap(&s[i], &s[j]);
      out[k] = in[k] ^ s[t];
    `;

    const tokens: string[] = [];
    const result = await manager.explainFunction(
      'rc4_decrypt',
      rc4Code,
      'x86_64',
      {
        temperature: 0.2,
        onToken: (tok) => tokens.push(tok.trim()),
      }
    );

    expect(result.summary).toContain('RC4');
    expect(result.patterns[0].name).toBe('RC4 Cryptographic Cipher');
    expect(result.functionality.length).toBeGreaterThan(0);
    expect(result.suggestions.length).toBeGreaterThan(0);
    expect(tokens.length).toBeGreaterThan(0);
    expect(tokens.join(' ')).toContain('rc4');
  });

  it('should generate explanations for TEA/XTEA cryptography code', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const teaCode = `
      uint32_t delta = 0x9E3779B9;
      v0 += ((v1<<4) ^ (v1>>5)) + v1;
    `;

    const result = await manager.explainFunction('tea_block', teaCode, 'arm64');
    expect(result.summary).toContain('Tiny Encryption Algorithm');
    expect(result.patterns[0].name).toBe('TEA/XTEA Block Cipher');
  });

  it('should generate explanations for Base64 code patterns', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const base64Code = `
      const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    `;

    const result = await manager.explainFunction(
      'b64_encode',
      base64Code,
      'wasm'
    );
    expect(result.summary).toContain('Base64');
    expect(result.patterns[0].name).toBe('Base64 Text Conversion');
  });

  it('should generate explanations for simple XOR keys', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const xorCode = `
      for (int i = 0; i < len; i++) {
        data[i] ^= 0x5A;
      }
    `;

    const result = await manager.explainFunction(
      'xor_obfuscation',
      xorCode,
      'x86'
    );
    expect(result.summary).toContain('XOR');
    expect(result.patterns[0].name).toBe('XOR Obfuscation');

    // Test XOR detected by function name only
    const resultByFuncName = await manager.explainFunction(
      'my_xor_func',
      'return data;',
      'x86'
    );
    expect(resultByFuncName.summary).toContain('XOR');
    expect(resultByFuncName.patterns[0].name).toBe('XOR Obfuscation');

    // Test XOR detected by '0xff' in body
    const resultByHex = await manager.explainFunction(
      'some_func',
      'val = val & 0xff;',
      'x86'
    );
    expect(resultByHex.summary).toContain('XOR');
    expect(resultByHex.patterns[0].name).toBe('XOR Obfuscation');

    // Test XOR detected by 'xor' in body
    const resultByLiteral = await manager.explainFunction(
      'some_func',
      'mov eax, ebx; xor eax, eax;',
      'x86'
    );
    expect(resultByLiteral.summary).toContain('XOR');
    expect(resultByLiteral.patterns[0].name).toBe('XOR Obfuscation');
  });

  it('should generate explanations for socket network code', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const netCode = `
      int s = socket(2, 1, 0);
      connect(s, addr, 16);
    `;

    const result = await manager.explainFunction('net_connect', netCode, 'x64');
    expect(result.summary).toContain('network');
    expect(result.patterns[0].name).toBe('Network Connection');
  });

  it('should generate fallback general explanation for unknown code', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');

    const unknownCode = `
      int a = 10;
      int b = 20;
      return a + b;
    `;

    const result = await manager.explainFunction(
      'simple_sum',
      unknownCode,
      'mips'
    );
    expect(result.summary).toContain('General logic loop');
    expect(result.patterns[0].name).toBe('Looping Iterative Routine');
  });

  it('should support unloading the model and releasing memory sessions', async () => {
    const manager = new OnDeviceLLMManager();
    await manager.loadModel('mock-model.onnx', 'wasm');
    expect(manager.isModelLoaded()).toBe(true);

    manager.unloadModel();
    expect(manager.isModelLoaded()).toBe(false);
  });
});
