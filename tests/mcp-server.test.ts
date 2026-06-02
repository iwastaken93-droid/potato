import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { server } from '../src/mcp-server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

describe('MCP Server URET Engine Tests', () => {
  let client: Client;

  beforeAll(async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client(
      { name: 'test-client', version: '1.0.0' },
      { capabilities: {} }
    );
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);
  });

  afterAll(async () => {
    await client.close();
    await server.close();
  });

  it('should list available tools', async () => {
    const result = await client.listTools();
    expect(result.tools).toBeDefined();
    expect(result.tools.length).toBeGreaterThan(0);
    const toolNames = result.tools.map((t: any) => t.name);
    expect(toolNames).toContain('disassemble');
    expect(toolNames).toContain('parseBinary');
    expect(toolNames).toContain('symbolicExecute');
    expect(toolNames).toContain('emulatorControl');
  });

  it('should disassemble binary data via MCP tool', async () => {
    // 90 is NOP
    const result = await client.callTool({
      name: 'disassemble',
      arguments: {
        data: '90',
        arch: 'x86_64',
      },
    });

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.success).toBe(true);
    expect(content.instructions.length).toBeGreaterThan(0);
    expect(content.instructions[0].op).toBe('nop');
  });

  it('should run symbolic execution via MCP tool', async () => {
    const result = await client.callTool({
      name: 'symbolicExecute',
      arguments: {
        instructions: [
          { address: 0x1000, op: 'mov', args: ['rax', 'x'] },
          { address: 0x1004, op: 'cmp', args: ['rax', '0x2a'] },
          { address: 0x1008, op: 'je', args: ['0x2000'] }
        ],
        inputs: [
          { name: 'x', min: 0, max: 100 }
        ],
        targetAddress: 0x2000
      },
    });

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.success).toBe(true);
    expect(content.pathFound).toBe(true);
    expect(content.solutions.x).toBe(42);
  });

  it('should resolve data from file path', async () => {
    const fs = await import('fs');
    const path = await import("path");
    const tempFile = path.resolve('temp_test_mcp_resolve.txt');
    fs.writeFileSync(tempFile, Buffer.from('90', 'hex'));

    try {
      const result = await client.callTool({
        name: 'disassemble',
        arguments: {
          data: tempFile,
          arch: 'x86_64',
        },
      });

      expect(result.isError).toBeUndefined();
      const content = JSON.parse(result.content[0].text);
      expect(content.success).toBe(true);
      expect(content.instructions.length).toBeGreaterThan(0);
      expect(content.instructions[0].op).toBe('nop');
    } finally {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    }
  });

  it('should run emulatorControl dynamic instruction execution', async () => {
    await client.callTool({
      name: 'emulatorControl',
      arguments: { action: 'reset', entryPoint: 0x1000 }
    });

    await client.callTool({
      name: 'emulatorControl',
      arguments: {
        action: 'writeMem',
        memory: [{ address: '0x1000', value: '90' }]
      }
    });

    const stepResult = await client.callTool({
      name: 'emulatorControl',
      arguments: { action: 'step', steps: 1 }
    });

    expect(stepResult.isError).toBeUndefined();
    const content = JSON.parse(stepResult.content[0].text);
    expect(content.success).toBe(true);
    expect(content.cpuState.rip).toBe('4097');
  });

  it('should executeScript with parsed metadata and sandbox fs context', async () => {
    const result = await client.callTool({
      name: 'executeScript',
      arguments: {
        data: '9090',
        script: 'return { size: fileSize, type: fileType, pathExists: fs.existsSync(".") };'
      }
    });

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.success).toBe(true);
    expect(content.result.size).toBe(2);
    expect(content.result.pathExists).toBe(true);
  });

  it('should patchBinary with simplified schema', async () => {
    const result = await client.callTool({
      name: 'patchBinary',
      arguments: {
        data: '90909090',
        offset: 1,
        patchedBytes: 'ebfe'
      }
    });

    expect(result.isError).toBeUndefined();
    const content = JSON.parse(result.content[0].text);
    expect(content.success).toBe(true);
    expect(content.patchedData).toBe('90ebfe90');
  });
});
