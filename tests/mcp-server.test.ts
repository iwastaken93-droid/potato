import { describe, it, expect, beforeAll } from 'vitest';
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
});
