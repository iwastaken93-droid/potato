import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { server } from '../src/mcp-server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

describe('MCP Server Debug Test', () => {
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

  it('debug step', async () => {
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

    console.log("DEBUG STEP RESULT:", JSON.stringify(stepResult, null, 2));
  });
});
