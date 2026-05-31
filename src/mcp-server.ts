import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { AIBridge, TOOL_SCHEMAS } from "./analyzer/aiBridge.js";

const server = new Server(
  {
    name: "uret-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Map TOOL_SCHEMAS to MCP Tool format
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = Object.values(TOOL_SCHEMAS).map((schema) => ({
    name: schema.name,
    description: schema.description,
    inputSchema: schema.parameters,
  }));

  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (!Object.prototype.hasOwnProperty.call(TOOL_SCHEMAS, name)) {
    throw new Error(`Unknown tool: ${name}`);
  }

  try {
    const result = await AIBridge.executeQuery({
      action: name,
      params: args || {},
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: error?.message || String(error),
        },
      ],
    };
  }
});

// Execute server if run directly
if (process.argv[1] && (process.argv[1].endsWith("mcp-server.ts") || process.argv[1].endsWith("mcp-server.js"))) {
  const transport = new StdioServerTransport();
  server.connect(transport).catch((err) => {
    console.error("MCP Server failed to start:", err);
    process.exit(1);
  });
}

export { server };
