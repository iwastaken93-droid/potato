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
    const fs = await import("fs");
    const path = await import("path");
    
    const resolveDataParam = (val: any): string => {
      if (typeof val === 'string' && val.trim().length > 0) {
        try {
          const resolvedPath = path.resolve(val.trim());
          if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
            const stats = fs.statSync(resolvedPath);
            if (stats.size > 10485760) {
              throw new Error('Input size exceeds 10MB limit');
            }
            const buffer = fs.readFileSync(resolvedPath);
            // Convert to hex representation since tools expect hex or base64 or utf8 bytes
            return buffer.toString("hex");
          }
        } catch (e: any) {
          if (e?.message === 'Input size exceeds 10MB limit') {
            throw e;
          }
          // ignore resolving errors and treat as normal data string
        }
      }
      return val;
    };

    const processedArgs = { ...(args || {}) };
    for (const key of ['data', 'dataA', 'dataB', 'filePath']) {
      if (key in processedArgs) {
        processedArgs[key] = resolveDataParam(processedArgs[key]);
      }
    }

    const result = await AIBridge.executeQuery({
      action: name,
      params: processedArgs,
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, (key, value) => typeof value === 'bigint' ? value.toString() : value, 2),
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
