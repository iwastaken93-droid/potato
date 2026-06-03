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
    
    const resolveWorkspacePath = (filePath: string): string => {
      filePath = filePath.trim();
      if (fs.existsSync(filePath) && fs.lstatSync(filePath).isFile()) {
        return filePath;
      }
      try {
        const resolvedPath = path.resolve(filePath);
        if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
          return resolvedPath;
        }
      } catch (_) {}

      const parts = filePath.split(/[/\\]/).filter(p => p.length > 0);
      const workspaceRoot = process.cwd();
      for (let i = parts.length - 1; i >= 0; i--) {
        const suffix = parts.slice(i).join("/");
        const testPath = path.join(workspaceRoot, suffix);
        if (fs.existsSync(testPath) && fs.lstatSync(testPath).isFile()) {
          return testPath;
        }
      }
      return filePath;
    };

    const resolveDataParam = (val: any): string => {
      if (typeof val === 'string' && val.trim().length > 0) {
        const trimmed = val.trim();
        if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
          try {
            const parsed = JSON.parse(trimmed);
            if (parsed && typeof parsed === 'object') {
              if (parsed.filePath) {
                return resolveDataParam(parsed.filePath);
              }
              if (parsed.data) {
                return resolveDataParam(parsed.data);
              }
            }
          } catch (e) {}
        }
        try {
          const resolvedPath = resolveWorkspacePath(trimmed);
          if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
            const stats = fs.statSync(resolvedPath);
            if (stats.size > 10485760) {
              throw new Error('Input size exceeds 10MB limit');
            }
            const buffer = fs.readFileSync(resolvedPath);
            return buffer.toString("hex");
          }
        } catch (e: any) {
          if (e?.message === 'Input size exceeds 10MB limit') {
            throw e;
          }
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
