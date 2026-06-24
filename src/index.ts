import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { scanPromptInjectionDef, handleScanPromptInjection } from "./tools/scanPromptInjection";
import { checkSensitiveDataDef, handleCheckSensitiveData } from "./tools/checkSensitiveData";
import { validateMcpConfigDef, handleValidateMcpConfig } from "./tools/validateMcpConfig";
import { auditAiOutputDef, handleAuditAiOutput } from "./tools/auditAiOutput";
import { detectSecretsDef, handleDetectSecrets } from "./tools/detectSecrets";
import { checkUrlSafetyDef, handleCheckUrlSafety } from "./tools/checkUrlSafety";

const server = new Server(
  {
    name: "ai-security-mcp-server",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      scanPromptInjectionDef,
      checkSensitiveDataDef,
      validateMcpConfigDef,
      auditAiOutputDef,
      detectSecretsDef,
      checkUrlSafetyDef
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "scan_prompt_injection": {
        if (!args || typeof args.prompt !== "string") {
          throw new Error("Missing prompt argument");
        }
        return handleScanPromptInjection({ prompt: args.prompt });
      }
      case "check_sensitive_data": {
        if (!args || typeof args.text !== "string") {
          throw new Error("Missing text argument");
        }
        return handleCheckSensitiveData({ text: args.text });
      }
      case "validate_mcp_config": {
        if (!args || typeof args.configContent !== "string") {
          throw new Error("Missing configContent argument");
        }
        return handleValidateMcpConfig({ configContent: args.configContent });
      }
      case "audit_ai_output": {
        if (!args || typeof args.text !== "string") {
          throw new Error("Missing text argument");
        }
        return handleAuditAiOutput({ text: args.text });
      }
      case "detect_secrets": {
        if (!args || typeof args.content !== "string") {
          throw new Error("Missing content argument");
        }
        return handleDetectSecrets({ content: args.content });
      }
      case "check_url_safety": {
        if (!args || typeof args.text !== "string") {
          throw new Error("Missing text argument");
        }
        return handleCheckUrlSafety({ text: args.text });
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: error.message || "An unknown error occurred"
        }
      ]
    };
  }
});

async function runServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

runServer().catch((error) => {
  process.exit(1);
});
