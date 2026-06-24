import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { scanPromptInjectionDef, handleScanPromptInjection } from "./tools/scanPromptInjection";
import { checkSensitiveDataDef, handleCheckSensitiveData } from "./tools/checkSensitiveData";
import { validateMcpConfigDef, handleValidateMcpConfig } from "./tools/validateMcpConfig";
import { auditAiOutputDef, handleAuditAiOutput } from "./tools/auditAiOutput";
import { detectSecretsDef, handleDetectSecrets } from "./tools/detectSecrets";
import { checkUrlSafetyDef, handleCheckUrlSafety } from "./tools/checkUrlSafety";

const stats = {
  scansRun: 0,
  threatsDetected: 0
};

const server = new Server(
  {
    name: "sentinel-mcp-server",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {},
      resources: {},
      prompts: {}
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
  stats.scansRun += 1;

  try {
    switch (name) {
      case "scan_prompt_injection": {
        const response = handleScanPromptInjection(args);
        const data = JSON.parse(response.content[0].text);
        if (data.detected) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      case "check_sensitive_data": {
        const response = handleCheckSensitiveData(args);
        const data = JSON.parse(response.content[0].text);
        if (data.detected) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      case "validate_mcp_config": {
        const response = handleValidateMcpConfig(args);
        const data = JSON.parse(response.content[0].text);
        if (!data.valid) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      case "audit_ai_output": {
        const response = handleAuditAiOutput(args);
        const data = JSON.parse(response.content[0].text);
        if (!data.secure) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      case "detect_secrets": {
        const response = handleDetectSecrets(args);
        const data = JSON.parse(response.content[0].text);
        if (data.detected) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      case "check_url_safety": {
        const response = handleCheckUrlSafety(args);
        const data = JSON.parse(response.content[0].text);
        if (!data.safe) {
          stats.threatsDetected += 1;
        }
        return response;
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    if (error instanceof z.ZodError) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Validation failed: ${error.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join(", ")}`
          }
        ]
      };
    }

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

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: [
      {
        uri: "ai-security://rules/active",
        name: "Active Security Rules",
        description: "List of active regular expressions and rules used by the security engines.",
        mimeType: "application/json"
      },
      {
        uri: "ai-security://stats/recent",
        name: "Live Session Audit Statistics",
        description: "Dynamic metrics showing total scans run and security threats flagged in the current session.",
        mimeType: "application/json"
      }
    ]
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  if (uri === "ai-security://rules/active") {
    const rules = {
      promptInjectionPatternsCount: 15,
      sensitivePatternsTypes: ["email", "tcKimlik", "creditCard", "apiKey", "genericToken", "iban", "ssn", "trPhone", "intlPhone"],
      dangerousCommandsCount: 14,
      harmfulPatternsCount: 5
    };
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(rules, null, 2)
        }
      ]
    };
  }

  if (uri === "ai-security://stats/recent") {
    return {
      contents: [
        {
          uri,
          mimeType: "application/json",
          text: JSON.stringify(stats, null, 2)
        }
      ]
    };
  }

  throw new Error(`Resource not found: ${uri}`);
});

server.setRequestHandler(ListPromptsRequestSchema, async () => {
  return {
    prompts: [
      {
        name: "security-audit-helper",
        description: "Pre-configured audit template to run comprehensive security checks on a block of content.",
        arguments: [
          {
            name: "content",
            description: "The text, code, or configuration to evaluate for security concerns.",
            required: true
          }
        ]
      }
    ]
  };
});

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name !== "security-audit-helper") {
    throw new Error(`Prompt not found: ${name}`);
  }

  if (!args || typeof args.content !== "string") {
    throw new Error("Missing content argument");
  }

  return {
    description: "SentinelMCP security audit template",
    messages: [
      {
        role: "user",
        content: {
          type: "text",
          text: `Please perform a comprehensive security audit on the following content:\n\n${args.content}\n\nExecute these SentinelMCP security scans:\n1. Prompt Injection Evasion checks\n2. PII / Sensitive data leakage checks\n3. Embedded secrets and credentials checks\n4. URL trust evaluation\n\nCompile all findings into a structured summary report.`
        }
      }
    ]
  };
});

async function runServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

runServer().catch((error) => {
  process.exit(1);
});
