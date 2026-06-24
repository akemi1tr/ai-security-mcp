import { validateMcpConfiguration } from "../utils/securityCheckers";

export const validateMcpConfigDef = {
  name: "validate_mcp_config",
  description: "Analyzes an MCP configuration JSON content, identifying excessive privileges, dangerous tool configurations, and command poisoning risks.",
  inputSchema: {
    type: "object",
    properties: {
      configContent: {
        type: "string",
        description: "The raw JSON configuration string of the MCP server configuration."
      }
    },
    required: ["configContent"]
  }
};

export function handleValidateMcpConfig(args: { configContent: string }) {
  const result = validateMcpConfiguration(args.configContent);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
