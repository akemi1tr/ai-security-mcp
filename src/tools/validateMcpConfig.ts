import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { validateMcpConfiguration } from "../utils/securityCheckers";

export const validateMcpConfigSchema = z.object({
  configContent: z.string().min(1, "Configuration content cannot be empty").describe("The raw JSON configuration string of the MCP server configuration.")
});

export const validateMcpConfigDef = {
  name: "validate_mcp_config",
  description: "Analyzes an MCP configuration JSON content, identifying excessive privileges, dangerous tool configurations, and command poisoning risks.",
  inputSchema: zodToJsonSchema(validateMcpConfigSchema)
};

export function handleValidateMcpConfig(args: unknown) {
  const parsed = validateMcpConfigSchema.parse(args);
  const result = validateMcpConfiguration(parsed.configContent);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
