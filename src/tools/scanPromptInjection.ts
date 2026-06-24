import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { calculatePromptInjectionScore } from "../utils/securityCheckers";

export const scanPromptInjectionSchema = z.object({
  prompt: z.string().min(1, "Prompt cannot be empty").describe("The prompt text to scan for security risks.")
});

export const scanPromptInjectionDef = {
  name: "scan_prompt_injection",
  description: "Analyzes a given prompt for injection attacks, jailbreaks, or prompt bypass attempts, producing a risk score.",
  inputSchema: zodToJsonSchema(scanPromptInjectionSchema)
};

export function handleScanPromptInjection(args: unknown) {
  const parsed = scanPromptInjectionSchema.parse(args);
  const result = calculatePromptInjectionScore(parsed.prompt);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
