import { calculatePromptInjectionScore } from "../utils/securityCheckers";

export const scanPromptInjectionDef = {
  name: "scan_prompt_injection",
  description: "Analyzes a given prompt for injection attacks, jailbreaks, or prompt bypass attempts, producing a risk score.",
  inputSchema: {
    type: "object",
    properties: {
      prompt: {
        type: "string",
        description: "The prompt text to scan for security risks."
      }
    },
    required: ["prompt"]
  }
};

export function handleScanPromptInjection(args: { prompt: string }) {
  const result = calculatePromptInjectionScore(args.prompt);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
