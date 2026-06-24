import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { auditOutputContent } from "../utils/securityCheckers";

export const auditAiOutputSchema = z.object({
  text: z.string().min(1, "Text cannot be empty").describe("The generated output text of the AI assistant.")
});

export const auditAiOutputDef = {
  name: "audit_ai_output",
  description: "Audits AI assistant output text for potential issues such as harmful content, sensitive data leaks, or hallucination cues.",
  inputSchema: zodToJsonSchema(auditAiOutputSchema)
};

export function handleAuditAiOutput(args: unknown) {
  const parsed = auditAiOutputSchema.parse(args);
  const result = auditOutputContent(parsed.text);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
