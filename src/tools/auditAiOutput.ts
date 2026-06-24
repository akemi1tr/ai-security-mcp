import { auditOutputContent } from "../utils/securityCheckers";

export const auditAiOutputDef = {
  name: "audit_ai_output",
  description: "Audits AI assistant output text for potential issues such as harmful content, sensitive data leaks, or hallucination cues.",
  inputSchema: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The generated output text of the AI assistant."
      }
    },
    required: ["text"]
  }
};

export function handleAuditAiOutput(args: { text: string }) {
  const result = auditOutputContent(args.text);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
