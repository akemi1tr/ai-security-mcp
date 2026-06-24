import { findSensitiveData } from "../utils/securityCheckers";

export const checkSensitiveDataDef = {
  name: "check_sensitive_data",
  description: "Scans text for sensitive information like credit cards, emails, TC identification numbers, and API keys, and offers masked recommendations.",
  inputSchema: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The text content to examine for sensitive data."
      }
    },
    required: ["text"]
  }
};

export function handleCheckSensitiveData(args: { text: string }) {
  const result = findSensitiveData(args.text);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
