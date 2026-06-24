import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { findSensitiveData } from "../utils/securityCheckers";

export const checkSensitiveDataSchema = z.object({
  text: z.string().min(1, "Text cannot be empty").describe("The text content to examine for sensitive data.")
});

export const checkSensitiveDataDef = {
  name: "check_sensitive_data",
  description: "Scans text for sensitive information like credit cards, emails, TC identification numbers, and API keys, and offers masked recommendations.",
  inputSchema: zodToJsonSchema(checkSensitiveDataSchema)
};

export function handleCheckSensitiveData(args: unknown) {
  const parsed = checkSensitiveDataSchema.parse(args);
  const result = findSensitiveData(parsed.text);
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2)
      }
    ]
  };
}
