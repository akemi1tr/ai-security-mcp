import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";

export interface SecretMatch {
  type: string;
  value: string;
  index: number;
}

export interface DetectSecretsResult {
  detected: boolean;
  secrets: {
    type: string;
    maskedValue: string;
    index: number;
  }[];
}

const SECRET_PATTERNS: Record<string, RegExp> = {
  awsAccessKey: /\bAKIA[0-9A-Z]{16}\b/g,
  awsSecretKey: /\b[a-zA-Z0-9+/]{40}\b/g,
  stripeLiveKey: /\b(?:rk|sk)_live_[0-9a-zA-Z]{24,99}\b/g,
  githubToken: /\bgh[oprs]_[0-9a-zA-Z]{36,255}\b/g,
  slackWebhook: /https:\/\/hooks\.slack\.com\/services\/[T0-9A-Za-z]{9}\/[B0-9A-Za-z]{9}\/[0-9A-Za-z]{24}/g,
  privateKey: /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g
};

export const detectSecretsSchema = z.object({
  content: z.string().min(1, "Content cannot be empty").describe("The text content or code to inspect for embedded credentials.")
});

export const detectSecretsDef = {
  name: "detect_secrets",
  description: "Scans code, configurations, or text for embedded secrets, private keys, API keys, or credentials.",
  inputSchema: zodToJsonSchema(detectSecretsSchema)
};

export function handleDetectSecrets(args: unknown) {
  const parsed = detectSecretsSchema.parse(args);
  const secrets: { type: string; maskedValue: string; index: number }[] = [];

  for (const [key, pattern] of Object.entries(SECRET_PATTERNS)) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(parsed.content)) !== null) {
      const val = match[0];
      let masked = val;
      if (val.length > 8) {
        masked = `${val.substring(0, 4)}...${val.substring(val.length - 4)}`;
      } else {
        masked = "****";
      }

      if (key === "awsSecretKey") {
        const hasAwsAccessKey = SECRET_PATTERNS.awsAccessKey.test(parsed.content);
        if (!hasAwsAccessKey) {
          continue;
        }
      }

      secrets.push({
        type: key,
        maskedValue: masked,
        index: match.index
      });
    }
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          detected: secrets.length > 0,
          secrets
        }, null, 2)
      }
    ]
  };
}
