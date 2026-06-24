export interface UrlSafetyIssue {
  url: string;
  reason: string;
  severity: "high" | "medium" | "low";
}

export interface UrlSafetyResult {
  safe: boolean;
  issues: UrlSafetyIssue[];
}

const URL_PATTERN = /https?:\/\/[^\s/$.?#].[^\s]*/gi;
const IP_URL_PATTERN = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
const SUSPICIOUS_TLDS = [".xyz", ".ru", ".su", ".tk", ".fit", ".zip", ".gq", ".cf", ".ga", ".ml"];
const SUSPICIOUS_WORDS = ["login", "verify", "update", "banking", "paypal", "secure-signin", "signin", "support-", "claim-"];

export const checkUrlSafetyDef = {
  name: "check_url_safety",
  description: "Extracts and checks URLs in the provided text for suspicious indicators such as IP address hosting, insecure HTTP protocols, high-risk TLDs, or phishing patterns.",
  inputSchema: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The text content containing URLs to evaluate."
      }
    },
    required: ["text"]
  }
};

export function handleCheckUrlSafety(args: { text: string }): { content: { type: string; text: string }[] } {
  const issues: UrlSafetyIssue[] = [];
  const urls: string[] = [];
  let match;

  URL_PATTERN.lastIndex = 0;
  while ((match = URL_PATTERN.exec(args.text)) !== null) {
    urls.push(match[0]);
  }

  const uniqueUrls = Array.from(new Set(urls));

  for (const url of uniqueUrls) {
    try {
      const urlObj = new URL(url);

      if (urlObj.protocol === "http:") {
        issues.push({
          url,
          reason: "Insecure protocol (HTTP instead of HTTPS)",
          severity: "low"
        });
      }

      if (IP_URL_PATTERN.test(url)) {
        issues.push({
          url,
          reason: "URL hosts on direct IP address instead of domain name",
          severity: "high"
        });
      }

      const hostname = urlObj.hostname.toLowerCase();
      const matchedTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
      if (matchedTld) {
        issues.push({
          url,
          reason: `High-risk TLD (${matchedTld}) associated with spam/malware`,
          severity: "medium"
        });
      }

      const matchedWord = SUSPICIOUS_WORDS.find((word) => url.toLowerCase().includes(word));
      if (matchedWord) {
        issues.push({
          url,
          reason: `Phishing keyword detected: ${matchedWord}`,
          severity: "high"
        });
      }
    } catch (error) {
      issues.push({
        url,
        reason: "Malformed URL syntax",
        severity: "low"
      });
    }
  }

  const hasHighOrMedium = issues.some((i) => i.severity === "high" || i.severity === "medium");

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          safe: !hasHighOrMedium,
          issues
        }, null, 2)
      }
    ]
  };
}
