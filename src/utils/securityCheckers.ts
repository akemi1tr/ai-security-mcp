import * as fs from "fs";
import * as path from "path";

export interface InjectionResult {
  detected: boolean;
  score: number;
  matchedPatterns: string[];
}

export interface SensitiveMatch {
  type: string;
  value: string;
  index: number;
}

export interface SensitiveDataResult {
  detected: boolean;
  matches: SensitiveMatch[];
  maskedText: string;
}

export interface McpConfigIssue {
  severity: "high" | "medium" | "low";
  type: string;
  message: string;
  recommendation: string;
}

export interface McpConfigResult {
  valid: boolean;
  issues: McpConfigIssue[];
}

export interface AuditResult {
  secure: boolean;
  riskScore: number;
  findings: string[];
}

interface InjectionPattern {
  regex: RegExp;
  weight: number;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  { regex: /\bignore\s+(?:[a-z]+\s+){0,3}instructions\b/i, weight: 40 },
  { regex: /\bforget\s+everything\b/i, weight: 40 },
  { regex: /\bsystem\s+override\b/i, weight: 40 },
  { regex: /\bjailbreak\b/i, weight: 40 },
  { regex: /\byou\s+are\s+now\s+a\b/i, weight: 25 },
  { regex: /\bact\s+as\s+a\b/i, weight: 25 },
  { regex: /\bdo\s+anything\s+now\b/i, weight: 25 },
  { regex: /\bdeveloper\s+mode\b/i, weight: 25 },
  { regex: /\bdownplay\s+safety\b/i, weight: 15 },
  { regex: /\[system\]/i, weight: 15 },
  { regex: /\[instruction\]/i, weight: 15 },
  { regex: /<\s*system\s*>/i, weight: 15 },
  { regex: /<\s*instruction\s*>/i, weight: 15 },
  { regex: /assistant\s*:\s*system/i, weight: 15 },
  { regex: /human\s*:\s*ignore/i, weight: 15 }
];

const SENSITIVE_PATTERNS: Record<string, RegExp> = {
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  tcKimlik: /\b[1-9]\d{10}\b/g,
  creditCard: /\b(?:\d[ -]*?){13,16}\b/g,
  apiKey: /\b(sk-[a-zA-Z0-9]{32,60}|AIzaSy[a-zA-Z0-9-_]{33})\b/g,
  genericToken: /\b(ghp_[a-zA-Z0-9]{36}|secret[_-]?[a-zA-Z0-9]{16,64})\b/g,
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9\s]{12,30}\b/g,
  ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
  trPhone: /\b(?:\+?90[- ]?)?5[0-9]{2}[- ]?[0-9]{3}[- ]?[0-9]{2}[- ]?[0-9]{2}\b/g,
  intlPhone: /\b\+(?:[0-9][- ]?){8,14}[0-9]\b/g
};

const DANGEROUS_COMMANDS = [
  "rm",
  "del",
  "curl",
  "wget",
  "bash",
  "sh",
  "powershell",
  "cmd",
  "sudo",
  "chmod",
  "chown",
  "nc",
  "netcat",
  "eval"
];

const HARMFUL_PATTERNS = [
  /\bhow\s+to\s+(?:hack|crack|bypass|exploit|exploit|phish)\b/i,
  /\bmake\s+(?:bomb|explosive|weapon|virus|malware)\b/i,
  /\bgenerate\s+(?:credentials|passwords|keys)\b/i,
  /\bexecute\s+arbitrary\b/i,
  /\bdenial\s+of\s+service\b/i
];

export function isValidTCKN(tckn: string): boolean {
  if (tckn.length !== 11) {
    return false;
  }
  if (!/^[1-9]\d{10}$/.test(tckn)) {
    return false;
  }
  const digits = tckn.split("").map(Number);
  const oddSum = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
  const evenSum = digits[1] + digits[3] + digits[5] + digits[7];
  const digit10 = ((oddSum * 7) - evenSum) % 10;
  if (digits[9] !== digit10) {
    return false;
  }
  const totalSum = digits.slice(0, 10).reduce((a, b) => a + b, 0);
  const digit11 = totalSum % 10;
  if (digits[10] !== digit11) {
    return false;
  }
  return true;
}

export function isValidIBAN(iban: string): boolean {
  const cleaned = iban.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{12,30}$/.test(cleaned)) {
    return false;
  }
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  const numeric = rearranged
    .split("")
    .map((char) => {
      const code = char.charCodeAt(0);
      if (code >= 65 && code <= 90) {
        return (code - 55).toString();
      }
      return char;
    })
    .join("");

  try {
    const ibanBigInt = BigInt(numeric);
    return ibanBigInt % 97n === 1n;
  } catch (e) {
    return false;
  }
}

export function isValidSSN(ssn: string): boolean {
  if (!/^\d{3}-\d{2}-\d{4}$/.test(ssn)) {
    return false;
  }
  const parts = ssn.split("-");
  const area = parseInt(parts[0], 10);
  const group = parseInt(parts[1], 10);
  const serial = parseInt(parts[2], 10);

  if (area === 0 || area === 666 || (area >= 900 && area <= 999)) {
    return false;
  }
  if (group === 0) {
    return false;
  }
  if (serial === 0) {
    return false;
  }
  return true;
}

export function loadCustomRules() {
  const configPath = path.join(process.cwd(), "security-rules.json");
  if (!fs.existsSync(configPath)) {
    return;
  }
  try {
    const content = fs.readFileSync(configPath, "utf-8");
    const config = JSON.parse(content);

    if (config.customPromptPatterns && Array.isArray(config.customPromptPatterns)) {
      for (const pattern of config.customPromptPatterns) {
        INJECTION_PATTERNS.push({
          regex: new RegExp(pattern, "i"),
          weight: 25
        });
      }
    }

    if (config.customSensitivePatterns && typeof config.customSensitivePatterns === "object") {
      for (const [key, patternStr] of Object.entries(config.customSensitivePatterns)) {
        if (typeof patternStr === "string") {
          SENSITIVE_PATTERNS[key] = new RegExp(patternStr, "g");
        }
      }
    }
  } catch (error) {
    process.stderr.write("Failed to load security-rules.json\n");
  }
}

export function calculatePromptInjectionScore(prompt: string): InjectionResult {
  const matchedPatterns: string[] = [];
  let score = 0;

  for (const item of INJECTION_PATTERNS) {
    if (item.regex.test(prompt)) {
      matchedPatterns.push(item.regex.source);
      score += item.weight;
    }
  }

  if (matchedPatterns.length > 1) {
    score += 15;
  }

  const finalScore = Math.min(score, 100);
  const detected = finalScore >= 25;

  return {
    detected,
    score: finalScore,
    matchedPatterns
  };
}

export function findSensitiveData(text: string): SensitiveDataResult {
  const matches: SensitiveMatch[] = [];
  let maskedText = text;

  for (const [key, pattern] of Object.entries(SENSITIVE_PATTERNS)) {
    let match;
    pattern.lastIndex = 0;
    while ((match = pattern.exec(text)) !== null) {
      if (key === "tcKimlik" && !isValidTCKN(match[0])) {
        continue;
      }
      if (key === "iban" && !isValidIBAN(match[0])) {
        continue;
      }
      if (key === "ssn" && !isValidSSN(match[0])) {
        continue;
      }
      matches.push({
        type: key,
        value: match[0],
        index: match.index
      });
    }
  }

  for (const match of matches) {
    const maskString = "*".repeat(match.value.length);
    maskedText = maskedText.replace(match.value, maskString);
  }

  return {
    detected: matches.length > 0,
    matches,
    maskedText
  };
}

export function validateMcpConfiguration(configContent: string): McpConfigResult {
  const issues: McpConfigIssue[] = [];

  try {
    const parsed = JSON.parse(configContent);
    const mcpServers = parsed.mcpServers;

    if (!mcpServers) {
      issues.push({
        severity: "high",
        type: "missing_mcp_servers",
        message: "Configuration file does not contain mcpServers property",
        recommendation: "Define your MCP servers inside an mcpServers object"
      });
      return { valid: false, issues };
    }

    for (const [serverName, serverConfig] of Object.entries<any>(mcpServers)) {
      if (!serverConfig.command) {
        issues.push({
          severity: "high",
          type: "missing_command",
          message: `Server ${serverName} has no command specified`,
          recommendation: "Ensure each server configuration defines a command property"
        });
        continue;
      }

      const commandParts = serverConfig.command.toLowerCase().split(/[/\\]/);
      const executableName = commandParts[commandParts.length - 1];

      if (DANGEROUS_COMMANDS.includes(executableName)) {
        issues.push({
          severity: "high",
          type: "dangerous_command",
          message: `Server ${serverName} executes a potentially dangerous shell command: ${serverConfig.command}`,
          recommendation: "Avoid running shell interpreters or network fetchers directly. Wrap execution in safe, isolated binaries"
        });
      }

      if (serverConfig.args) {
        for (const arg of serverConfig.args) {
          if (typeof arg === "string") {
            const hasDangerousArgPattern = /([|&;$><`"\r\n])/.test(arg);
            if (hasDangerousArgPattern) {
              issues.push({
                severity: "medium",
                type: "unsafe_argument",
                message: `Server ${serverName} contains potentially dangerous characters in argument: ${arg}`,
                recommendation: "Avoid shell metacharacters in command arguments to prevent command injection"
              });
            }
          }
        }
      }

      if (serverConfig.env && typeof serverConfig.env === "object") {
        for (const [envKey, envValue] of Object.entries(serverConfig.env)) {
          if (typeof envValue === "string") {
            const lowerEnvValue = envValue.toLowerCase();
            const lowerEnvKey = envKey.toLowerCase();
            if (
              lowerEnvValue.includes("password") ||
              lowerEnvValue.includes("secret") ||
              lowerEnvValue.includes("key") ||
              lowerEnvKey.includes("password") ||
              lowerEnvKey.includes("secret") ||
              lowerEnvKey.includes("key")
            ) {
              issues.push({
                severity: "low",
                type: "sensitive_env",
                message: `Server ${serverName} environment variable ${envKey} may contain sensitive credentials`,
                recommendation: "Use OS-level environment variables instead of hardcoding secrets in configuration files"
              });
            }
          }
        }
      }
    }
  } catch (error) {
    issues.push({
      severity: "high",
      type: "invalid_json",
      message: "Configuration file is not a valid JSON",
      recommendation: "Ensure configuration syntax is correct JSON format"
    });
  }

  return {
    valid: issues.filter((issue) => issue.severity === "high").length === 0,
    issues
  };
}

export function auditOutputContent(text: string): AuditResult {
  const findings: string[] = [];
  let riskScore = 0;

  for (const pattern of HARMFUL_PATTERNS) {
    if (pattern.test(text)) {
      findings.push(`Harmful content detected matching: ${pattern.source}`);
      riskScore += 35;
    }
  }

  const sensitiveCheck = findSensitiveData(text);
  if (sensitiveCheck.detected) {
    findings.push(`Sensitive data leakage detected: ${sensitiveCheck.matches.length} matches`);
    riskScore += 25 * sensitiveCheck.matches.length;
  }

  const hallucinationPatterns = [
    /\bas\s+an\s+ai\b/i,
    /\bmy\s+knowledge\s+cutoff\b/i,
    /\bi\s+do\s+not\s+have\s+access\b/i
  ];

  for (const pattern of hallucinationPatterns) {
    if (pattern.test(text)) {
      findings.push(`Standard AI constraint phrase detected matching: ${pattern.source}`);
      riskScore += 3;
    }
  }

  const finalScore = Math.min(riskScore, 100);
  const secure = finalScore < 30;

  return {
    secure,
    riskScore: finalScore,
    findings
  };
}

loadCustomRules();
