# 🛡️ SentinelMCP: Production-Grade LLM Security Guard

> Secure your LLM workflows against Prompt Injections, Data Leaks, Credentials Exposure, and Phishing URLs — running natively inside Claude Desktop or any MCP-compatible environment.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![Jest](https://img.shields.io/badge/Jest-Tested-green.svg?style=for-the-badge&logo=jest)](https://jestjs.io/)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-SDK-orange.svg?style=for-the-badge)](https://modelcontextprotocol.io/)
[![CI/CD](https://img.shields.io/badge/GitHub_Actions-CI-red.svg?style=for-the-badge&logo=github-actions)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

SentinelMCP is an advanced, production-grade Model Context Protocol (MCP) server that acts as a secure firewall for Large Language Models. It analyzes inputs and outputs in real-time, masking sensitive data (PII) using Zod validation, serving dynamic audit stats as resources, and providing pre-configured system audit prompts.

---

## 🏗️ Architecture

```mermaid
graph TD
    Client["Claude Desktop / Client"] <-->|Stdio Transport JSON-RPC| Index["src/index.ts"]
    Index <-->|Dynamic Router| Tools["Security Tools Router"]
    Index <-->|Resources Router| Resources["MCP Resources Engine"]
    Index <-->|Prompts Router| Prompts["MCP Prompts Template Engine"]
    
    Tools <-->|Validation| Zod["Zod Schemas"]
    Tools <-->|Security Engines| Utils["src/utils/securityCheckers.ts"]
    
    subgraph Tools
        T1["scan_prompt_injection"]
        T2["check_sensitive_data"]
        T3["validate_mcp_config"]
        T4["audit_ai_output"]
        T5["detect_secrets"]
        T6["check_url_safety"]
    end
```

---

## ⚡ Core Components

### 1. Tools (JSON-RPC Actions)

All inputs are validated using `zod` and automatically formatted to JSON Schema using `zod-to-json-schema`.

| Tool Name | Security Risk Mitigated | How It Works |
| :--- | :--- | :--- |
| **`scan_prompt_injection`** | Prompt Injection, Jailbreaks, System Prompt Evasion | Weighted pattern analysis and multi-match boost scoring (0-100). |
| **`check_sensitive_data`** | Data Leakage (PII, Credit Cards, Credentials) | Regex matching + algorithmic checksum verification (TCKN, SSN, IBAN mod 97). |
| **`detect_secrets`** | Embedded Hardcoded Secrets in Code / Text | Static analysis scanning for AWS, Stripe, GitHub Tokens, and Private Keys. |
| **`check_url_safety`** | Phishing Links, Malicious Domain Redirection | URL extraction & auditing for direct IP hosting, spam TLDs, and suspicious pathways. |
| **`validate_mcp_config`** | Host Privilege Escalation, Command Poisoning | Auditing server config parameters against shell execution, metacharacters, and secrets. |
| **`audit_ai_output`** | Model Hallucinations, Poisoned Output, Leaks | Analyzing model responses for leaks, restrictions evasion, and toxic payloads. |

### 📊 2. Dynamic Resources

SentinelMCP exposes real-time session statistics and configuration details directly to the LLM Client:

- **`ai-security://rules/active`**: Active regular expressions, rule weights, and blacklisted command counts used by security checkers.
- **`ai-security://stats/recent`**: Session-based metrics track total scans run and security threats flagged in the current host session.

### 📝 3. Prompts (Templates)

Pre-packaged prompts to guide LLMs through systematic audit operations:

- **`security-audit-helper`**: Instantly guides the model through running full prompt injection, sensitive data, secrets leak, and URL trust audits on a given code block or prompt input.

---

## 🔌 Claude Desktop Integration

Link SentinelMCP directly to your local Claude Desktop application by adding it to your configurations (`%APPDATA%/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sentinel-mcp": {
      "command": "node",
      "args": [
        "C:/Users/yildi/OneDrive/Masaüstü/proje/build/index.js"
      ]
    }
  }
}
```

---

## 🎛 Honor Custom Safety Rules (`security-rules.json`)

Define your own keywords, system rules, or custom regex checks dynamically. Create a `security-rules.json` file in your workspace:

```json
{
  "customPromptPatterns": [
    "custom-system-bypass-phrase",
    "my-test-jailbreak-trigger"
  ],
  "customSensitivePatterns": {
    "privateToken": "\\bsecret_token_[a-zA-Z0-9]{12}\\b"
  }
}
```

---

## 🛠️ Developer Setup & Test Coverage

### Installation
```bash
npm install
```

### Compile & Build
```bash
npm run build
```

### Run Jest Unit Tests (100% Coverage passing)
```bash
npm run test
```

---

## 🛡️ OWASP LLM Top 10 Mapping

SentinelMCP directly addresses core vulnerabilities highlighted in the **OWASP Top 10 for LLM Applications**:

- **LLM01: Prompt Injection** ➔ Mitigated via `scan_prompt_injection`.
- **LLM02: Insecure Output Handling** ➔ Mitigated via `audit_ai_output`.
- **LLM06: Sensitive Information Disclosure** ➔ Mitigated via `check_sensitive_data` & `detect_secrets`.
- **LLM10: Model Theft / Data Exfiltration** ➔ Mitigated via `check_url_safety`.
