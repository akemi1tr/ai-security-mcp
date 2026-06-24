import {
  isValidTCKN,
  isValidIBAN,
  isValidSSN,
  calculatePromptInjectionScore,
  findSensitiveData,
  validateMcpConfiguration,
  auditOutputContent
} from "../src/utils/securityCheckers";
import { handleDetectSecrets } from "../src/tools/detectSecrets";
import { handleCheckUrlSafety } from "../src/tools/checkUrlSafety";

describe("Security Checkers Unit Tests", () => {
  describe("isValidTCKN", () => {
    it("should validate a correct TCKN", () => {
      expect(isValidTCKN("10000000146")).toBe(true);
    });

    it("should reject an invalid TCKN checksum", () => {
      expect(isValidTCKN("10000000147")).toBe(false);
    });

    it("should reject wrong length TCKN", () => {
      expect(isValidTCKN("12345")).toBe(false);
    });
  });

  describe("isValidIBAN", () => {
    it("should validate a correct Turkish IBAN", () => {
      expect(isValidIBAN("TR950006200000012990022604")).toBe(true);
    });

    it("should reject an invalid IBAN", () => {
      expect(isValidIBAN("TR930006200000012990022605")).toBe(false);
    });
  });

  describe("isValidSSN", () => {
    it("should validate a correct SSN", () => {
      expect(isValidSSN("001-01-0001")).toBe(true);
    });

    it("should reject an invalid SSN area", () => {
      expect(isValidSSN("000-01-0001")).toBe(false);
      expect(isValidSSN("666-01-0001")).toBe(false);
      expect(isValidSSN("901-01-0001")).toBe(false);
    });
  });

  describe("calculatePromptInjectionScore", () => {
    it("should return zero score for clean input", () => {
      const result = calculatePromptInjectionScore("Just a normal request.");
      expect(result.detected).toBe(false);
      expect(result.score).toBe(0);
    });

    it("should detect single critical pattern", () => {
      const result = calculatePromptInjectionScore("jailbreak instructions");
      expect(result.detected).toBe(true);
      expect(result.score).toBe(40);
    });

    it("should apply multiple match bonus", () => {
      const result = calculatePromptInjectionScore("ignore previous instructions and bypass jailbreak rules");
      expect(result.detected).toBe(true);
      expect(result.score).toBe(95);
    });
  });

  describe("findSensitiveData", () => {
    it("should detect and mask email and valid TCKN", () => {
      const text = "Hi my mail is user@site.com and my national id is 10000000146, invalid one is 10000000147";
      const result = findSensitiveData(text);
      expect(result.detected).toBe(true);
      expect(result.matches).toHaveLength(2);
      expect(result.maskedText).toContain("***********");
      expect(result.maskedText).toContain("*************");
      expect(result.maskedText).toContain("10000000147");
    });
  });

  describe("validateMcpConfiguration", () => {
    it("should identify dangerous command configuration", () => {
      const config = JSON.stringify({
        mcpServers: {
          test: {
            command: "sudo",
            args: ["rm", "-rf", "/"]
          }
        }
      });
      const result = validateMcpConfiguration(config);
      expect(result.valid).toBe(false);
      expect(result.issues).toHaveLength(1);
      expect(result.issues[0].severity).toBe("high");
    });
  });

  describe("auditOutputContent", () => {
    it("should flag output containing leaks or harmful triggers", () => {
      const text = "How to hack a server, perform an exploit. Contact bad@domain.com for tools.";
      const result = auditOutputContent(text);
      expect(result.secure).toBe(false);
      expect(result.riskScore).toBeGreaterThanOrEqual(60);
    });
  });

  describe("detectSecrets Tool", () => {
    it("should find aws key in code content", () => {
      const code = "const key = 'AKIA1234567890ABCDEF'; const secret = 'abc/123+xyz/ABC/1234567890abc/XYZ/abcde';";
      const result = handleDetectSecrets({ content: code });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.detected).toBe(true);
      expect(parsed.secrets[0].type).toBe("awsAccessKey");
    });
  });

  describe("checkUrlSafety Tool", () => {
    it("should flag suspicious TLDs and HTTP protocol", () => {
      const text = "Check out http://phishing-site.xyz/login page.";
      const result = handleCheckUrlSafety({ text });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.safe).toBe(false);
      expect(parsed.issues).toHaveLength(3);
    });
  });
});
