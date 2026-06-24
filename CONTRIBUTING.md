# Contributing to SentinelMCP

Thank you for your interest in contributing to SentinelMCP! We welcome contributions from the community to make LLM integrations safer and more secure.

---

## 🚀 How to Contribute

1. **Fork the Repository:** Create a personal fork of the project on GitHub.
2. **Clone Locally:**
   ```bash
   git clone https://github.com/your-username/ai-security-mcp.git
   cd ai-security-mcp
   ```
3. **Install Dependencies:**
   ```bash
   npm install
   ```
4. **Create a Feature Branch:**
   ```bash
   git checkout -b feat/your-awesome-feature
   ```
5. **Implement Your Changes:** Keep code clean, type-safe, and free of unnecessary comment lines.
6. **Write & Run Tests:** Ensure all new logic has comprehensive test coverage.
   ```bash
   npm run test
   ```
7. **Commit Your Changes:** Follow descriptive commit naming conventions:
   ```bash
   git commit -m "feat: add support for European SSN verification"
   ```
8. **Push and Pull Request:** Push branch to your fork and submit a PR to the main branch.

---

## 🎨 Code Style Guidelines

- **TypeScript Standard:** Use clean, functional components. Avoid `any` types.
- **No Comment Bloat:** Code should be self-documenting with clean, descriptive variable names.
- **Testing Requirements:** Every pull request containing logic changes must include corresponding Jest tests in the `tests/` folder.
- **CI/CD Compliance:** Ensure that `npx tsc --noEmit` and `npm run test` pass successfully before opening a PR.
