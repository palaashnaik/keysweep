# keysweep spec (v0.1.0)

Source: ai-project-radar idea #3, built in Rust at the owner's request (2026-10-19).

## Problem
AI coding tools keep model-provider keys in plaintext dotfiles, MCP configs, shell profiles and
project `.env` files. A leaked or drained key (see the OpenCode PSA that prompted this idea) is
hard to reason about when you don't know where your keys are.

## Scope
1. **Scan**: built-in registry of where AI tools store credentials (Claude Code, Claude Desktop,
   OpenCode, Codex CLI, Gemini CLI, Aider, Continue, Cursor, Windsurf, VS Code, Cline, Roo, Zed,
   Goose, Amp, llm, Copilot, Hugging Face, shell profiles), plus a walk of project folders for
   `.env*`, `.envrc`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings*.json`.
2. **Detect**: provider-specific key formats (Anthropic, OpenAI, Google, OpenRouter, Groq, xAI,
   Hugging Face, Replicate, Perplexity, Fireworks, ElevenLabs, GitHub) and a context detector for
   `*_API_KEY=`-style assignments with entropy and placeholder filtering.
3. **Risk**: plaintext, group/world-readable, cloud-synced (iCloud Drive, iCloud Desktop &
   Documents, Dropbox, Google Drive, OneDrive, Box, ~/Library/CloudStorage), tracked by git,
   present in git history, exported from a shell profile. Key age from file mtime.
4. **Report**: table, JSON, SARIF; revoke and spend-limit links per provider; `--fail-on`.
5. **Fix** (dry run by default): chmod 600; move keys into the macOS Keychain and rewrite the
   source to a Keychain lookup (shell), an env reference (configs that support one) or a comment
   (`.env`); `keysweep env` re-exports them.

## Acceptance criteria
- [x] `keysweep scan` lists tool, file:line, provider, fingerprint, risks, severity, age.
- [x] Raw keys never appear in any output format (tested for table, JSON, SARIF, stderr).
- [x] Git history detection never puts a key on a command line.
- [x] `keysweep fix` is a dry run unless `--apply`; refuses to act on stale findings.
- [x] Keychain write is verified by reading back through `security` before the file is changed.
- [x] Original file is backed up (0600) before any rewrite.
- [x] Tests pass without real keys (keys are generated at runtime, not stored in the repo).

## Out of scope for v0.1.0
TUI, 1Password backend, canary decoy files, Linux/Windows secret stores, live key validation.
