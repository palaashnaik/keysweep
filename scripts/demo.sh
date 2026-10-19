#!/usr/bin/env bash
# Build a throwaway fake home with planted (random, fake) keys and scan it.
# Usage: scripts/demo.sh [scan|fix] [extra args]   e.g. scripts/demo.sh fix --all
set -euo pipefail
rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
H="$(mktemp -d)"
trap 'rm -rf "$H"' EXIT

mkdir -p "$H/.local/share/opencode" "$H/.claude" "$H/code/webapp" "$H/Library/CloudStorage/Dropbox-Personal/side/.cursor"
printf 'export PATH=$PATH:/opt/bin\nexport ANTHROPIC_API_KEY="sk-ant-api03-%s"\n' "$(rnd 93)" > "$H/.zshrc"
chmod 644 "$H/.zshrc"
printf '{"anthropic":{"type":"api","key":"sk-ant-api03-%s"},"openai":{"type":"api","key":"sk-proj-%s"}}\n' "$(rnd 93)" "$(rnd 120)" > "$H/.local/share/opencode/auth.json"
chmod 600 "$H/.local/share/opencode/auth.json"
printf '{\n  "env": {\n    "OPENROUTER_API_KEY": "sk-or-v1-%s"\n  }\n}\n' "$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 64)" > "$H/.claude/settings.json"
printf 'GROQ_API_KEY=gsk_%s\nMISTRAL_API_KEY=%s\n' "$(rnd 52)" "$(rnd 32)" > "$H/code/webapp/.env"
( cd "$H/code/webapp" && git init -q && git add .env && git -c user.name=demo -c user.email=demo@example.com -c commit.gpgsign=false commit -qm "add env" )
printf '{ "mcpServers": { "gemini": { "env": { "GEMINI_API_KEY": "AIza%s" } } } }\n' "$(rnd 35)" > "$H/Library/CloudStorage/Dropbox-Personal/side/.cursor/mcp.json"

KS="${KEYSWEEP_BIN:-$(dirname "$0")/../target/debug/keysweep}"
CMD="${1:-scan}"; shift || true
KEYSWEEP_HOME="$H" "$KS" "$CMD" --path "$H/code" --path "$H/Library/CloudStorage" "$@"
