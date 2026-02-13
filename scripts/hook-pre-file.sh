#!/bin/bash
# Privacy Shield - PreToolUse hook for file operations (Read, Edit, Write)
# Exit 0 = allow, Exit 2 = block
# Only blocks Write/Edit to EXACT sensitive file patterns — no broad substrings

PARSE="${CLAUDE_PLUGIN_ROOT}/scripts/parse-input.js"
PARSED=$(cat | node "$PARSE" "tool_name" "tool_input.file_path")
TOOL_NAME=$(echo "$PARSED" | sed -n '1p')
FILE_PATH=$(echo "$PARSED" | sed -n '2p')

[ -z "$FILE_PATH" ] && exit 0

# Normalize: backslash to slash, lowercase
NORM=$(echo "$FILE_PATH" | tr '\\' '/' | tr '[:upper:]' '[:lower:]')

# Only block Write/Edit — Read always allowed
[ "$TOOL_NAME" != "Write" ] && [ "$TOOL_NAME" != "Edit" ] && exit 0

# ── Exact sensitive file patterns (no broad substrings) ──
# .env files (but not .envrc or random files with "env" in name)
echo "$NORM" | grep -qP '/(\.env|\.env\.\w+)$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en .env: $FILE_PATH" >&2; exit 2; }

# SSH private keys
echo "$NORM" | grep -qP '/id_(rsa|ed25519|ecdsa|dsa)$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en clave SSH: $FILE_PATH" >&2; exit 2; }

# .ssh directory config
echo "$NORM" | grep -qP '/\.ssh/(config|authorized_keys|known_hosts)$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en SSH config: $FILE_PATH" >&2; exit 2; }

# Certificates and private keys
echo "$NORM" | grep -qP '\.(pem|pfx|p12)$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en certificado/clave: $FILE_PATH" >&2; exit 2; }

# Cloud credentials (exact paths)
echo "$NORM" | grep -qP '/\.aws/credentials$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en AWS credentials: $FILE_PATH" >&2; exit 2; }
echo "$NORM" | grep -qP '/\.docker/config\.json$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en Docker config: $FILE_PATH" >&2; exit 2; }
echo "$NORM" | grep -qP '/\.kube/config$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en Kube config: $FILE_PATH" >&2; exit 2; }

# Auth config files (exact filenames)
echo "$NORM" | grep -qP '/\.netrc$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en .netrc: $FILE_PATH" >&2; exit 2; }
echo "$NORM" | grep -qP '/\.npmrc$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en .npmrc: $FILE_PATH" >&2; exit 2; }
echo "$NORM" | grep -qP '/\.pypirc$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en .pypirc: $FILE_PATH" >&2; exit 2; }

# Crypto wallets
echo "$NORM" | grep -qP '/wallet\.dat$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en wallet: $FILE_PATH" >&2; exit 2; }

# GPG private keys
echo "$NORM" | grep -qP '/\.gnupg/.*\.(key|gpg)$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en GPG key: $FILE_PATH" >&2; exit 2; }

# Password stores
echo "$NORM" | grep -qP '/\.password-store/' && { echo "PRIVACY-SHIELD: Bloqueado escritura en password store: $FILE_PATH" >&2; exit 2; }

# GitHub CLI tokens
echo "$NORM" | grep -qP '/\.config/gh/hosts\.yml$' && { echo "PRIVACY-SHIELD: Bloqueado escritura en GitHub CLI tokens: $FILE_PATH" >&2; exit 2; }

exit 0
