#!/bin/bash
# Privacy Shield - PreToolUse hook for Bash commands
# Exit 0 = allow, Exit 2 = block
# Only blocks truly dangerous patterns — normal dev commands pass through

PARSE="${CLAUDE_PLUGIN_ROOT}/scripts/parse-input.js"
COMMAND=$(cat | node "$PARSE" "tool_input.command" | head -1)

[ -z "$COMMAND" ] && exit 0

# ── Critical: Destructive ──
echo "$COMMAND" | grep -qP 'rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+[/~]' && { echo "PRIVACY-SHIELD: Bloqueado rm -rf en directorio sistema/home" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'rm\s+-rf?\s+/(?!\w)' && { echo "PRIVACY-SHIELD: Bloqueado rm -rf /" >&2; exit 2; }
echo "$COMMAND" | grep -qP ':\s*\(\)\s*\{.*\|.*&\s*\}' && { echo "PRIVACY-SHIELD: Bloqueado fork bomb" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'mkfs\b' && { echo "PRIVACY-SHIELD: Bloqueado formateo de disco" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'dd\s+if=.*of=/dev/' && { echo "PRIVACY-SHIELD: Bloqueado escritura directa a dispositivo" >&2; exit 2; }

# ── Critical: Remote execution ──
echo "$COMMAND" | grep -qP 'curl\s+.*\|\s*(bash|sh|zsh|python)' && { echo "PRIVACY-SHIELD: Bloqueado pipe de descarga a shell" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'wget\s+.*\|\s*(bash|sh|zsh|python)' && { echo "PRIVACY-SHIELD: Bloqueado pipe de descarga a shell" >&2; exit 2; }

# ── Critical: Reverse shells ──
echo "$COMMAND" | grep -qP 'bash\s+-i\s+>&?\s*/dev/tcp' && { echo "PRIVACY-SHIELD: Bloqueado reverse shell" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'nc\s+(-e|-c|--exec)\s' && { echo "PRIVACY-SHIELD: Bloqueado netcat con ejecución" >&2; exit 2; }

# ── Critical: Exfiltration ──
echo "$COMMAND" | grep -qP 'cat\s+.*\.(env|pem|key|ssh).*\|\s*curl' && { echo "PRIVACY-SHIELD: Bloqueado exfiltración de archivos sensibles" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'base64\s+.*\|\s*(curl|wget|nc)' && { echo "PRIVACY-SHIELD: Bloqueado encoding+exfiltración" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'tar\s+.*\|\s*(curl|wget|nc)' && { echo "PRIVACY-SHIELD: Bloqueado empaquetado+exfiltración" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)' && { echo "PRIVACY-SHIELD: Bloqueado decodificación base64 a shell" >&2; exit 2; }

# ── High: Firewall disable ──
echo "$COMMAND" | grep -qP 'iptables\s+.*-F' && { echo "PRIVACY-SHIELD: Bloqueado flush de firewall" >&2; exit 2; }
echo "$COMMAND" | grep -qP 'ufw\s+disable' && { echo "PRIVACY-SHIELD: Bloqueado desactivación de firewall" >&2; exit 2; }

exit 0
