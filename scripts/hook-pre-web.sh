#!/bin/bash
# Privacy Shield - PreToolUse hook for WebFetch
# Exit 0 = allow, Exit 2 = block

PARSE="${CLAUDE_PLUGIN_ROOT}/scripts/parse-input.js"
URL=$(cat | node "$PARSE" "tool_input.url" | head -1)

[ -z "$URL" ] && exit 0

DOMAIN=$(echo "$URL" | sed -E 's|https?://([^/:]+).*|\1|' | tr '[:upper:]' '[:lower:]')

# ── Block exfiltration/C2 domains ──
for pattern in "pastebin.com/raw" "requestbin." "webhook.site" "pipedream.net" "ngrok.io" "ngrok.app" "serveo.net" "localtunnel.me" "burpcollaborator" "interact.sh" "oast.fun" "dnslog." "canarytokens.com"; do
  echo "$URL" | grep -qi "$pattern" && { echo "PRIVACY-SHIELD: Bloqueado dominio de exfiltración: $DOMAIN" >&2; exit 2; }
done

# ── Block URL shorteners ──
for s in "bit.ly" "tinyurl.com" "t.co" "goo.gl" "is.gd" "rebrand.ly" "ow.ly" "buff.ly" "adf.ly" "shorte.st" "cutt.ly" "rb.gy" "shorturl.at" "tiny.cc"; do
  [ "$DOMAIN" = "$s" ] && { echo "PRIVACY-SHIELD: Bloqueado acortador: $DOMAIN" >&2; exit 2; }
done

# ── Block dangerous protocols ──
echo "$URL" | grep -qiP '^(javascript|vbscript|data:text/html):' && { echo "PRIVACY-SHIELD: Bloqueado protocolo peligroso" >&2; exit 2; }

# ── Block high-risk TLDs ──
TLD=$(echo "$DOMAIN" | grep -oP '\.[^.]+$')
for t in ".tk" ".ml" ".ga" ".cf" ".gq" ".buzz" ".zip" ".mov"; do
  [ "$TLD" = "$t" ] && { echo "PRIVACY-SHIELD: Bloqueado TLD de alto riesgo: $TLD" >&2; exit 2; }
done

exit 0
