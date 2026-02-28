#!/usr/bin/env node
// Privacy Shield - PreToolUse hook for WebFetch (macOS + Linux)
// Exit 0 = allow, Exit 2 = block

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  let url = '';
  try {
    const input = JSON.parse(data);
    url = (input.tool_input && input.tool_input.url) || '';
  } catch {
    process.exit(0); // fail-safe
  }

  if (!url) process.exit(0);

  const urlLower = url.toLowerCase();

  // Extract domain from URL
  const domainMatch = urlLower.match(/^https?:\/\/([^/:]+)/);
  const domain = domainMatch ? domainMatch[1] : '';

  // ── Block exfiltration/C2 domains ──
  const exfilPatterns = [
    'pastebin.com/raw', 'requestbin.', 'webhook.site', 'pipedream.net',
    'ngrok.io', 'ngrok.app', 'serveo.net', 'localtunnel.me',
    'burpcollaborator', 'interact.sh', 'oast.fun', 'dnslog.',
    'canarytokens.com',
  ];
  for (const pattern of exfilPatterns) {
    if (urlLower.includes(pattern)) {
      process.stderr.write(`PRIVACY-SHIELD: Bloqueado dominio de exfiltración: ${domain}\n`);
      process.exit(2);
    }
  }

  // ── Block URL shorteners ──
  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rebrand.ly',
    'ow.ly', 'buff.ly', 'adf.ly', 'shorte.st', 'cutt.ly', 'rb.gy',
    'shorturl.at', 'tiny.cc',
  ];
  if (shorteners.includes(domain)) {
    process.stderr.write(`PRIVACY-SHIELD: Bloqueado acortador: ${domain}\n`);
    process.exit(2);
  }

  // ── Block dangerous protocols ──
  if (/^(javascript|vbscript|data:text\/html):/i.test(url)) {
    process.stderr.write('PRIVACY-SHIELD: Bloqueado protocolo peligroso\n');
    process.exit(2);
  }

  // ── Block high-risk TLDs ──
  const riskyTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.zip', '.mov'];
  const tldMatch = domain.match(/\.[^.]+$/);
  if (tldMatch && riskyTLDs.includes(tldMatch[0])) {
    process.stderr.write(`PRIVACY-SHIELD: Bloqueado TLD de alto riesgo: ${tldMatch[0]}\n`);
    process.exit(2);
  }

  process.exit(0);
});
