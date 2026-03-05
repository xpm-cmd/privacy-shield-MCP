#!/usr/bin/env node
// Privacy Shield - PreToolUse hook for WebFetch (macOS + Linux)
// Exit 0 = allow, Exit 2 = block

const { printBox, t } = require('./format-message.js');

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
      printBox('block', `${t('Dominio de exfiltración/C2', 'Exfiltration/C2 domain')}: ${domain}`,
        t('URL apunta a un servicio conocido de exfiltración de datos', 'URL points to a known data exfiltration service'),
        t('Usa un dominio de confianza para enviar datos o archivos', 'Use a trusted domain to send data or files'));
      process.exit(2);
    }
  }

  // ── Block URL shorteners ──
  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'rebrand.ly',
    'ow.ly', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc', 'cutt.ly',
    'rb.gy', 'v.gd', 'shorturl.at', 'tiny.cc', 'lnkd.in',
  ];
  function isDomainOrSubdomain(dom, blocked) {
    return dom === blocked || dom.endsWith('.' + blocked);
  }

  if (shorteners.some(s => isDomainOrSubdomain(domain, s))) {
    printBox('block', `${t('Acortador de URL bloqueado', 'URL shortener blocked')}: ${domain}`,
      t('Los acortadores ocultan el destino final — posible phishing o malware', 'Shorteners hide the final destination — possible phishing or malware'),
      t('Expande la URL primero: curl -sI https://... o usa la URL destino directamente', 'Expand the URL first: curl -sI https://... or use the destination URL directly'));
    process.exit(2);
  }

  // ── Block dangerous protocols ──
  if (/^(javascript|vbscript|data:text\/html):/i.test(url)) {
    printBox('block', t('Protocolo peligroso detectado', 'Dangerous protocol detected'),
      t('javascript:, vbscript: y data: pueden ejecutar código arbitrario', 'javascript:, vbscript: and data: can execute arbitrary code'),
      t('Usa URLs con https:// únicamente', 'Use URLs with https:// only'));
    process.exit(2);
  }

  // ── Block high-risk TLDs ──
  const riskyTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.zip', '.mov'];
  const tldMatch = domain.match(/\.[^.]+$/);
  if (tldMatch && riskyTLDs.includes(tldMatch[0])) {
    printBox('block', `${t('TLD de alto riesgo', 'High-risk TLD')}: ${tldMatch[0]}`,
      t('Este dominio usa un TLD frecuentemente asociado a malware y phishing', 'This domain uses a TLD frequently associated with malware and phishing'),
      t('Verifica si la URL es realmente necesaria o usa una fuente alternativa', 'Verify if the URL is necessary or use an alternative source'));
    process.exit(2);
  }

  process.exit(0);
});
