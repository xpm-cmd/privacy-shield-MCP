/**
 * network.ts - Módulo de Seguridad de Red (Capa 2)
 *
 * Valida URLs, dominios, y conexiones externas:
 * - Detección de dominios maliciosos
 * - Bloqueo de acortadores de URL
 * - Verificación de patrones de phishing
 * - Detección de IPs directas sospechosas
 * - Lista blanca/negra configurable
 */

import type { RiskLevel } from './types.js';

// ============================================================
// Listas de dominios
// ============================================================

/** Acortadores de URL que ocultan el destino real */
const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly",
  "ow.ly", "buff.ly", "adf.ly", "shorte.st", "bc.vc", "cutt.ly",
  "rb.gy", "v.gd", "shorturl.at", "tiny.cc", "lnkd.in",
]);

/** TLDs de alto riesgo (frecuentemente usados en phishing/malware) */
const HIGH_RISK_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq",       // Freenom (gratuitos, abusados)
  ".buzz", ".top", ".xyz", ".club",          // Frecuente en spam
  ".work", ".click", ".link",                // Frecuente en phishing
  ".zip", ".mov",                            // Confusión con extensiones de archivo
]);

/** Dominios conocidos de data exfiltration / C2 (ejemplos) */
const KNOWN_MALICIOUS_PATTERNS: RegExp[] = [
  /pastebin\.com\/raw/i,        // Raw pastes (frecuente en C2)
  /requestbin\./i,              // Captura de requests
  /webhook\.site/i,             // Captura de webhooks
  /pipedream\.net/i,            // Captura de requests
  /ngrok\.(io|app)/i,          // Tunnels (exfiltración)
  /serveo\.net/i,              // Tunnels
  /localtunnel\.me/i,          // Tunnels
  /burpcollaborator/i,         // Herramienta de pentesting
  /interact\.sh/i,             // OOB exfiltration
  /oast\.fun/i,                // OOB testing
  /dnslog\./i,                 // DNS exfiltration
  /canarytokens\.com/i,        // Tracking tokens
];

/**
 * Patrones de URL sospechosos. `part` says which piece of the URL the pattern reads:
 * the whole URL, the authority (userinfo@host:port) or the path. A host ending in ".com"
 * or ".sh" is a TLD, not a file extension, and an "@" in a path is not a credential.
 */
const SUSPICIOUS_URL_PATTERNS: Array<{ pattern: RegExp; reason: string; part: 'url' | 'authority' | 'path' }> = [
  { pattern: /javascript:/i, reason: "Protocolo javascript: (posible XSS)", part: 'url' },
  { pattern: /data:text\/html/i, reason: "Data URI con HTML (posible XSS)", part: 'url' },
  { pattern: /vbscript:/i, reason: "Protocolo VBScript", part: 'url' },
  { pattern: /@/, reason: "URL con credenciales embebidas (@)", part: 'authority' },
  { pattern: /\.(exe|bat|cmd|ps1|msi|scr|pif|com|vbs|wsf)$/i, reason: "Descarga de ejecutable", part: 'path' },
  { pattern: /\.(sh|bash|zsh)$/i, reason: "Descarga de script shell", part: 'path' },
  { pattern: /[?&](cmd|exec|command|run|eval)=/i, reason: "Parámetro de ejecución en query string", part: 'url' },
  { pattern: /(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/, reason: "IP directa en lugar de dominio", part: 'url' },
  { pattern: /%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}/i, reason: "URL con encoding excesivo (posible ofuscación)", part: 'url' },
  { pattern: /--[^/]*\./i, reason: "Dominio con doble guión (posible punycode attack)", part: 'authority' },
];

/**
 * Marcas imitadas con frecuencia. `legit` son los dominios reales de la marca: ellos y sus
 * subdominios (www.google.com, api.github.com, registry.npmjs.org) no son typosquatting.
 */
const TYPOSQUAT_BRANDS: Array<{ real: string; legit: string[]; legitPattern?: RegExp; fakes: RegExp[] }> = [
  {
    real: "github.com",
    legit: ["github.com", "github.io", "githubusercontent.com", "githubassets.com", "githubapp.com"],
    fakes: [/g[il1]thub/i, /guthub/i, /githuh/i],
  },
  {
    real: "google.com",
    legit: ["google.com", "googleapis.com", "googleusercontent.com", "googlesource.com", "googlevideo.com", "googletagmanager.com"],
    legitPattern: /(?:^|\.)google\.(?:com?\.)?[a-z]{2,3}$/, // google.de, google.co.uk
    fakes: [/g[o0]{2}gle/i, /gogle/i, /googl[e3]/i],
  },
  { real: "anthropic.com", legit: ["anthropic.com"], fakes: [/anth[r0]pic/i, /anthroplc/i] },
  { real: "npmjs.com", legit: ["npmjs.com", "npmjs.org"], fakes: [/npmj[s5]/i, /npm-js/i] },
];

/** domain is d or a subdomain of d */
function isSameOrSubdomain(domain: string, d: string): boolean {
  return domain === d || domain.endsWith("." + d);
}

function isUrlShortener(domain: string): boolean {
  for (const s of URL_SHORTENERS) {
    if (isSameOrSubdomain(domain, s)) return true;
  }
  return false;
}

// ============================================================
// Funciones internas
// ============================================================

interface UrlAnalysis {
  url: string;
  status: string;
  risk: RiskLevel;
  reasons: string[];
}

interface NetworkResult {
  safe: boolean;
  risk_level: RiskLevel;
  urls_analyzed: UrlAnalysis[];
  domains_contacted: string[];
  summary: string;
  recommendations: string[];
}

interface DomainSafetyResult {
  safe: boolean;
  reason: string;
}

function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    // Si no es parseable, intentar extraer dominio manualmente
    const match = url.match(/(?:https?:\/\/)?(?:[^/@\s]*@)?([^/:?\s]+)/);
    return match ? match[1].toLowerCase().replace(/\.$/, "") : "";
  }
}

/** The authority (userinfo@host:port) and path of a URL, for patterns that read only one of them. */
function urlParts(url: string): { authority: string; path: string } {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)([^?#]*)/i.exec(url);
  return m ? { authority: m[1], path: m[2] } : { authority: "", path: url.split(/[?#]/)[0] };
}

function getTLD(domain: string): string {
  const parts = domain.split(".");
  if (parts.length >= 2) {
    return "." + parts[parts.length - 1];
  }
  return "";
}

function analyzeUrl(url: string): UrlAnalysis {
  const reasons: string[] = [];
  let risk: RiskLevel = "safe";
  let status = "safe";
  const riskOrder: Record<RiskLevel, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

  const domain = extractDomain(url);
  const tld = getTLD(domain);

  // 1. Verificar acortadores (también www.bit.ly y otros subdominios)
  if (isUrlShortener(domain)) {
    reasons.push(`🔗 Acortador de URL: ${domain} (oculta el destino real)`);
    risk = "high";
    status = "blocked";
  }

  // 2. Verificar TLDs de alto riesgo
  if (HIGH_RISK_TLDS.has(tld)) {
    reasons.push(`🌐 TLD de alto riesgo: ${tld}`);
    if (riskOrder["medium"] > riskOrder[risk]) risk = "medium";
    if (status === "safe") status = "suspicious";
  }

  // 3. Verificar dominios maliciosos conocidos
  for (const pattern of KNOWN_MALICIOUS_PATTERNS) {
    if (pattern.test(url)) {
      reasons.push(`⚠️ Dominio/servicio de exfiltración potencial: ${domain}`);
      risk = "critical";
      status = "blocked";
      break;
    }
  }

  // 4. Verificar patrones sospechosos en la URL
  const parts = urlParts(url);
  for (const { pattern, reason, part } of SUSPICIOUS_URL_PATTERNS) {
    const subject = part === 'authority' ? parts.authority : part === 'path' ? parts.path : url;
    if (pattern.test(subject)) {
      reasons.push(`🔍 ${reason}`);
      if (riskOrder["medium"] > riskOrder[risk]) risk = "medium";
      if (status === "safe") status = "suspicious";
    }
  }

  // 5. Verificar HTTP sin S
  if (url.startsWith("http://") && !domain.includes("localhost") && !domain.includes("127.0.0.1")) {
    reasons.push("🔓 Conexión HTTP sin cifrar (datos visibles en tránsito)");
    if (riskOrder["low"] > riskOrder[risk]) risk = "low";
    if (status === "safe") status = "warning";
  }

  // 6. Verificar longitud sospechosa (URLs muy largas = ofuscación)
  if (url.length > 500) {
    reasons.push("📏 URL excesivamente larga (posible ofuscación de payload)");
    if (riskOrder["medium"] > riskOrder[risk]) risk = "medium";
    if (status === "safe") status = "suspicious";
  }

  // 7. Detección de homoglyph/typosquatting en dominios populares
  for (const { real, legit, legitPattern, fakes } of TYPOSQUAT_BRANDS) {
    const isLegit = legit.some(d => isSameOrSubdomain(domain, d)) || (legitPattern?.test(domain) ?? false);
    if (isLegit) continue;
    if (fakes.some(fake => fake.test(domain))) {
      reasons.push(`🎭 Posible typosquatting: "${domain}" parece imitar "${real}"`);
      risk = "high";
      status = "blocked";
    }
  }

  return { url, status, risk, reasons };
}

// ============================================================
// Funciones de análisis (API pública)
// ============================================================

export function analyzeNetwork(text: string): NetworkResult {
  // Extraer URLs del texto
  const urlRegex = /https?:\/\/[^\s<>"'{}\[\]|\\^`]+/gi;
  const urls: string[] = [...new Set(text.match(urlRegex) || [])]; // Deduplicar

  const urlFindings = urls.map(analyzeUrl);
  const domains = [...new Set(urls.map(extractDomain).filter(Boolean))];

  const riskOrder: Record<RiskLevel, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const overallRisk = urlFindings.reduce<RiskLevel>(
    (max, f) => (riskOrder[f.risk] > riskOrder[max] ? f.risk : max),
    "safe",
  );

  const blocked = urlFindings.filter(f => f.status === "blocked");
  const suspicious = urlFindings.filter(f => f.status === "suspicious");

  const recommendations: string[] = [];
  if (blocked.length > 0) {
    recommendations.push("🚫 URLs bloqueadas detectadas — NO acceder a estos enlaces");
  }
  if (suspicious.length > 0) {
    recommendations.push("⚠️ Verificar URLs sospechosas manualmente antes de acceder");
  }
  if (urlFindings.some(f => f.reasons.some(r => r.includes("HTTP sin cifrar")))) {
    recommendations.push("🔒 Preferir HTTPS sobre HTTP para proteger datos en tránsito");
  }

  return {
    safe: blocked.length === 0 && suspicious.length === 0,
    risk_level: overallRisk,
    urls_analyzed: urlFindings,
    domains_contacted: domains,
    summary: urlFindings.length === 0
      ? "✅ No se detectaron URLs en el contenido."
      : blocked.length > 0
        ? `🚫 ${blocked.length} URL(s) bloqueada(s), ${suspicious.length} sospechosa(s) de ${urlFindings.length} analizada(s)`
        : suspicious.length > 0
          ? `⚠️ ${suspicious.length} URL(s) sospechosa(s) de ${urlFindings.length} analizada(s)`
          : `✅ ${urlFindings.length} URL(s) analizada(s), todas parecen seguras`,
    recommendations: recommendations.length > 0 ? recommendations : ["URLs parecen seguras"],
  };
}

/**
 * Verifica si un dominio destino es seguro para enviar datos
 */
export function isDomainSafeForDataSending(domain: string): DomainSafetyResult {
  const d = domain.toLowerCase().replace(/\.$/, "");

  // Verificar contra listas
  if (isUrlShortener(d)) {
    return { safe: false, reason: "Acortador de URL — destino real desconocido" };
  }

  for (const pattern of KNOWN_MALICIOUS_PATTERNS) {
    if (pattern.test(d)) {
      return { safe: false, reason: "Dominio asociado a exfiltración de datos" };
    }
  }

  const tld = getTLD(d);
  if (HIGH_RISK_TLDS.has(tld)) {
    return { safe: false, reason: `TLD de alto riesgo: ${tld}` };
  }

  return { safe: true, reason: "Dominio no está en listas de bloqueo" };
}
