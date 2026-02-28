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
    ".tk", ".ml", ".ga", ".cf", ".gq", // Freenom (gratuitos, abusados)
    ".buzz", ".top", ".xyz", ".club", // Frecuente en spam
    ".work", ".click", ".link", // Frecuente en phishing
    ".zip", ".mov", // Confusión con extensiones de archivo
]);
/** Dominios conocidos de data exfiltration / C2 (ejemplos) */
const KNOWN_MALICIOUS_PATTERNS = [
    /pastebin\.com\/raw/i, // Raw pastes (frecuente en C2)
    /requestbin\./i, // Captura de requests
    /webhook\.site/i, // Captura de webhooks
    /pipedream\.net/i, // Captura de requests
    /ngrok\.(io|app)/i, // Tunnels (exfiltración)
    /serveo\.net/i, // Tunnels
    /localtunnel\.me/i, // Tunnels
    /burpcollaborator/i, // Herramienta de pentesting
    /interact\.sh/i, // OOB exfiltration
    /oast\.fun/i, // OOB testing
    /dnslog\./i, // DNS exfiltration
    /canarytokens\.com/i, // Tracking tokens
];
/** Patrones de URL sospechosos */
const SUSPICIOUS_URL_PATTERNS = [
    { pattern: /javascript:/i, reason: "Protocolo javascript: (posible XSS)" },
    { pattern: /data:text\/html/i, reason: "Data URI con HTML (posible XSS)" },
    { pattern: /vbscript:/i, reason: "Protocolo VBScript" },
    { pattern: /@/, reason: "URL con credenciales embebidas (@)" },
    { pattern: /\.(exe|bat|cmd|ps1|msi|scr|pif|com|vbs|wsf)(\?|$)/i, reason: "Descarga de ejecutable" },
    { pattern: /\.(sh|bash|zsh)(\?|$)/i, reason: "Descarga de script shell" },
    { pattern: /[?&](cmd|exec|command|run|eval)=/i, reason: "Parámetro de ejecución en query string" },
    { pattern: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, reason: "IP directa en lugar de dominio" },
    { pattern: /%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}/i, reason: "URL con encoding excesivo (posible ofuscación)" },
    { pattern: /https?:\/\/[^/]*--[^/]*\./i, reason: "Dominio con doble guión (posible punycode attack)" },
];
function extractDomain(url) {
    try {
        const parsed = new URL(url);
        return parsed.hostname.toLowerCase();
    }
    catch {
        // Si no es parseable, intentar extraer dominio manualmente
        const match = url.match(/(?:https?:\/\/)?([^/:?\s]+)/);
        return match ? match[1].toLowerCase() : "";
    }
}
function getTLD(domain) {
    const parts = domain.split(".");
    if (parts.length >= 2) {
        return "." + parts[parts.length - 1];
    }
    return "";
}
function analyzeUrl(url) {
    const reasons = [];
    let risk = "safe";
    let status = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const domain = extractDomain(url);
    const tld = getTLD(domain);
    // 1. Verificar acortadores
    if (URL_SHORTENERS.has(domain)) {
        reasons.push(`🔗 Acortador de URL: ${domain} (oculta el destino real)`);
        risk = "high";
        status = "blocked";
    }
    // 2. Verificar TLDs de alto riesgo
    if (HIGH_RISK_TLDS.has(tld)) {
        reasons.push(`🌐 TLD de alto riesgo: ${tld}`);
        if (riskOrder["medium"] > riskOrder[risk])
            risk = "medium";
        if (status === "safe")
            status = "suspicious";
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
    for (const { pattern, reason } of SUSPICIOUS_URL_PATTERNS) {
        if (pattern.test(url)) {
            reasons.push(`🔍 ${reason}`);
            if (riskOrder["medium"] > riskOrder[risk])
                risk = "medium";
            if (status === "safe")
                status = "suspicious";
        }
    }
    // 5. Verificar HTTP sin S
    if (url.startsWith("http://") && !domain.includes("localhost") && !domain.includes("127.0.0.1")) {
        reasons.push("🔓 Conexión HTTP sin cifrar (datos visibles en tránsito)");
        if (riskOrder["low"] > riskOrder[risk])
            risk = "low";
        if (status === "safe")
            status = "warning";
    }
    // 6. Verificar longitud sospechosa (URLs muy largas = ofuscación)
    if (url.length > 500) {
        reasons.push("📏 URL excesivamente larga (posible ofuscación de payload)");
        if (riskOrder["medium"] > riskOrder[risk])
            risk = "medium";
        if (status === "safe")
            status = "suspicious";
    }
    // 7. Detección de homoglyph/typosquatting en dominios populares
    const typosquatPatterns = [
        { real: "github.com", fakes: [/g[il1]thub/i, /guthub/i, /githuh/i] },
        { real: "google.com", fakes: [/g[o0]{2}gle/i, /gogle/i, /googl[e3]/i] },
        { real: "anthropic.com", fakes: [/anth[r0]pic/i, /anthroplc/i] },
        { real: "npmjs.com", fakes: [/npmj[s5]/i, /npm-js/i] },
    ];
    for (const { real, fakes } of typosquatPatterns) {
        if (domain !== real) {
            for (const fake of fakes) {
                if (fake.test(domain) && domain !== real) {
                    reasons.push(`🎭 Posible typosquatting: "${domain}" parece imitar "${real}"`);
                    risk = "high";
                    status = "blocked";
                    break;
                }
            }
        }
    }
    return { url, status, risk, reasons };
}
// ============================================================
// Funciones de análisis (API pública)
// ============================================================
export function analyzeNetwork(text) {
    // Extraer URLs del texto
    const urlRegex = /https?:\/\/[^\s<>"'{}\[\]|\\^`]+/gi;
    const urls = [...new Set(text.match(urlRegex) || [])]; // Deduplicar
    const urlFindings = urls.map(analyzeUrl);
    const domains = [...new Set(urls.map(extractDomain).filter(Boolean))];
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const overallRisk = urlFindings.reduce((max, f) => (riskOrder[f.risk] > riskOrder[max] ? f.risk : max), "safe");
    const blocked = urlFindings.filter(f => f.status === "blocked");
    const suspicious = urlFindings.filter(f => f.status === "suspicious");
    const recommendations = [];
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
export function isDomainSafeForDataSending(domain) {
    const d = domain.toLowerCase();
    // Verificar contra listas
    if (URL_SHORTENERS.has(d)) {
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
//# sourceMappingURL=network.js.map