/**
 * privacy.ts - Módulo de Protección de Privacidad (Capa 1)
 *
 * Detecta y protege datos personales sensibles:
 * - PII (Personally Identifiable Information)
 * - Secretos y credenciales
 * - Datos financieros
 * - Información de salud
 */
/** Luhn checksum: real card numbers pass it, random 13-19 digit ids almost never do. */
function luhnValid(digits) {
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
        let d = Number(digits[digits.length - 1 - i]);
        if (i % 2 === 1) {
            d *= 2;
            if (d > 9)
                d -= 9;
        }
        sum += d;
    }
    return sum % 10 === 0;
}
/** A lat/lon pair must be in range and not hug 0,0 (where plain numeric pairs live). */
function plausibleCoordinates(m) {
    const lat = Number(m[1]);
    const lon = Number(m[2]);
    return Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && (Math.abs(lat) >= 1 || Math.abs(lon) >= 1);
}
const DETECTION_PATTERNS = [
    // --- Credenciales y Secretos ---
    {
        name: "API Key genérica",
        type: "secret",
        pattern: /(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
        risk: "critical",
        redact: (m) => m.replace(/([a-zA-Z0-9_\-]{20,})/, (k) => k.slice(0, 4) + "****" + k.slice(-4)),
    },
    {
        name: "AWS Access Key",
        type: "secret",
        pattern: /AKIA[0-9A-Z]{16}/g,
        risk: "critical",
        redact: (m) => m.slice(0, 8) + "****" + m.slice(-4),
    },
    {
        name: "AWS Secret Key",
        type: "secret",
        pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?/gi,
        risk: "critical",
        redact: (m) => m.replace(/([a-zA-Z0-9/+=]{40})/, "****REDACTED****"),
    },
    {
        name: "Token Bearer/JWT",
        type: "secret",
        pattern: /(?:bearer\s+|token[:=]\s*['"]?)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi,
        risk: "critical",
        redact: (m) => m.slice(0, 15) + "...****REDACTED****",
    },
    {
        name: "Clave privada SSH/PEM",
        type: "secret",
        pattern: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----[\s\S]*?-----END/gi,
        risk: "critical",
        redact: () => "-----BEGIN PRIVATE KEY-----\n****REDACTED****\n-----END PRIVATE KEY-----",
    },
    {
        name: "Credenciales en URL",
        type: "secret",
        // scheme://user:password@host — the password part has no "/", "@" or quotes
        pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@'"]+:[^\s/@'"]{3,}@[^\s'"]+/gi,
        risk: "high",
        redact: (m) => m.replace(/^([^:]+:\/\/[^:]+:)[^@]+@/, "$1****REDACTED****@"),
    },
    {
        name: "Password en texto plano",
        type: "secret",
        // Key may carry a prefix/suffix (db_password, "password"). The value must be either a
        // quoted literal without spaces, or a bare value that contains a digit or symbol and is
        // not a reference (env lookup, attribute access, template, call or type annotation).
        pattern: /[\w-]*(?:password|passwd|pwd|contraseña)[\w-]*["']?\s*[:=]\s*(?:(["'])[^"'\s]{6,}\1|(?![$%{<])(?!(?:process\.env|os\.environ|import\.meta|env|settings|config|self|this|props|args|request)\b)(?=[^\s'"(),;{}[\]<>]*[\d!@#%^&*+~])[^\s'"(),;{}[\]<>]{6,}(?![(\w.]))/gi,
        risk: "critical",
        redact: (m) => m.replace(/([:=]\s*).*$/s, "$1****REDACTED****"),
        // passwordLabel="Password", password_hash=…, passwordRules: … name a field, not a secret
        validate: (m) => !/(?:hash|hashed|label|placeholder|hint|rules|policy|field|input)["']?\s*$/i.test(m[0].split(/[:=]/)[0]),
    },
    {
        name: "Token de GitHub",
        type: "secret",
        pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})/g,
        risk: "critical",
        redact: (m) => m.slice(0, 6) + "****REDACTED****",
    },
    {
        name: "Anthropic API Key",
        type: "secret",
        pattern: /\bsk-ant-[a-zA-Z0-9_-]{20,}/g,
        risk: "critical",
        redact: (_m) => "sk-ant-****REDACTED****",
    },
    {
        name: "OpenAI API Key",
        type: "secret",
        // Project/service-account/admin keys (sk-proj-…, may contain - and _) and legacy sk-<alnum>
        pattern: /\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|(?!ant-)[A-Za-z0-9]{20,}\b)/g,
        risk: "critical",
        redact: (_m) => "sk-****REDACTED****",
    },
    {
        name: "Google API Key",
        type: "secret",
        pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
        risk: "critical",
        redact: (m) => m.slice(0, 6) + "****REDACTED****",
    },
    {
        name: "Token de Slack",
        type: "secret",
        pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
        risk: "critical",
        redact: (m) => m.slice(0, 5) + "****REDACTED****",
    },
    {
        name: "Token de Hugging Face",
        type: "secret",
        pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
        risk: "critical",
        redact: (_m) => "hf_****REDACTED****",
    },
    {
        name: "Stripe live key",
        type: "secret",
        pattern: /\b[sr]k_live_[A-Za-z0-9]{20,}/g,
        risk: "critical",
        redact: (m) => m.slice(0, 8) + "****REDACTED****",
    },
    {
        name: "Variable .env con secreto",
        type: "secret",
        // dotenv style only: UPPER_CASE name, "=" with no spaces (code constants use "X = 1"),
        // a non-empty value that is not a bare number, empty quotes or a $reference.
        pattern: /^(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*=(?![\d.]+\s*$)(?!(["'])\1\s*$)(?!\$)\S.*$/gm,
        risk: "high",
        redact: (m) => m.replace(/=.*$/, "=****REDACTED****"),
    },
    // --- PII: Datos Personales ---
    {
        name: "Email",
        type: "pii",
        pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
        risk: "medium",
        redact: (m) => {
            const [user, domain] = m.split("@");
            return user.slice(0, 2) + "***@" + domain;
        },
    },
    {
        name: "Teléfono (formato internacional)",
        type: "pii",
        // Separators are optional so E.164 (+56912345678) is caught; the area code may be one
        // digit (+56 9 …). The lookbehind keeps "3+12345678" (arithmetic) out.
        pattern: /(?:(?:tel|phone|fax|móvil|celular|teléfono|whatsapp)\s*[:=]?\s*)?(?<![\w+])\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/gi,
        risk: "medium",
        redact: (m) => m.slice(0, 4) + "****" + m.slice(-2),
    },
    {
        name: "SSN / Número de seguro social",
        type: "pii",
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        risk: "critical",
        redact: () => "***-**-****",
    },
    {
        name: "RUT chileno",
        type: "pii",
        pattern: /\b\d{1,2}\.\d{3}\.\d{3}-[\dkK]\b/g,
        risk: "high",
        redact: (_m) => "**.***.***-*",
    },
    {
        name: "DNI/Cédula (genérico)",
        type: "pii",
        pattern: /(?:DNI|cedula|cédula|CI|RUN)\s*[:=]?\s*\d{6,12}/gi,
        risk: "high",
        redact: (m) => m.replace(/\d{6,12}/, "****REDACTED****"),
    },
    {
        name: "Tarjeta de crédito",
        type: "financial",
        pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
        risk: "critical",
        redact: (m) => "**** **** **** " + m.slice(-4),
        validate: (m) => luhnValid(m[0]),
    },
    {
        name: "IBAN",
        type: "financial",
        pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g,
        risk: "high",
        redact: (m) => m.slice(0, 4) + "****" + m.slice(-4),
    },
    {
        name: "Dirección IP privada",
        type: "network",
        pattern: /\b(?:10\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d))\b/g,
        risk: "medium",
        redact: (m) => m.split(".").slice(0, 2).join(".") + ".***.***",
    },
    {
        name: "Dirección IP pública",
        type: "network",
        pattern: /\b(?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
        risk: "low",
        redact: (m) => m.split(".").slice(0, 2).join(".") + ".*.*",
    },
    {
        name: "Coordenadas GPS",
        type: "pii",
        // Exactly a pair: not preceded by another number in a list, not followed by a third one
        pattern: /(?<![\d.]\s*,\s*|[\d.])([-+]?\d{1,3}\.\d{4,}),\s*([-+]?\d{1,3}\.\d{4,})(?!\d|\s*,\s*[-+]?\d)/g,
        risk: "medium",
        redact: () => "[COORDS_REDACTED]",
        validate: plausibleCoordinates,
    },
];
// ============================================================
// Funciones de análisis
// ============================================================
export function analyzePrivacy(text) {
    const findings = [];
    let redactedText = text;
    let maxRisk = "safe";
    const riskOrder = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const dp of DETECTION_PATTERNS) {
        // Reset lastIndex for global regex
        dp.pattern.lastIndex = 0;
        let match;
        while ((match = dp.pattern.exec(text)) !== null) {
            if (dp.validate && !dp.validate(match))
                continue;
            const rawMatch = match[0];
            const redacted = dp.redact(rawMatch);
            // Encontrar la línea aproximada
            const beforeMatch = text.slice(0, match.index);
            const lineNum = (beforeMatch.match(/\n/g) || []).length + 1;
            findings.push({
                type: dp.type,
                description: dp.name,
                risk: dp.risk,
                match: redacted, // Ya redactado para seguridad
                location: `línea ~${lineNum}`,
                redacted,
            });
            // Redactar en el texto. split/join instead of String.replace: a replacement string
            // is parsed for $&, $1 … and a redaction holding "$&" would re-insert the raw secret.
            redactedText = redactedText.split(rawMatch).join(redacted);
            if (riskOrder[dp.risk] > riskOrder[maxRisk]) {
                maxRisk = dp.risk;
            }
        }
    }
    // Resumen
    const secretCount = findings.filter(f => f.type === "secret").length;
    const piiCount = findings.filter(f => f.type === "pii").length;
    const financialCount = findings.filter(f => f.type === "financial").length;
    const networkCount = findings.filter(f => f.type === "network").length;
    const parts = [];
    if (secretCount > 0)
        parts.push(`🔑 ${secretCount} credencial(es)/secreto(s)`);
    if (piiCount > 0)
        parts.push(`👤 ${piiCount} dato(s) personal(es)`);
    if (financialCount > 0)
        parts.push(`💳 ${financialCount} dato(s) financiero(s)`);
    if (networkCount > 0)
        parts.push(`🌐 ${networkCount} dato(s) de red`);
    return {
        safe: findings.length === 0,
        risk_level: maxRisk,
        findings,
        redacted_text: redactedText,
        summary: findings.length === 0
            ? "✅ No se detectaron datos sensibles."
            : `🛡️ Detectados ${findings.length} elemento(s) sensible(s): ${parts.join(" | ")}`,
    };
}
/**
 * Analiza un archivo específico por datos sensibles
 */
export function analyzeFilePath(filepath) {
    // Normalize Windows backslashes to forward slashes for matching
    const normalizedPath = filepath.replace(/\\/g, "/");
    const sensitivePatterns = [
        { pattern: /\.env($|\.)/, reason: "Archivo de variables de entorno" },
        { pattern: /id_rsa|id_ed25519|id_ecdsa/, reason: "Clave SSH privada" },
        { pattern: /\.pem$/, reason: "Certificado/clave PEM" },
        { pattern: /\.key$/, reason: "Archivo de clave privada" },
        { pattern: /known_hosts/, reason: "Archivo de hosts SSH conocidos" },
        { pattern: /\.netrc/, reason: "Credenciales de red" },
        { pattern: /\.npmrc/, reason: "Configuración npm (puede contener tokens)" },
        { pattern: /\.pypirc/, reason: "Credenciales de PyPI" },
        { pattern: /credentials/i, reason: "Archivo de credenciales" },
        { pattern: /secrets?\./, reason: "Archivo de secretos" },
        { pattern: /\.kube\/config/, reason: "Configuración de Kubernetes" },
        { pattern: /\.docker\/config\.json/, reason: "Credenciales de Docker" },
        { pattern: /\.aws\/credentials/, reason: "Credenciales AWS" },
        { pattern: /\.ssh\//, reason: "Directorio SSH" },
        { pattern: /\.gnupg\//, reason: "Directorio GPG" },
        { pattern: /wallet\.dat/, reason: "Billetera de criptomonedas" },
        { pattern: /\.password-store\//, reason: "Almacén de contraseñas" },
        { pattern: /\.config\/gh\/hosts\.yml/, reason: "Tokens de GitHub CLI" },
    ];
    for (const { pattern, reason } of sensitivePatterns) {
        if (pattern.test(normalizedPath)) {
            return { is_sensitive: true, reason };
        }
    }
    return { is_sensitive: false, reason: "Archivo no parece sensible" };
}
//# sourceMappingURL=privacy.js.map