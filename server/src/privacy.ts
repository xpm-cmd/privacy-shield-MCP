/**
 * privacy.ts - Módulo de Protección de Privacidad (Capa 1)
 *
 * Detecta y protege datos personales sensibles:
 * - PII (Personally Identifiable Information)
 * - Secretos y credenciales
 * - Datos financieros
 * - Información de salud
 */

import type { RiskLevel } from './types.js';

// ============================================================
// Patrones de detección
// ============================================================

interface DetectionPattern {
  name: string;
  type: 'secret' | 'pii' | 'financial' | 'network';
  pattern: RegExp;
  risk: RiskLevel;
  redact: (match: string) => string;
}

interface PrivacyFinding {
  type: string;
  description: string;
  risk: RiskLevel;
  match: string;
  location: string;
  redacted: string;
}

interface PrivacyResult {
  safe: boolean;
  risk_level: RiskLevel;
  findings: PrivacyFinding[];
  redacted_text: string;
  summary: string;
}

interface FilePathResult {
  is_sensitive: boolean;
  reason: string;
}

const DETECTION_PATTERNS: DetectionPattern[] = [
  // --- Credenciales y Secretos ---
  {
    name: "API Key genérica",
    type: "secret",
    pattern: /(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
    risk: "critical",
    redact: (m: string) => m.replace(/([a-zA-Z0-9_\-]{20,})/, (k) => k.slice(0, 4) + "****" + k.slice(-4)),
  },
  {
    name: "AWS Access Key",
    type: "secret",
    pattern: /AKIA[0-9A-Z]{16}/g,
    risk: "critical",
    redact: (m: string) => m.slice(0, 8) + "****" + m.slice(-4),
  },
  {
    name: "AWS Secret Key",
    type: "secret",
    pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?/gi,
    risk: "critical",
    redact: (m: string) => m.replace(/([a-zA-Z0-9/+=]{40})/, "****REDACTED****"),
  },
  {
    name: "Token Bearer/JWT",
    type: "secret",
    pattern: /(?:bearer\s+|token[:=]\s*['"]?)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/gi,
    risk: "critical",
    redact: (m: string) => m.slice(0, 15) + "...****REDACTED****",
  },
  {
    name: "Clave privada SSH/PEM",
    type: "secret",
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END/gi,
    risk: "critical",
    redact: () => "-----BEGIN PRIVATE KEY-----\n****REDACTED****\n-----END PRIVATE KEY-----",
  },
  {
    name: "Password en texto plano",
    type: "secret",
    pattern: /(?:password|passwd|pwd|contraseña)\s*[:=]\s*['"]?([^\s'"]{6,})['"]?/gi,
    risk: "critical",
    redact: (m: string) => m.replace(/[:=]\s*['"]?([^\s'"]{6,})['"]?/, ": ****REDACTED****"),
  },
  {
    name: "Token de GitHub",
    type: "secret",
    pattern: /gh[ps]_[a-zA-Z0-9]{36,}/g,
    risk: "critical",
    redact: (m: string) => m.slice(0, 6) + "****REDACTED****",
  },
  {
    name: "Anthropic API Key",
    type: "secret",
    pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    risk: "critical",
    redact: (_m: string) => "sk-ant-****REDACTED****",
  },
  {
    name: "OpenAI API Key",
    type: "secret",
    pattern: /sk-(?!ant-)[a-zA-Z0-9]{20,}/g,
    risk: "critical",
    redact: (_m: string) => "sk-****REDACTED****",
  },
  {
    name: "Variable .env con secreto",
    type: "secret",
    pattern: /^[A-Z_]*(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*\s*=\s*.+$/gim,
    risk: "high",
    redact: (m: string) => m.replace(/=\s*.+$/, "= ****REDACTED****"),
  },
  // --- PII: Datos Personales ---
  {
    name: "Email",
    type: "pii",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    risk: "medium",
    redact: (m: string) => {
      const [user, domain] = m.split("@");
      return user.slice(0, 2) + "***@" + domain;
    },
  },
  {
    name: "Teléfono (formato internacional)",
    type: "pii",
    pattern: /(?:(?:tel|phone|fax|móvil|celular|teléfono|whatsapp)\s*[:=]?\s*)?\+\d{1,3}[-.\s]\(?\d{2,4}\)?[-.\s]\d{3,4}[-.\s]?\d{3,4}\b/gi,
    risk: "medium",
    redact: (m: string) => m.slice(0, 4) + "****" + m.slice(-2),
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
    redact: (_m: string) => "**.***.***-*",
  },
  {
    name: "DNI/Cédula (genérico)",
    type: "pii",
    pattern: /(?:DNI|cedula|cédula|CI|RUN)\s*[:=]?\s*\d{6,12}/gi,
    risk: "high",
    redact: (m: string) => m.replace(/\d{6,12}/, "****REDACTED****"),
  },
  {
    name: "Tarjeta de crédito",
    type: "financial",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    risk: "critical",
    redact: (m: string) => "**** **** **** " + m.slice(-4),
  },
  {
    name: "IBAN",
    type: "financial",
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b/g,
    risk: "high",
    redact: (m: string) => m.slice(0, 4) + "****" + m.slice(-4),
  },
  {
    name: "Dirección IP privada",
    type: "network",
    pattern: /\b(?:10\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d))\b/g,
    risk: "medium",
    redact: (m: string) => m.split(".").slice(0, 2).join(".") + ".***.***",
  },
  {
    name: "Dirección IP pública",
    type: "network",
    pattern: /\b(?!10\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
    risk: "low",
    redact: (m: string) => m.split(".").slice(0, 2).join(".") + ".*.*",
  },
  {
    name: "Coordenadas GPS",
    type: "pii",
    pattern: /[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}/g,
    risk: "medium",
    redact: () => "[COORDS_REDACTED]",
  },
];

// ============================================================
// Funciones de análisis
// ============================================================

export function analyzePrivacy(text: string): PrivacyResult {
  const findings: PrivacyFinding[] = [];
  let redactedText = text;
  let maxRisk: RiskLevel = "safe";
  const riskOrder: Record<RiskLevel, number> = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };

  for (const dp of DETECTION_PATTERNS) {
    // Reset lastIndex for global regex
    dp.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = dp.pattern.exec(text)) !== null) {
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

      // Redactar en el texto
      redactedText = redactedText.replace(rawMatch, redacted);

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

  const parts: string[] = [];
  if (secretCount > 0) parts.push(`🔑 ${secretCount} credencial(es)/secreto(s)`);
  if (piiCount > 0) parts.push(`👤 ${piiCount} dato(s) personal(es)`);
  if (financialCount > 0) parts.push(`💳 ${financialCount} dato(s) financiero(s)`);
  if (networkCount > 0) parts.push(`🌐 ${networkCount} dato(s) de red`);

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
export function analyzeFilePath(filepath: string): FilePathResult {
  // Normalize Windows backslashes to forward slashes for matching
  const normalizedPath = filepath.replace(/\\/g, "/");

  const sensitivePatterns: Array<{ pattern: RegExp; reason: string }> = [
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
