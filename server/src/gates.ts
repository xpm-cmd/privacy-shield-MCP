/**
 * gates.ts - Enforcement gates system for Privacy Shield v2
 *
 * Modular gate system with aggregation. Each gate evaluates a specific
 * aspect of content/tool usage and returns a GateDecision or null (no issue).
 */

import type { RiskLevel, GateDecision } from './types.js';
import { RISK_ORDER } from './types.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export interface GateConfig {
  diffSizeThreshold?: number;
  allowedTools?: string[];
  customSecretPatterns?: Array<{ pattern: RegExp; name: string }>;
}

// ---------------------------------------------------------------------------
// Built-in secret patterns (8)
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/gi, name: 'API Key' },
  { pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, name: 'Secret/Password' },
  { pattern: /(?:token|bearer)\s*[:=]\s*['"][^'"]{10,}['"]/gi, name: 'Token/Bearer' },
  { pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, name: 'PEM Private Key' },
  { pattern: /sk-[a-zA-Z0-9]{20,}/g, name: 'OpenAI/Anthropic Key' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub PAT' },
  { pattern: /npm_[a-zA-Z0-9]{36}/g, name: 'npm Token' },
  { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key' },
];

// ---------------------------------------------------------------------------
// Decision severity helpers
// ---------------------------------------------------------------------------

const DECISION_SEVERITY: Record<GateDecision['decision'], number> = {
  allow: 0,
  warn: 1,
  'require-confirmation': 2,
  block: 3,
};

// ---------------------------------------------------------------------------
// Gate: diff size
// ---------------------------------------------------------------------------

/**
 * Warns when a diff/content exceeds a line-count threshold.
 *
 * @param content  - The full text content to measure.
 * @param threshold - Maximum acceptable line count (default 300).
 * @returns A warning GateDecision or null if within threshold.
 */
export function diffSizeGate(
  content: string,
  threshold: number = 300,
): GateDecision | null {
  const lineCount = content.split('\n').length;

  if (lineCount > threshold) {
    return {
      gate: 'diff-size',
      decision: 'warn',
      risk: 'medium',
      reason: `Cambio de ${lineCount} lineas excede el umbral de ${threshold}`,
      remediation: [
        'Considerar dividir en cambios mas pequeños',
        'Hacer staging incremental',
        'Ejecutar tests entre cambios',
      ],
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Gate: tool allowlist
// ---------------------------------------------------------------------------

/**
 * Blocks tool invocations that are not on the allowlist.
 * Supports wildcard matching: an entry ending with `*` matches any tool
 * whose name starts with the prefix before the `*`.
 *
 * @param toolName     - The tool being invoked.
 * @param allowedTools - List of allowed tool names / patterns.
 * @returns A blocking GateDecision or null if the tool is allowed.
 */
export function toolAllowlistGate(
  toolName: string,
  allowedTools: string[],
): GateDecision | null {
  const isAllowed = allowedTools.some((allowed) => {
    if (allowed.endsWith('*')) {
      const prefix = allowed.slice(0, -1);
      return toolName.startsWith(prefix);
    }
    return toolName === allowed;
  });

  if (isAllowed) {
    return null;
  }

  return {
    gate: 'tool-allowlist',
    decision: 'block',
    risk: 'high',
    reason: `Herramienta '${toolName}' no esta en la lista permitida`,
    remediation: [
      'Agregar la herramienta a la allowlist si es necesaria',
      `Herramientas permitidas: ${allowedTools.join(', ')}`,
    ],
  };
}

// ---------------------------------------------------------------------------
// Gate: secret detection
// ---------------------------------------------------------------------------

/**
 * Redacts a matched secret value for safe logging.
 * If longer than 12 chars, shows first 4 + '****' + last 4.
 * Otherwise replaces entirely with asterisks.
 */
function redact(value: string): string {
  if (value.length > 12) {
    return value.slice(0, 4) + '****' + value.slice(-4);
  }
  return '*'.repeat(value.length);
}

/**
 * Scans content for hard-coded secrets using built-in patterns.
 *
 * @param content - The text content to scan.
 * @returns A blocking GateDecision or null if no secrets detected.
 */
export function secretDetectionGate(content: string): GateDecision | null {
  const redactedMatches: string[] = [];

  for (const { pattern, name } of SECRET_PATTERNS) {
    // Reset stateful regex before use
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(content)) !== null) {
      redactedMatches.push(`${name}: ${redact(match[0])}`);
    }
  }

  if (redactedMatches.length === 0) {
    return null;
  }

  const matchCount = redactedMatches.length;

  return {
    gate: 'secrets',
    decision: 'block',
    risk: 'critical',
    reason: `${matchCount} secreto(s) detectado(s) en contenido`,
    remediation: [
      'Mover secretos a variables de entorno',
      'Usar .gitignore para archivos sensibles',
      'Considerar un gestor de secretos',
    ],
    metadata: { secrets_found: redactedMatches },
  };
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/**
 * Given an array of gate results (some may be null), returns the single
 * most restrictive decision, or null if every gate passed.
 */
export function aggregateGates(
  results: (GateDecision | null)[],
): GateDecision | null {
  const actual = results.filter(
    (r): r is GateDecision => r !== null,
  );

  if (actual.length === 0) {
    return null;
  }

  actual.sort(
    (a, b) => DECISION_SEVERITY[b.decision] - DECISION_SEVERITY[a.decision],
  );

  return actual[0];
}

// ---------------------------------------------------------------------------
// Run all gates
// ---------------------------------------------------------------------------

/**
 * Convenience function that runs diffSizeGate and secretDetectionGate on the
 * provided content, aggregates the results, and returns the most restrictive
 * decision (or null if everything passes).
 *
 * @param content - Text content to evaluate.
 * @param config  - Optional gate configuration overrides.
 */
export function runAllGates(
  content: string,
  config?: GateConfig,
): GateDecision | null {
  const results: (GateDecision | null)[] = [
    diffSizeGate(content, config?.diffSizeThreshold),
    secretDetectionGate(content),
  ];

  return aggregateGates(results);
}
