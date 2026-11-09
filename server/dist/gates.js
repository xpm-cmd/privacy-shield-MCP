/**
 * gates.ts - Enforcement gates system for Privacy Shield v2
 *
 * Modular gate system with aggregation. Each gate evaluates a specific
 * aspect of content/tool usage and returns a GateDecision or null (no issue).
 */
import { analyzePrivacy } from './privacy.js';
// ---------------------------------------------------------------------------
// Secret patterns
// ---------------------------------------------------------------------------
// Key formats (Anthropic, OpenAI sk-proj-, GitHub ghp_/github_pat_, AWS, Slack, Stripe,
// private key blocks …) come from privacy.ts so both layers stay in step. The patterns
// below only cover what privacy.ts does not: quoted assignments, npm tokens and a private
// key header whose body was cut off.
const SECRET_PATTERNS = [
    { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]/gi, name: 'API Key' },
    { pattern: /(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]/gi, name: 'Secret/Password' },
    { pattern: /(?:token|bearer)\s*[:=]\s*['"][^'"]{10,}['"]/gi, name: 'Token/Bearer' },
    { pattern: /npm_[a-zA-Z0-9]{36}/g, name: 'npm Token' },
    { pattern: /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?![\s\S]*?-----END)/g, name: 'Private key header' },
];
// ---------------------------------------------------------------------------
// Decision severity helpers
// ---------------------------------------------------------------------------
const DECISION_SEVERITY = {
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
export function diffSizeGate(content, threshold = 300) {
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
export function toolAllowlistGate(toolName, allowedTools) {
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
function redact(value) {
    if (value.length > 12) {
        return value.slice(0, 4) + '****' + value.slice(-4);
    }
    return '*'.repeat(value.length);
}
/**
 * Scans content for hard-coded secrets: every secret rule of privacy.ts, the gate's own
 * patterns and any custom patterns.
 *
 * @param content - The text content to scan.
 * @param customPatterns - Extra patterns, e.g. internal token formats.
 * @returns A blocking GateDecision or null if no secrets detected.
 */
export function secretDetectionGate(content, customPatterns = []) {
    const redactedMatches = [];
    const privacy = analyzePrivacy(content);
    for (const finding of privacy.findings) {
        if (finding.type === 'secret') {
            redactedMatches.push(`${finding.description}: ${finding.redacted}`);
        }
    }
    // Scan what privacy.ts left unredacted, so one secret is not counted twice.
    const rest = privacy.redacted_text;
    for (const { pattern, name } of [...SECRET_PATTERNS, ...customPatterns]) {
        // A non-global regex would make exec() return the same match forever.
        const re = pattern.global ? pattern : new RegExp(pattern.source, pattern.flags + 'g');
        re.lastIndex = 0;
        let match;
        while ((match = re.exec(rest)) !== null) {
            if (match[0].length === 0) {
                re.lastIndex++;
                continue;
            }
            if (match[0].includes('****'))
                continue; // already redacted by privacy.ts
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
export function aggregateGates(results) {
    const actual = results.filter((r) => r !== null);
    if (actual.length === 0) {
        return null;
    }
    actual.sort((a, b) => DECISION_SEVERITY[b.decision] - DECISION_SEVERITY[a.decision]);
    return actual[0];
}
// ---------------------------------------------------------------------------
// Run all gates
// ---------------------------------------------------------------------------
/**
 * Runs diffSizeGate, secretDetectionGate and, when `allowedTools` and `toolName` are
 * given, toolAllowlistGate; returns the most restrictive decision (or null if
 * everything passes).
 *
 * @param content - Text content to evaluate.
 * @param config  - Optional gate configuration overrides.
 */
export function runAllGates(content, config) {
    const results = [
        diffSizeGate(content, config?.diffSizeThreshold),
        secretDetectionGate(content, config?.customSecretPatterns),
    ];
    if (config?.allowedTools && config.toolName) {
        results.push(toolAllowlistGate(config.toolName, config.allowedTools));
    }
    return aggregateGates(results);
}
//# sourceMappingURL=gates.js.map