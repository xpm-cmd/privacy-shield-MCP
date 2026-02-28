/**
 * audit.ts - Módulo de Audit Log (Capa 5)
 *
 * Registro persistente de todas las operaciones analizadas:
 * - Log rotativo con límite configurable
 * - Formato JSON Lines (.jsonl) para fácil parsing
 * - Resumen de sesión con estadísticas
 * - Redacción automática de datos sensibles en logs
 * - Anonimización de rutas de usuario
 */
import { writeFile, readFile, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
// ============================================================
// Configuración
// ============================================================
const LOG_DIR = join(homedir(), ".privacy-shield");
const LOG_FILE = join(LOG_DIR, "audit.jsonl");
const MAX_LOG_SIZE_MB = 10;
const MAX_LOG_LINES = 10000;
// Sesión actual en memoria
let currentSessionId = `session_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
const sessionEntries = [];
// ============================================================
// Funciones internas
// ============================================================
async function ensureLogDir() {
    try {
        await mkdir(LOG_DIR, { recursive: true });
    }
    catch {
        // ya existe
    }
}
async function rotateIfNeeded() {
    try {
        const stats = await stat(LOG_FILE);
        if (stats.size > MAX_LOG_SIZE_MB * 1024 * 1024) {
            const content = await readFile(LOG_FILE, "utf-8");
            const lines = content.trim().split("\n");
            // Mantener solo las últimas MAX_LOG_LINES/2 líneas
            const kept = lines.slice(-Math.floor(MAX_LOG_LINES / 2));
            await writeFile(LOG_FILE, kept.join("\n") + "\n", "utf-8");
        }
    }
    catch {
        // archivo no existe aún
    }
}
// ============================================================
// Redacción y anonimización
// ============================================================
const SENSITIVE_KEYS = new Set([
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key',
    'apiKey', 'auth', 'authorization', 'credential', 'credentials',
    'private_key', 'privateKey', 'access_key', 'accessKey', 'session',
    'cookie', 'jwt', 'bearer', 'key',
]);
function isBase64(value) {
    return value.length > 20 && /^[A-Za-z0-9+/]+=*$/.test(value) && value.length % 4 === 0;
}
export function redactObject(obj) {
    if (obj === null || obj === undefined) {
        return obj;
    }
    if (typeof obj === 'string') {
        if (isBase64(obj)) {
            return '[BASE64_REDACTED]';
        }
        return obj;
    }
    if (typeof obj !== 'object') {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(item => redactObject(item));
    }
    const redacted = {};
    for (const [k, v] of Object.entries(obj)) {
        if (SENSITIVE_KEYS.has(k.toLowerCase())) {
            redacted[k] = '[REDACTED]';
        }
        else if (typeof v === 'string' && isBase64(v)) {
            redacted[k] = '[BASE64_REDACTED]';
        }
        else if (typeof v === 'object' && v !== null) {
            redacted[k] = redactObject(v);
        }
        else {
            redacted[k] = v;
        }
    }
    return redacted;
}
export function anonymizePath(text) {
    return text
        .replace(/\/Users\/[a-zA-Z0-9_-]+\//g, '[PATH]/')
        .replace(/\/home\/[a-zA-Z0-9_-]+\//g, '[PATH]/')
        .replace(/C:\\Users\\[^\\]+\\/gi, '[PATH]\\');
}
// ============================================================
// API pública
// ============================================================
export function setSessionId(id) {
    currentSessionId = id;
}
export function getSessionId() {
    return currentSessionId;
}
export async function logEntry(entry) {
    const fullEntry = {
        timestamp: new Date().toISOString(),
        session_id: currentSessionId,
        ...entry,
    };
    // Keep original in sessionEntries for session_summary
    sessionEntries.push(fullEntry);
    // Write sanitized version to file
    const sanitized = redactObject(fullEntry);
    try {
        await ensureLogDir();
        await rotateIfNeeded();
        await writeFile(LOG_FILE, JSON.stringify(sanitized) + "\n", { flag: "a" });
    }
    catch {
        // Fallo silencioso — el audit log no debe romper la funcionalidad principal
    }
}
export function getSessionSummary() {
    const byRisk = {};
    const byTool = {};
    let blockedCount = 0;
    const findings = [];
    for (const entry of sessionEntries) {
        const riskLevel = entry.risk_level;
        const toolName = entry.tool_name;
        const safe = entry.safe;
        const summary = entry.summary;
        if (riskLevel) {
            byRisk[riskLevel] = (byRisk[riskLevel] || 0) + 1;
        }
        if (toolName) {
            byTool[toolName] = (byTool[toolName] || 0) + 1;
        }
        if (!safe) {
            blockedCount++;
            if (findings.length < 10) {
                findings.push(summary);
            }
        }
    }
    return {
        session_id: currentSessionId,
        started_at: sessionEntries[0]?.timestamp || new Date().toISOString(),
        ended_at: sessionEntries[sessionEntries.length - 1]?.timestamp || new Date().toISOString(),
        total_scans: sessionEntries.length,
        by_risk: byRisk,
        by_tool: byTool,
        blocked_count: blockedCount,
        top_findings: findings,
    };
}
export async function getRecentLogs(count = 50) {
    try {
        await ensureLogDir();
        const content = await readFile(LOG_FILE, "utf-8");
        const lines = content.trim().split("\n").filter(Boolean);
        return lines.slice(-count).map((line) => JSON.parse(line));
    }
    catch {
        return [];
    }
}
export function getLogPath() {
    return LOG_FILE;
}
export function createLogger(prefix) {
    return {
        info: (message, data) => logEntry({ event: 'log', level: 'info', prefix, message: anonymizePath(message), data: data ? redactObject(data) : undefined }),
        warn: (message, data) => logEntry({ event: 'log', level: 'warn', prefix, message: anonymizePath(message), data: data ? redactObject(data) : undefined }),
        error: (message, data) => logEntry({ event: 'log', level: 'error', prefix, message: anonymizePath(message), data: data ? redactObject(data) : undefined }),
        child: (name) => createLogger(`${prefix}:${name}`),
    };
}
//# sourceMappingURL=audit.js.map