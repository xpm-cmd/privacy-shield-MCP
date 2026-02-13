/**
 * audit.ts - Módulo de Audit Log (Capa 5)
 *
 * Registro persistente de todas las operaciones analizadas:
 * - Log rotativo con límite configurable
 * - Formato JSON Lines (.jsonl) para fácil parsing
 * - Resumen de sesión con estadísticas
 */
import { writeFile, readFile, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
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
    sessionEntries.push(fullEntry);
    try {
        await ensureLogDir();
        await rotateIfNeeded();
        await writeFile(LOG_FILE, JSON.stringify(fullEntry) + "\n", { flag: "a" });
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
        byRisk[entry.risk_level] = (byRisk[entry.risk_level] || 0) + 1;
        if (entry.tool_name) {
            byTool[entry.tool_name] = (byTool[entry.tool_name] || 0) + 1;
        }
        if (!entry.safe) {
            blockedCount++;
            if (findings.length < 10) {
                findings.push(entry.summary);
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
//# sourceMappingURL=audit.js.map