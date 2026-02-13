/**
 * audit.ts - Módulo de Audit Log (Capa 5)
 *
 * Registro persistente de todas las operaciones analizadas:
 * - Log rotativo con límite configurable
 * - Formato JSON Lines (.jsonl) para fácil parsing
 * - Resumen de sesión con estadísticas
 */
export interface AuditEntry {
    timestamp: string;
    session_id: string;
    event: string;
    tool_name?: string;
    risk_level: string;
    safe: boolean;
    summary: string;
    details?: Record<string, unknown>;
}
export interface SessionSummary {
    session_id: string;
    started_at: string;
    ended_at: string;
    total_scans: number;
    by_risk: Record<string, number>;
    by_tool: Record<string, number>;
    blocked_count: number;
    top_findings: string[];
}
export declare function setSessionId(id: string): void;
export declare function getSessionId(): string;
export declare function logEntry(entry: Omit<AuditEntry, "timestamp" | "session_id">): Promise<void>;
export declare function getSessionSummary(): SessionSummary;
export declare function getRecentLogs(count?: number): Promise<AuditEntry[]>;
export declare function getLogPath(): string;
