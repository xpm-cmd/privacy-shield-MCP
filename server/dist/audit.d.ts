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
export declare function redactObject(obj: unknown): unknown;
export declare function anonymizePath(text: string): string;
export declare function setSessionId(id: string): void;
export declare function getSessionId(): string;
export declare function logEntry(entry: Record<string, unknown>): Promise<void>;
export declare function getSessionSummary(): Record<string, unknown>;
export declare function getRecentLogs(count?: number): Promise<Record<string, unknown>[]>;
export declare function getLogPath(): string;
interface Logger {
    info: (message: string, data?: unknown) => Promise<void>;
    warn: (message: string, data?: unknown) => Promise<void>;
    error: (message: string, data?: unknown) => Promise<void>;
    child: (name: string) => Logger;
}
export declare function createLogger(prefix: string): Logger;
export {};
