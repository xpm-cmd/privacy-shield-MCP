/**
 * exfiltration.ts - Módulo Anti-Exfiltración (Capa 4)
 *
 * Protege contra la salida no autorizada de datos:
 * - Monitoreo de datos en tránsito saliente
 * - Protección de archivos sensibles
 * - Detección de técnicas de exfiltración
 * - Audit log de conexiones externas
 */
import type { RiskLevel } from "./privacy.js";
export interface ExfiltrationFinding {
    technique: string;
    description: string;
    risk: RiskLevel;
    data_type: string;
    destination?: string;
}
export interface ExfiltrationResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: ExfiltrationFinding[];
    files_at_risk: Array<{
        path: string;
        reason: string;
    }>;
    summary: string;
    recommendations: string[];
}
export declare function analyzeExfiltration(text: string): ExfiltrationResult;
/**
 * Verifica si una operación de archivo es segura
 */
export declare function checkFileOperation(operation: "read" | "write" | "delete" | "send", filepath: string): {
    allowed: boolean;
    risk: RiskLevel;
    reason: string;
};
