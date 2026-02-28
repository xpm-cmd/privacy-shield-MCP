/**
 * exfiltration.ts - Módulo Anti-Exfiltración (Capa 4)
 *
 * Protege contra la salida no autorizada de datos:
 * - Monitoreo de datos en tránsito saliente
 * - Protección de archivos sensibles
 * - Detección de técnicas de exfiltración
 * - Audit log de conexiones externas
 */
import type { RiskLevel } from './types.js';
interface ExfilFinding {
    technique: string;
    description: string;
    risk: RiskLevel;
    data_type: string;
    destination?: string;
}
interface FileAtRisk {
    path: string;
    reason: string;
}
interface ExfiltrationResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: ExfilFinding[];
    files_at_risk: FileAtRisk[];
    summary: string;
    recommendations: string[];
}
interface FileOperationResult {
    allowed: boolean;
    risk: RiskLevel;
    reason: string;
}
export declare function analyzeExfiltration(text: string): ExfiltrationResult;
/**
 * Verifica si una operación de archivo es segura
 */
export declare function checkFileOperation(operation: string, filepath: string): FileOperationResult;
export {};
