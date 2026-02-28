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
export declare function analyzePrivacy(text: string): PrivacyResult;
/**
 * Analiza un archivo específico por datos sensibles
 */
export declare function analyzeFilePath(filepath: string): FilePathResult;
export {};
