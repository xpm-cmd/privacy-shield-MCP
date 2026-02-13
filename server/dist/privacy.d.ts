/**
 * privacy.ts - Módulo de Protección de Privacidad (Capa 1)
 *
 * Detecta y protege datos personales sensibles:
 * - PII (Personally Identifiable Information)
 * - Secretos y credenciales
 * - Datos financieros
 * - Información de salud
 */
export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";
export interface Finding {
    type: string;
    description: string;
    risk: RiskLevel;
    match: string;
    location: string;
    redacted: string;
}
export interface PrivacyResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: Finding[];
    redacted_text: string;
    summary: string;
}
export declare function analyzePrivacy(text: string): PrivacyResult;
/**
 * Analiza un archivo específico por datos sensibles
 */
export declare function analyzeFilePath(filepath: string): {
    is_sensitive: boolean;
    reason: string;
};
