/**
 * network.ts - Módulo de Seguridad de Red (Capa 2)
 *
 * Valida URLs, dominios, y conexiones externas:
 * - Detección de dominios maliciosos
 * - Bloqueo de acortadores de URL
 * - Verificación de patrones de phishing
 * - Detección de IPs directas sospechosas
 * - Lista blanca/negra configurable
 */
import type { RiskLevel } from "./privacy.js";
export interface UrlFinding {
    url: string;
    status: "safe" | "blocked" | "suspicious" | "warning";
    risk: RiskLevel;
    reasons: string[];
}
export interface NetworkResult {
    safe: boolean;
    risk_level: RiskLevel;
    urls_analyzed: UrlFinding[];
    domains_contacted: string[];
    summary: string;
    recommendations: string[];
}
export declare function analyzeNetwork(text: string): NetworkResult;
/**
 * Verifica si un dominio destino es seguro para enviar datos
 */
export declare function isDomainSafeForDataSending(domain: string): {
    safe: boolean;
    reason: string;
};
