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
import type { RiskLevel } from './types.js';
interface UrlAnalysis {
    url: string;
    status: string;
    risk: RiskLevel;
    reasons: string[];
}
interface NetworkResult {
    safe: boolean;
    risk_level: RiskLevel;
    urls_analyzed: UrlAnalysis[];
    domains_contacted: string[];
    summary: string;
    recommendations: string[];
}
interface DomainSafetyResult {
    safe: boolean;
    reason: string;
}
export declare function analyzeNetwork(text: string): NetworkResult;
/**
 * Verifica si un dominio destino es seguro para enviar datos
 */
export declare function isDomainSafeForDataSending(domain: string): DomainSafetyResult;
export {};
