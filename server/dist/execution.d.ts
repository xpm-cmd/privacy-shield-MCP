/**
 * execution.ts - Módulo de Seguridad de Ejecución (Capa 3)
 *
 * Analiza comandos y código antes de ejecución:
 * - Comandos bash destructivos
 * - Prompt injection en archivos
 * - Código con patrones maliciosos
 * - Dependencias vulnerables
 */
import type { RiskLevel } from "./privacy.js";
export interface ExecutionFinding {
    category: "bash" | "prompt_injection" | "code" | "dependency";
    description: string;
    risk: RiskLevel;
    detail: string;
}
export interface ExecutionResult {
    safe: boolean;
    risk_level: RiskLevel;
    findings: ExecutionFinding[];
    summary: string;
    recommendations: string[];
}
export declare function analyzeBash(command: string): ExecutionResult;
export declare function analyzePromptInjection(text: string): ExecutionResult;
export declare function analyzeCode(code: string, filePath?: string): ExecutionResult;
