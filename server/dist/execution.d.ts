/**
 * execution.ts - Modulo de Seguridad de Ejecucion (Capa 3) v2
 *
 * Analiza comandos y codigo antes de ejecucion:
 * - Comandos bash destructivos
 * - Prompt injection en archivos (con confidence scoring)
 * - Codigo con patrones maliciosos
 * - Dependencias vulnerables
 * - GitHub Actions workflow injection
 */
import type { AnalysisResult } from './types.js';
/**
 * Analyzes a bash command for destructive or malicious patterns.
 */
export declare function analyzeBash(command: string): AnalysisResult;
/**
 * Analyzes text for prompt injection patterns.
 * Enhanced v2: normalizes input, computes per-match confidence, deduplicates
 * by category (keeping highest confidence), and supports quick scan mode.
 */
export declare function analyzePromptInjection(text: string, options?: {
    quickScan?: boolean;
}): AnalysisResult;
/**
 * Fast pre-filter: checks only critical patterns and returns on first match.
 * Used for high-throughput scenarios where full analysis is too expensive.
 */
export declare function quickScanPromptInjection(text: string): {
    threat: boolean;
    confidence: number;
};
/**
 * Analyzes source code for malicious patterns, including GitHub Actions
 * workflow injection detection.
 */
export declare function analyzeCode(code: string, filePath?: string): AnalysisResult;
