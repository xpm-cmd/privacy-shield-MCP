/**
 * gates.ts - Enforcement gates system for Privacy Shield v2
 *
 * Modular gate system with aggregation. Each gate evaluates a specific
 * aspect of content/tool usage and returns a GateDecision or null (no issue).
 */
import type { GateDecision } from './types.js';
export interface GateConfig {
    diffSizeThreshold?: number;
    /** Tools allowed to run; entries ending in `*` match by prefix. Needs `toolName`. */
    allowedTools?: string[];
    /** Tool being evaluated against `allowedTools`. */
    toolName?: string;
    customSecretPatterns?: Array<{
        pattern: RegExp;
        name: string;
    }>;
}
/**
 * Warns when a diff/content exceeds a line-count threshold.
 *
 * @param content  - The full text content to measure.
 * @param threshold - Maximum acceptable line count (default 300).
 * @returns A warning GateDecision or null if within threshold.
 */
export declare function diffSizeGate(content: string, threshold?: number): GateDecision | null;
/**
 * Blocks tool invocations that are not on the allowlist.
 * Supports wildcard matching: an entry ending with `*` matches any tool
 * whose name starts with the prefix before the `*`.
 *
 * @param toolName     - The tool being invoked.
 * @param allowedTools - List of allowed tool names / patterns.
 * @returns A blocking GateDecision or null if the tool is allowed.
 */
export declare function toolAllowlistGate(toolName: string, allowedTools: string[]): GateDecision | null;
/**
 * Scans content for hard-coded secrets: every secret rule of privacy.ts, the gate's own
 * patterns and any custom patterns.
 *
 * @param content - The text content to scan.
 * @param customPatterns - Extra patterns, e.g. internal token formats.
 * @returns A blocking GateDecision or null if no secrets detected.
 */
export declare function secretDetectionGate(content: string, customPatterns?: Array<{
    pattern: RegExp;
    name: string;
}>): GateDecision | null;
/**
 * Given an array of gate results (some may be null), returns the single
 * most restrictive decision, or null if every gate passed.
 */
export declare function aggregateGates(results: (GateDecision | null)[]): GateDecision | null;
/**
 * Runs diffSizeGate, secretDetectionGate and, when `allowedTools` and `toolName` are
 * given, toolAllowlistGate; returns the most restrictive decision (or null if
 * everything passes).
 *
 * @param content - Text content to evaluate.
 * @param config  - Optional gate configuration overrides.
 */
export declare function runAllGates(content: string, config?: GateConfig): GateDecision | null;
