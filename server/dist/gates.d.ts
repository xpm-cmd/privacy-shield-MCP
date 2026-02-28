/**
 * gates.ts - Enforcement gates system for Privacy Shield v2
 *
 * Modular gate system with aggregation. Each gate evaluates a specific
 * aspect of content/tool usage and returns a GateDecision or null (no issue).
 */
import type { GateDecision } from './types.js';
export interface GateConfig {
    diffSizeThreshold?: number;
    allowedTools?: string[];
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
 * Scans content for hard-coded secrets using built-in patterns.
 *
 * @param content - The text content to scan.
 * @returns A blocking GateDecision or null if no secrets detected.
 */
export declare function secretDetectionGate(content: string): GateDecision | null;
/**
 * Given an array of gate results (some may be null), returns the single
 * most restrictive decision, or null if every gate passed.
 */
export declare function aggregateGates(results: (GateDecision | null)[]): GateDecision | null;
/**
 * Convenience function that runs diffSizeGate and secretDetectionGate on the
 * provided content, aggregates the results, and returns the most restrictive
 * decision (or null if everything passes).
 *
 * @param content - Text content to evaluate.
 * @param config  - Optional gate configuration overrides.
 */
export declare function runAllGates(content: string, config?: GateConfig): GateDecision | null;
