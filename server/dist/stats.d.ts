/**
 * stats.ts - Detection Statistics Tracking
 *
 * Tracks scan metrics with persistence:
 * - Total scans and detections by category
 * - Average latency per scan
 * - Exponential moving average for effectiveness
 * - Persists to ~/.privacy-shield/stats.json
 */
import type { DetectionStats } from './types.js';
/**
 * Record a scan with its result.
 * @param category - The scan type (e.g., 'privacy', 'network', 'injection')
 * @param detected - Whether something was detected
 * @param latencyMs - How long the scan took
 */
export declare function recordScan(category: string, detected: boolean, latencyMs: number): void;
/**
 * Get current detection statistics.
 */
export declare function getStats(): DetectionStats;
/**
 * Get a human-readable summary of stats.
 */
export declare function getStatsSummary(): string;
/**
 * Reset all statistics.
 */
export declare function resetStats(): void;
/**
 * Force save (useful on shutdown).
 */
export declare function flushStats(): void;
