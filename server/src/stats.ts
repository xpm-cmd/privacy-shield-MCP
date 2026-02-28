/**
 * stats.ts - Detection Statistics Tracking
 *
 * Tracks scan metrics with persistence:
 * - Total scans and detections by category
 * - Average latency per scan
 * - Exponential moving average for effectiveness
 * - Persists to ~/.privacy-shield/stats.json
 */

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { DetectionStats } from './types.js';

// ============================================================
// Constants
// ============================================================

const STATS_DIR = join(homedir(), '.privacy-shield');
const STATS_FILE = join(STATS_DIR, 'stats.json');
const EMA_ALPHA = 0.1; // Smoothing factor for exponential moving average
const SAVE_DEBOUNCE_MS = 5000; // Don't save more often than this

// ============================================================
// State
// ============================================================

let stats: DetectionStats = {
  totalScans: 0,
  totalDetections: 0,
  avgLatencyMs: 0,
  detectionsByCategory: {},
  lastUpdated: new Date().toISOString(),
};

let saveTimer: ReturnType<typeof setTimeout> | null = null;
let loaded = false;

// ============================================================
// Persistence
// ============================================================

function loadStats(): void {
  if (loaded) return;
  loaded = true;
  try {
    const raw = readFileSync(STATS_FILE, 'utf8');
    const parsed = JSON.parse(raw) as DetectionStats;
    // Validate shape
    if (typeof parsed.totalScans === 'number' && typeof parsed.totalDetections === 'number') {
      stats = parsed;
    }
  } catch {
    // No stats file yet — use defaults
  }
}

function saveStats(): void {
  try {
    mkdirSync(STATS_DIR, { recursive: true });
    stats.lastUpdated = new Date().toISOString();
    writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
  } catch {
    // Best effort — don't crash on save failure
  }
}

function debouncedSave(): void {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveStats();
    saveTimer = null;
  }, SAVE_DEBOUNCE_MS);
}

// ============================================================
// Public API
// ============================================================

/**
 * Record a scan with its result.
 * @param category - The scan type (e.g., 'privacy', 'network', 'injection')
 * @param detected - Whether something was detected
 * @param latencyMs - How long the scan took
 */
export function recordScan(
  category: string,
  detected: boolean,
  latencyMs: number,
): void {
  loadStats();

  stats.totalScans++;

  if (detected) {
    stats.totalDetections++;
    stats.detectionsByCategory[category] =
      (stats.detectionsByCategory[category] || 0) + 1;
  }

  // Update average latency using EMA
  if (stats.avgLatencyMs === 0) {
    stats.avgLatencyMs = latencyMs;
  } else {
    stats.avgLatencyMs = EMA_ALPHA * latencyMs + (1 - EMA_ALPHA) * stats.avgLatencyMs;
  }

  debouncedSave();
}

/**
 * Get current detection statistics.
 */
export function getStats(): DetectionStats {
  loadStats();
  return { ...stats };
}

/**
 * Get a human-readable summary of stats.
 */
export function getStatsSummary(): string {
  loadStats();

  if (stats.totalScans === 0) {
    return 'No scans recorded yet.';
  }

  const detectionRate = ((stats.totalDetections / stats.totalScans) * 100).toFixed(1);
  const topCategories = Object.entries(stats.detectionsByCategory)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([cat, count]) => `  ${cat}: ${count}`)
    .join('\n');

  return [
    `Total scans: ${stats.totalScans}`,
    `Total detections: ${stats.totalDetections} (${detectionRate}%)`,
    `Avg latency: ${stats.avgLatencyMs.toFixed(1)}ms`,
    topCategories ? `Top categories:\n${topCategories}` : '',
    `Last updated: ${stats.lastUpdated}`,
  ].filter(Boolean).join('\n');
}

/**
 * Reset all statistics.
 */
export function resetStats(): void {
  stats = {
    totalScans: 0,
    totalDetections: 0,
    avgLatencyMs: 0,
    detectionsByCategory: {},
    lastUpdated: new Date().toISOString(),
  };
  saveStats();
}

/**
 * Force save (useful on shutdown).
 */
export function flushStats(): void {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  saveStats();
}
