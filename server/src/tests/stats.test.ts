/**
 * Tests for stats.ts — detection statistics persistence
 */
import { describe, it, expect, vi, afterAll } from 'vitest';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

// Point stats.json at a throwaway home directory.
const { home } = vi.hoisted(() => ({ home: { dir: '' } }));
vi.mock('os', async (importOriginal) => {
  const os = await importOriginal<typeof import('os')>();
  const fs = await import('node:fs');
  const path = await import('node:path');
  home.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-stats-'));
  return { ...os, default: { ...os, homedir: () => home.dir }, homedir: () => home.dir };
});

const { recordScan, getStats, flushStats } = await import('../stats.js');

afterAll(() => flushStats());

describe('loading a stats.json with a missing field', () => {
  it('records scans instead of throwing', () => {
    mkdirSync(join(home.dir, '.privacy-shield'), { recursive: true });
    // Written by an older version or by hand: no detectionsByCategory.
    writeFileSync(join(home.dir, '.privacy-shield', 'stats.json'), JSON.stringify({ totalScans: 3, totalDetections: 1, avgLatencyMs: 2 }));

    expect(() => recordScan('privacy', true, 5)).not.toThrow();
    const stats = getStats();
    expect(stats.totalScans).toBe(4);
    expect(stats.totalDetections).toBe(2);
    expect(stats.detectionsByCategory.privacy).toBe(1);
  });
});
