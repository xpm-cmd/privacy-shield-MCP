/**
 * Tests for audit.ts — Layer 5: audit log redaction and reading
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// Point the audit log at a throwaway home directory.
vi.mock('node:os', async (importOriginal) => {
  const os = await importOriginal<typeof import('node:os')>();
  const fs = await import('node:fs');
  const path = await import('node:path');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-audit-'));
  return { ...os, default: { ...os, homedir: () => home }, homedir: () => home };
});

const { redactObject, logEntry, getRecentLogs, getLogPath } = await import('../audit.js');

// Secret-shaped fixture built from parts so repo scanners don't flag this file.
const GH_TOKEN = 'gh' + 'p_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

describe('redactObject — sensitive keys', () => {
  it.each(['privateKey', 'accessKey', 'apiKey', 'clientSecret', 'db_password', 'githubToken', 'Authorization'])(
    'redacts the value of %s',
    (key) => {
      const out = redactObject({ [key]: 'plain-value-123' }) as Record<string, unknown>;
      expect(out[key]).toBe('[REDACTED]');
    },
  );

  it('keeps ordinary fields', () => {
    const out = redactObject({ session_id: 's1', tool_name: 'scan', total_tokens: 3 }) as Record<string, unknown>;
    expect(out).toEqual({ session_id: 's1', tool_name: 'scan', total_tokens: 3 });
  });
});

describe('redactObject — secrets inside values', () => {
  it('redacts a token embedded in a logged command', () => {
    const out = redactObject({ details: { command: `curl -H "Authorization: Bearer ${GH_TOKEN}" https://api.github.com/user` } });
    expect(JSON.stringify(out)).not.toContain(GH_TOKEN);
  });
});

describe('logEntry', () => {
  it('never writes a secret from analyze_command details to disk', async () => {
    await logEntry({ event: 'analyze_command', summary: 'ok', details: { command: `echo ${GH_TOKEN}` } });
    expect(readFileSync(getLogPath(), 'utf-8')).not.toContain(GH_TOKEN);
  });
});

describe('getRecentLogs', () => {
  it('skips a corrupt line instead of returning nothing', async () => {
    mkdirSync(dirname(getLogPath()), { recursive: true });
    writeFileSync(getLogPath(), [
      JSON.stringify({ event: 'first' }),
      '{"event": "truncated',
      JSON.stringify({ event: 'second' }),
    ].join('\n') + '\n');
    const logs = await getRecentLogs(10);
    expect(logs.map(l => l.event)).toEqual(['first', 'second']);
  });
});
