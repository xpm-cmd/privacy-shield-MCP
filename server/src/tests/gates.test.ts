/**
 * Tests for gates.ts — Enforcement Gates
 */
import { describe, it, expect } from 'vitest';
import {
  diffSizeGate,
  toolAllowlistGate,
  secretDetectionGate,
  aggregateGates,
  runAllGates,
} from '../gates.js';

// ============================================================
// diffSizeGate
// ============================================================

describe('diffSizeGate', () => {
  it('returns null for small content', () => {
    const content = 'line1\nline2\nline3';
    const result = diffSizeGate(content);
    expect(result).toBeNull();
  });

  it('warns for content exceeding default threshold', () => {
    const lines = Array.from({ length: 400 }, (_, i) => `line ${i}`);
    const content = lines.join('\n');
    const result = diffSizeGate(content);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('warn');
    expect(result!.gate).toBe('diff-size');
  });

  it('respects custom threshold', () => {
    const content = Array.from({ length: 50 }, (_, i) => `line ${i}`).join('\n');
    const result = diffSizeGate(content, 30);
    expect(result).not.toBeNull();
  });

  it('returns require-confirmation for very large content', () => {
    const lines = Array.from({ length: 1500 }, (_, i) => `line ${i}`);
    const content = lines.join('\n');
    const result = diffSizeGate(content);
    expect(result).not.toBeNull();
    // Should be warn or require-confirmation for very large
    expect(['warn', 'require-confirmation']).toContain(result!.decision);
  });
});

// ============================================================
// toolAllowlistGate
// ============================================================

describe('toolAllowlistGate', () => {
  const allowedTools = ['Read', 'Grep', 'mcp__privacy-shield__*'];

  it('allows listed tools', () => {
    const result = toolAllowlistGate('Read', allowedTools);
    expect(result).toBeNull();
  });

  it('allows wildcard matches', () => {
    const result = toolAllowlistGate('mcp__privacy-shield__scan_privacy', allowedTools);
    expect(result).toBeNull();
  });

  it('blocks unlisted tools', () => {
    const result = toolAllowlistGate('Bash', allowedTools);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
  });

  it('blocks tools not matching wildcard', () => {
    const result = toolAllowlistGate('mcp__other-server__tool', allowedTools);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
  });
});

// ============================================================
// secretDetectionGate
// ============================================================

describe('secretDetectionGate', () => {
  it('detects API keys', () => {
    const content = 'const apiKey = "sk-1234567890abcdef1234567890abcdef"';
    const result = secretDetectionGate(content);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
  });

  it('detects AWS access keys', () => {
    const content = 'AKIAIOSFODNN7EXAMPLE';
    const result = secretDetectionGate(content);
    expect(result).not.toBeNull();
  });

  it('detects GitHub PAT (36 chars after prefix)', () => {
    // ghp_ pattern requires exactly 36 alphanumeric chars after prefix
    const content = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234';
    const result = secretDetectionGate(content);
    expect(result).not.toBeNull();
  });

  it('returns null for clean content', () => {
    const content = 'const greeting = "Hello, World!";\nfunction add(a, b) { return a + b; }';
    const result = secretDetectionGate(content);
    expect(result).toBeNull();
  });

  it('detects PEM private keys', () => {
    const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
    const result = secretDetectionGate(content);
    expect(result).not.toBeNull();
  });
});

// ============================================================
// aggregateGates
// ============================================================

describe('aggregateGates', () => {
  it('returns null for all-null results', () => {
    const result = aggregateGates([null, null, null]);
    expect(result).toBeNull();
  });

  it('returns most restrictive decision', () => {
    const warnDecision = {
      gate: 'diff-size',
      decision: 'warn' as const,
      risk: 'medium' as const,
      reason: 'Large diff',
      remediation: [],
    };
    const blockDecision = {
      gate: 'secrets',
      decision: 'block' as const,
      risk: 'critical' as const,
      reason: 'Secret found',
      remediation: ['Remove secret'],
    };
    const result = aggregateGates([warnDecision, blockDecision, null]);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
    expect(result!.gate).toBe('secrets');
  });

  it('handles single non-null result', () => {
    const decision = {
      gate: 'test',
      decision: 'allow' as const,
      risk: 'safe' as const,
      reason: 'OK',
      remediation: [],
    };
    const result = aggregateGates([null, decision, null]);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('allow');
  });
});

// ============================================================
// runAllGates
// ============================================================

describe('runAllGates', () => {
  it('returns null for clean small content', () => {
    const result = runAllGates('const x = 1;');
    expect(result).toBeNull();
  });

  it('detects secrets in content', () => {
    // Use a PEM key which is reliably detected
    const result = runAllGates('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----');
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
  });

  it('accepts custom diff threshold', () => {
    const smallContent = Array.from({ length: 20 }, (_, i) => `line ${i}`).join('\n');
    const result = runAllGates(smallContent, { diffSizeThreshold: 10 });
    expect(result).not.toBeNull();
    expect(result!.gate).toBe('diff-size');
  });
});

// ============================================================
// Secret formats the gate used to miss (shared with privacy.ts)
// ============================================================

describe('secretDetectionGate — modern key formats', () => {
  // Fixtures are built from parts so the repo's own secret scanners don't flag this file.
  const body = 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z' + 'Ab3dEf6hIj9kLm2nOp5qRs8t';
  it.each([
    ['Anthropic', 'sk-' + 'ant-' + 'api03-' + body],
    ['OpenAI project', 'sk-' + 'proj-' + body],
    ['GitHub fine-grained PAT', 'github' + '_pat_' + '11ABCDEFG0' + body],
    ['OpenSSH private key', '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----'],
  ])('detects %s', (_name, secret) => {
    const result = secretDetectionGate(`const value = "${secret}";`);
    expect(result).not.toBeNull();
    expect(result!.decision).toBe('block');
  });
});

describe('runAllGates — tool allowlist', () => {
  it('blocks a tool that is not in allowedTools', () => {
    const result = runAllGates('hello', { allowedTools: ['Read', 'mcp__privacy-shield__*'], toolName: 'Bash' });
    expect(result).not.toBeNull();
    expect(result!.gate).toBe('tool-allowlist');
    expect(result!.decision).toBe('block');
  });

  it('passes a tool that matches a wildcard entry', () => {
    const result = runAllGates('hello', { allowedTools: ['mcp__privacy-shield__*'], toolName: 'mcp__privacy-shield__scan_code' });
    expect(result).toBeNull();
  });

  it('applies custom secret patterns from the config', () => {
    const result = runAllGates('internal id ACME-0000-SECRET-1234', {
      customSecretPatterns: [{ pattern: /ACME-\d{4}-SECRET-\d{4}/g, name: 'ACME internal token' }],
    });
    expect(result).not.toBeNull();
    expect(result!.gate).toBe('secrets');
  });
});
