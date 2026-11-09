/**
 * Tests for network.ts — Layer 2: URL and domain validation
 */
import { describe, it, expect } from 'vitest';
import { analyzeNetwork, isDomainSafeForDataSending } from '../network.js';

function verdict(url: string) {
  const r = analyzeNetwork(url);
  return { status: r.urls_analyzed[0]?.status, reasons: r.urls_analyzed[0]?.reasons ?? [], risk: r.risk_level };
}

describe('typosquatting', () => {
  it.each([
    'https://www.google.com/search?q=x',
    'https://api.github.com/repos/a/b',
    'https://registry.npmjs.org/lodash',
    'https://www.npmjs.com/package/lodash',
    'https://raw.githubusercontent.com/a/b/main/README.md',
    'https://www.google.de/',
  ])('does not flag the real domain or its subdomains: %s', (url) => {
    const v = verdict(url);
    expect(v.reasons.some(r => r.includes('typosquatting'))).toBe(false);
    expect(v.status).not.toBe('blocked');
  });

  it.each([
    'https://g00gle.com/',
    'https://githuh.com/login',
    'https://github.com.evil.io/login',
    'https://npmj5.com/',
  ])('still flags look-alikes: %s', (url) => {
    const v = verdict(url);
    expect(v.status).toBe('blocked');
    expect(v.reasons.some(r => r.includes('typosquatting'))).toBe(true);
  });
});

describe('URL shorteners', () => {
  it('blocks a shortener behind www.', () => {
    expect(verdict('https://www.bit.ly/abc').status).toBe('blocked');
  });

  it('does not treat www.bit.ly as safe for data sending', () => {
    expect(isDomainSafeForDataSending('www.bit.ly').safe).toBe(false);
  });
});

describe('URL parts are checked in the right place', () => {
  it('does not call a .com host an executable download', () => {
    const v = verdict('https://example.com');
    expect(v.reasons.some(r => r.includes('ejecutable'))).toBe(false);
    expect(v.status).toBe('safe');
  });

  it('still flags an executable in the path', () => {
    expect(verdict('https://example.com/setup.exe').reasons.some(r => r.includes('ejecutable'))).toBe(true);
  });

  it('does not call a .sh host a shell script', () => {
    expect(verdict('https://bun.sh/docs').reasons.some(r => r.includes('script shell'))).toBe(false);
  });

  it('does not read an @ in the path as embedded credentials', () => {
    expect(verdict('https://medium.com/@someone/post').reasons.some(r => r.includes('credenciales'))).toBe(false);
  });

  it('flags userinfo in the authority', () => {
    expect(verdict('https://user:pw@example.com/').reasons.some(r => r.includes('credenciales'))).toBe(true);
  });
});
