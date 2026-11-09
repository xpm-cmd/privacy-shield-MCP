#!/usr/bin/env node
// Tests for hook-pre-web.js
// Run: node scripts/test-hook-pre-web.js

const { execFileSync } = require('child_process');
const { join } = require('path');

const HOOK = join(__dirname, 'hook-pre-web.js');

let passed = 0;
let failed = 0;

function runHook(stdin) {
  try {
    execFileSync('node', [HOOK], { input: stdin, stdio: ['pipe', 'pipe', 'pipe'], timeout: 5000 });
    return 0;
  } catch (e) {
    return e.status;
  }
}

function test(name, url, expectedExit) {
  const actual = runHook(JSON.stringify({ tool_name: 'WebFetch', tool_input: { url, prompt: 'x' } }));
  if (actual === expectedExit) {
    passed++;
    console.log(`  PASS: ${name} (exit ${actual})`);
  } else {
    failed++;
    console.log(`  FAIL: ${name} — expected exit ${expectedExit}, got ${actual} (${url})`);
  }
}

console.log('\n=== Allowed ===');
test('Plain https site', 'https://example.com/docs', 0);
test('Subdomain of a normal site', 'https://docs.github.com/en', 0);
test('Domain that only starts like a shortener', 'https://t.co.example.com/', 0);

console.log('\n=== Shorteners (host taken from the WHATWG URL parser) ===');
test('Shortener', 'https://bit.ly/x', 2);
test('Shortener in upper case', 'HTTPS://BIT.LY/x', 2);
test('Shortener behind userinfo', 'https://user@bit.ly/x', 2);
test('Shortener behind a trusted-looking userinfo', 'https://github.com@bit.ly/', 2);
test('Shortener with trailing dot', 'https://bit.ly./x', 2);
test('Shortener without slashes after the scheme', 'https:bit.ly/x', 2);

console.log('\n=== High-risk TLDs (aligned with server/src/network.ts) ===');
test('Freenom TLD with trailing dot', 'https://evil.tk./', 2);
test('.xyz TLD', 'https://example.xyz/', 2);

console.log('\n=== Exfiltration services ===');
test('webhook.site', 'https://webhook.site/abc', 2);

console.log('\n=== Dangerous or unparseable URLs ===');
test('javascript: URL', 'javascript:alert(1)', 2);
test('data: URL', 'data:text/html,<p>x</p>', 2);
test('Unparseable URL', 'not a url', 2);

console.log('\n=== Malformed input stays fail-safe ===');
const malformed = runHook('{not json');
if (malformed === 0) { passed++; console.log('  PASS: Malformed stdin (exit 0)'); }
else { failed++; console.log(`  FAIL: Malformed stdin — expected exit 0, got ${malformed}`); }

console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${'='.repeat(40)}\n`);

process.exit(failed > 0 ? 1 : 0);
