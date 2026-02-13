#!/usr/bin/env node
// Tests for hook-pre-file.js
// Run: node scripts/test-hook-pre-file.js

const { execFileSync } = require('child_process');
const { join } = require('path');
const { unlinkSync, readdirSync, mkdirSync } = require('fs');
const { homedir } = require('os');

const HOOK = join(__dirname, 'hook-pre-file.js');
const STATE_DIR = join(homedir(), '.privacy-shield');
const TEST_SESSION = 'test-session-' + Date.now();

let passed = 0;
let failed = 0;

function cleanState() {
  try {
    for (const f of readdirSync(STATE_DIR)) {
      if (f.includes(TEST_SESSION)) {
        unlinkSync(join(STATE_DIR, f));
      }
    }
  } catch { /* ok */ }
}

function runHook(input) {
  try {
    execFileSync('node', [HOOK], {
      input: JSON.stringify(input),
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000,
    });
    return 0;
  } catch (e) {
    return e.status;
  }
}

function test(name, input, expectedExit) {
  const actual = runHook(input);
  if (actual === expectedExit) {
    passed++;
    console.log(`  PASS: ${name} (exit ${actual})`);
  } else {
    failed++;
    console.log(`  FAIL: ${name} — expected exit ${expectedExit}, got ${actual}`);
  }
}

// ─── Tests ───

console.log('\nPrivacy Shield hook-pre-file.js tests\n');

// Ensure clean state
cleanState();

// Layer 1: Path blocks (always block, no state)
console.log('Layer 1: Path-based blocks');

test('Block .env file', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/app/.env', content: 'DB_HOST=localhost' }
}, 2);

test('Block .env.production', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/app/.env.production', content: 'KEY=val' }
}, 2);

test('Block SSH key', {
  session_id: TEST_SESSION,
  tool_name: 'Edit',
  tool_input: { file_path: '/home/user/.ssh/id_rsa', new_string: 'key data' }
}, 2);

test('Block .env on second attempt (always blocks)', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/app/.env', content: 'DB_HOST=localhost' }
}, 2);

test('Block PEM certificate', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/certs/server.pem', content: 'cert data' }
}, 2);

// Layer 2: Content patterns (block once, allow on retry)
console.log('\nLayer 2: Content patterns (block once, then allow)');

test('Block dangerous content first time', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/utils.js', content: 'const r = eval("1+1");' }
}, 2);

test('Allow same file+pattern on second attempt', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/utils.js', content: 'const r = eval("2+2");' }
}, 0);

test('Block same pattern in DIFFERENT file', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/other.js', content: 'eval("code");' }
}, 2);

test('Block innerHTML assignment first time', {
  session_id: TEST_SESSION,
  tool_name: 'Edit',
  tool_input: { file_path: '/src/render.js', new_string: 'el.innerHTML = data;' }
}, 2);

test('Allow innerHTML on retry', {
  session_id: TEST_SESSION,
  tool_name: 'Edit',
  tool_input: { file_path: '/src/render.js', new_string: 'el.innerHTML = data;' }
}, 0);

// MultiEdit
test('Block MultiEdit with dangerous pattern', {
  session_id: TEST_SESSION,
  tool_name: 'MultiEdit',
  tool_input: {
    file_path: '/src/app.py',
    edits: [{ new_string: 'import pickle\npickle.loads(data)' }]
  }
}, 2);

// Safe content
console.log('\nSafe operations');

test('Allow safe content', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/index.js', content: 'console.log("hello");' }
}, 0);

test('Allow Read tool (always passes)', {
  session_id: TEST_SESSION,
  tool_name: 'Read',
  tool_input: { file_path: '/app/.env' }
}, 0);

test('Allow empty content', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/empty.js', content: '' }
}, 0);

test('Allow no file_path', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { content: 'eval("bad")' }
}, 0);

// Edge cases
console.log('\nEdge cases');

test('Malformed JSON input (fail-safe allows)', {}, 0);

test('Windows path normalization', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: 'C:\\Users\\test\\.env', content: 'KEY=val' }
}, 2);

test('Hardcoded secret detected', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/config.js', content: 'const password = "SuperSecret123!";' }
}, 2);

test('Hardcoded secret with test/example excluded', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/config.js', content: 'const password = "test_placeholder_value";' }
}, 0);

// Cleanup
cleanState();

// Summary
console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${'='.repeat(40)}\n`);

process.exit(failed > 0 ? 1 : 0);
