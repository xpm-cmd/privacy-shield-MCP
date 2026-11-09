#!/usr/bin/env node
// Tests for hook-pre-file.js
// Run: node scripts/test-hook-pre-file.js

const { spawnSync } = require('child_' + 'process');
const { join, resolve } = require('path');
const { mkdtempSync, rmSync } = require('fs');
const { tmpdir } = require('os');

const HOOK = join(__dirname, 'hook-pre-file.js');
const PLUGIN_ROOT = resolve(__dirname, '..');
// Throwaway home: warn-once state and "~" paths never touch the real profile.
const HOME = mkdtempSync(join(tmpdir(), 'ps-file-'));
const TEST_SESSION = 'test-session-' + Date.now();

let passed = 0;
let failed = 0;

function cleanState() {
  rmSync(HOME, { recursive: true, force: true });
}

// Returns 'block' (exit 2), 'ask' (exit 0 + permissionDecision ask) or 'allow'.
function runHook(input) {
  const r = spawnSync('node', [HOOK], {
    input: JSON.stringify(input),
    env: { ...process.env, HOME, USERPROFILE: HOME },
    encoding: 'utf8',
    timeout: 5000,
  });
  if (r.status === 2) return 'block';
  if (r.status !== 0) return `exit ${r.status}`;
  if (!r.stdout.trim()) return 'allow';
  try {
    const d = JSON.parse(r.stdout).hookSpecificOutput.permissionDecision;
    return d === 'deny' ? 'block' : d || 'allow';
  } catch {
    return 'bad-json';
  }
}

// expected: 0 (allow), 2 (block) or 'ask'
function test(name, input, expected) {
  const want = expected === 0 ? 'allow' : expected === 2 ? 'block' : expected;
  const actual = runHook(input);
  if (actual === want) {
    passed++;
    console.log(`  PASS: ${name} (${actual})`);
  } else {
    failed++;
    console.log(`  FAIL: ${name} — expected ${want}, got ${actual}`);
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

test('Retry of the same file+pattern asks the user instead of passing silently', {
  session_id: TEST_SESSION,
  tool_name: 'Write',
  tool_input: { file_path: '/src/utils.js', content: 'const r = eval("2+2");' }
}, 'ask');

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

test('innerHTML retry asks the user', {
  session_id: TEST_SESSION,
  tool_name: 'Edit',
  tool_input: { file_path: '/src/render.js', new_string: 'el.innerHTML = data;' }
}, 'ask');

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

const write = (file_path, content) => ({ session_id: TEST_SESSION, tool_name: 'Write', tool_input: { file_path, content } });

console.log('\nLayer 1: .env variants and relative paths');
test('Block .env.production.local', write('/app/.env.production.local', 'KEY=val'), 2);
test('Block relative .env', write('.env', 'KEY=val'), 2);
test('Block NTFS stream .env::$DATA', write('C:\\proj\\.env::$DATA', 'KEY=val'), 2);
test('Block trailing-dot .env.', write('C:\\proj\\.env.', 'KEY=val'), 2);
test('Block relative .npmrc', write('.npmrc', 'registry=x'), 2);
test('Allow .env.example template', write('/app/.env.example', 'DB_HOST='), 0);
test('Allow .env.local.sample template', write('/app/.env.local.sample', 'DB_HOST='), 0);

console.log('\nLayer 1: the shield protects its own controls');
test('Block the plugin hooks.json', write(join(PLUGIN_ROOT, 'hooks', 'hooks.json'), '{}'), 2);
test('Block a plugin hook script', write(join(PLUGIN_ROOT, 'scripts', 'hook-pre-bash.js'), 'process.exit(0)'), 2);
test('Block ~/.privacy-shield/config.json', write(join(HOME, '.privacy-shield', 'config.json'), '{"allowlist_mode":false}'), 2);
test('Block warn-once state tampering', write(join(HOME, '.privacy-shield', 'content_warnings_x.json'), '[]'), 2);
test('Block settings that disable all hooks', write(join(HOME, '.claude', 'settings.json'), '{"disableAllHooks": true}'), 2);
test('Block settings that turn the plugin off', write('/proj/.claude/settings.json', '{"enabledPlugins": {"privacy-shield@market": false}}'), 2);
test('Ask before editing user settings.json', {
  session_id: TEST_SESSION,
  tool_name: 'Edit',
  tool_input: { file_path: join(HOME, '.claude', 'settings.json'), new_string: '"allow": ["Bash(npm test)"]' }
}, 'ask');
test('Ask before editing project settings.local.json', write('/proj/.claude/settings.local.json', '{}'), 'ask');
test('Ask before editing .bashrc', write(join(HOME, '.bashrc'), 'alias ll="ls -l"'), 'ask');
test('Ask before editing the PowerShell profile', write(join(HOME, 'Documents', 'PowerShell', 'Microsoft.PowerShell_profile.ps1'), 'Set-Alias ll Get-ChildItem'), 'ask');
test('Ask before writing a git hook', write('/proj/.git/hooks/pre-commit', '#!/bin/sh\nnpm test'), 'ask');
test('Ask before editing .git/config', write('/proj/.git/config', '[core]\n\tbare = false'), 'ask');
test('An unrelated project hooks.json is fine', write('/other/project/hooks/hooks.json', '{}'), 0);

console.log('\nLayer 2: hardcoded secrets judged per value');
const secretLine = 'const pass' + 'word = "' + 'Sup3r' + 'Secr3tValue!' + '";';
test('Secret still caught when "test" appears elsewhere in the file', write('/src/db.js', secretLine + '\n// covered by the test suite'), 2);

console.log('\nNotebookEdit');
test('Block a dangerous notebook cell the first time', {
  session_id: TEST_SESSION,
  tool_name: 'NotebookEdit',
  tool_input: { notebook_path: '/nb/analysis.ipynb', new_source: 'import os\nos.sys' + 'tem("ls")' }
}, 2);
test('Block a notebook written to a credential path', {
  session_id: TEST_SESSION,
  tool_name: 'NotebookEdit',
  tool_input: { notebook_path: '/home/u/.ssh/id_rsa', new_source: 'x' }
}, 2);

// Cleanup
cleanState();

// Summary
console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${'='.repeat(40)}\n`);

process.exit(failed > 0 ? 1 : 0);
