#!/usr/bin/env node
// Tests for hooks/hooks.json: every tool that can run commands or write files is
// covered, every referenced script exists, and hooks only emit fields that Claude
// Code honors for their event.
// Run: node scripts/test-hooks-config.js

const { spawnSync } = require('child_' + 'process');
const { join, resolve } = require('path');
const { readFileSync, existsSync } = require('fs');

const ROOT = resolve(__dirname, '..');
const config = JSON.parse(readFileSync(join(ROOT, 'hooks', 'hooks.json'), 'utf8'));

let passed = 0;
let failed = 0;

function ok(name, cond, detail) {
  if (cond) { passed++; console.log(`  PASS: ${name}`); }
  else { failed++; console.log(`  FAIL: ${name}${detail ? ' — ' + detail : ''}`); }
}

// Claude Code treats a matcher of letters, digits, _, -, space, comma and | as a list of
// exact tool names; anything else is an unanchored JavaScript regex.
function matcherMatches(matcher, tool) {
  if (!matcher || matcher === '*') return true;
  if (/^[A-Za-z0-9_\- ,|]+$/.test(matcher)) {
    return matcher.split(/[|,]/).map(s => s.trim()).includes(tool);
  }
  return new RegExp(matcher).test(tool);
}

function scriptsFor(event, tool) {
  return (config.hooks[event] || [])
    .filter(entry => matcherMatches(entry.matcher, tool))
    .flatMap(entry => entry.hooks.map(h => h.command));
}

function scriptPath(command) {
  const m = command.match(/\$\{CLAUDE_PLUGIN_ROOT\}\/(\S+)/);
  return m ? join(ROOT, m[1]) : null;
}

console.log('\nPrivacy Shield hooks.json tests\n');

console.log('PreToolUse coverage');
const expected = {
  Bash: 'hook-pre-bash.js',
  PowerShell: 'hook-pre-bash.js',
  Edit: 'hook-pre-file.js',
  Write: 'hook-pre-file.js',
  MultiEdit: 'hook-pre-file.js',
  NotebookEdit: 'hook-pre-file.js',
  WebFetch: 'hook-pre-web.js',
};
for (const [tool, script] of Object.entries(expected)) {
  const cmds = scriptsFor('PreToolUse', tool);
  ok(`${tool} runs ${script}`, cmds.some(c => c.includes(script)), `got [${cmds.join(', ')}]`);
}

console.log('\nReferenced scripts exist');
for (const [event, entries] of Object.entries(config.hooks)) {
  for (const entry of entries) {
    for (const h of entry.hooks) {
      const p = scriptPath(h.command);
      ok(`${event}/${entry.matcher || '*'}: ${h.command}`, p && existsSync(p), p);
    }
  }
}

console.log('\nPermissionRequest hooks only emit honored fields');
// PermissionRequest honors hookSpecificOutput.decision {behavior, message, updatedInput,
// updatedPermissions, interrupt}. additionalContext is ignored for this event.
const ALLOWED_PERMISSION_KEYS = new Set(['hookEventName', 'decision']);
const permissionHooks = (config.hooks.PermissionRequest || []).flatMap(e => e.hooks);
if (permissionHooks.length === 0) {
  ok('no PermissionRequest hooks registered', true);
}
for (const h of permissionHooks) {
  const p = scriptPath(h.command);
  const r = spawnSync('node', [p], {
    input: JSON.stringify({ hook_event_name: 'PermissionRequest', tool_name: 'Bash', tool_input: { command: 'rm -rf build' } }),
    encoding: 'utf8',
    timeout: 5000,
  });
  const out = r.stdout.trim();
  let keys = [];
  try { keys = out ? Object.keys(JSON.parse(out).hookSpecificOutput || {}) : []; } catch { keys = ['<invalid JSON>']; }
  const ignored = keys.filter(k => !ALLOWED_PERMISSION_KEYS.has(k));
  ok(`${h.command} emits only honored keys`, ignored.length === 0, `ignored keys: ${ignored.join(', ')}`);
}

console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
console.log(`${'='.repeat(40)}\n`);

process.exit(failed > 0 ? 1 : 0);
