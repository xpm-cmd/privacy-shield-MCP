#!/usr/bin/env node
// Privacy Shield v2 - PreToolUse hook for file operations (Edit, Write, MultiEdit)
// Exit 0 = allow, Exit 2 = block
// Layer 1 (sensitive paths): ALWAYS blocks the operation
// Layer 2 (code patterns):   Blocks FIRST time per file+rule, allows subsequent attempts
//                             (security-guidance "warn once" pattern)
// Layer 3 (diff size):       Warns on large writes (>300 lines) — first time only

const { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, statSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const STATE_DIR = join(homedir(), '.privacy-shield');
const CLEANUP_MAX_AGE_DAYS = 30;
const CLEANUP_PROBABILITY = 0.1; // 10% chance per run

// ─── State file helpers (Set-based, like security-guidance) ───

function getStateFilePath(sessionId) {
  return join(STATE_DIR, `content_warnings_${sessionId || 'default'}.json`);
}

function loadState(sessionId) {
  try {
    return new Set(JSON.parse(readFileSync(getStateFilePath(sessionId), 'utf8')));
  } catch {
    return new Set();
  }
}

function saveState(sessionId, state) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(getStateFilePath(sessionId), JSON.stringify([...state]));
  } catch { /* best effort */ }
}

function maybeCleanupOldStates() {
  if (Math.random() > CLEANUP_PROBABILITY) return;
  try {
    const now = Date.now();
    const maxAge = CLEANUP_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
    for (const f of readdirSync(STATE_DIR)) {
      if (!f.startsWith('content_warnings_')) continue;
      const fp = join(STATE_DIR, f);
      try {
        if (now - statSync(fp).mtimeMs > maxAge) unlinkSync(fp);
      } catch { /* skip */ }
    }
  } catch { /* best effort */ }
}

// ─── Main ───

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const toolName = input.tool_name || '';
    const toolInput = input.tool_input || {};
    const filePath = toolInput.file_path || '';
    const sessionId = input.session_id || 'default';

    if (!filePath) process.exit(0);

    // Read always allowed
    if (toolName !== 'Write' && toolName !== 'Edit' && toolName !== 'MultiEdit') process.exit(0);

    // ═══════════════════════════════════════════════
    // LAYER 1: Sensitive file path checks (ALWAYS BLOCK)
    // ═══════════════════════════════════════════════
    const norm = filePath.replace(/\\/g, '/').toLowerCase();

    const pathBlocks = [
      [/(\/\.env|\/\.env\.\w+)$/, '.env file'],
      [/\/id_(rsa|ed25519|ecdsa|dsa)$/, 'SSH key'],
      [/\/\.ssh\/(config|authorized_keys|known_hosts)$/, 'SSH config'],
      [/\.(pem|pfx|p12)$/, 'certificate/private key'],
      [/\/\.aws\/credentials$/, 'AWS credentials'],
      [/\/\.docker\/config\.json$/, 'Docker config'],
      [/\/\.kube\/config$/, 'Kube config'],
      [/\/\.netrc$/, '.netrc'],
      [/\/\.npmrc$/, '.npmrc'],
      [/\/\.pypirc$/, '.pypirc'],
      [/\/wallet\.dat$/, 'crypto wallet'],
      [/\/\.gnupg\/.*\.(key|gpg)$/, 'GPG key'],
      [/\/\.password-store\//, 'password store'],
      [/\/\.config\/gh\/hosts\.yml$/, 'GitHub CLI tokens'],
    ];

    for (const [regex, desc] of pathBlocks) {
      if (regex.test(norm)) {
        process.stderr.write(`PRIVACY-SHIELD: Blocked write to ${desc}: ${filePath}\n`);
        process.exit(2);
      }
    }

    // ═══════════════════════════════════════════════
    // LAYER 2: Dangerous code patterns in content
    // Block FIRST time per file+rule, allow on retry
    // ═══════════════════════════════════════════════
    let content = '';
    if (toolName === 'Write') {
      content = toolInput.content || '';
    } else if (toolName === 'Edit') {
      content = toolInput.new_string || '';
    } else if (toolName === 'MultiEdit') {
      const edits = toolInput.edits || [];
      content = edits.map(e => e.new_string || '').join(' ');
    }

    if (!content) process.exit(0);

    // Normalize path for warningKey (keep full path, just fix slashes)
    const normPath = filePath.replace(/\\/g, '/');

    const contentPatterns = [
      // GitHub Actions injection (only for workflow files)
      { id: 'gha-injection',
        test: () => /\.github\/workflows\/.*\.ya?ml$/.test(normPath) &&
          /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits|pages)/.test(content),
        msg: 'GitHub Actions workflow injection: unsafe ${{ github.event.* }} interpolation in run:. Use env: variables instead.' },

      // Command injection
      { id: 'cmd-injection',
        test: () => content.includes('child_process.exec') || content.includes('execSync('),
        msg: 'Command injection risk: child_process.exec/execSync detected. Use execFile() or spawn() with separate arguments.' },

      // Code injection
      { id: 'new-function',
        test: () => content.includes('new Function(') || content.includes('new Function ('),
        msg: 'Code injection risk: new Function() can run arbitrary code. Consider safer alternatives.' },
      { id: 'eval',
        test: () => /\beval\s*\(/.test(content),
        msg: 'Code injection risk: eval() can run arbitrary code. Use JSON.parse() for data or safer alternatives.' },

      // XSS
      { id: 'dangerously-set-innerhtml',
        test: () => content.includes('dangerouslySetInnerHTML'),
        msg: 'XSS risk: dangerouslySetInnerHTML detected. Sanitize with DOMPurify or use safer alternatives.' },
      { id: 'document-write',
        test: () => content.includes('document.write'),
        msg: 'XSS risk: document.write() detected. Use DOM methods like createElement/appendChild.' },
      { id: 'innerhtml-assign',
        test: () => /\.innerHTML\s*=/.test(content),
        msg: 'XSS risk: innerHTML assignment detected. Use textContent for plain text or sanitize with DOMPurify.' },

      // Unsafe deserialization
      { id: 'pickle',
        test: () => /\bpickle\.(loads?|dumps?)\b/.test(content) || content.includes('import pickle'),
        msg: 'Unsafe deserialization: pickle can run arbitrary code. Use JSON or another safe format.' },

      // Shell injection (Python)
      { id: 'os-system',
        test: () => content.includes('os.system(') || content.includes('from os import system'),
        msg: 'Shell injection risk: os.system() detected. Use subprocess.run() with list arguments.' },

      // Shell injection (Python subprocess with shell=True)
      { id: 'subprocess-shell',
        test: () => /subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/s.test(content),
        msg: 'Shell injection risk: subprocess with shell=True detected. Use shell=False with list arguments.' },

      // SQL injection
      { id: 'sql-fstring',
        test: () => /f["'].*SELECT\b.*\{/.test(content) || /f["'].*INSERT\b.*\{/.test(content) || /f["'].*UPDATE\b.*\{/.test(content) || /f["'].*DELETE\b.*\{/.test(content),
        msg: 'SQL injection risk: f-string with SQL query detected. Use parameterized queries (?) or an ORM.' },

      // Hardcoded secrets
      { id: 'hardcoded-secret',
        test: () => /(password|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i.test(content) && !/example|test|placeholder|changeme|xxx|dummy/i.test(content),
        msg: 'Possible hardcoded secret detected. Use environment variables or a secret manager.' },
    ];

    // ═══════════════════════════════════════════════
    // LAYER 3: Diff size gate (warn on large writes)
    // ═══════════════════════════════════════════════
    const DIFF_SIZE_THRESHOLD = 300;
    const lineCount = content.split('\n').length;
    if (lineCount > DIFF_SIZE_THRESHOLD) {
      const sizeKey = `${normPath}-diff-size-${lineCount > 1000 ? '1000+' : '300+'}`;
      const sizeState = loadState(sessionId);
      if (!sizeState.has(sizeKey)) {
        sizeState.add(sizeKey);
        saveState(sessionId, sizeState);
        process.stderr.write(`PRIVACY-SHIELD: Large write detected (${lineCount} lines to ${filePath}). Consider splitting into smaller edits.\n`);
        process.exit(2);
      }
    }

    // Find all matching patterns
    const matched = contentPatterns.filter(p => p.test());
    if (matched.length === 0) process.exit(0);

    // Load state and check for new (unseen) warnings
    const state = loadState(sessionId);
    const newWarnings = [];

    for (const pattern of matched) {
      const warningKey = `${normPath}-${pattern.id}`;
      if (!state.has(warningKey)) {
        state.add(warningKey);
        newWarnings.push(pattern.msg);
      }
    }

    if (newWarnings.length > 0) {
      // First time seeing these patterns for this file — block + warn
      saveState(sessionId, state);
      maybeCleanupOldStates();
      process.stderr.write(`PRIVACY-SHIELD: ${newWarnings.join(' | ')}\n`);
      process.exit(2);
    }

    // All matched patterns were already seen — allow silently
    maybeCleanupOldStates();
    process.exit(0);

  } catch {
    process.exit(0); // Allow on error
  }
});
