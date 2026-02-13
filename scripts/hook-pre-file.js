#!/usr/bin/env node
// Privacy Shield - PreToolUse hook for file operations (Edit, Write, MultiEdit)
// Exit 0 = allow, Exit 2 = block
// Layer 1 (sensitive paths): ALWAYS blocks the operation
// Layer 2 (code patterns):   Blocks FIRST time per file+rule, allows subsequent attempts
//                             (security-guidance "warn once" pattern)

const { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, statSync } = require('fs');
const { join } = require('path');
const { homedir } = require('os');

const STATE_DIR = join(homedir(), '.privacy-shield');
const CLEANUP_MAX_AGE_DAYS = 30;
const CLEANUP_PROBABILITY = 0.1; // 10% chance per run

// ─── State file helpers ───

function getStateFilePath(sessionId) {
  return join(STATE_DIR, `content_warnings_${sessionId || 'default'}.json`);
}

function loadState(sessionId) {
  try {
    return JSON.parse(readFileSync(getStateFilePath(sessionId), 'utf8'));
  } catch {
    return {};
  }
}

function saveState(sessionId, state) {
  try {
    mkdirSync(STATE_DIR, { recursive: true });
    writeFileSync(getStateFilePath(sessionId), JSON.stringify(state));
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
      [/(\/\.env|\/\.env\.\w+)$/, 'archivo .env'],
      [/\/id_(rsa|ed25519|ecdsa|dsa)$/, 'clave SSH'],
      [/\/\.ssh\/(config|authorized_keys|known_hosts)$/, 'SSH config'],
      [/\.(pem|pfx|p12)$/, 'certificado/clave privada'],
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
        process.stderr.write(`PRIVACY-SHIELD: Bloqueado escritura en ${desc}: ${filePath}\n`);
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

    // Path-based content checks
    const normPath = filePath.replace(/\\/g, '/').replace(/^\/+/, '');

    const contentPatterns = [
      // GitHub Actions injection (only for workflow files)
      { id: 'gha-injection',
        test: () => /\.github\/workflows\/.*\.ya?ml$/.test(normPath) &&
          /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits|pages)/.test(content),
        msg: 'GitHub Actions workflow injection: uso inseguro de interpolacion ${{ github.event.* }} en run:. Usa variables env: en su lugar.' },

      // Command injection
      { id: 'cmd-injection',
        test: () => content.includes('child_process.exec') || content.includes('execSync('),
        msg: 'Command injection risk: child_process.exec/execSync. Usa execFile() o spawn() con argumentos separados.' },

      // Code injection
      { id: 'new-function',
        test: () => content.includes('new Function(') || content.includes('new Function ('),
        msg: 'Code injection risk: new Function() ejecuta codigo arbitrario. Considera alternativas seguras.' },
      { id: 'eval',
        test: () => /\beval\s*\(/.test(content),
        msg: 'Code injection risk: eval() ejecuta codigo arbitrario. Usa JSON.parse() para datos o alternativas seguras.' },

      // XSS
      { id: 'dangerously-set-innerhtml',
        test: () => content.includes('dangerouslySetInnerHTML'),
        msg: 'XSS risk: dangerouslySetInnerHTML. Sanitiza con DOMPurify o usa alternativas seguras.' },
      { id: 'document-write',
        test: () => content.includes('document.write'),
        msg: 'XSS risk: document.write(). Usa metodos DOM como createElement/appendChild.' },
      { id: 'innerhtml-assign',
        test: () => /\.innerHTML\s*=/.test(content),
        msg: 'XSS risk: innerHTML assignment. Usa textContent para texto plano o sanitiza con DOMPurify.' },

      // Unsafe deserialization
      { id: 'pickle',
        test: () => /\bpickle\.(loads?|dumps?)\b/.test(content) || content.includes('import pickle'),
        msg: 'Deserializacion insegura: pickle puede ejecutar codigo arbitrario. Usa JSON u otro formato seguro.' },

      // Shell injection (Python)
      { id: 'os-system',
        test: () => content.includes('os.system(') || content.includes('from os import system'),
        msg: 'Shell injection risk: os.system(). Usa subprocess.run() con argumentos como lista.' },

      // Shell injection (Python subprocess with shell=True)
      { id: 'subprocess-shell',
        test: () => /subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/s.test(content),
        msg: 'Shell injection risk: subprocess con shell=True. Usa shell=False con argumentos como lista.' },

      // SQL injection
      { id: 'sql-fstring',
        test: () => /f["'].*SELECT\b.*\{/.test(content) || /f["'].*INSERT\b.*\{/.test(content) || /f["'].*UPDATE\b.*\{/.test(content) || /f["'].*DELETE\b.*\{/.test(content),
        msg: 'SQL injection risk: f-string con query SQL. Usa parametros (?) o un ORM.' },

      // Hardcoded secrets
      { id: 'hardcoded-secret',
        test: () => /(password|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i.test(content) && !/example|test|placeholder|changeme|xxx|dummy/i.test(content),
        msg: 'Posible secreto hardcodeado detectado. Usa variables de entorno o un gestor de secretos.' },
    ];

    // Find all matching patterns
    const matched = contentPatterns.filter(p => p.test());
    if (matched.length === 0) process.exit(0);

    // Load state and check for new (unseen) warnings
    const state = loadState(sessionId);
    const newWarnings = [];

    for (const pattern of matched) {
      const warningKey = `${normPath}-${pattern.id}`;
      if (!state[warningKey]) {
        state[warningKey] = Date.now();
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
