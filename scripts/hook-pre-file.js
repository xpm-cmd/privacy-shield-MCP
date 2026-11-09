#!/usr/bin/env node
// Privacy Shield v2 - PreToolUse hook for file operations (Edit, Write, MultiEdit, NotebookEdit)
// Exit 2 = block (stderr goes to Claude). Exit 0 = allow, or ask the user when stdout
// carries a PreToolUse permissionDecision of "ask".
// Layer 1 (sensitive paths): credential files and the shield's own controls are blocked;
//                            Claude/shell/git config files need the user's approval
// Layer 2 (code patterns):   Blocks the FIRST time per file+rule so Claude can reconsider;
//                            a retry goes to the user instead of passing silently
// Layer 3 (diff size):       Warns on large writes (>300 lines) — first time only

const { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, statSync } = require('fs');
const { join, resolve } = require('path');
const { homedir } = require('os');
const { printBox, t } = require('./format-message.js');
const { isEnvFileName, normalizeForMatch, classifyControlPath, disablesShield } = require('./sensitive-paths.js');

const HOME = homedir();
const STATE_DIR = join(HOME, '.privacy-shield');
const PLUGIN_ROOT = resolve(__dirname, '..');
const CLEANUP_MAX_AGE_DAYS = 30;
const CLEANUP_PROBABILITY = 0.1; // 10% chance per run
const FILE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

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

// ─── Decisions ───

function block(title, reason, action) {
  printBox('block', title, reason, action);
  process.exit(2);
}

// The reason is shown to the user in the permission prompt; additionalContext tells Claude.
function ask(reasons) {
  const reason = `Privacy Shield: ${reasons.join(' | ')}`;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: reason,
      additionalContext: reason,
    },
  }));
  process.exit(0);
}

// Credential files: always blocked. Tested against normalizeForMatch() output.
const CREDENTIAL_PATHS = [
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

// A hardcoded value only counts when the value itself is not a placeholder.
const PLACEHOLDER_VALUE = /example|test|placeholder|changeme|xxx|dummy|your[_-]|<[^>]*>|\$\{/i;

function hasHardcodedSecret(content) {
  const re = /(password|secret|api_key|apikey|token)\s*=\s*["']([^"']{8,})["']/gi;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (!PLACEHOLDER_VALUE.test(m[2])) return true;
  }
  return false;
}

// ─── Main ───

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const toolName = input.tool_name || '';
    const toolInput = input.tool_input || {};
    const filePath = toolInput.file_path || toolInput.notebook_path || '';
    const sessionId = input.session_id || 'default';

    if (!filePath) process.exit(0);

    // Read always allowed
    if (!FILE_TOOLS.has(toolName)) process.exit(0);

    let content = '';
    if (toolName === 'Write') {
      content = toolInput.content || '';
    } else if (toolName === 'Edit') {
      content = toolInput.new_string || '';
    } else if (toolName === 'MultiEdit') {
      const edits = toolInput.edits || [];
      content = edits.map(e => e.new_string || '').join(' ');
    } else if (toolName === 'NotebookEdit') {
      content = toolInput.new_source || '';
    }

    // ═══════════════════════════════════════════════
    // LAYER 1: Sensitive file paths
    // ═══════════════════════════════════════════════
    const normForCheck = normalizeForMatch(filePath);
    const askReasons = [];

    const base = normForCheck.split('/').pop();
    const credential = isEnvFileName(base)
      ? '.env file'
      : (CREDENTIAL_PATHS.find(([re]) => re.test(normForCheck)) || [])[1];
    if (credential) {
      block(`${t('Escritura bloqueada', 'Write blocked')}: ${credential}`,
        t(`El archivo ${filePath} contiene credenciales o claves sensibles`, `File ${filePath} contains sensitive credentials or keys`),
        t('Mueve el archivo fuera de rutas protegidas o usa variables de entorno', 'Move the file out of protected paths or use environment variables'));
    }

    const control = classifyControlPath(filePath, HOME, PLUGIN_ROOT);
    if (control) {
      if (control.level === 'block' || (control.settings && disablesShield(content))) {
        block(`${t('Escritura bloqueada', 'Write blocked')}: ${control.desc}`,
          t(`${filePath} controla las protecciones de Privacy Shield`, `${filePath} controls Privacy Shield's protections`),
          t('Si el cambio es intencional, hazlo tú manualmente', 'If the change is intended, make it yourself outside Claude'));
      }
      askReasons.push(t(`escritura en ${control.desc}: ${filePath}`, `write to ${control.desc}: ${filePath}`));
    }

    if (!content) {
      if (askReasons.length) ask(askReasons);
      process.exit(0);
    }

    // ═══════════════════════════════════════════════
    // LAYER 2: Dangerous code patterns in content
    // Block FIRST time per file+rule, ask the user on retry
    // ═══════════════════════════════════════════════

    // Normalize path for warningKey (keep full path, just fix slashes)
    const normPath = filePath.replace(/\\/g, '/').replace(/^[A-Za-z]:/, '');

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

      // Hardcoded secrets (judged per value, so "test" elsewhere in the file doesn't hide one)
      { id: 'hardcoded-secret',
        test: () => hasHardcodedSecret(content),
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
        printBox('warn', `${t('Escritura grande detectada', 'Large write detected')}: ${lineCount} ${t('líneas en', 'lines in')} ${filePath}`,
          t('Cambios muy grandes son difíciles de revisar y pueden ocultar modificaciones no deseadas', 'Very large changes are hard to review and may hide unwanted modifications'),
          t('Divide en edits más pequeños. Reintenta para continuar de todos modos', 'Split into smaller edits. Retry to continue anyway'));
        process.exit(2);
      }
    }

    // Find all matching patterns
    const matched = contentPatterns.filter(p => p.test());
    if (matched.length === 0) {
      if (askReasons.length) ask(askReasons);
      process.exit(0);
    }

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
      // First time seeing these patterns for this file — block so Claude can reconsider
      saveState(sessionId, state);
      maybeCleanupOldStates();
      printBox('warn', newWarnings[0],
        newWarnings.length > 1
          ? `+${newWarnings.length - 1} ${t('patrón(es) adicional(es) detectados', 'additional pattern(s) detected')}`
          : t('Patrón de seguridad detectado en el contenido', 'Security pattern detected in content'),
        t('Revisa el código. Si es necesario, reintenta y el usuario decidirá', 'Review the code. If it is needed, retry and the user will decide'));
      process.exit(2);
    }

    // Claude already saw these warnings and retried: the user decides, not the retry.
    maybeCleanupOldStates();
    ask([...askReasons, ...matched.map(p => p.msg)]);

  } catch {
    process.exit(0); // Allow on error
  }
});
