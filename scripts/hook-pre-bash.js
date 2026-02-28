#!/usr/bin/env node
// Privacy Shield v2 - PreToolUse hook for Bash commands
// Exit 0 = allow, Exit 2 = block
//
// Features:
// - Destructive command blocking (original)
// - Configurable allowlist mode (~/.privacy-shield/config.json)
// - Supply chain warnings for install commands
// - Per-argument validation (null bytes, unquoted metacharacters)

const { readFileSync } = require('fs');
const { join, basename } = require('path');
const { homedir } = require('os');

const CONFIG_PATH = join(homedir(), '.privacy-shield', 'config.json');

// ─── Configuration ───

function loadConfig() {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

// Factory presets for allowlist mode
const PRESETS = {
  development: [
    // Cross-platform
    'git', 'npm', 'npx', 'yarn', 'pnpm', 'bun', 'node', 'tsc', 'tsx',
    'vitest', 'jest', 'eslint', 'prettier', 'python', 'python3',
    'pip', 'pip3', 'uv', 'cargo', 'rustc', 'go', 'make', 'cmake',
    'docker', 'docker-compose', 'curl', 'wget', 'ssh', 'scp',
    // Unix
    'ls', 'cat', 'head', 'tail', 'grep', 'rg', 'find', 'wc', 'sort',
    'uniq', 'diff', 'echo', 'printf', 'mkdir', 'cp', 'mv', 'touch',
    'pwd', 'which', 'env',
    // Windows equivalents
    'dir', 'type', 'more', 'findstr', 'where', 'copy', 'move', 'md',
    'set', 'cls', 'powershell', 'pwsh', 'code',
  ],
  'read-only': [
    // Unix
    'ls', 'cat', 'head', 'tail', 'grep', 'rg', 'find', 'wc', 'sort',
    'uniq', 'diff', 'echo', 'pwd', 'which', 'env', 'file', 'stat',
    'git log', 'git status', 'git diff', 'git branch', 'git show',
    // Windows equivalents
    'dir', 'type', 'more', 'findstr', 'where', 'set',
  ],
};

function getFirstCommand(command) {
  // Extract the first command from a pipeline or chain
  // "git status && npm test" -> "git"
  // "cat foo | grep bar" -> "cat"
  const cleaned = command.trim();
  const match = cleaned.match(/^(\S+)/);
  return match ? match[1] : '';
}

function checkAllowlist(command, config) {
  if (!config.allowlist_mode) return null; // Allowlist mode not enabled

  const preset = config.allowlist_preset || 'development';
  const allowedBase = PRESETS[preset] || PRESETS.development;
  const allowedExtra = config.allowlist_extra || [];
  const allowed = new Set([...allowedBase, ...allowedExtra]);

  const firstCmd = getFirstCommand(command);
  if (!firstCmd) return null;

  // Check if the base command is in the allowlist
  // Use path.basename for cross-platform: /usr/bin/git -> git, C:\Program Files\Git\bin\git.exe -> git.exe -> git
  let baseName = basename(firstCmd);
  // Strip .exe/.cmd/.bat suffix on Windows
  baseName = baseName.replace(/\.(exe|cmd|bat|ps1)$/i, '');
  if (allowed.has(baseName)) return null; // Allowed

  return `Comando "${baseName}" no esta en la allowlist (preset: ${preset}). Configura en ${CONFIG_PATH}`;
}

// ─── Supply chain warnings ───

function checkSupplyChain(command) {
  const warnings = [];

  // Detect install commands
  const isNpmInstall = /npm\s+(install|i|add)\s/i.test(command);
  const isYarnAdd = /yarn\s+(add|install)\s/i.test(command);
  const isPnpmAdd = /pnpm\s+(add|install)\s/i.test(command);
  const isBunAdd = /bun\s+(add|install)\s/i.test(command);
  const isPipInstall = /pip3?\s+install\s/i.test(command);
  const isGitClone = /git\s+clone\s/i.test(command);

  if (!isNpmInstall && !isYarnAdd && !isPnpmAdd && !isBunAdd && !isPipInstall && !isGitClone) {
    return null; // Not an install command
  }

  // Check for URL-based installs (higher risk)
  if (/\s(https?:\/\/|git\+|github:)\S+/.test(command)) {
    warnings.push('Instalando desde URL/GitHub directamente — no pasa por registry');
  }

  // Check for global installs
  if (/\s(-g|--global)\s/.test(command)) {
    warnings.push('Instalacion global detectada');
  }

  // Check for typosquatting candidates
  const popular = ['lodash', 'express', 'react', 'vue', 'webpack', 'typescript',
    'eslint', 'prettier', 'jest', 'axios', 'moment', 'chalk', 'next', 'nuxt'];
  const packageMatch = command.match(/(?:install|add|i)\s+([a-z0-9@._-]+)/i);
  if (packageMatch) {
    const pkgName = packageMatch[1].split('@')[0].toLowerCase();
    for (const pop of popular) {
      if (pkgName !== pop && levenshtein(pkgName, pop) === 1) {
        warnings.push(`"${pkgName}" se parece a "${pop}" (typosquatting?)`);
      }
    }
  }

  if (warnings.length === 0) return null;

  // Supply chain warnings are informational (stderr), not blocking
  return warnings.join(' | ');
}

// Simple Levenshtein for short strings
function levenshtein(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const m = [];
  for (let i = 0; i <= a.length; i++) {
    m[i] = [i];
    for (let j = 1; j <= b.length; j++) {
      m[i][j] = i === 0 ? j : Math.min(
        m[i-1][j] + 1, m[i][j-1] + 1,
        m[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1)
      );
    }
  }
  return m[a.length][b.length];
}

// ─── Argument validation ───

function checkArguments(command) {
  // Check for null bytes (used to bypass filters)
  if (command.includes('\x00') || command.includes('\\x00') || command.includes('\\0')) {
    return 'Null byte detectado en comando (posible bypass de filtros)';
  }

  // Check for excessive backtick nesting (command substitution abuse)
  const backtickCount = (command.match(/`/g) || []).length;
  if (backtickCount > 4) {
    return 'Excesivas sustituciones de comando anidadas';
  }

  return null;
}

// ─── Main ───

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  let command = '';
  try {
    const input = JSON.parse(data);
    command = (input.tool_input && input.tool_input.command) || '';
  } catch {
    process.exit(0); // fail-safe: allow on parse error
  }

  if (!command) process.exit(0);

  // Load config
  const config = loadConfig();

  // 1. Hard blocks (always enforced, regardless of allowlist)
  const rules = [
    // ── Critical: Destructive ──
    [/rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+[/~]/, 'Bloqueado rm -rf en directorio sistema/home'],
    [/rm\s+-rf?\s+\/(?!\w)/, 'Bloqueado rm -rf /'],
    [/:\s*\(\)\s*\{.*\|.*&\s*\}/, 'Bloqueado fork bomb'],
    [/\bmkfs\b/, 'Bloqueado formateo de disco'],
    [/\bdd\s+if=.*of=\/dev\//, 'Bloqueado escritura directa a dispositivo'],

    // ── Critical: Remote execution ──
    [/curl\s+.*\|\s*(bash|sh|zsh|python)/, 'Bloqueado pipe de descarga a shell'],
    [/wget\s+.*\|\s*(bash|sh|zsh|python)/, 'Bloqueado pipe de descarga a shell'],

    // ── Critical: Reverse shells ──
    [/bash\s+-i\s+>&?\s*\/dev\/tcp/, 'Bloqueado reverse shell'],
    [/nc\s+(-e|-c|--exec)\s/, 'Bloqueado netcat con ejecucion'],

    // ── Critical: Exfiltration ──
    [/cat\s+.*\.(env|pem|key|ssh).*\|\s*curl/, 'Bloqueado exfiltracion de archivos sensibles'],
    [/base64\s+.*\|\s*(curl|wget|nc)/, 'Bloqueado encoding+exfiltracion'],
    [/tar\s+.*\|\s*(curl|wget|nc)/, 'Bloqueado empaquetado+exfiltracion'],
    [/echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)/, 'Bloqueado decodificacion base64 a shell'],

    // ── High: Firewall disable ──
    [/iptables\s+.*-F/, 'Bloqueado flush de firewall'],
    [/\bufw\s+disable\b/, 'Bloqueado desactivacion de firewall'],

    // ── Windows: Destructive ──
    [/del\s+\/[fFsS].*[/\\][*.]/, 'Bloqueado eliminacion recursiva (Windows del /F /S)'],
    [/rd\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, 'Bloqueado eliminacion de directorio raiz (Windows)'],
    [/rmdir\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, 'Bloqueado eliminacion de directorio raiz (Windows)'],
    [/format\s+[A-Z]:\s*/i, 'Bloqueado formateo de disco (Windows)'],

    // ── Windows: Remote execution ──
    [/powershell\s+.*-[eE](?:nc(?:odedCommand)?)\s+/i, 'Bloqueado PowerShell con comando codificado'],
    [/Invoke-WebRequest\s+.*\|\s*(?:Invoke-Expression|iex)/i, 'Bloqueado descarga+ejecucion PowerShell (IWR|IEX)'],
    [/iwr\s+.*\|\s*iex/i, 'Bloqueado descarga+ejecucion PowerShell (alias)'],
    [/DownloadString\s*\(\s*['"]https?:/i, 'Bloqueado descarga de script remoto via WebClient'],

    // ── Windows: Reverse shell ──
    [/New-Object\s+System\.Net\.Sockets\.TCPClient/i, 'Bloqueado reverse shell PowerShell'],

    // ── Windows: Security bypass ──
    [/Set-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$true/i, 'Bloqueado desactivacion de Windows Defender'],
  ];

  for (const [regex, message] of rules) {
    if (regex.test(command)) {
      process.stderr.write(`PRIVACY-SHIELD: ${message}\n`);
      process.exit(2);
    }
  }

  // 2. Argument validation
  const argIssue = checkArguments(command);
  if (argIssue) {
    process.stderr.write(`PRIVACY-SHIELD: ${argIssue}\n`);
    process.exit(2);
  }

  // 3. Allowlist check (if enabled)
  const allowlistIssue = checkAllowlist(command, config);
  if (allowlistIssue) {
    process.stderr.write(`PRIVACY-SHIELD: ${allowlistIssue}\n`);
    process.exit(2);
  }

  // 4. Supply chain warnings (informational, not blocking)
  const supplyChainWarning = checkSupplyChain(command);
  if (supplyChainWarning) {
    process.stderr.write(`PRIVACY-SHIELD [supply-chain]: ${supplyChainWarning}\n`);
    // Note: we do NOT exit(2) here — just warn.
    // The install proceeds, but the user sees the warning.
  }

  process.exit(0);
});
