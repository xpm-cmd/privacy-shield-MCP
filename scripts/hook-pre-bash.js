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
const { printBox, t } = require('./format-message.js');

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

  return t(
    `Comando "${baseName}" no esta en la allowlist (preset: ${preset}). Configura en ${CONFIG_PATH}`,
    `Command "${baseName}" is not in the allowlist (preset: ${preset}). Configure in ${CONFIG_PATH}`
  );
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
    warnings.push(t('Instalando desde URL/GitHub directamente — no pasa por registry', 'Installing directly from URL/GitHub — bypasses registry'));
  }

  // Check for global installs
  if (/\s(-g|--global)\s/.test(command)) {
    warnings.push(t('Instalacion global detectada', 'Global install detected'));
  }

  // Check for typosquatting candidates
  const popular = ['lodash', 'express', 'react', 'vue', 'webpack', 'typescript',
    'eslint', 'prettier', 'jest', 'axios', 'moment', 'chalk', 'next', 'nuxt'];
  const packageMatch = command.match(/(?:install|add|i)\s+([a-z0-9@._-]+)/i);
  if (packageMatch) {
    const pkgName = packageMatch[1].split('@')[0].toLowerCase();
    for (const pop of popular) {
      if (pkgName !== pop && levenshtein(pkgName, pop) === 1) {
        warnings.push(t(`"${pkgName}" se parece a "${pop}" (typosquatting?)`, `"${pkgName}" looks like "${pop}" (typosquatting?)`));
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
    [/rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+[/~]/, t('Bloqueado rm -rf en directorio sistema/home', 'Blocked rm -rf on system/home directory')],
    [/rm\s+-rf?\s+\/(?!\w)/, t('Bloqueado rm -rf /', 'Blocked rm -rf /')],
    [/:\s*\(\)\s*\{.*\|.*&\s*\}/, t('Bloqueado fork bomb', 'Blocked fork bomb')],
    [/\bmkfs\b/, t('Bloqueado formateo de disco', 'Blocked disk format')],
    [/\bdd\s+if=.*of=\/dev\//, t('Bloqueado escritura directa a dispositivo', 'Blocked direct device write')],

    // ── Critical: Remote execution ──
    [/curl\s+.*\|\s*(bash|sh|zsh|python)/, t('Bloqueado pipe de descarga a shell', 'Blocked download-to-shell pipe')],
    [/wget\s+.*\|\s*(bash|sh|zsh|python)/, t('Bloqueado pipe de descarga a shell', 'Blocked download-to-shell pipe')],

    // ── Critical: Reverse shells ──
    [/bash\s+-i\s+>&?\s*\/dev\/tcp/, t('Bloqueado reverse shell', 'Blocked reverse shell')],
    [/nc\s+(-e|-c|--exec)\s/, t('Bloqueado netcat con ejecucion', 'Blocked netcat with execution')],

    // ── Critical: Exfiltration ──
    [/cat\s+.*\.(env|pem|key|ssh).*\|\s*curl/, t('Bloqueado exfiltracion de archivos sensibles', 'Blocked sensitive file exfiltration')],
    [/base64\s+.*\|\s*(curl|wget|nc)/, t('Bloqueado encoding+exfiltracion', 'Blocked encoding+exfiltration')],
    [/tar\s+.*\|\s*(curl|wget|nc)/, t('Bloqueado empaquetado+exfiltracion', 'Blocked archive+exfiltration')],
    [/echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh)/, t('Bloqueado decodificacion base64 a shell', 'Blocked base64 decode to shell')],

    // ── High: Firewall disable ──
    [/iptables\s+.*-F/, t('Bloqueado flush de firewall', 'Blocked firewall flush')],
    [/\bufw\s+disable\b/, t('Bloqueado desactivacion de firewall', 'Blocked firewall disable')],

    // ── Windows: Destructive ──
    [/del\s+\/[fFsS].*[/\\][*.]/, t('Bloqueado eliminacion recursiva (Windows del /F /S)', 'Blocked recursive delete (Windows del /F /S)')],
    [/rd\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, t('Bloqueado eliminacion de directorio raiz (Windows)', 'Blocked root directory deletion (Windows)')],
    [/rmdir\s+\/[sS]\s+\/[qQ]\s+[A-Z]:\\/i, t('Bloqueado eliminacion de directorio raiz (Windows)', 'Blocked root directory deletion (Windows)')],
    [/format\s+[A-Z]:\s*/i, t('Bloqueado formateo de disco (Windows)', 'Blocked disk format (Windows)')],

    // ── Windows: Remote execution ──
    [/powershell\s+.*-[eE](?:nc(?:odedCommand)?)\s+/i, t('Bloqueado PowerShell con comando codificado', 'Blocked PowerShell with encoded command')],
    [/Invoke-WebRequest\s+.*\|\s*(?:Invoke-Expression|iex)/i, t('Bloqueado descarga+ejecucion PowerShell (IWR|IEX)', 'Blocked download+execute PowerShell (IWR|IEX)')],
    [/iwr\s+.*\|\s*iex/i, t('Bloqueado descarga+ejecucion PowerShell (alias)', 'Blocked download+execute PowerShell (alias)')],
    [/DownloadString\s*\(\s*['"]https?:/i, t('Bloqueado descarga de script remoto via WebClient', 'Blocked remote script download via WebClient')],

    // ── Windows: Reverse shell ──
    [/New-Object\s+System\.Net\.Sockets\.TCPClient/i, t('Bloqueado reverse shell PowerShell', 'Blocked PowerShell reverse shell')],

    // ── Windows: Security bypass ──
    [/Set-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$true/i, t('Bloqueado desactivacion de Windows Defender', 'Blocked Windows Defender disable')],
  ];

  for (const [regex, message] of rules) {
    if (regex.test(command)) {
      printBox('block', message,
        t('Patrón de seguridad crítico detectado en el comando',
          'Critical security pattern detected in the command'),
        t('Reformula el comando sin la parte peligrosa o usa alternativas seguras',
          'Reformulate the command without the dangerous part or use safe alternatives'));
      process.exit(2);
    }
  }

  // 2. Argument validation
  const argIssue = checkArguments(command);
  if (argIssue) {
    printBox('block', argIssue,
      t('Argumento del comando contiene caracteres peligrosos',
        'Command argument contains dangerous characters'),
      t('Usa comillas adecuadas y evita null bytes o anidamiento excesivo',
        'Use proper quoting and avoid null bytes or excessive nesting'));
    process.exit(2);
  }

  // 3. Allowlist check (if enabled)
  const allowlistIssue = checkAllowlist(command, config);
  if (allowlistIssue) {
    printBox('block', allowlistIssue,
      t('Modo allowlist activo — solo comandos en la lista están permitidos',
        'Allowlist mode active — only listed commands are permitted'),
      t('Agrega el comando a allowlist_extra en ~/.privacy-shield/config.json',
        'Add the command to allowlist_extra in ~/.privacy-shield/config.json'));
    process.exit(2);
  }

  // 4. Supply chain warnings (informational, not blocking)
  const supplyChainWarning = checkSupplyChain(command);
  if (supplyChainWarning) {
    printBox('warn', supplyChainWarning,
      t('Posible riesgo en cadena de suministro',
        'Possible supply chain risk'),
      t('Verifica el paquete en npmjs.com antes de instalar',
        'Check the package on npmjs.com before installing'));
    // Note: we do NOT exit(2) here — just warn.
  }

  process.exit(0);
});
