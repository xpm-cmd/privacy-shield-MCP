#!/usr/bin/env node
// Privacy Shield v2 - PreToolUse hook for the Bash and PowerShell tools
// Exit 2 = block (stderr goes to Claude). Exit 0 = allow, or ask the user when stdout
// carries a PreToolUse permissionDecision of "ask".
//
// Features:
// - Destructive / remote-execution / exfiltration blocking, independent of flag order,
//   case, wrappers (sudo, env, xargs …) and nesting (bash -c, pwsh -Command, $( ))
// - Configurable allowlist mode (~/.privacy-shield/config.json), checked for every
//   command in the line, not only the first word
// - Supply chain warnings, shown to the user in the permission prompt

const { readFileSync } = require('fs');
const { join, resolve } = require('path');
const { homedir } = require('os');
const { printBox, t } = require('./format-message.js');
const { parseShell, unwrap, subIds, commandsInSubs, allPipelines, plain } = require('./shell-parse.js');
const { findSensitivePath, classifyControlPath, disablesShield } = require('./sensitive-paths.js');

const HOME = homedir();
const CONFIG_PATH = join(HOME, '.privacy-shield', 'config.json');
const PLUGIN_ROOT = resolve(__dirname, '..');

// ─── Configuration ───

function loadConfig() {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

const PS_READ_ONLY = [
  'get-childitem', 'gci', 'get-content', 'gc', 'select-string', 'sls', 'get-location', 'gl',
  'test-path', 'get-item', 'gi', 'get-itemproperty', 'measure-object', 'select-object',
  'where-object', 'sort-object', 'group-object', 'foreach-object', 'format-table',
  'format-list', 'out-string', 'write-output', 'write-host', 'get-command', 'resolve-path',
  'split-path', 'join-path', 'get-date', 'convertfrom-json', 'convertto-json', 'get-filehash',
];

// Factory presets for allowlist mode. Two-word entries ("git log") allow one subcommand.
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
    'pwd', 'which', 'env', 'cd',
    // Windows equivalents
    'dir', 'type', 'more', 'findstr', 'where', 'copy', 'move', 'md',
    'set', 'cls', 'powershell', 'pwsh', 'code',
    // PowerShell
    ...PS_READ_ONLY,
    'set-location', 'sl', 'new-item', 'ni', 'copy-item', 'move-item', 'rename-item',
    'set-content', 'add-content', 'out-file', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm',
  ],
  'read-only': [
    // Unix
    'ls', 'cat', 'head', 'tail', 'grep', 'rg', 'find', 'wc', 'sort',
    'uniq', 'diff', 'echo', 'pwd', 'which', 'env', 'file', 'stat', 'cd',
    'git log', 'git status', 'git diff', 'git branch', 'git show',
    // Windows equivalents
    'dir', 'type', 'more', 'findstr', 'where', 'set',
    // PowerShell
    ...PS_READ_ONLY,
  ],
};

// ─── Command classes ───

const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'mksh', 'ash', 'fish', 'csh', 'tcsh',
  'pwsh', 'powershell', 'cmd', 'iex', 'invoke-expression', 'source', '.', 'eval']);
const INTERPRETERS = /^(?:python[\d.]*|py|perl|ruby|node|nodejs|php|lua|deno|bun)$/;
const DOWNLOADERS = new Set(['curl', 'wget', 'wget2', 'fetch', 'aria2c', 'http', 'https', 'xh',
  'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod']);
const NETWORK_SENDERS = new Set([...DOWNLOADERS, 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'scp',
  'sftp', 'rsync', 'ftp', 'ssh', 'gh', 'send-mailmessage']);
const PS_REMOVE = new Set(['remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir']);

/** Does this interpreter read its program from stdin (no -c/-e/-m and no script file)? */
function interpreterReadsStdin(args) {
  for (const a of args) {
    if (a === '-') return true;
    if (/^-(?:c|e|m|p|r|E)$|^--(?:eval|print|command)\b/.test(a)) return false;
    if (!a.startsWith('-')) return false; // script file argument
  }
  return true;
}

function executesStdin(cmd) {
  const { name, args } = unwrap(cmd.words);
  if (SHELLS.has(name)) return true;
  if (INTERPRETERS.test(name)) return interpreterReadsStdin(args);
  return false;
}

function involvesDownload(cmd, subs) {
  const all = [cmd, ...commandsInSubs(cmd.words.flatMap(subIds), subs)];
  return all.some(c => DOWNLOADERS.has(unwrap(c.words).name));
}

function referencesSensitiveFile(cmd, subs) {
  const all = [cmd, ...commandsInSubs(cmd.words.flatMap(subIds), subs)];
  for (const c of all) {
    for (const w of c.words.slice(1)) {
      const hit = findSensitivePath(plain(w));
      if (hit) return hit;
    }
    for (const r of c.redirects) {
      if (r.dir === '<') {
        const hit = findSensitivePath(plain(r.target));
        if (hit) return hit;
      }
    }
  }
  return null;
}

// ─── Root / home targets ───

function normTarget(t) {
  let s = plain(t).trim().replace(/\\/g, '/').toLowerCase();
  let prev;
  do { prev = s; s = s.replace(/(?:\/\*|\/\.|\*|\/)$/, ''); } while (s !== prev);
  return s;
}

const HOME_VARS = /^(?:~[\w.-]*|\$home|\$\{home\}|\$env:(?:userprofile|homepath|homedrive|systemdrive|systemroot|windir)|\$\{env:(?:userprofile|homepath|systemdrive|systemroot)\}|%(?:userprofile|homepath|homedrive|systemdrive|systemroot|windir)%)$/;
const SYSTEM_DIRS = /^(?:\/(?:home|users|root|etc|usr|bin|sbin|lib|lib64|var|boot|opt|system|library|applications|private|[a-z])|\/home\/[^/]+|\/users\/[^/]+|\/[a-z]\/users(?:\/[^/]+)?|[a-z]:|[a-z]:\/(?:windows|users|program files(?: \(x86\))?|programdata)|[a-z]:\/users\/[^/]+)$/;

function isRootOrHome(t) {
  const s = normTarget(t);
  return s === '' || HOME_VARS.test(s) || SYSTEM_DIRS.test(s);
}

function isAbsoluteOrHome(t) {
  const s = plain(t).trim();
  return s.startsWith('/') || s.startsWith('~') || /^\$\{?home\b/i.test(s) || isRootOrHome(s);
}

/** rm -r … on an absolute or home path (Bash), Remove-Item -Recurse on root/home (PowerShell). */
function recursiveDeleteTarget(name, args, shell) {
  if (shell === 'bash' && name === 'rm') {
    let recursive = false;
    const targets = [];
    let flagsDone = false;
    for (const a of args) {
      if (!flagsDone && a === '--') { flagsDone = true; continue; }
      if (!flagsDone && /^--/.test(a)) { if (a === '--recursive') recursive = true; continue; }
      if (!flagsDone && /^-[A-Za-z]+$/.test(a)) { if (/[rR]/.test(a)) recursive = true; continue; }
      targets.push(a);
    }
    return recursive ? targets.find(isAbsoluteOrHome) || null : null;
  }
  if (shell === 'powershell' && PS_REMOVE.has(name)) {
    let recursive = false;
    const targets = [];
    for (let k = 0; k < args.length; k++) {
      const a = args[k];
      const flag = a.toLowerCase();
      if (/^-r(?:e(?:c(?:u(?:r(?:se?)?)?)?)?)?(?::\$true)?$/.test(flag) || /^\/s$/.test(flag) || /^-[a-z]*r[a-z]*$/.test(flag) && flag.length <= 3) {
        recursive = true;
        continue;
      }
      if (/^-(?:path|literalpath|lp|pspath)$/.test(flag)) { if (args[k + 1]) targets.push(args[++k]); continue; }
      if (/^-(?:filter|include|exclude|credential|stream)$/.test(flag)) { k++; continue; }
      if (flag.startsWith('-') || /^\/[a-z]$/.test(flag)) continue;
      targets.push(...a.split(',').filter(Boolean));
    }
    return recursive ? targets.find(isRootOrHome) || null : null;
  }
  return null;
}

// ─── Writes to control files (settings, shell profiles, the shield itself) ───

const WRITE_ALL_ARGS = new Set(['tee', 'set-content', 'sc', 'add-content', 'ac', 'out-file', 'new-item', 'ni', 'touch', 'truncate']);
const WRITE_LAST_ARG = new Set(['cp', 'mv', 'install', 'ln', 'copy-item', 'copy', 'cpi', 'move-item', 'move', 'mi']);

function expandHome(word) {
  return plain(word).replace(/^(?:~|\$\{?home\}?|\$\{?env:userprofile\}?|%userprofile%)(?=$|[\\/])/i, () => HOME);
}

/** Files a command writes: output redirects, tee/Set-Content paths, cp/mv destination. */
function writeTargets(name, args, redirects) {
  const out = redirects.filter(r => r.dir === '>').map(r => r.target);
  if (WRITE_ALL_ARGS.has(name)) {
    for (let k = 0; k < args.length; k++) {
      const f = args[k].toLowerCase();
      if (/^-(?:path|filepath|literalpath|lp)$/.test(f)) { if (args[k + 1]) out.push(args[++k]); continue; }
      if (/^-(?:value|encoding|inputobject|itemtype|type|name|width)$/.test(f)) { k++; continue; }
      if (!f.startsWith('-')) out.push(args[k]);
    }
  } else if (WRITE_LAST_ARG.has(name)) {
    const dest = args.findIndex(a => /^-(?:destination|dest)$/i.test(a));
    const positional = args.filter(a => !a.startsWith('-'));
    if (dest !== -1 && args[dest + 1]) out.push(args[dest + 1]);
    else if (positional.length >= 2) out.push(positional[positional.length - 1]);
  }
  return out;
}

// ─── Structural analysis ───

const NESTED_SHELLS = { bash: 'bash', sh: 'bash', zsh: 'bash', dash: 'bash', ksh: 'bash', pwsh: 'powershell', powershell: 'powershell', cmd: 'bash' };

/** The script string a nested shell runs (bash -c '…', pwsh -Command …, cmd /c …). */
function nestedScript(name, args) {
  const shell = NESTED_SHELLS[name];
  if (!shell) return null;
  const idx = args.findIndex(a => {
    const f = a.toLowerCase();
    if (name === 'cmd') return f === '/c' || f === '/k';
    if (shell === 'powershell') return /^[-/]c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/.test(f);
    return /^-[a-z]*c[a-z]*$/.test(f);
  });
  if (idx === -1 || idx + 1 >= args.length) return null;
  const rest = shell === 'powershell' || name === 'cmd' ? args.slice(idx + 1).join(' ') : args[idx + 1];
  return { shell, script: rest };
}

function isEncodedFlag(a) {
  const f = a.toLowerCase().replace(/^[-/]+/, '');
  return f === 'ec' || (f.startsWith('e') && 'encodedcommand'.startsWith(f));
}

/**
 * Analyze a command line. Returns { block, asks, commands } where commands is the flat list
 * of { chain, name, args } that would run (used by the allowlist).
 */
function analyze(command, shell, depth = 0) {
  const parsed = parseShell(command, shell);
  const pipelines = allPipelines(parsed);
  const commands = [];
  const asks = [];
  let block = null;

  const flag = (msg) => { if (!block) block = msg; };

  for (const pipeline of pipelines) {
    // Download piped into something that executes its stdin
    const firstDownload = pipeline.findIndex(c => involvesDownload(c, parsed.subs));
    if (firstDownload !== -1 && pipeline.slice(firstDownload + 1).some(executesStdin)) {
      flag(t('Bloqueado pipe de descarga a shell', 'Blocked download-to-shell pipe'));
    }

    // Credential file feeding a later network stage
    for (let k = 0; k < pipeline.length - 1; k++) {
      const hit = referencesSensitiveFile(pipeline[k], parsed.subs);
      if (hit && pipeline.slice(k + 1).some(c => NETWORK_SENDERS.has(unwrap(c.words).name))) {
        flag(t(`Bloqueado envio de ${hit} por red`, `Blocked sending ${hit} over the network`));
      }
    }

    for (const cmd of pipeline) {
      const u = unwrap(cmd.words);
      commands.push(u);
      const { name, args } = u;

      for (const target of writeTargets(name, args, cmd.redirects)) {
        const control = classifyControlPath(expandHome(target), HOME, PLUGIN_ROOT);
        if (!control) continue;
        if (control.level === 'block' || (control.settings && disablesShield(command))) {
          flag(t(`Bloqueada escritura en ${control.desc}`, `Blocked write to ${control.desc}`));
        } else {
          asks.push(t(`escritura en ${control.desc}: ${plain(target)}`, `write to ${control.desc}: ${plain(target)}`));
        }
      }

      if (!name) continue;

      const target = recursiveDeleteTarget(name, args, shell);
      if (target) {
        flag(t(`Bloqueado borrado recursivo de ${target}`, `Blocked recursive delete of ${target}`));
      }

      // Downloaded code handed to a shell or interpreter: bash <(curl …), iex (irm …)
      if (SHELLS.has(name) || INTERPRETERS.test(name)) {
        const ids = args.flatMap(subIds);
        if (commandsInSubs(ids, parsed.subs).some(c => DOWNLOADERS.has(unwrap(c.words).name))) {
          flag(t('Bloqueado codigo descargado ejecutado por un shell', 'Blocked downloaded code passed to a shell'));
        }
      }

      if ((name === 'pwsh' || name === 'powershell') && args.some(isEncodedFlag)) {
        flag(t('Bloqueado PowerShell con comando codificado', 'Blocked PowerShell with encoded command'));
      }

      if (NETWORK_SENDERS.has(name)) {
        const hit = referencesSensitiveFile(cmd, parsed.subs);
        if (hit) flag(t(`Bloqueado envio de ${hit} por red`, `Blocked sending ${hit} over the network`));
      }

      const nested = depth < 3 && nestedScript(name, args.map(plain));
      if (nested) {
        const inner = analyze(nested.script, nested.shell, depth + 1);
        if (inner.block) flag(inner.block);
        commands.push(...inner.commands);
        asks.push(...inner.asks);
      }
    }
  }

  return { block, asks, commands };
}

// Patterns that are easiest to express on the raw text. Command names match in any case.
const RAW_RULES = [
  [/:\s*\(\)\s*\{.*\|.*&\s*\}/, t('Bloqueado fork bomb', 'Blocked fork bomb')],
  [/\bmkfs\b/i, t('Bloqueado formateo de disco', 'Blocked disk format')],
  [/\bdd\s+if=.*of=\/dev\//i, t('Bloqueado escritura directa a dispositivo', 'Blocked direct device write')],

  // Reverse shells
  [/\bbash\s+-i\s+>&?\s*\/dev\/tcp/i, t('Bloqueado reverse shell', 'Blocked reverse shell')],
  [/\b(?:nc|ncat|netcat)\s+(?:\S+\s+)*?(?:-e|-c|--exec|--sh-exec)\s/i, t('Bloqueado netcat con ejecucion', 'Blocked netcat with execution')],

  // Encoding + exfiltration
  [/\bbase64\s+.*\|\s*(?:curl|wget|nc)\b/i, t('Bloqueado encoding+exfiltracion', 'Blocked encoding+exfiltration')],
  [/\btar\s+.*\|\s*(?:curl|wget|nc)\b/i, t('Bloqueado empaquetado+exfiltracion', 'Blocked archive+exfiltration')],
  [/\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:sudo\s+)?(?:\S*\/)?(?:bash|sh|zsh)\b/i, t('Bloqueado decodificacion base64 a shell', 'Blocked base64 decode to shell')],

  // Firewall disable
  [/iptables\s+.*-F/, t('Bloqueado flush de firewall', 'Blocked firewall flush')],
  [/\bufw\s+disable\b/i, t('Bloqueado desactivacion de firewall', 'Blocked firewall disable')],

  // Windows: destructive
  [/\bdel\s+\/[fFsS].*[/\\][*.]/i, t('Bloqueado eliminacion recursiva (Windows del /F /S)', 'Blocked recursive delete (Windows del /F /S)')],
  [/\b(?:rd|rmdir)\s+\/s\s+\/q\s+[A-Z]:\\/i, t('Bloqueado eliminacion de directorio raiz (Windows)', 'Blocked root directory deletion (Windows)')],
  [/\bformat\s+[A-Z]:\s*/i, t('Bloqueado formateo de disco (Windows)', 'Blocked disk format (Windows)')],

  // Windows: remote execution (also reached through cmd /c, which is not parsed)
  [/\b(?:powershell|pwsh)(?:\.exe)?\b.*\s[-/]e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c\w*)?)?)?)?)?)?)?\s/i, t('Bloqueado PowerShell con comando codificado', 'Blocked PowerShell with encoded command')],
  [/\b(?:iex|invoke-expression)\b[\s\S]*?\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)\b/i, t('Bloqueado descarga+ejecucion PowerShell', 'Blocked download+execute PowerShell')],
  [/\b(?:irm|iwr|invoke-restmethod|invoke-webrequest)\b[^;\n]*\|\s*(?:iex|invoke-expression)\b/i, t('Bloqueado descarga+ejecucion PowerShell', 'Blocked download+execute PowerShell')],
  [/\[scriptblock\]::create\s*\([\s\S]*?\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)\b/i, t('Bloqueado descarga+ejecucion PowerShell', 'Blocked download+execute PowerShell')],
  [/DownloadString\s*\(\s*['"]https?:/i, t('Bloqueado descarga de script remoto via WebClient', 'Blocked remote script download via WebClient')],

  // Windows: reverse shell / security bypass
  [/New-Object\s+System\.Net\.Sockets\.TCPClient/i, t('Bloqueado reverse shell PowerShell', 'Blocked PowerShell reverse shell')],
  [/Set-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$true/i, t('Bloqueado desactivacion de Windows Defender', 'Blocked Windows Defender disable')],
];

// ─── Allowlist ───

function checkAllowlist(commands, config) {
  if (!config.allowlist_mode) return null;

  const preset = config.allowlist_preset || 'development';
  const allowedBase = PRESETS[preset] || PRESETS.development;
  const allowedExtra = config.allowlist_extra || [];
  const allowed = new Set([...allowedBase, ...allowedExtra].map(s => String(s).toLowerCase()));

  for (const { chain, name, args } of commands) {
    for (const w of chain) {
      if (!allowed.has(w)) return deny(w);
    }
    // Expressions ($var, (group), "literal") are not programs
    if (!name || /^[$\u0001]/.test(name) || /\u0001/.test(name)) continue;
    const sub = args[0] ? `${name} ${String(args[0]).toLowerCase()}` : null;
    if (allowed.has(name) || (sub && allowed.has(sub))) continue;
    return deny(sub && [...allowed].some(a => a.startsWith(name + ' ')) ? sub : name);
  }
  return null;

  function deny(what) {
    return t(
      `Comando "${what}" no esta en la allowlist (preset: ${preset}). Configura en ${CONFIG_PATH}`,
      `Command "${what}" is not in the allowlist (preset: ${preset}). Configure in ${CONFIG_PATH}`
    );
  }
}

// ─── Supply chain warnings ───

function checkSupplyChain(command) {
  const warnings = [];

  const isNpmInstall = /npm\s+(install|i|add)\s/i.test(command);
  const isYarnAdd = /yarn\s+(add|install)\s/i.test(command);
  const isPnpmAdd = /pnpm\s+(add|install)\s/i.test(command);
  const isBunAdd = /bun\s+(add|install)\s/i.test(command);
  const isPipInstall = /pip3?\s+install\s/i.test(command);
  const isGitClone = /git\s+clone\s/i.test(command);

  if (!isNpmInstall && !isYarnAdd && !isPnpmAdd && !isBunAdd && !isPipInstall && !isGitClone) {
    return null;
  }

  if (/\s(https?:\/\/|git\+|github:)\S+/.test(command)) {
    warnings.push(t('Instalando desde URL/GitHub directamente — no pasa por registry', 'Installing directly from URL/GitHub — bypasses registry'));
  }

  if (/\s(-g|--global)\s/.test(command)) {
    warnings.push(t('Instalacion global detectada', 'Global install detected'));
  }

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

  return warnings.length ? warnings.join(' | ') : null;
}

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

// ─── Main ───

function block(message, reason, action) {
  printBox('block', message, reason, action);
  process.exit(2);
}

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  let command = '';
  let toolName = '';
  try {
    const input = JSON.parse(data);
    toolName = input.tool_name || '';
    command = (input.tool_input && input.tool_input.command) || '';
  } catch {
    process.exit(0); // fail-safe: allow on parse error
  }

  if (!command) process.exit(0);
  const shell = toolName === 'PowerShell' ? 'powershell' : 'bash';
  const config = loadConfig();

  // 1. Null bytes (used to cut a command in two for filters that stop at \0)
  if (command.includes('\x00')) {
    block(t('Null byte detectado en comando (posible bypass de filtros)', 'Null byte in command (possible filter bypass)'),
      t('Argumento del comando contiene caracteres peligrosos', 'Command argument contains dangerous characters'),
      t('Elimina el byte nulo del comando', 'Remove the null byte from the command'));
  }

  // 2. Hard blocks (always enforced, regardless of allowlist)
  const result = analyze(command, shell);
  const rawHit = RAW_RULES.find(([re]) => re.test(command));
  const blockMsg = result.block || (rawHit && rawHit[1]);
  if (blockMsg) {
    block(blockMsg,
      t('Patrón de seguridad crítico detectado en el comando', 'Critical security pattern detected in the command'),
      t('Reformula el comando sin la parte peligrosa o usa alternativas seguras', 'Reformulate the command without the dangerous part or use safe alternatives'));
  }

  // 3. Allowlist check (if enabled)
  const allowlistIssue = checkAllowlist(result.commands, config);
  if (allowlistIssue) {
    block(allowlistIssue,
      t('Modo allowlist activo — solo comandos en la lista están permitidos', 'Allowlist mode active — only listed commands are permitted'),
      t('Agrega el comando a allowlist_extra en ~/.privacy-shield/config.json', 'Add the command to allowlist_extra in ~/.privacy-shield/config.json'));
  }

  // 4. Supply chain warnings and control-file writes: ask the user. A hook that exits 0
  //    can only reach the user and Claude through JSON on stdout; stderr reaches neither.
  const supplyChainWarning = checkSupplyChain(command);
  const askReasons = [...result.asks];
  if (supplyChainWarning) {
    askReasons.push(`${supplyChainWarning}. ${t('Verifica el paquete antes de instalar.', 'Check the package before installing.')}`);
  }
  if (askReasons.length) {
    const reason = `Privacy Shield: ${askReasons.join(' | ')}`;
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

  process.exit(0);
});
