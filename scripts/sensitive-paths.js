// Privacy Shield - shared knowledge about credential files, used by the hooks.

// .env.example, .env.sample … are committed templates without real values.
const ENV_TEMPLATE_PARTS = new Set(['example', 'examples', 'sample', 'samples', 'template', 'templates', 'dist', 'tmpl', 'tpl', 'schema']);

/** True for ".env" and ".env.<anything>" except committed templates such as ".env.example". */
function isEnvFileName(name) {
  const m = /^\.env((?:\.[^.]+)*)$/i.exec(name);
  if (!m) return false;
  const parts = m[1].toLowerCase().split('.').filter(Boolean);
  return !parts.some(p => ENV_TEMPLATE_PARTS.has(p));
}

// Credential files that should never travel over the network. Each regex is tested against
// a single path-like token (shell argument, @file reference, -InFile value …).
const SENSITIVE_TOKEN_RULES = [
  [/(?:^|[/\\])id_(?:rsa|ed25519|ecdsa|dsa)$/i, 'SSH private key'],
  [/\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$/i, 'private key / keystore'],
  [/(?:^|[/\\])\.ssh[/\\]/i, 'SSH directory'],
  [/(?:^|[/\\])\.aws[/\\]credentials$/i, 'AWS credentials'],
  [/(?:^|[/\\])\.(?:npmrc|netrc|pypirc|git-credentials)$/i, 'credentials file'],
  [/(?:^|[/\\])\.docker[/\\]config\.json$/i, 'Docker credentials'],
  [/(?:^|[/\\])\.kube[/\\]config$/i, 'Kubernetes config'],
  [/(?:^|[/\\])\.config[/\\]gh[/\\]hosts\.yml$/i, 'GitHub CLI tokens'],
  [/(?:^|[/\\])\.gnupg[/\\]/i, 'GPG keyring'],
  [/(?:^|[/\\])\.password-store[/\\]/i, 'password store'],
  [/(?:^|[/\\])wallet\.dat$/i, 'crypto wallet'],
];

/**
 * Find a credential file referenced in a shell word such as ".env", "@.env",
 * "file=@~/.ssh/id_rsa", "--post-file=.env" or ".\.env::$DATA".
 * @returns {string|null} description of what was found
 */
function findSensitivePath(word) {
  const tokens = String(word).split(/[\s=@,'"<>()]+/).filter(Boolean);
  for (let token of tokens) {
    // NTFS alternate data stream (".env::$DATA", ".env:stream") and trailing dots/spaces
    // name the same file on Windows.
    token = token.replace(/(?<=[^:\\/]):(?![\\/]).*$/, '').replace(/[. ]+$/, '');
    const base = token.split(/[\\/]/).pop();
    if (isEnvFileName(base)) return '.env file';
    for (const [re, desc] of SENSITIVE_TOKEN_RULES) {
      if (re.test(token)) return desc;
    }
  }
  return null;
}

/**
 * Normalize a path for rule matching: forward slashes, lower case, no drive letter, no
 * NTFS stream suffix (".env::$DATA"), no trailing dots/spaces (Windows drops them), and a
 * leading "/" so relative paths ("/.env" vs ".env") match the same rules.
 */
function normalizeForMatch(p) {
  let s = String(p || '').replace(/\\/g, '/');
  s = s.replace(/^\/\/[?.]\//, '');                     // \\?\C:\…  \\.\C:\…
  s = s.replace(/(?<=[^:/]):(?!\/).*$/, '');           // alternate data stream
  s = s.split('/').map(seg => (seg === '.' || seg === '..' ? seg : seg.replace(/[. ]+$/, ''))).join('/');
  s = s.toLowerCase().replace(/^[a-z]:/, '');
  if (!s.startsWith('/')) s = '/' + s;
  return s;
}

/**
 * Files that control Claude Code, this plugin or the shell. Writing them can switch the
 * shield off or run code later, outside any hook.
 * @param {string} filePath  path as given by the tool
 * @param {string} home      user home directory
 * @param {string} pluginRoot directory that holds hooks/ and scripts/ of this plugin
 * @returns {{ level: 'block'|'ask', desc: string } | null}
 */
function classifyControlPath(filePath, home, pluginRoot) {
  const p = normalizeForMatch(filePath);
  const under = (dir) => {
    const d = normalizeForMatch(dir).replace(/\/+$/, '');
    return p === d || p.startsWith(d + '/');
  };

  if (['hooks', 'scripts', '.claude-plugin'].some(d => under(pluginRoot + '/' + d)) || p === normalizeForMatch(pluginRoot + '/.mcp.json')) {
    return { level: 'block', desc: 'Privacy Shield plugin files' };
  }
  if (under(home + '/.privacy-shield')) {
    return { level: 'block', desc: 'Privacy Shield config and state' };
  }
  if (/\/\.claude\/settings(?:\.local)?\.json$/.test(p)) {
    return { level: 'ask', desc: 'Claude Code settings (permissions and hooks)', settings: true };
  }
  const base = p.split('/').pop();
  if (/^\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|zlogout|kshrc|cshrc|tcshrc|envrc)$/.test(base) ||
      /\/\.config\/fish\/config\.fish$/.test(p)) {
    return { level: 'ask', desc: 'shell startup file' };
  }
  if (/\/(?:windows)?powershell(?:\/\d+)?\/(?:[\w.]+_)?profile\.ps1$/.test(p)) {
    return { level: 'ask', desc: 'PowerShell profile' };
  }
  if (/\/\.git\/hooks\//.test(p) || /\/\.git\/config$/.test(p)) {
    return { level: 'ask', desc: 'git hooks/config (runs code on git commands)' };
  }
  return null;
}

/** Settings content that turns hooks or this plugin off. */
function disablesShield(content) {
  return /"disableAllHooks"\s*:\s*true/.test(content) ||
    /"privacy-shield(?:@[^"]*)?"\s*:\s*false/i.test(content);
}

module.exports = { isEnvFileName, findSensitivePath, normalizeForMatch, classifyControlPath, disablesShield };
