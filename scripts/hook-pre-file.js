#!/usr/bin/env node
// Privacy Shield - PreToolUse hook for file operations (Edit, Write, MultiEdit)
// Exit 0 = allow, Exit 2 = block
// Checks: (1) sensitive file paths, (2) dangerous code patterns in content

let data = '';
process.stdin.on('data', c => data += c);
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const toolName = input.tool_name || '';
    const toolInput = input.tool_input || {};
    const filePath = toolInput.file_path || '';

    if (!filePath) process.exit(0);

    // Read always allowed
    if (toolName !== 'Write' && toolName !== 'Edit' && toolName !== 'MultiEdit') process.exit(0);

    // ═══════════════════════════════════════════════
    // LAYER 1: Sensitive file path checks
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

    // Skip content checks for documentation/config files (avoid false positives)
    if (/\.(md|mdx|txt|rst|adoc|log|csv|json|ya?ml|toml|ini|cfg|conf|xml|html?|svg)$/i.test(norm)) process.exit(0);

    // Path-based content checks
    const normPath = filePath.replace(/\\/g, '/').replace(/^\/+/, '');

    if (/\.github\/workflows\/.*\.ya?ml$/.test(normPath)) {
      // Check for unsafe GitHub Actions interpolation
      if (/\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits|pages)/.test(content)) {
        warn('GitHub Actions workflow injection: uso inseguro de interpolacion ${{ github.event.* }} en run:. Usa variables env: en su lugar.');
      }
    }

    // Substring-based content checks
    const contentPatterns = [
      // Command injection
      { test: () => content.includes('child_process.exec') || content.includes('execSync('),
        msg: 'Command injection risk: child_process.exec/execSync. Usa execFile() o spawn() con argumentos separados.' },

      // Code injection
      { test: () => content.includes('new Function(') || content.includes('new Function ('),
        msg: 'Code injection risk: new Function() ejecuta codigo arbitrario. Considera alternativas seguras.' },
      { test: () => /\beval\s*\(/.test(content),
        msg: 'Code injection risk: eval() ejecuta codigo arbitrario. Usa JSON.parse() para datos o alternativas seguras.' },

      // XSS
      { test: () => content.includes('dangerouslySetInnerHTML'),
        msg: 'XSS risk: dangerouslySetInnerHTML. Sanitiza con DOMPurify o usa alternativas seguras.' },
      { test: () => content.includes('document.write'),
        msg: 'XSS risk: document.write(). Usa metodos DOM como createElement/appendChild.' },
      { test: () => /\.innerHTML\s*=/.test(content),
        msg: 'XSS risk: innerHTML assignment. Usa textContent para texto plano o sanitiza con DOMPurify.' },

      // Unsafe deserialization
      { test: () => /\bpickle\.(loads?|dumps?)\b/.test(content) || content.includes('import pickle'),
        msg: 'Deserializacion insegura: pickle puede ejecutar codigo arbitrario. Usa JSON u otro formato seguro.' },

      // Shell injection (Python)
      { test: () => content.includes('os.system(') || content.includes('from os import system'),
        msg: 'Shell injection risk: os.system(). Usa subprocess.run() con argumentos como lista.' },

      // Shell injection (Python subprocess with shell=True)
      { test: () => /subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True/s.test(content),
        msg: 'Shell injection risk: subprocess con shell=True. Usa shell=False con argumentos como lista.' },

      // SQL injection
      { test: () => /f["'].*SELECT\b.*\{/.test(content) || /f["'].*INSERT\b.*\{/.test(content) || /f["'].*UPDATE\b.*\{/.test(content) || /f["'].*DELETE\b.*\{/.test(content),
        msg: 'SQL injection risk: f-string con query SQL. Usa parametros (?) o un ORM.' },

      // Hardcoded secrets
      { test: () => /(password|secret|api_key|apikey|token)\s*=\s*["'][^"']{8,}["']/i.test(content) && !/example|test|placeholder|changeme|xxx|dummy/i.test(content),
        msg: 'Posible secreto hardcodeado detectado. Usa variables de entorno o un gestor de secretos.' },
    ];

    for (const pattern of contentPatterns) {
      if (pattern.test()) {
        warn(pattern.msg);
      }
    }

    process.exit(0);

  } catch {
    process.exit(0); // Allow on error
  }
});

function warn(msg) {
  process.stderr.write(`PRIVACY-SHIELD: ${msg}\n`);
  process.exit(2);
}
