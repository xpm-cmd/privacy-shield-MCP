/**
 * supply-chain.ts - Supply Chain Security (Layer 7)
 *
 * Scans packages and repositories before installation:
 * - Detects suspicious install scripts (preinstall, postinstall)
 * - Identifies risky dependency patterns (GitHub URLs, "latest" versions)
 * - Checks for known malicious package name patterns (typosquatting)
 * - Validates Hugging Face model repos for suspicious files
 * - Functional approach: alert on real signals, no overreaction
 */

import type { RiskLevel, Finding, AnalysisResult } from './types.js';
import { RISK_ORDER } from './types.js';

// ============================================================
// Types
// ============================================================

interface PackageJsonScanResult {
  safe: boolean;
  risk_level: RiskLevel;
  findings: Finding[];
  summary: string;
  recommendations: string[];
}

interface RepoScanResult {
  safe: boolean;
  risk_level: RiskLevel;
  findings: Finding[];
  summary: string;
  suspicious_files: string[];
  recommendations: string[];
}

// ============================================================
// Dangerous install script patterns
// ============================================================

const DANGEROUS_SCRIPT_PATTERNS: Array<{
  pattern: RegExp;
  risk: RiskLevel;
  description: string;
  confidence: number;
}> = [
  // Network calls in install scripts
  {
    pattern: /curl\s+.*\|\s*(bash|sh|node|python)/i,
    risk: 'critical',
    description: 'Install script pipes remote content to interpreter',
    confidence: 0.95,
  },
  {
    pattern: /wget\s+.*-O\s*-\s*\|\s*(bash|sh)/i,
    risk: 'critical',
    description: 'Install script downloads and executes remote code',
    confidence: 0.95,
  },
  // File system manipulation outside package dir
  {
    pattern: /rm\s+(-rf?|--recursive)\s+(\/|~\/\.|\/home|\/Users)/i,
    risk: 'critical',
    description: 'Install script deletes files outside package directory',
    confidence: 0.9,
  },
  {
    pattern: /rmdir\s+.*(\$HOME|~\/|\/home|\/Users)/i,
    risk: 'critical',
    description: 'Install script removes user directories',
    confidence: 0.9,
  },
  // Cache manipulation (exactly what claude-flow did)
  {
    pattern: /\.npm\/_(?:npx|cacache|logs)/i,
    risk: 'high',
    description: 'Install script manipulates npm internal cache directories',
    confidence: 0.85,
  },
  {
    pattern: /\.npm\/_preinstall/i,
    risk: 'high',
    description: 'Install script references npm preinstall internals',
    confidence: 0.85,
  },
  // Encoded/obfuscated payloads
  {
    pattern: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*,\s*['"]base64['"]\)/i,
    risk: 'high',
    description: 'Install script contains base64-encoded payload',
    confidence: 0.8,
  },
  {
    pattern: /atob\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*\)/i,
    risk: 'high',
    description: 'Install script decodes base64 content',
    confidence: 0.8,
  },
  // Environment variable exfiltration
  {
    pattern: /process\.env\b.*(?:fetch|http|request|axios|XMLHttpRequest)/i,
    risk: 'critical',
    description: 'Install script may exfiltrate environment variables',
    confidence: 0.85,
  },
  {
    pattern: /process\.env\b.*(?:curl|wget|nc\b)/i,
    risk: 'critical',
    description: 'Install script sends env vars to external service',
    confidence: 0.9,
  },
  // Global installs without consent
  {
    pattern: /npm\s+install\s+(-g|--global)\s/i,
    risk: 'medium',
    description: 'Install script installs global packages',
    confidence: 0.75,
  },
  // Permission changes
  {
    pattern: /chmod\s+([0-7]*[2367][0-7]*|[augo]*\+[rwxst])\s/i,
    risk: 'medium',
    description: 'Install script modifies file permissions',
    confidence: 0.6,
  },
  // Network listeners
  {
    pattern: /\.(listen|createServer)\s*\(/i,
    risk: 'medium',
    description: 'Install script opens network listener',
    confidence: 0.65,
  },
  // Reverse shell patterns
  {
    pattern: /\/dev\/tcp\//i,
    risk: 'critical',
    description: 'Install script contains reverse shell pattern',
    confidence: 0.95,
  },
  // Dynamic require/import (obfuscation)
  {
    pattern: /require\s*\(\s*(?:Buffer|atob|String\.fromCharCode)/i,
    risk: 'high',
    description: 'Install script uses dynamic require with encoding',
    confidence: 0.8,
  },
];

// ============================================================
// Risky dependency patterns
// ============================================================

const RISKY_DEP_PATTERNS: Array<{
  check: (name: string, version: string) => boolean;
  risk: RiskLevel;
  description: string;
}> = [
  {
    check: (_n, v) => /^https?:\/\//.test(v) || v.startsWith('git+'),
    risk: 'medium',
    description: 'Dependency from URL/Git (bypasses npm registry integrity checks)',
  },
  {
    check: (_n, v) => /^github:/.test(v) || /^[\w-]+\/[\w-]+$/.test(v),
    risk: 'low',
    description: 'Dependency from GitHub shorthand (less auditable than registry)',
  },
  {
    check: (_n, v) => v === '*' || v === 'latest',
    risk: 'medium',
    description: 'Dependency uses wildcard version (unpredictable updates)',
  },
  {
    check: (_n, v) => v.startsWith('file:'),
    risk: 'low',
    description: 'Dependency from local file path',
  },
];

// ============================================================
// Known typosquatting / malicious package patterns
// ============================================================

const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'vue', 'angular', 'webpack', 'babel',
  'typescript', 'eslint', 'prettier', 'jest', 'mocha', 'axios',
  'moment', 'chalk', 'commander', 'dotenv', 'mongoose', 'sequelize',
  'next', 'nuxt', 'gatsby', 'tailwindcss', 'postcss',
];

function isTyposquatCandidate(name: string): string | null {
  const lower = name.toLowerCase();
  for (const popular of POPULAR_PACKAGES) {
    if (lower === popular) continue;
    // Check Levenshtein distance = 1 (single char difference)
    if (levenshteinDistance(lower, popular) === 1) {
      return popular;
    }
    // Check common typosquat patterns: prefix/suffix additions
    if (lower === popular + 'js' || lower === popular + '-js' ||
        lower === popular + 'node' || lower === popular + '-node' ||
        lower === 'node-' + popular || lower === 'js-' + popular) {
      return popular;
    }
  }
  return null;
}

function levenshteinDistance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3; // early exit
  const matrix: number[][] = [];
  for (let i = 0; i <= a.length; i++) {
    matrix[i] = [i];
    for (let j = 1; j <= b.length; j++) {
      if (i === 0) {
        matrix[i][j] = j;
      } else {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost,
        );
      }
    }
  }
  return matrix[a.length][b.length];
}

// ============================================================
// Suspicious file patterns (repo scanning)
// ============================================================

const SUSPICIOUS_FILE_PATTERNS: Array<{
  pattern: RegExp;
  risk: RiskLevel;
  description: string;
}> = [
  { pattern: /\.exe$/i, risk: 'high', description: 'Binary executable in repo' },
  { pattern: /\.dll$/i, risk: 'high', description: 'Dynamic library in repo' },
  { pattern: /\.so$/i, risk: 'medium', description: 'Shared object in repo' },
  { pattern: /\.dylib$/i, risk: 'medium', description: 'Dynamic library (macOS) in repo' },
  { pattern: /\.bat$/i, risk: 'medium', description: 'Windows batch script' },
  { pattern: /\.ps1$/i, risk: 'medium', description: 'PowerShell script in repo' },
  { pattern: /\.msi$/i, risk: 'high', description: 'Windows installer in repo' },
  { pattern: /\.wasm$/i, risk: 'low', description: 'WebAssembly binary in repo' },
  // Python-specific
  { pattern: /setup\.py$/i, risk: 'low', description: 'Python setup.py (may run arbitrary code on install)' },
  // Serialized model files that can run code on deserialization
  { pattern: /\.pkl$/i, risk: 'high', description: 'Serialized Python object (can run code on deserialization)' },
  { pattern: /\.pt$/i, risk: 'medium', description: 'PyTorch model (uses unsafe deserialization internally)' },
  { pattern: /\.pth$/i, risk: 'medium', description: 'PyTorch model checkpoint' },
  { pattern: /\.bin$/i, risk: 'low', description: 'Binary file in repo' },
  // Obfuscated or minified files in unexpected places
  { pattern: /\.min\.js$/i, risk: 'low', description: 'Minified JS (harder to audit)' },
];

// ============================================================
// Main analysis functions
// ============================================================

/**
 * Scan a package.json content for supply chain risks.
 * Designed to be practical: flags real dangers, not every dependency.
 */
export function analyzePackageJson(packageJsonContent: string): PackageJsonScanResult {
  const findings: Finding[] = [];
  let maxRisk: RiskLevel = 'safe';

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(packageJsonContent) as Record<string, unknown>;
  } catch {
    return {
      safe: false,
      risk_level: 'medium',
      findings: [{ category: 'parse_error', description: 'Invalid JSON in package.json', risk: 'medium' }],
      summary: 'Could not parse package.json',
      recommendations: ['Verify the file is valid JSON'],
    };
  }

  // 1. Check install scripts
  const scripts = (pkg.scripts || {}) as Record<string, string>;
  const dangerousHooks = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];

  for (const hook of dangerousHooks) {
    const script = scripts[hook];
    if (!script) continue;

    // First, just flag that the hook exists
    if (hook === 'preinstall' || hook === 'postinstall') {
      findings.push({
        category: 'install_script',
        description: `Package has ${hook} script: "${script.slice(0, 100)}${script.length > 100 ? '...' : ''}"`,
        risk: 'low',
        detail: `Install hooks run automatically. Verify the script is safe.`,
      });
    }

    // Then check for dangerous patterns in the script
    for (const dp of DANGEROUS_SCRIPT_PATTERNS) {
      if (dp.pattern.test(script)) {
        const finding: Finding = {
          category: 'dangerous_install_script',
          description: dp.description,
          risk: dp.risk,
          detail: `In "${hook}": ${script.slice(0, 150)}`,
          confidence: dp.confidence,
        };
        findings.push(finding);
        if (RISK_ORDER[dp.risk] > RISK_ORDER[maxRisk]) {
          maxRisk = dp.risk;
        }
      }
    }
  }

  // 2. Check dependencies for risky patterns
  const allDeps: Record<string, string> = {
    ...(pkg.dependencies as Record<string, string> || {}),
    ...(pkg.devDependencies as Record<string, string> || {}),
    ...(pkg.optionalDependencies as Record<string, string> || {}),
  };

  let riskyDepCount = 0;
  for (const [name, version] of Object.entries(allDeps)) {
    // Check risky version patterns
    for (const rp of RISKY_DEP_PATTERNS) {
      if (rp.check(name, version)) {
        findings.push({
          category: 'risky_dependency',
          description: `${name}@${version}: ${rp.description}`,
          risk: rp.risk,
        });
        if (RISK_ORDER[rp.risk] > RISK_ORDER[maxRisk]) {
          maxRisk = rp.risk;
        }
        riskyDepCount++;
      }
    }

    // Check typosquatting
    const typosquatOf = isTyposquatCandidate(name);
    if (typosquatOf) {
      findings.push({
        category: 'typosquatting',
        description: `"${name}" looks similar to popular package "${typosquatOf}"`,
        risk: 'medium',
        detail: 'Verify this is the intended package and not a typosquat',
      });
      if (RISK_ORDER['medium'] > RISK_ORDER[maxRisk]) {
        maxRisk = 'medium';
      }
    }
  }

  // 3. Check for suspicious package metadata
  const depCount = Object.keys(allDeps).length;
  if (depCount === 0 && Object.keys(scripts).some(s => dangerousHooks.includes(s))) {
    findings.push({
      category: 'suspicious_metadata',
      description: 'Package has install scripts but zero dependencies (unusual)',
      risk: 'medium',
    });
  }

  // Build recommendations
  const recommendations: string[] = [];
  const hasDangerousScripts = findings.some(f => f.category === 'dangerous_install_script');
  const hasRiskyDeps = findings.some(f => f.category === 'risky_dependency');
  const hasTyposquat = findings.some(f => f.category === 'typosquatting');

  if (hasDangerousScripts) {
    recommendations.push('Review install scripts carefully before proceeding');
    recommendations.push('Consider using --ignore-scripts flag for npm install');
  }
  if (hasRiskyDeps) {
    recommendations.push('Pin dependency versions instead of using wildcards or "latest"');
    if (riskyDepCount > 0) {
      recommendations.push('Prefer npm registry packages over Git/URL dependencies');
    }
  }
  if (hasTyposquat) {
    recommendations.push('Double-check package names that resemble popular packages');
  }

  const safe = maxRisk === 'safe' || maxRisk === 'low';

  // Summary: concise, no overreaction
  let summary: string;
  if (findings.length === 0) {
    summary = 'No supply chain risks detected in package.json';
  } else if (hasDangerousScripts) {
    const critCount = findings.filter(f => f.risk === 'critical').length;
    summary = critCount > 0
      ? `${critCount} critical install script issue(s) found — review before installing`
      : `${findings.length} finding(s) in package.json — review install scripts`;
  } else {
    summary = `${findings.length} minor finding(s) in package.json`;
  }

  return { safe, risk_level: maxRisk, findings, summary, recommendations };
}

/**
 * Scan a list of file paths from a repository for suspicious files.
 * Used when cloning/downloading from GitHub or Hugging Face.
 */
export function analyzeRepoFiles(filePaths: string[]): RepoScanResult {
  const findings: Finding[] = [];
  const suspiciousFiles: string[] = [];
  let maxRisk: RiskLevel = 'safe';

  for (const filePath of filePaths) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    const fileName = normalizedPath.split('/').pop() || '';

    for (const sp of SUSPICIOUS_FILE_PATTERNS) {
      if (sp.pattern.test(fileName)) {
        findings.push({
          category: 'suspicious_file',
          description: `${sp.description}: ${fileName}`,
          risk: sp.risk,
          detail: normalizedPath,
        });
        suspiciousFiles.push(normalizedPath);
        if (RISK_ORDER[sp.risk] > RISK_ORDER[maxRisk]) {
          maxRisk = sp.risk;
        }
        break; // one match per file is enough
      }
    }
  }

  // Check for unusual patterns in the repo structure
  const hasPackageJson = filePaths.some(f => f.endsWith('package.json'));
  const hasSetupPy = filePaths.some(f => f.endsWith('setup.py'));
  const hasBinaries = findings.filter(f => f.risk === 'high').length;

  const recommendations: string[] = [];
  if (hasBinaries > 0) {
    recommendations.push('Binary files detected — verify they are necessary and from trusted sources');
  }
  if (hasPackageJson) {
    recommendations.push('Run scan_package_json on package.json before installing');
  }
  if (hasSetupPy) {
    recommendations.push('Review setup.py before running pip install (it can run arbitrary Python)');
  }

  const unsafeModelFiles = findings.filter(f =>
    f.description.includes('deserialization') || f.description.includes('Serialized'));
  if (unsafeModelFiles.length > 0) {
    recommendations.push('Serialized model files can run code on load — prefer safetensors format');
  }

  const safe = maxRisk === 'safe' || maxRisk === 'low';
  let summary: string;
  if (findings.length === 0) {
    summary = `Scanned ${filePaths.length} files — no suspicious files detected`;
  } else {
    summary = `Found ${findings.length} suspicious file(s) out of ${filePaths.length} scanned`;
  }

  return { safe, risk_level: maxRisk, findings, summary, suspicious_files: suspiciousFiles, recommendations };
}

/**
 * Quick scan an install command to check if it needs deeper inspection.
 * Returns whether the install target should be fetched and scanned.
 */
export function analyzeInstallCommand(command: string): {
  should_scan: boolean;
  package_manager: string;
  targets: string[];
  risk_signals: string[];
} {
  const riskSignals: string[] = [];
  let packageManager = '';
  const targets: string[] = [];

  // Detect package manager and extract targets
  const npmMatch = command.match(/npm\s+(?:install|i|add)\s+(.*)/i);
  const yarnMatch = command.match(/yarn\s+(?:add|install)\s+(.*)/i);
  const pnpmMatch = command.match(/pnpm\s+(?:add|install)\s+(.*)/i);
  const bunMatch = command.match(/bun\s+(?:add|install)\s+(.*)/i);
  const pipMatch = command.match(/pip3?\s+install\s+(.*)/i);
  const uvMatch = command.match(/uv\s+(?:pip\s+install|add)\s+(.*)/i);

  const match = npmMatch || yarnMatch || pnpmMatch || bunMatch || pipMatch || uvMatch;
  if (!match) {
    // Check for git clone
    const gitMatch = command.match(/git\s+clone\s+(.*)/i);
    if (gitMatch) {
      packageManager = 'git';
      const parts = gitMatch[1].trim().split(/\s+/);
      targets.push(parts[0]);
      riskSignals.push('Repository clone — inspect package.json/setup.py after cloning');
      return { should_scan: true, package_manager: packageManager, targets, risk_signals: riskSignals };
    }
    return { should_scan: false, package_manager: '', targets: [], risk_signals: [] };
  }

  if (npmMatch) packageManager = 'npm';
  else if (yarnMatch) packageManager = 'yarn';
  else if (pnpmMatch) packageManager = 'pnpm';
  else if (bunMatch) packageManager = 'bun';
  else if (pipMatch) packageManager = 'pip';
  else if (uvMatch) packageManager = 'uv';

  // Parse targets (skip flags)
  const args = match[1].trim().split(/\s+/);
  for (const arg of args) {
    if (arg.startsWith('-')) continue;
    if (!arg) continue;
    targets.push(arg);
  }

  // Check for risk signals
  for (const target of targets) {
    if (/^https?:\/\//.test(target) || target.startsWith('git+')) {
      riskSignals.push(`URL-based install: ${target}`);
    }
    if (/^github:/.test(target) || /^[\w-]+\/[\w-]+$/.test(target)) {
      riskSignals.push(`GitHub-based install: ${target}`);
    }
    const typosquat = isTyposquatCandidate(target.split('@')[0]);
    if (typosquat) {
      riskSignals.push(`"${target}" resembles popular package "${typosquat}"`);
    }
  }

  // Global install check
  if (/\s-g\s|\s--global\s/.test(command)) {
    riskSignals.push('Global installation requested');
  }

  // --ignore-scripts check (informational)
  if (/--ignore-scripts/.test(command)) {
    riskSignals.push('--ignore-scripts flag present (install scripts will NOT run)');
  }

  const shouldScan = targets.length > 0;
  return { should_scan: shouldScan, package_manager: packageManager, targets, risk_signals: riskSignals };
}

/**
 * Comprehensive supply chain scan: combines install command analysis
 * with package.json content scanning.
 */
export function analyzeSupplyChain(
  command: string,
  packageJsonContent?: string,
  repoFiles?: string[],
): AnalysisResult {
  const findings: Finding[] = [];
  let maxRisk: RiskLevel = 'safe';
  const recommendations: string[] = [];

  // 1. Analyze the install command
  const cmdAnalysis = analyzeInstallCommand(command);
  if (cmdAnalysis.risk_signals.length > 0) {
    for (const signal of cmdAnalysis.risk_signals) {
      findings.push({
        category: 'install_command',
        description: signal,
        risk: signal.includes('URL-based') ? 'medium' : 'low',
      });
    }
  }

  // 2. If package.json content provided, scan it
  if (packageJsonContent) {
    const pkgResult = analyzePackageJson(packageJsonContent);
    findings.push(...pkgResult.findings);
    recommendations.push(...pkgResult.recommendations);
    if (RISK_ORDER[pkgResult.risk_level] > RISK_ORDER[maxRisk]) {
      maxRisk = pkgResult.risk_level;
    }
  }

  // 3. If repo files provided, scan them
  if (repoFiles && repoFiles.length > 0) {
    const repoResult = analyzeRepoFiles(repoFiles);
    findings.push(...repoResult.findings);
    recommendations.push(...repoResult.recommendations);
    if (RISK_ORDER[repoResult.risk_level] > RISK_ORDER[maxRisk]) {
      maxRisk = repoResult.risk_level;
    }
  }

  // Compute overall risk from findings
  for (const f of findings) {
    if (RISK_ORDER[f.risk] > RISK_ORDER[maxRisk]) {
      maxRisk = f.risk;
    }
  }

  const safe = maxRisk === 'safe' || maxRisk === 'low';

  let summary: string;
  if (findings.length === 0) {
    summary = 'No supply chain risks detected';
  } else {
    const critical = findings.filter(f => f.risk === 'critical').length;
    const high = findings.filter(f => f.risk === 'high').length;
    if (critical > 0) {
      summary = `Supply chain alert: ${critical} critical issue(s) — review before installing`;
    } else if (high > 0) {
      summary = `${high} high-risk finding(s) in supply chain scan`;
    } else {
      summary = `${findings.length} finding(s) in supply chain scan — minor issues`;
    }
  }

  return { safe, risk_level: maxRisk, findings, summary, recommendations };
}
