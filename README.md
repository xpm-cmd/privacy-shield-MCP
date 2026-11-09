# Privacy Shield v2

A Claude Code plugin providing **7-layer security protection** through real-time hooks and **21 MCP tools**. Cross-platform: macOS, Linux, and Windows.

## Installation

### macOS / Linux

1. Copy the plugin to your Claude Code plugins cache:

```bash
mkdir -p ~/.claude/plugins/cache/local/privacy-shield/2.0.0
cp -r . ~/.claude/plugins/cache/local/privacy-shield/2.0.0/
```

2. Copy hidden files explicitly (dotfiles may be skipped by `cp -r`):

```bash
cp -r .claude-plugin ~/.claude/plugins/cache/local/privacy-shield/2.0.0/
cp .mcp.json ~/.claude/plugins/cache/local/privacy-shield/2.0.0/
```

3. Install server dependencies:

```bash
cd ~/.claude/plugins/cache/local/privacy-shield/2.0.0/server
npm install --omit=dev
```

### Windows (PowerShell)

1. Copy the plugin:

```powershell
$dest = "$env:USERPROFILE\.claude\plugins\cache\local\privacy-shield\2.0.0"
New-Item -ItemType Directory -Path $dest -Force
Copy-Item -Recurse -Force * $dest
Copy-Item -Recurse -Force .claude-plugin $dest
Copy-Item -Force .mcp.json $dest
```

2. Install server dependencies:

```powershell
cd "$env:USERPROFILE\.claude\plugins\cache\local\privacy-shield\2.0.0\server"
npm install --omit=dev
```

### All Platforms

4. Register the plugin in `~/.claude/plugins/installed_plugins.json` under the `"plugins"` key:

```json
"privacy-shield@local": [
  {
    "scope": "user",
    "installPath": "<absolute-path-to-cache>/local/privacy-shield/2.0.0",
    "version": "2.0.0",
    "installedAt": "2026-02-28T00:00:00.000Z",
    "lastUpdated": "2026-02-28T00:00:00.000Z"
  }
]
```

5. Enable in `~/.claude/settings.json`:

```json
"enabledPlugins": {
  "privacy-shield@local": true
}
```

6. Restart Claude Code.

## How It Works

Privacy Shield operates on two levels:

- **Hooks** run automatically before every tool call (Bash, Edit, Write, WebFetch) and block dangerous operations in real time.
- **MCP tools** are available on demand for deeper analysis of text, code, URLs, commands, and files.

## Hooks (Real-Time Protection)

### Bash Command Validation

Blocks dangerous shell commands before execution. Covers both Unix and Windows threats:

| Category | Unix Patterns | Windows Patterns |
|---|---|---|
| Destructive | `rm -rf /`, fork bombs, `mkfs`, `dd of=/dev/` | `del /F /S`, `rd /S /Q C:\`, `format C:` |
| Remote execution | `curl \| bash`, `wget \| python` | `IWR \| IEX`, `powershell -EncodedCommand`, `DownloadString` |
| Reverse shells | `bash -i >& /dev/tcp`, `nc -e` | `New-Object TCPClient` |
| Exfiltration | `cat .env \| curl`, `base64 \| curl` | `certutil -urlcache`, `bitsadmin /transfer` |
| Security bypass | `iptables -F`, `ufw disable` | `Set-MpPreference -DisableRealtimeMonitoring` |

The same hook covers the `Bash` and `PowerShell` tools. Commands are parsed into pipelines rather than matched as raw text, so flag order (`rm -fr`, `rm -r -f`), case (`RM`, `CURL`), wrappers (`sudo`, `env`, `xargs`, `/bin/sh`), substitutions (`bash <(curl …)`, `iex (irm …)`) and nested shells (`bash -c`, `pwsh -Command`) don't change the verdict. PowerShell-specific checks: `Remove-Item -Recurse` on root/home, `iex`/`irm` download-and-run, `-enc`/`-e` encoded commands, and `Get-Content .env | Invoke-RestMethod`.

Additional features:
- **Configurable allowlist mode** via `~/.privacy-shield/config.json` with factory presets (`development`, `read-only`). Every command in the line is checked (after `&&`, `;`, `|` and inside `$( )`), wrappers such as `env` and `sudo` must be allowed too, and two-word entries (`git log`) allow one subcommand
- **Control files**: shell writes (`>`, `tee`, `cp`, `Set-Content` …) to the shield's own files are blocked; writes to Claude settings, shell profiles and git hooks ask the user
- **Supply chain warnings** for install commands (`npm install`, `pip install`, `git clone`) are shown to the user in the permission prompt
- **Typosquatting detection** for popular packages
- **Argument validation**: null bytes

### File Operation Validation

Layered protection for file operations (Write/Edit/MultiEdit/NotebookEdit). Read operations are always allowed.

**Layer 1: Path-based blocks** always block writes to sensitive files. Paths are matched after normalization, so relative paths, NTFS streams (`.env::$DATA`) and trailing dots don't slip through:

| Category | Files |
|---|---|
| Environment | `.env`, `.env.local`, `.env.production.local` (templates such as `.env.example` are allowed) |
| SSH | `id_rsa`, `id_ed25519`, `authorized_keys`, `.ssh/config` |
| Certificates | `.pem`, `.pfx`, `.p12` |
| Cloud credentials | `.aws/credentials`, `.docker/config.json`, `.kube/config` |
| Auth configs | `.netrc`, `.npmrc`, `.pypirc` |
| Secrets | `wallet.dat`, `.gnupg/*.key`, `.password-store/`, `.config/gh/hosts.yml` |

The shield also protects its own controls. Writes to the plugin's `hooks/`, `scripts/` and `.claude-plugin/`, to `~/.privacy-shield/`, and to Claude settings that set `disableAllHooks` or turn the plugin off are blocked. Writes to `.claude/settings*.json`, shell startup files (`.bashrc`, `.zshrc` …), the PowerShell profile, `.git/hooks/*` and `.git/config` need the user's approval.

**Layer 2: Content pattern detection** blocks the first time a dangerous pattern is detected in a file, so Claude can reconsider. A retry goes to the user as a permission prompt instead of passing silently. Hardcoded secrets are judged per value, so a placeholder such as `"test_value"` is ignored while a real value elsewhere in the same file is still caught.

**Layer 3: Diff size gate** warns on writes exceeding 300 lines (configurable).

### WebFetch Validation

Blocks outbound requests to dangerous destinations:

| Category | Examples |
|---|---|
| Exfiltration endpoints | `pastebin.com/raw`, `webhook.site`, `requestbin`, `ngrok`, `pipedream` |
| URL shorteners | `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd` (17 total) |
| Dangerous protocols | `javascript:`, `vbscript:`, `data:text/html:` |
| High-risk TLDs | `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.zip`, `.mov` |

## MCP Tools (21 On-Demand Tools)

### Layer 1: Privacy

| Tool | Description |
|---|---|
| `scan_privacy` | Detects PII, API keys, SSH keys, JWTs, passwords |
| `check_file_sensitivity` | Checks if a file path is sensitive |
| `redact_text` | Returns text with sensitive data replaced by placeholders |
| `full_security_scan` | Runs all analysis layers at once |

### Layer 2: Network

| Tool | Description |
|---|---|
| `validate_urls` | Detects shorteners, malicious domains, phishing, typosquatting |
| `check_domain` | Checks if a domain is safe for data sending |

### Layer 3: Execution

| Tool | Description |
|---|---|
| `analyze_command` | Detects dangerous bash/PowerShell patterns |
| `detect_prompt_injection` | Identifies jailbreak and prompt injection attempts with confidence scoring |
| `scan_code` | Detects unsafe code patterns (eval, exec, XSS, deserialization, GH Actions injection) |

### Layer 4: Anti-Exfiltration

| Tool | Description |
|---|---|
| `check_exfiltration` | Detects data exfiltration techniques |
| `check_file_operation` | Validates if a file operation is safe |

### Layer 5: Audit

| Tool | Description |
|---|---|
| `session_summary` | Security stats for the current session |
| `audit_log` | Recent entries from persistent audit log |
| `set_session` | Set custom session ID for grouping scans |

### Layer 6: Adversarial (Multi-Agent)

| Tool | Description |
|---|---|
| `detect_adversarial` | Detect threats in agent action sequences (memory poisoning, privilege escalation) |
| `check_collusion` | Verify agent interaction graph for collusion rings and coordinated behavior |
| `quorum_vote` | Byzantine voting (2/3 majority) for validating cross-agent writes |

### Layer 7: Supply Chain

| Tool | Description |
|---|---|
| `scan_supply_chain` | Full analysis: install command + package.json + repo files |
| `scan_package_json` | Detect dangerous install scripts, risky dependencies, typosquatting |
| `scan_repo_files` | Scan for suspicious file formats (executables, serialized models, DLLs) |

### Enforcement & Stats

| Tool | Description |
|---|---|
| `run_gates` | Run enforcement gates (diff size, tool allowlist, secret detection) |
| `detection_stats` | View scan metrics and detection rates |

## Plugin Structure

```
privacy-shield/
├── .claude-plugin/
│   └── plugin.json             # Plugin manifest (v2.0.0)
├── .mcp.json                   # MCP server definition
├── hooks/
│   └── hooks.json              # Hook event configuration
├── scripts/
│   ├── hook-pre-bash.js        # Bash/PowerShell command validator
│   ├── hook-pre-file.js        # File path + content + diff size validator
│   ├── hook-pre-web.js         # URL validator
│   ├── shell-parse.js          # Quote-aware Bash/PowerShell command parser
│   ├── sensitive-paths.js      # Credential and control-file rules shared by hooks
│   ├── test-hook*.js           # Hook tests (npm run test:hooks)
│   └── parse-input.js          # Shared JSON field extractor
└── server/
    ├── package.json            # Node.js module config
    ├── tsconfig.json           # TypeScript configuration
    ├── vitest.config.ts        # Test configuration
    ├── src/                    # TypeScript source (11 modules)
    │   ├── index.ts            # MCP server entry (21 tools)
    │   ├── types.ts            # Shared type definitions
    │   ├── privacy.ts          # Layer 1: PII & secrets
    │   ├── network.ts          # Layer 2: URL & domain validation
    │   ├── execution.ts        # Layer 3: Bash, prompt injection, code
    │   ├── exfiltration.ts     # Layer 4: Data exfiltration
    │   ├── audit.ts            # Layer 5: Logging & redaction
    │   ├── adversarial.ts      # Layer 6: Multi-agent threats
    │   ├── supply-chain.ts     # Layer 7: Package & repo scanning
    │   ├── gates.ts            # Enforcement gates
    │   ├── stats.ts            # Detection statistics
    │   └── tests/              # 122 tests (vitest)
    ├── dist/                   # Compiled JavaScript
    └── node_modules/           # Runtime dependencies
```

## Configuration

Optional config file at `~/.privacy-shield/config.json`:

```json
{
  "allowlist_mode": true,
  "allowlist_preset": "development",
  "allowlist_extra": ["custom-tool"]
}
```

Presets: `development` (common dev tools), `read-only` (safe read commands only).

## Documentation

| Guide | Description |
|-------|-------------|
| [WINDOWS-SETUP.md](docs/WINDOWS-SETUP.md) | Step-by-step installation for Windows, PowerShell setup, common issues |
| [MACOS-SETUP.md](docs/MACOS-SETUP.md) | Step-by-step installation for macOS, Homebrew, Gatekeeper issues |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Allowlist mode, presets, custom commands, state files |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common errors and how to fix them |

## Requirements

- Node.js >= 18
- Claude Code with plugin support

## Disclaimer

Privacy Shield is provided **as-is** without warranty of any kind. It is a best-effort tool and does not guarantee complete protection against all security threats. It is not a substitute for proper security audits, penetration testing, or secure development practices.

The authors are not responsible for any damages, data loss, or security breaches that occur while using this software.

## License

MIT
