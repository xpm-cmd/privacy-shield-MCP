# Privacy Shield

A Claude Code plugin that provides 5-layer security protection through real-time hooks and 14 MCP tools.

## Installation

1. Copy the plugin to your Claude Code plugins cache:

```bash
mkdir -p ~/.claude/plugins/cache/local/privacy-shield/1.0.0
cp -r . ~/.claude/plugins/cache/local/privacy-shield/1.0.0/
```

2. Copy hidden files explicitly (dotfiles may be skipped by `cp -r`):

```bash
cp -r .claude-plugin ~/.claude/plugins/cache/local/privacy-shield/1.0.0/
cp .mcp.json ~/.claude/plugins/cache/local/privacy-shield/1.0.0/
```

3. Install server dependencies:

```bash
cd ~/.claude/plugins/cache/local/privacy-shield/1.0.0/server
npm install --omit=dev
```

4. Register the plugin in `~/.claude/plugins/installed_plugins.json` under the `"plugins"` key:

```json
"privacy-shield@local": [
  {
    "scope": "user",
    "installPath": "<absolute-path-to-cache>/local/privacy-shield/1.0.0",
    "version": "1.0.0",
    "installedAt": "2026-02-12T00:00:00.000Z",
    "lastUpdated": "2026-02-12T00:00:00.000Z"
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

Blocks dangerous shell commands before execution:

| Category | Patterns |
|---|---|
| Destructive | `rm -rf /`, fork bombs, `mkfs`, `dd of=/dev/` |
| Remote execution | `curl \| bash`, `wget \| python` |
| Reverse shells | `bash -i >& /dev/tcp`, `nc -e /bin/bash` |
| Exfiltration | `cat .env \| curl`, `base64 \| curl`, `tar \| nc` |
| Firewall disable | `iptables -F`, `ufw disable` |

### File Operation Validation

Blocks writes to sensitive files and detects dangerous code patterns in source files. Read operations are always allowed. Documentation files (.md, .txt, .json, .yml, etc.) are excluded from content scanning to avoid false positives.

**Path-based blocks** (Write/Edit/MultiEdit):

| Category | Files |
|---|---|
| Environment | `.env`, `.env.local`, `.env.production` |
| SSH | `id_rsa`, `id_ed25519`, `authorized_keys`, `.ssh/config` |
| Certificates | `.pem`, `.pfx`, `.p12` |
| Cloud credentials | `.aws/credentials`, `.docker/config.json`, `.kube/config` |
| Auth configs | `.netrc`, `.npmrc`, `.pypirc` |
| Secrets | `wallet.dat`, `.gnupg/*.key`, `.password-store/`, `.config/gh/hosts.yml` |

**Content-based blocks** (scans source code being written):

| Pattern | Risk |
|---|---|
| `${{ github.event.* }}` in workflow files | GitHub Actions injection |
| `child_process.exec`, `execSync` | Command injection |
| `new Function()`, `eval()` | Code injection |
| `dangerouslySetInnerHTML`, `document.write`, `.innerHTML =` | XSS |
| `pickle.load`, `pickle.loads` | Unsafe deserialization |
| `os.system()`, `subprocess(shell=True)` | Shell injection |
| f-string SQL queries | SQL injection |
| Hardcoded passwords, secrets, API keys | Credential exposure |

### WebFetch Validation

Blocks outbound requests to dangerous destinations:

| Category | Examples |
|---|---|
| Exfiltration endpoints | `pastebin.com/raw`, `webhook.site`, `requestbin`, `ngrok`, `pipedream` |
| URL shorteners | `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `is.gd` (14 total) |
| Dangerous protocols | `javascript:`, `vbscript:`, `data:text/html:` |
| High-risk TLDs | `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.buzz`, `.zip`, `.mov` |

### Permission Context Injection

When Claude requests permission for a tool, the hook injects a prompt requiring Claude to explain what the action does, why it is necessary, what it affects, and whether it is reversible.

## MCP Tools (On-Demand Analysis)

### Layer 1: Privacy

| Tool | Description |
|---|---|
| `scan_privacy` | Detects PII, API keys, SSH keys, JWTs, passwords |
| `check_file_sensitivity` | Checks if a file path is sensitive |
| `redact_text` | Returns text with sensitive data replaced by placeholders |
| `full_security_scan` | Runs all 4 analysis layers at once |

### Layer 2: Network

| Tool | Description |
|---|---|
| `validate_urls` | Detects shorteners, malicious domains, phishing, typosquatting |
| `check_domain` | Checks if a domain is safe for data sending |

### Layer 3: Execution

| Tool | Description |
|---|---|
| `analyze_command` | Detects dangerous bash patterns |
| `detect_prompt_injection` | Identifies jailbreak and prompt injection attempts |
| `scan_code` | Detects unsafe code patterns (eval, exec, XSS, deserialization) |

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

The audit log persists at `~/.privacy-shield/audit.jsonl` across sessions.

## Plugin Structure

```
privacy-shield/
├── .claude-plugin/
│   └── plugin.json          # Plugin manifest
├── .mcp.json                # MCP server definition
├── hooks/
│   └── hooks.json           # Hook event configuration
├── scripts/
│   ├── hook-pre-bash.sh     # Bash command validator
│   ├── hook-pre-file.js     # File path + content validator
│   ├── hook-pre-file.sh     # Legacy file path validator (bash)
│   ├── hook-pre-web.sh      # URL validator
│   ├── hook-permission.js   # Permission context injector
│   └── parse-input.js       # Shared JSON field extractor
└── server/
    ├── package.json          # Node.js module config
    ├── dist/                 # Compiled MCP server (14 tools)
    └── node_modules/         # Runtime dependencies
```

## Requirements

- Node.js >= 18
- Claude Code with plugin support

## License

MIT
