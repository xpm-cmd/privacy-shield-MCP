# Privacy Shield MCP — Installation on macOS

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| macOS | 12 Monterey | 14 Sonoma+ |
| Node.js | 18.0.0 | 20 LTS |
| Claude Code | Latest | Latest |

> **Apple Silicon (M1/M2/M3):** Fully supported. Node.js runs natively — no Rosetta 2 required.

---

## Step 1: Verify Node.js

```bash
node --version
# Should show v18.x.x or higher

npm --version
# Should show 8.x or higher
```

If Node.js is not installed, use Homebrew:

```bash
brew install node@20
```

Or download the LTS installer from [nodejs.org](https://nodejs.org).

---

## Step 2: Clone the repository

```bash
git clone https://github.com/xpm-cmd/privacy-shield-MCP.git
cd privacy-shield-MCP
```

---

## Step 3: Install dependencies and build

```bash
cd server
npm install --omit=dev
npm run build
```

> **Note:** If `npm audit` reports vulnerabilities, run:
> ```bash
> npm audit fix
> npm run build
> ```

---

## Step 4: Install the plugin

```bash
DEST="$HOME/.claude/plugins/cache/local/privacy-shield/2.0.0"
mkdir -p "$DEST"

# Copy all files including dotfiles
cp -r . "$DEST/"
cp -r .claude-plugin "$DEST/"
cp .mcp.json "$DEST/"
```

> **Important:** The `cp -r .` command may skip dotfiles. The two explicit copies above ensure `.claude-plugin/` and `.mcp.json` are included.

---

## Step 5: Register the plugin in Claude Code

### 5a. Edit `installed_plugins.json`

Open `~/.claude/plugins/installed_plugins.json` and add:

```json
"privacy-shield@local": [
  {
    "scope": "user",
    "installPath": "/Users/YOUR_USERNAME/.claude/plugins/cache/local/privacy-shield/2.0.0",
    "version": "2.0.0",
    "installedAt": "2026-01-01T00:00:00.000Z",
    "lastUpdated": "2026-01-01T00:00:00.000Z"
  }
]
```

Replace `YOUR_USERNAME` with your actual macOS username (`echo $USER`).

### 5b. Enable in `settings.json`

Edit `~/.claude/settings.json` and add to `enabledPlugins`:

```json
{
  "enabledPlugins": {
    "privacy-shield@local": true
  }
}
```

---

## Step 6: Verify the installation

**Restart Claude Code** and test by running in the chat:

```
Use the full_security_scan tool with the text "password=test123"
```

If Privacy Shield is active, you should see a security analysis response.

---

## Common Issues on macOS

### "permission denied" when running hook scripts

```bash
# Fix permissions on hook scripts:
chmod +x ~/.claude/plugins/cache/local/privacy-shield/2.0.0/scripts/*.js
```

### "node: command not found" in hooks

Hooks run in a minimal shell environment. If Node.js is installed via Homebrew, add it to your PATH:

```bash
# Add to ~/.zshrc or ~/.bash_profile:
export PATH="/opt/homebrew/bin:$PATH"          # Apple Silicon
export PATH="/usr/local/bin:$PATH"             # Intel Mac
```

Then restart Claude Code.

### Gatekeeper blocks the plugin

macOS may quarantine downloaded files. If you see a "cannot be opened because the developer cannot be verified" error:

```bash
# Remove quarantine from the plugin directory:
xattr -r -d com.apple.quarantine ~/.claude/plugins/cache/local/privacy-shield/
```

### Privacy Shield tools don't appear in Claude Code

1. Verify `installed_plugins.json` uses the **full absolute path** (not `~` or relative paths)
2. Verify `dist/index.js` exists in `server/`:
   ```bash
   ls ~/.claude/plugins/cache/local/privacy-shield/2.0.0/server/dist/
   ```
3. Restart Claude Code completely (Cmd+Q, then reopen)

### Hook doesn't block dangerous commands

Check that `hooks/hooks.json` has the correct matchers:

```json
{
  "hooks": [
    {
      "event": "PreToolUse",
      "matchers": [{"tool_name": "Bash"}],
      "command": "node ${CLAUDE_PLUGIN_ROOT}/scripts/hook-pre-bash.js"
    }
  ]
}
```

---

## Uninstalling Privacy Shield

```bash
# 1. Remove from installed_plugins.json and enabledPlugins in settings.json

# 2. Remove plugin files:
rm -rf ~/.claude/plugins/cache/local/privacy-shield/

# 3. Remove session data (optional):
rm -rf ~/.privacy-shield/
```

---

## File Paths on macOS

| File | Location |
|------|----------|
| User config | `~/.privacy-shield/config.json` |
| Audit log | `~/.privacy-shield/audit.jsonl` |
| Statistics | `~/.privacy-shield/stats.json` |
| Plugin cache | `~/.claude/plugins/cache/local/privacy-shield/` |
| Claude settings | `~/.claude/settings.json` |

### Recommended permissions

```bash
chmod 700 ~/.privacy-shield/
chmod 600 ~/.privacy-shield/audit.jsonl
chmod 600 ~/.privacy-shield/config.json
```
