#!/usr/bin/env node
// Privacy Shield - Shared message formatter for hook scripts
// Auto-detects system language and renders visual box-style warnings

const WIDTH = 56;
const LINE = '─'.repeat(WIDTH);

// ── Language detection ──────────────────────────────────────
// Priority: Intl API → LANG env var → LANGUAGE env var → default English
function detectLang() {
  try {
    const locale =
      Intl.DateTimeFormat().resolvedOptions().locale ||   // Node.js Intl (most reliable)
      process.env.LANG ||                                  // Unix/Linux/macOS
      process.env.LANGUAGE ||                              // Linux secondary
      process.env.LC_MESSAGES ||                           // Linux tertiary
      '';
    return locale.toLowerCase().startsWith('es') ? 'es' : 'en';
  } catch {
    return 'en';
  }
}

const LANG = detectLang();

// ── Translations ────────────────────────────────────────────
const T = {
  block: { en: '🛡 BLOCKED',  es: '🛡 BLOQUEADO'   },
  warn:  { en: '⚠ WARNING',  es: '⚠ ADVERTENCIA'  },
  info:  { en: 'ℹ INFO',     es: 'ℹ INFO'          },
  reason:{ en: 'Reason:',    es: 'Motivo:'         },
  action:{ en: 'Action:',    es: 'Acción:'         },
};

/**
 * Translate a message pair based on detected system language.
 * Usage: t('mensaje en español', 'message in English')
 * @param {string} es - Spanish string
 * @param {string} en - English string
 * @returns {string}
 */
function t(es, en) {
  return LANG === 'es' ? es : en;
}

/**
 * Print a Privacy Shield block/warning box to stderr.
 * Labels (Reason/Action) are auto-translated based on system locale.
 *
 * @param {'block'|'warn'|'info'} type - Severity level
 * @param {string} title               - Short summary (caller provides already-translated string)
 * @param {string} [reason]            - Why it was blocked/warned
 * @param {string} [solution]          - How to proceed or fix
 */
function printBox(type, title, reason, solution) {
  const icon   = (T[type] || T.block)[LANG];
  const label  = '  PRIVACY-SHIELD';
  const header = `${label} ${LINE.slice(label.length + 1)}`;

  const lines = [`${icon}: ${title}`];
  if (reason)   lines.push(`${T.reason[LANG]}   ${reason}`);
  if (solution) lines.push(`${T.action[LANG]}   ${solution}`);

  const out = [
    `\n${header}`,
    ...lines.map(l => `  ${l}`),
    `  ${LINE}\n`,
  ].join('\n');

  process.stderr.write(out);
}

module.exports = { printBox, t, LANG, LINE, WIDTH };
